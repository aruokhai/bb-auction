use std::{collections::{BTreeSet, HashSet}, iter::Once, sync::Arc};

use crate::{
    bidder, brandt::{
        AuctionParams, BidVector, derive_bidder_gamma_matrix, derive_bidder_phi_matrix, is_winner, make_onehot_bid
    }, channel::{AuctionChannel, GrpcBidderChannel, allowlist_from_keys, create_envelope}, elgamal::PublicKey, error::AuctionError, seller::BidCollationFinalization, serde::projective_point, types::{BidderPhiMatrix, BidderShareMatrix, EncBidVector}
};
use k256::{
    ProjectivePoint, Scalar, SecretKey, elliptic_curve::{Field, ScalarPrimitive, ops::MulByGenerator, scalar}
};
use k256::schnorr::{SigningKey as SchnorrSigningKey, VerifyingKey as SchnorrVerifyingKey};
use rand::{CryptoRng, Rng, RngCore};
use serde::{Deserialize, Serialize};
use tokio::{sync::{Mutex, RwLock, SetOnce, mpsc, oneshot, watch}, task};

#[derive(Clone, Serialize, Deserialize)]
pub struct BidKeyAnnouncement {
    #[serde(with = "projective_point")]
    pub public_key: ProjectivePoint,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct BidVectorAnnouncement {
    #[serde(with = "projective_point")]
    pub public_key: ProjectivePoint,
    pub enc_bits: EncBidVector, // length = K
}

#[derive(Clone, Serialize, Deserialize)]
pub struct BidShareAnnouncement {
    #[serde(with = "projective_point")]
    pub public_key: ProjectivePoint,
    pub blinded_share: BidderShareMatrix,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct BidPartialMessage {
    pub phi_matrix: BidderPhiMatrix,
}

pub struct Bidder {
    secret_key: Scalar,
    public_key: ProjectivePoint,
    auction_state: Arc<RwLock<BidState>>,
    auction_channel: GrpcBidderChannel,
    bidding_handler: task::JoinHandle<()>,
    bid_tx: Option<oneshot::Sender<(AuctionParams, BidAmount)>>,
    bid_state_rx: watch::Receiver<BidState>,
}


type GroupPubKey = PublicKey;

#[derive(Clone)]
pub enum BidState {
    NotStarted,
    BidKeyAnnounced(ProjectivePoint),
    BidVectorAnnounced(GroupPubKey, BidVector),
    BidShareAnnounced(BidderShareMatrix),
    BidPartialsSubmitted(BidderPhiMatrix),
    Finished(bool),
}

pub type BidAmount = u64;

impl Bidder {
    pub async fn new<R: RngCore + CryptoRng + Send + 'static>(
        mut rng: R,
        seller_endpoint: String,
        
    ) -> Self {
        let secret_key = Scalar::random(&mut rng);
        let public_key = ProjectivePoint::mul_by_generator(&secret_key);

        let secret_key_bytes = secret_key.to_bytes();
        let signing_key =
            SchnorrSigningKey::from_bytes(&secret_key_bytes).expect("invalid secret key bytes");
        let auction_channel = GrpcBidderChannel::connect(
            seller_endpoint,
            format!("{:?}", public_key),
            signing_key,
            HashSet::new(),
        ).await.unwrap();

        let (bid_state_tx, _bid_state_rx) = watch::channel(BidState::NotStarted);
        let (one_tx, one_rx) = oneshot::channel::<(AuctionParams, BidAmount)>();

        let channel = auction_channel.clone();
        let runner_secret_key = secret_key.clone();
        let runner_public_key = public_key.clone();
        let bidding_handler = task::spawn(run(
            rng,
            channel,
            runner_secret_key,
            runner_public_key,
            one_rx,
            bid_state_tx,
        ));

        Self {
            secret_key,
            public_key,
            auction_channel,
            auction_state: Arc::new(RwLock::new(BidState::NotStarted)),
            bidding_handler,
            bid_tx: Some(one_tx),
            bid_state_rx: _bid_state_rx,

        }
    }

    pub async fn initiate_bid(&mut self, params: AuctionParams, amount: BidAmount) {
        let bid_one_shot = self.bid_tx.take();
        bid_one_shot.unwrap().send((params, amount));

        let auction_state = self.auction_state.clone();
        let bidder_state_rx = self.bid_state_rx.clone();
        tokio::spawn(async move {
            while bidder_state_rx.clone().changed().await.is_ok() {
                let new_state = bidder_state_rx.borrow().clone();
                let mut state_guard = auction_state.write().await;
                *state_guard = new_state;
            }
        });
  
    }

    pub fn public_key(&self) -> ProjectivePoint {
        self.public_key
    }
}

fn aggregate_public_key(keys: &[ProjectivePoint]) -> ProjectivePoint {
    keys.iter()
        .fold(ProjectivePoint::IDENTITY, |acc, pk| acc + pk)
}



async fn run<R:RngCore + CryptoRng + Send>(
    mut rng: R,
    channel: GrpcBidderChannel,
    secret_key: Scalar,
    public_key: ProjectivePoint,
    bid_details: oneshot::Receiver<(AuctionParams, BidAmount)>,
    bid_state_tx: watch::Sender<BidState>,
) {
    
    let bidders_keys = Arc::new(Mutex::new(Vec::new()));
    let bidders_bid_list = Arc::new(Mutex::new(BTreeSet::new()));
    let bidder_share_list = Arc::new(Mutex::new(BTreeSet::new()));
    let maybe_bid_vector: SetOnce<BidVector> =  SetOnce::const_new();
    
    let (auction_params, bid_amount) = bid_details.await.unwrap();

    while let Ok(msg) = channel.receive_broadcast_message().await {
        if let Ok(announcement) = msg.decode::<BidKeyAnnouncement>() {
                let mut keys = bidders_keys.lock().await;
                if !keys.iter().any(|pk| pk == &announcement.public_key) {
                    keys.push(announcement.public_key);
                }
                // When all keys gathered, compute bid vector and announce it once.
                if keys.len() as u64 == auction_params.num_bidders {
                    let group_pk_point = aggregate_public_key(&keys);
                    let group_pk = crate::elgamal::K256Group::to_public_key(&group_pk_point);
                    let bid_vector = make_onehot_bid(
                        &mut rng,
                        secret_key,
                        public_key,
                        &group_pk,
                        &auction_params,
                        bid_amount,
                    );
                    let clone_enc = bid_vector.enc_bits.clone();
                    let mut bids = bidders_bid_list.lock().await;
                    bids.insert(clone_enc.clone());

                    let bid_env = create_envelope(
                        "BidVectorAnnouncement",
                        BidVectorAnnouncement {
                            public_key: public_key,
                            enc_bits: clone_enc,
                        },
                    )
                    .map_err(|err| AuctionError::Other(err.to_string())).unwrap();

                    channel
                        .send_broadcast_message(bid_env)
                        .await
                        .map_err(|err| AuctionError::BroadcastError(err)).unwrap();

                    maybe_bid_vector.set(bid_vector.clone());
                    bid_state_tx.send(BidState::BidVectorAnnounced(group_pk, bid_vector.clone())).unwrap();
                }
            }

            if let Ok(bid_message) = msg.decode::<BidVectorAnnouncement>() {
                let mut bids = bidders_bid_list.lock().await;
                bids.insert(bid_message.enc_bits);

                if bids.len() as u64 == auction_params.num_bidders {
                    let bid_vector = maybe_bid_vector.wait().await;
                    let shares = bid_vector.compute_bidder_share(&mut rng, bids.clone()).unwrap();
                    let mut share_set = bidder_share_list.lock().await;
                    share_set.insert(shares.clone());

                    let share_env = create_envelope(
                        "BidShareAnnouncement",
                        BidShareAnnouncement {
                            public_key: public_key,
                            blinded_share: shares.clone(),
                        },
                    )
                    .map_err(|err| AuctionError::Other(err.to_string())).unwrap();

                    channel
                        .send_broadcast_message(share_env)
                        .await
                        .map_err(|err| AuctionError::BroadcastError(err)).unwrap();

                    bid_state_tx.send(BidState::BidShareAnnounced(shares)).unwrap();
                }
            }

            if let Ok(share_message) = msg.decode::<BidShareAnnouncement>() {
                let mut share_set = bidder_share_list.lock().await;
                share_set.insert(share_message.blinded_share);

                if share_set.len() as u64 == auction_params.num_bidders  {

                    let bids = bidders_bid_list.lock().await;
                    let bid_vector = maybe_bid_vector.wait().await;
                    let phi = bid_vector.derive_phi(&mut rng, share_set.clone(), bids.clone());

                    let phi_env = create_envelope(
                        "BidPartialMessage",
                        BidPartialMessage { phi_matrix: phi.clone() },
                    )
                    .map_err(|err| AuctionError::Other(err.to_string())).unwrap();

                    channel
                        .send_direct_message(phi_env)
                        .await
                        .map_err(|err| AuctionError::BroadcastError(err)).unwrap();

                    bid_state_tx.send(BidState::BidPartialsSubmitted(phi)).unwrap()

                }
            } 

            if let Ok(finalization) = msg.decode::<BidCollationFinalization>() {
                // Compute winner flag.
                let bidder_gamma_matrix = derive_bidder_gamma_matrix(
                    bidder_share_list.lock().await.clone().into_iter().collect(),
                    &auction_params,
                    public_key,
                );
                for winner_phi in finalization.collated_phi.iter() {
                    if winner_phi.public_key != public_key {
                        continue;
                    }
                    let winner_bool =  is_winner(&winner_phi.matrix, bidder_gamma_matrix) ;
                    bid_state_tx.send(BidState::Finished(winner_bool)).unwrap();
                    break;
                }
                bid_state_tx.send(BidState::Finished(false)).unwrap();
                break;

                
            }
    }

}


