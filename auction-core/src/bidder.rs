use core::num;
use std::sync::Arc;

use elastic_elgamal::PublicKey;
use k256::{
    elliptic_curve::{ops::MulByGenerator, Field},
    ProjectivePoint, Scalar,
};
use rand::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};
use tokio::{sync::{self, Mutex, RwLock}, task};
use crate::{bidder, brandt::{AuctionParams, BidderShare, Delta, EncBidVector, Gamma, Phi, make_onehot_bid}, channel::{self, AuctionChannel, create_envelope}, elgamal::K256Group, error::AuctionError, proof::SecretKeyProof, seller::BidCollationFinalization, serde::projective_point};

use crate::{
    brandt::BidVector,
    channel::{
        MessageEnvelope,
    },
};

#[derive(Clone, Serialize, Deserialize)]
pub struct BidKeyAnnouncement {
    #[serde(with = "projective_point")]
    pub public_key: ProjectivePoint,
    pub proof_of_knowledge: SecretKeyProof,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct BidVectorAnnouncement {
    #[serde(with = "projective_point")]
    pub public_key: ProjectivePoint,
    pub enc_bits: EncBidVector, // length = K
    pub enc_bits_proofs: Vec<elastic_elgamal::RingProof<K256Group>>, // length = K
}

#[derive(Clone, Serialize, Deserialize)]
pub struct BidPartialMessage {
    #[serde(with = "projective_point::vec")]
    pub phi: Phi 
}

#[derive(Clone, Serialize, Deserialize)]
pub struct BidShareAnnoucement {
    #[serde(with = "projective_point")]
    pub public_key: ProjectivePoint,
    pub blinded_share: BidderShare,

}

/// Represents a bidder participating in the auction protocol.
pub struct Bidder<Channel: AuctionChannel + Clone> {
    secret_key: Scalar,
    public_key: ProjectivePoint,
    bid_state: Arc<Mutex<BidState>>,
    auction_params: AuctionParams,
    auction_channel: Channel,
    bidding_handler: task::JoinHandle<()>,
}

pub struct AuctionState {
    bidders_keys: Vec<ProjectivePoint>,
    bidders_bid_list: Vec<EncBidVector>,
    blinded_bidder_share_list: Vec<BidderShare>,
    phi: Option<Phi>,
}

pub struct BidState {
    pub group_public_key: PublicKey<K256Group>,
    pub bid_vector: Option<BidVector>,
    pub bid_status: BidStatus,
    pub bid_amount: u64,
}

#[derive(Clone, PartialEq, PartialOrd)]
pub enum BidStatus {
    NotStarted,
    BidKeyAnnoucement,
    BidVectorAnnounced,
    BidShareAnnounced,
    BidPartialsSubmitted,
    Finished,
}



impl<Channel: AuctionChannel + Clone + Send + 'static> Bidder<Channel> {
    pub fn new<R: RngCore + CryptoRng + Send + 'static>(mut rng: R, auction_channel: Channel, auction_params: AuctionParams ) -> Self {
        let secret_key = Scalar::random(&mut rng);
        let public_key = ProjectivePoint::mul_by_generator(&secret_key);

        let bid_state = Arc::new(Mutex::new(BidState {
            group_public_key: K256Group::to_public_key(&ProjectivePoint::IDENTITY),
            bid_vector: None,
            bid_status: BidStatus::NotStarted,
            bid_amount: 0,
        }));

        // Clone values for the spawned task to avoid moving the originals.
        let bid_state_task = Arc::clone(&bid_state);
        let auction_channel_task = auction_channel.clone();
        let auction_params_task = auction_params.clone();
        let secret_key_task = secret_key.clone();
        let public_key_task = public_key.clone();

        let bidding_handler = tokio::spawn(async move {
            run_loop(rng, secret_key_task, public_key_task, bid_state_task, auction_channel_task, auction_params_task).await;
        });

        Self {
            secret_key,
            public_key,
            bid_state,
            auction_params,
            auction_channel,
            bidding_handler,
        }
    }


    pub async fn initiaite_bidding<R: RngCore + CryptoRng>(&mut self, rng: &mut R, bid_amount: u64) -> Result<(), AuctionError > {

        let proof_of_knowledge = SecretKeyProof::new(&self.secret_key, &self.public_key, rng);

        let dkg_message = BidKeyAnnouncement {
            public_key: self.public_key,
            proof_of_knowledge,
        };
        let message_envelope  = create_envelope("BidKeyAnnouncement", dkg_message).unwrap();
        self.auction_channel.send_broadcast_message(message_envelope).await.map_err(|err| AuctionError::BroadcastError(err))?;

        let mut bid_state = self.bid_state.lock().await;
        bid_state.bid_amount = bid_amount;
        bid_state.bid_status = BidStatus::BidKeyAnnoucement;
        
        Ok(())
    }

}


pub async fn run_loop<Channel: AuctionChannel + Clone + Send + 'static, R: RngCore + CryptoRng + Send + 'static>(mut rng: R, secret_key: Scalar, public_key: ProjectivePoint, bid_state: Arc<Mutex<BidState>>, auction_channel: Channel, auction_params: AuctionParams) {
    let auction_state = Arc::new(RwLock::new(AuctionState {
        bidders_keys: Vec::new(),
        bidders_bid_list: Vec::new(),
        blinded_bidder_share_list: Vec::new(),
        phi: None,
    }));

    let num_bidders = auction_params.num_bidders as usize; 
        
    while let Ok(msg) = auction_channel.receive_broadcast_message().await {
        let mut auction_state = auction_state.write().await;
        let mut bid_state = bid_state.lock().await;

        if let Ok(dkg_announcement) = msg.decode::<BidKeyAnnouncement>() {
           
            let  bidders_keys = &mut auction_state.bidders_keys;
             if bidders_keys.len() >= num_bidders {
                println!("All bidders' keys have been received.");
                continue;
            }
            bidders_keys.push(dkg_announcement.public_key);
            if bidders_keys.len() == num_bidders {
                // Sum all public keys
                let sum = bidders_keys.iter().fold(ProjectivePoint::IDENTITY, |acc, pk| acc + pk);
                let group_pk = K256Group::to_public_key(&sum);
                bid_state.group_public_key = group_pk.clone();
               

                let bid_vector = make_onehot_bid(& mut rng, secret_key, public_key, &group_pk, &auction_params, bid_state.bid_amount);
                bid_state.bid_vector = Some(bid_vector.clone()); 

                 let bid_announcement = BidVectorAnnouncement {
                    public_key,
                    enc_bits: bid_vector.enc_bits.clone(),
                    enc_bits_proofs: bid_vector.enc_bits_proofs.clone(),
                };

                auction_state.bidders_bid_list.push(bid_vector.enc_bits.clone());
                auction_state.bidders_keys.push(public_key);

                let envelope = create_envelope("BidAnnouncement", bid_announcement).unwrap();
                let res = auction_channel.send_broadcast_message(envelope).await.map_err(|err| AuctionError::BidPublishErr(err));
                if !res.is_ok() {
                    println!("Bid Announcement Error");
                    continue;
                }

                bid_state.bid_status = BidStatus::BidVectorAnnounced;

            }
        }
        if let Ok(bid_announcement) = msg.decode::<BidVectorAnnouncement>() {
            let bidders_bid_list = &mut auction_state.bidders_bid_list;
             
            if bidders_bid_list.len() >= num_bidders {
                println!("All bidders' bids have been received.");
                continue;
            }
            bidders_bid_list.push(bid_announcement.enc_bits);
            let bid_vector = match &bid_state.bid_vector {
                Some(bv) => bv,
                None => {
                    println!("Bid vector not set yet.");
                    continue;
                }
            };
            if bidders_bid_list.len() == num_bidders {
                println!("All bidders' bids have been received.");
                let bidder_share= &bid_vector.compute_bidder_share(
                    &bidders_bid_list.clone(),
                    &bid_state.group_public_key,
                ); 
                let bid_collation_announcement = BidShareAnnoucement {
                    public_key: public_key.clone(),
                    blinded_share: bidder_share.clone(),
                };
                let envelope = create_envelope("BidCollationAnnouncement", bid_collation_announcement).unwrap();
                let res = auction_channel.send_broadcast_message(envelope).await;
                if !res.is_ok() {
                    println!("Bid Collation Error");
                    continue;
                }
               bid_state.bid_status = BidStatus::BidShareAnnounced;
               auction_state.blinded_bidder_share_list.push(bidder_share.clone());
            }
        }
        if let Ok(bid_collation_announcement) = msg.decode::<BidShareAnnoucement>() {
            let blinded_bidder_share_list = &mut auction_state.blinded_bidder_share_list; 
            let bid_vector = match &bid_state.bid_vector {
                Some(bv) => bv,
                None => {
                    println!("Bid vector not set yet.");
                    continue;
                }
            }; 
            if blinded_bidder_share_list.len() >= num_bidders {
                println!("All bidders' bid collation have been received.");
                continue;
            }
            blinded_bidder_share_list.push(bid_collation_announcement.blinded_share);                    
            if blinded_bidder_share_list.len() == num_bidders {
                let all_deltas = blinded_bidder_share_list.iter().map(|sh| sh.delta.clone()).collect::<Vec<_>>();
                let phi = &bid_vector.derive_phi(&all_deltas);
                let phi_message = BidPartialMessage {
                    phi: phi.clone()
                };
                let envelope = create_envelope("PhiMessage", phi_message).unwrap();
                let res = auction_channel.send_direct_message(envelope).await;
                if !res.is_ok() {
                    println!("Direct Message Error");
                    continue;
                }
                bid_state.bid_status = BidStatus::BidPartialsSubmitted
            }
        }
        if let Ok(bid_collation_finalization) =  msg.decode::<BidCollationFinalization>() {
             let blinded_bidder_share_list = &mut auction_state.blinded_bidder_share_list; 
            let bid_vector = match &bid_state.bid_vector {
                Some(bv) => bv,
                None => {
                    println!("Bid vector not set yet.");
                    continue;
                }
            }; 
            let gamma_list: Vec<Vec<ProjectivePoint>> = blinded_bidder_share_list.iter().map(|sh| sh.delta.clone()).collect::<Vec<_>>();
            let phi_list = bid_collation_finalization.collated_phi;
            let is_winner = bid_vector.is_winner(&phi_list, &gamma_list);
            if is_winner {
                println!("I am a fucking winner")
            }
        }
    }
}
        

    
