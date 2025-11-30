use std::{collections::{BTreeSet, HashSet}, net::SocketAddr};

use crate::{
    bidder::{BidPartialMessage, BidShareAnnouncement},
    brandt::{AuctionParams, derive_bidder_phi_matrix},
    channel::{AuctionChannel, GrpcSellerChannel, allowlist_from_keys, create_envelope},
    error::AuctionError,
    types::BidderPhiMatrix,
};
use k256::{ProjectivePoint, elliptic_curve::{Field, ops::MulByGenerator}, schnorr::{SigningKey as SchnorrSigningKey, VerifyingKey as SchnorrVerifyingKey}};
use serde::{Deserialize, Serialize};
use crate::serde::{projective_point, projective_point::vec_vec};
use k256::Scalar;
use tokio::task;
use rand_core::RngCore;
use rand_core::CryptoRng;
use crate::types::Phi;

#[derive(Clone, Serialize, Deserialize)]
pub struct BidCollationFinalization {
    pub collated_phi: Vec<BidderWinningMatrix>,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct BidderWinningMatrix {
    #[serde(with = "projective_point")]
    pub public_key: ProjectivePoint,
    #[serde(with = "projective_point::vec_vec")]
    pub matrix: Vec<Vec<ProjectivePoint>>,
}

pub struct Seller {
    auction_params: AuctionParams,
    auction_channel: GrpcSellerChannel,
    collation_handler: task::JoinHandle<()>,
}



pub enum SellerState {
    AwaitingBids,
    BidsFinalized,
    WinnerDetected,
}



impl Seller {
    pub async fn new<R: RngCore + CryptoRng + Send + 'static>(
         mut rng: R,
        addr: SocketAddr,
        auction_params: AuctionParams) -> Self {
            let secret_key= Scalar::random(&mut rng);

            let secret_key_bytes = secret_key.to_bytes();
            let signing_key =
                SchnorrSigningKey::from_bytes(&secret_key_bytes).expect("invalid secret key bytes");

            let auction_channel= GrpcSellerChannel::serve(addr, signing_key, HashSet::new())
                .await
                .expect("failed to start gRPC seller channel");

            let selling_handler = task::spawn(run_seller(auction_params.clone(), auction_channel.clone()));

            Self {
                auction_params,
                auction_channel,
                collation_handler: selling_handler,
            }
        }
    
}

/// Seller loop: collects direct phi messages from bidders and broadcasts
/// a finalization once all `num_bidders` have been received.
pub async fn run_seller<C>(
    auction_params: AuctionParams,
    channel: C,
) 
where
    C: AuctionChannel + Clone + Send + Sync + 'static,
{
    let mut phi_set: BTreeSet<BidderPhiMatrix> = BTreeSet::new();
    let mut bidder_share_set: BTreeSet<crate::types::BidderShareMatrix> = BTreeSet::new();
    let num_bidders = auction_params.num_bidders as usize;

    loop {
        tokio::select! {
            direct_msg = channel.receive_direct_message() => {
                let msg = match direct_msg {
                    Ok(msg) => msg,
                    Err(_) => continue,
                };
                if let Ok(partial) = msg.decode::<BidPartialMessage>() {
                    phi_set.insert(partial.phi_matrix);
                }
            }
            broadcast_msg = channel.receive_broadcast_message() => {
                let msg = match broadcast_msg {
                    Ok(msg) => msg,
                    Err(_) => continue,
                };
                if let Ok(share) = msg.decode::<BidShareAnnouncement>() {
                    bidder_share_set.insert(share.blinded_share);
                }
            }
        }

        if phi_set.len() == num_bidders && bidder_share_set.len() == num_bidders {
            let mut bidders_winning_matrices: Vec<BidderWinningMatrix> = Vec::new();
            let phi_list = phi_set.iter().cloned().collect::<Vec<_>>();
            let bidder_share_list = bidder_share_set.iter().cloned().collect::<Vec<_>>();
            for bidder_phi in &phi_list {
                let winning_matrix = derive_bidder_phi_matrix(
                    phi_list.clone(),
                    &auction_params,
                    bidder_phi.public_key,
                    bidder_share_list.clone(),
                );
                bidders_winning_matrices.push(BidderWinningMatrix {
                    public_key: bidder_phi.public_key,
                    matrix: winning_matrix,
                });
            }
            let envelope = create_envelope("BidCollationFinalization", BidCollationFinalization {
                collated_phi: bidders_winning_matrices,
            })
                .map_err(|err| AuctionError::Other(err.to_string())).unwrap();
            channel
                .send_broadcast_message(envelope)
                .await
                .map_err(AuctionError::BroadcastError).unwrap();
            break;
        }
    }

}
