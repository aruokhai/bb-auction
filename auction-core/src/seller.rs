use std::{collections::BTreeSet, net::SocketAddr};

use crate::{
    bidder::BidPartialMessage,
    brandt::AuctionParams,
    channel::{allowlist_from_keys, create_envelope, AuctionChannel, GrpcSellerChannel},
    error::AuctionError,
    types::BidderPhiMatrix,
};
use k256::{ProjectivePoint, schnorr::{SigningKey as SchnorrSigningKey, VerifyingKey as SchnorrVerifyingKey}};
use serde::{Deserialize, Serialize};
use crate::serde::{projective_point, projective_point::vec_vec};

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

// pub struct Seller<Channel: AuctionChannel + Clone> {
//     auction_params: AuctionParams,
//     auction_channel: GrpcSellerChannel,
//     collation_handler: Arc<Mutex<Option<task::JoinHandle<()>>>>,
//     // loop_events_tx: SellerEventSender,
//     events_tx: SellerEventSender,
//     events_rx: Mutex<Option<SellerEventReceiver>>,
// }

// pub struct AuctionState {
//     phi_list: Vec<Phi>,
// }

// pub enum SellerState {
//     AwaitingBids,
//     BidsFinalized,
//     WinnerDetected,
// }

// #[derive(Debug, Clone)]
// pub enum SellerEvent {
//     Info(&'static str),
//     Error(&'static str),
//     CollationFinalized(BidCollationFinalization),
// }

// /// Seller loop: collects direct phi messages from bidders and broadcasts
// /// a finalization once all `num_bidders` have been received.
// pub async fn run_seller<Channel: AuctionChannel + Send + Sync + 'static>(
//     auction_params: AuctionParams,
//     auction_channel: Channel,
// ) -> Result<(), AuctionError> {
//     let mut phi_list: BTreeSet<BidderPhiMatrix> = BTreeSet::new();
//     let num_bidders = auction_params.num_bidders as usize;

//     loop {
//         let msg = auction_channel
//             .receive_direct_message()
//             .await
//             .map_err(AuctionError::BroadcastError)?;

//         if let Ok(partial) = msg.decode::<BidPartialMessage>() {
//             phi_list.insert(partial.phi_matrix);
//             if phi_list.len() == num_bidders {
//                 let finalization = BidCollationFinalization {
//                     collated_phi: phi_list.clone().into_iter().collect(),
//                 };
//                 let envelope = create_envelope("BidCollationFinalization", finalization)
//                     .map_err(|err| AuctionError::Other(err.to_string()))?;
//                 auction_channel
//                     .send_broadcast_message(envelope)
//                     .await
//                     .map_err(AuctionError::BroadcastError)?;
//                 break;
//             }
//         }
//     }

//     Ok(())
// }

// /// Starts the gRPC seller gateway and runs the auction loop using it as
// /// the underlying transport.
// pub async fn serve_grpc_seller(
//     auction_params: AuctionParams,
//     addr: SocketAddr,
//     signing_key: SchnorrSigningKey,
//     allowed_signers: impl IntoIterator<Item = SchnorrVerifyingKey>,
// ) -> Result<(), AuctionError> {
//     let allowlist = allowlist_from_keys(allowed_signers);
//     let channel = GrpcSellerChannel::serve(addr, signing_key, allowlist)
//         .await
//         .map_err(AuctionError::BroadcastError)?;
//     run_seller(auction_params, channel).await
// }
