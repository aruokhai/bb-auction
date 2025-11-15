pub mod bidder;
pub mod brandt;
pub mod channel;
pub mod elgamal;
pub mod error;
pub mod proof;
pub mod seller;
pub mod serde;
pub mod types;

// #[cfg(test)]
// mod tests {
//     use crate::{
//         bidder::{Bidder, BidderEvent, BidderEventReceiver},
//         brandt::AuctionParams,
//         channel::test_utils::InMemoryAuctionChannel,
//         seller::{BidCollationFinalization, Seller, SellerEvent, SellerEventReceiver},
//     };
//     use rand::{SeedableRng, rngs::StdRng};
//     use tokio::time::{Duration, timeout};

//     #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
//     async fn auction_flow_selects_highest_bidder() {
//         let auction_params = AuctionParams {
//             k: 10,
//             min: 0,
//             max: 90,
//             m: 1,
//             num_bidders: 10,
//         };
//         let num_bidders = auction_params.num_bidders as usize;

//         let channel = InMemoryAuctionChannel::new();
//         let seller = Seller::new(auction_params.clone(), channel.clone());
//         seller
//             .initiate_auction()
//             .await
//             .expect("seller loop should start");

//         let mut bidders = Vec::with_capacity(num_bidders);
//         for idx in 0..num_bidders {
//             let seed = [idx as u8 + 1; 32];
//             let bidder = Bidder::new(
//                 StdRng::from_seed(seed),
//                 channel.clone(),
//                 auction_params.clone(),
//             );
//             bidders.push(bidder);
//         }

//         for (idx, bidder) in bidders.iter_mut().enumerate() {
//             let mut bid_rng = StdRng::from_seed([idx as u8 + 101; 32]);
//             let bid_amount = (idx as u64) * 10;

//             println!("Bidder {} bidding amount {}", idx, bid_amount);
//             bidder
//                 .initiaite_bidding(&mut bid_rng, bid_amount)
//                 .await
//                 .expect("bidder should announce bid");
//         }

//         let mut seller_events = seller
//             .take_event_receiver()
//             .await
//             .expect("seller event receiver available");
        
//         let mut bidder_event_receivers = Vec::with_capacity(num_bidders);
//         for bidder in bidders.iter() {
//             let rx = bidder
//                 .take_event_receiver()
//                 .await
//                 .expect("bidder event receiver available");
//             bidder_event_receivers.push(rx);
//         }

//         let finalization = timeout(
//             Duration::from_secs(10),
//             wait_for_finalization(&mut seller_events),
//         )
//         .await
//         .expect("seller should finalize bids");
//         assert_eq!(
//             finalization.collated_phi.len(),
//             auction_params.num_bidders as usize,
//             "seller should collect phi from every bidder"
//         );

//         let mut winner_events = Vec::with_capacity(num_bidders);
//         for rx in bidder_event_receivers.iter_mut() {
//             let is_winner = wait_for_winner_flag(rx).await;
//             winner_events.push(is_winner);
//         }
//         assert_eq!(
//             winner_events.len(),
//             num_bidders,
//             "each bidder should learn the auction result"
//         );

//         let expected_winner_idx = num_bidders - 1;
//          let actual_winner_idx = winner_events
//             .iter()
//             .enumerate()
//             .find_map(|(idx, is_winner)| if *is_winner { Some(idx) } else { None });
//         assert_eq!(
//             actual_winner_idx,
//             Some(expected_winner_idx),
//             "highest bidder should be the unique winner"
//         );

//     }

//     async fn wait_for_finalization(rx: &mut SellerEventReceiver) -> BidCollationFinalization {
//         while let Some(event) = rx.recv().await {
//             if let SellerEvent::CollationFinalized(finalization) = event {
//                 return finalization;
//             }
//         }
//         panic!("seller channel closed before finalization");
//     }

//     async fn wait_for_winner_flag(rx: &mut BidderEventReceiver) -> bool {
//         loop {
//             match rx.recv().await {
//                 Some(BidderEvent::IsWinner(flag)) => break flag,
//                 Some(_) => continue,
//                 None => panic!("bidder event channel closed"),
//             }
//         }
//     }
// }
