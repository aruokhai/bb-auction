// use std::sync::Arc;

// use crate::{
//     bidder::BidPartialMessage,
//     brandt::{AuctionParams, Phi},
//     channel::{AuctionChannel, create_envelope},
//     error::AuctionError,
//     serde::projective_point,
// };
// use serde::{Deserialize, Serialize};
// use tokio::{
//     sync::{Mutex, RwLock, mpsc},
//     task,
// };

// #[derive(Debug, Clone, Serialize, Deserialize)]
// pub struct BidCollationFinalization {
//     #[serde(with = "projective_point::vec_vec")]
//     pub collated_phi: Vec<Phi>,
// }

// pub struct Seller<Channel: AuctionChannel + Clone> {
//     auction_params: AuctionParams,
//     auction_channel: Channel,
//     supervisor_handle: task::JoinHandle<()>,
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

// pub type SellerEventSender = mpsc::UnboundedSender<SellerEvent>;
// pub type SellerEventReceiver = mpsc::UnboundedReceiver<SellerEvent>;

// impl<Channel: AuctionChannel + Clone + Send + 'static> Seller<Channel> {
//     pub fn new(auction_params: AuctionParams, auction_channel: Channel) -> Self {
//         let (internal_events_tx, internal_events_rx) = mpsc::unbounded_channel();
//         let (events_tx, events_rx) = mpsc::unbounded_channel();
//         let collation_handler = Arc::new(Mutex::new(None));

//         let supervisor_handle = spawn_seller_supervisor(
//             internal_events_rx,
//             events_tx.clone(),
//             collation_handler.clone(),
//         );

//         Self {
//             auction_params,
//             auction_channel,
//             supervisor_handle,
//             collation_handler,
//             loop_events_tx: internal_events_tx,
//             events_tx,
//             events_rx: Mutex::new(Some(events_rx)),
//         }
//     }

//     pub fn event_sender(&self) -> SellerEventSender {
//         self.events_tx.clone()
//     }

//     pub async fn take_event_receiver(&self) -> Option<SellerEventReceiver> {
//         self.events_rx.lock().await.take()
//     }

//     pub async fn initiate_auction(&self) -> Result<(), AuctionError> {
//         let mut collation_guard = self.collation_handler.lock().await;
//         if collation_guard.is_some() {
//             return Err(AuctionError::Other(
//                 "Auction collation loop is already running.".to_string(),
//             ));
//         }

//         let auction_channel = self.auction_channel.clone();
//         let auction_params = self.auction_params.clone();
//         let events_tx = self.loop_events_tx.clone();

//         let collation_handle = tokio::spawn(async move {
//             run_seller_loop(auction_channel, auction_params, events_tx).await;
//         });
//         *collation_guard = Some(collation_handle);

//         Ok(())
//     }
// }

// fn spawn_seller_supervisor(
//     mut internal_events_rx: SellerEventReceiver,
//     external_events_tx: SellerEventSender,
//     collation_handler: Arc<Mutex<Option<task::JoinHandle<()>>>>,
// ) -> task::JoinHandle<()> {
//     tokio::spawn(async move {
//         while let Some(event) = internal_events_rx.recv().await {
//             let should_shutdown = matches!(
//                 event,
//                 SellerEvent::Error(_) | SellerEvent::CollationFinalized(_)
//             );
//             let _ = external_events_tx.send(event.clone());

//             if should_shutdown {
//                 if let Some(handle) = collation_handler.lock().await.take() {
//                     handle.abort();
//                 }

//                 let notice = match event {
//                     SellerEvent::Error(_) => "Seller loop stopped due to an unrecoverable error.",
//                     SellerEvent::CollationFinalized(_) => {
//                         "Seller loop stopped after broadcasting finalization."
//                     }
//                     _ => unreachable!(),
//                 };
//                 let _ = external_events_tx.send(SellerEvent::Info(notice));
//                 break;
//             }
//         }
//     })
// }

// pub async fn run_seller_loop<Channel: AuctionChannel + Clone + Send + 'static>(
//     auction_channel: Channel,
//     auction_params: AuctionParams,
//     events_tx: SellerEventSender,
// ) {
//     let auction_state = Arc::new(RwLock::new(AuctionState {
//         phi_list: Vec::new(),
//     }));
//     let num_bidders = auction_params.num_bidders as usize;

//     loop {
//         match auction_channel.receive_direct_message().await {
//             Ok(message) => match message.decode::<BidPartialMessage>() {
//                 Ok(bid_partial_message) => {
//                     let mut state = auction_state.write().await;
//                     state.phi_list.push(bid_partial_message.phi);
//                     let share_count = state.phi_list.len();

//                     if share_count < num_bidders {
//                         let _ = events_tx.send(SellerEvent::Info(
//                             "Received bidder phi share; awaiting more.",
//                         ));
//                     }

//                     if share_count == num_bidders {
//                         let finalization_message = BidCollationFinalization {
//                             collated_phi: state.phi_list.clone(),
//                         };

//                         let envelope = match create_envelope(
//                             "BidCollationFinalization",
//                             &finalization_message,
//                         ) {
//                             Ok(env) => env,
//                             Err(err) => {
//                                 eprintln!(
//                                     "Failed to create BidCollationFinalization envelope: {err}"
//                                 );
//                                 let _ = events_tx.send(SellerEvent::Error(
//                                     "Failed to create BidCollationFinalization envelope.",
//                                 ));
//                                 break;
//                             }
//                         };

//                         if let Err(err) = auction_channel.send_broadcast_message(envelope).await {
//                             eprintln!("Failed to broadcast BidCollationFinalization: {}", err);
//                             let _ = events_tx.send(SellerEvent::Error(
//                                 "Failed to broadcast BidCollationFinalization.",
//                             ));
//                         } else {
//                             let _ = events_tx
//                                 .send(SellerEvent::CollationFinalized(finalization_message));
//                         }
//                         break;
//                     }
//                 }
//                 Err(err) => {
//                     eprintln!("Failed to decode BidPartialMessage: {err}");
//                     let _ =
//                         events_tx.send(SellerEvent::Error("Failed to decode BidPartialMessage."));
//                     break;
//                 }
//             },
//             Err(err) => {
//                 eprintln!("Failed to receive direct message: {}", err);
//                 let _ = events_tx.send(SellerEvent::Error(
//                     "Failed to receive direct message from channel.",
//                 ));
//                 break;
//             }
//         }
//     }
// }
