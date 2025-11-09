use core::sync;
use std::sync::Arc;

use serde::{Deserialize, Serialize};
use crate::{bidder::{self, BidParams, BidPartialMessage}, brandt::{add_blinding_scalars, compute_partial_winning_vector, is_winner, make_onehot_bid, partially_decrypt, AuctionParams, Delta, EncBidVector, Gamma, Phi}, channel::{self, create_envelope, AuctionChannel}, elgamal::K256Group, error::AuctionError, proof::SecretKeyProof, serde::projective_point};
use tokio::sync::RwLock;

#[derive(Clone, Serialize, Deserialize)]
pub struct BidCollationFinalization {
    #[serde(with = "projective_point::vec_vec")]
    pub collated_phi: Vec<Phi>
}

pub struct Seller<Channel: AuctionChannel<K> + Clone, K: Copy> {
    auction_params: AuctionParams,
    auction_channel: Channel,
    phi_list: Arc<RwLock<Vec<Gamma>>>,
    channel_key: K,
}

impl<Channel: AuctionChannel<K> + Clone, K: Copy> Seller<Channel, K> {
    pub fn new(
        bid_params: BidParams,
        bid_channel: Channel,
        channel_key: K,
    ) -> Self {
        Self {
            bid_params,
            auction_channel: bid_channel,
            phi_list: Arc::new(RwLock::new(Vec::new())),
            channel_key,
        }
    }

    pub fn create_auction(
        &self,
        auction_params: AuctionParams,
    ) -> Result<(), AuctionError> {
        let bid_channel = self.auction_channel.clone();
        let phi_list = self.phi_list.clone();
        let channel_key = self.channel_key;

        tokio::spawn(async move {
            let mut receiver = bid_channel.subscribe(channel_key).await;

            while let Some(message) = receiver.recv().await {
                match message.decode::<BidPartialMessage>() {
                    Ok(phi) => {
                        let mut phi_list_lock = phi_list.write().await;
                        phi_list_lock.push(phi);
                    }
                    Err(e) => {
                        eprintln!("Failed to decode Gamma message: {}", e);
                    }
                }
            }
        });

        Ok(())
    }



}