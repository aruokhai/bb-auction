use core::sync;
use std::sync::Arc;

use serde::{Deserialize, Serialize};
use crate::{bidder::{self, BidParams, PartialDecryptMessage}, brandt::{add_blinding_scalars, compute_partial_winning_vector, determine_winner, make_onehot_bid, partially_decrypt, AuctionParams, Delta, EncBidVector, Gamma, Phi}, channel::{self, create_envelope, BidChannel}, elgamal::K256Group, error::AuctionError, proof::SecretKeyProof, serde::projective_point};
use tokio::sync::RwLock;

#[derive(Clone, Serialize, Deserialize)]
pub struct BidCollationFinalization {
    #[serde(with = "projective_point")]
    pub collated_phi: Phi
}

pub struct Seller<Channel: BidChannel<K> + Clone, K: Copy> {
    bid_range: Option<BidParams>,
    bid_channel: Channel,
    phi_list: Arc<RwLock<Vec<Gamma>>>,
    channel_key: K,
}

impl<Channel: BidChannel<K> + Clone, K> Seller<Channel, K> {
    pub fn new(
        bid_range: BidParams,
        bid_channel: Channel,
        channel_key: K,
    ) -> Self {
        Self {
            bid_range,
            bid_channel,
            phi_list: Arc::new(RwLock::new(Vec::new())),
            channel_key,
        }
    }

    pub fn create_auction(
        &self,
        auction_params: AuctionParams,
    ) -> Result<(), AuctionError> {
        let bid_channel = self.bid_channel.clone();
        let phi_list = self.phi_list.clone();
        let channel_key = self.channel_key;

        tokio::spawn(async move {
            let mut receiver = bid_channel.subscribe(channel_key).await;

            while let Some(message) = receiver.recv().await {
                match message.decode::<PartialDecryptMessage>() {
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