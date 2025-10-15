use core::num;
use std::{collections::{BTreeMap, BTreeSet, HashSet}, sync::Arc};

use elastic_elgamal::{group::{self, ElementOps}, Ciphertext, PublicKey};
use k256::{
    elliptic_curve::{ops::MulByGenerator, Field},
    ProjectivePoint, Scalar,
};
use rand::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};
use tokio::{sync::{self, Mutex}, task};
use crate::{bidder, brandt::{compute_partial_winning_vector, make_onehot_bid, AuctionParams, EncBidVector}, elgamal::K256Group, error::AuctionError, proof::SecretKeyProof, serde::projective_point};

use crate::{
    brandt::BidderVector,
    broadcast::{
        receive_envelope, send_envelope, EnvelopeReceiver, EnvelopeSender, MessageEnvelope,
        SendEnvelopeError,
    },
};

#[derive(Clone, Serialize, Deserialize)]
pub struct DKGKeyAnnouncement {
    #[serde(with = "projective_point")]
    pub public_key: ProjectivePoint,
    pub proof_of_knowledge: SecretKeyProof,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct BidAnnouncement {
    #[serde(with = "projective_point")]
    pub public_key: ProjectivePoint,
    pub enc_bits: EncBidVector, // length = K
    pub enc_bits_proofs: Vec<elastic_elgamal::RingProof<K256Group>>, // length = K
}

/// Represents a bidder participating in the auction protocol.
pub struct Bidder {
    secret_key: Scalar,
    public_key: ProjectivePoint,
    group_public_key: Arc<Mutex<PublicKey<K256Group>>>,
    bid_vector: Option<BidderVector>,
    bid_range: BidParams,
    sender: EnvelopeSender,
    bidders_keys: Arc<sync::RwLock<Vec<ProjectivePoint>>>,
    bidders_bid_map: Arc<sync::RwLock<Vec<EncBidVector>>>,
    bid_state: Arc<Mutex<BidState>>,
}

#[derive(Clone, PartialEq, PartialOrd)]
pub enum BidState {
    NotStarted,
    DKGInProgress,
    DKGCompleted,
    BidSubmitted,
    BidsAcknowledged,
    AuctionEnded,
}

pub struct BidParams {
    pub min: u64,
    pub max: u64,
    pub step: u64,
    pub winners_size: usize,
}

impl Bidder {
    pub fn new<R: RngCore + CryptoRng>(rng: &mut R, sender: EnvelopeSender, bid_range: BidParams ) -> Self {
        let secret_key = Scalar::random(rng);
        let public_key = ProjectivePoint::mul_by_generator(&secret_key);
        let group_public_key = K256Group::to_public_key(&ProjectivePoint::IDENTITY);

        Self {
            secret_key,
            public_key,
            group_public_key: Arc::new(Mutex::new(group_public_key)),
            bid_vector: None,
            bid_range,
            sender,
            bidders_keys: Arc::new(sync::RwLock::new(Vec::new())),
            bidders_bid_map: Arc::new(sync::RwLock::new(Vec::new())),
            bid_state: Arc::new(Mutex::new(BidState::NotStarted)),
        }
    }

    pub fn initiate_dkg<R: RngCore + CryptoRng>(&mut self, rng: &mut R, num_bidders: usize) {
        let proof_of_knowledge = SecretKeyProof::new(&self.secret_key, &self.public_key, rng);

        self.bidders_keys.blocking_write().push(self.public_key);

        let dkg_message = DKGKeyAnnouncement {
            public_key: self.public_key,
            proof_of_knowledge,
        };

       
        task::spawn({
            let bidders_keys = self.bidders_keys.clone();
            let bidders_bid_map = self.bidders_bid_map.clone();
            let group_public_key = self.group_public_key.clone();
            let mut inbox = self.sender.subscribe();
            let bid_state = self.bid_state.clone();
            let bid_vector = self.bid_vector.clone();
            let auction_params = AuctionParams {
                n_prices: self.bid_range.step as usize,
                m_winners: self.bid_range.winners_size,
            };

            async move {
                while let Ok(msg) = inbox.recv().await {
                    if let Ok(dkg_announcement) = msg.decode::<DKGKeyAnnouncement>() {
                        let mut keys = bidders_keys.write().await;
                         if keys.len() >= num_bidders {
                            println!("All bidders' keys have been received.");
                            continue;
                        }
                        keys.push(dkg_announcement.public_key);

                        if keys.len() == num_bidders {
                            // Sum all public keys
                            let sum = keys.iter().fold(ProjectivePoint::IDENTITY, |acc, pk| acc + pk);
                            let group_pk = K256Group::to_public_key(&sum);
                            *group_public_key.lock().await = group_pk;
                        
                            *bid_state.lock().await = BidState::DKGCompleted;
                        }
                    }

                    if let Ok(bid_announcement) = msg.decode::<BidAnnouncement>() {
                        let mut bid_map = bidders_bid_map.write().await; 
                        if bid_map.len() >= num_bidders {
                            println!("All bidders' bids have been received.");
                            continue;
                        }

                        bid_map.push(bid_announcement.enc_bits);

                        if bid_map.len() == num_bidders {
                            println!("All bidders' bids have been received.");
                            *bid_state.lock().await = BidState::BidsAcknowledged;

                            let (gamma, delta) = compute_partial_winning_vector(
                                &bid_vector.clone().unwrap(),
                                &bid_map.clone(),
                                &auction_params,
                                &*group_public_key.lock().await,
                            ); 

                        }
                    }
                }
            }
        });
        
        self.publish("DKGKeyAnnouncement", dkg_message)
            .expect("failed to publish DKG key announcement");

        *self.bid_state.blocking_lock() = BidState::DKGInProgress;

    }

    pub fn set_bid_vector<R: RngCore + CryptoRng>(&mut self, rng: &mut R, bid_index: usize) -> Result<(), AuctionError > {
        let group_pk = self.group_public_key.blocking_lock().clone();
        let k = self.bid_range.step as usize;
        if *self.bid_state.blocking_lock() < BidState::DKGCompleted {
            return Err(AuctionError::DkgNotCompleted);
        }
        
        let bid_vector = make_onehot_bid(rng, &group_pk, k, bid_index);
        self.bid_vector = Some(bid_vector); 

        Ok(())
    }

    pub fn publish_bid(&self) -> Result<(), AuctionError> {
        if self.bid_vector.is_none() {
            return Err(AuctionError::BidNotSet);
        }
        if *self.bid_state.blocking_lock() < BidState::DKGCompleted {
            return Err(AuctionError::DkgNotCompleted);
        }

        let bid_announcement = BidAnnouncement {
            public_key: self.public_key,
            enc_bits: self.bid_vector.as_ref().unwrap().enc_bits.clone(),
            enc_bits_proofs: self.bid_vector.as_ref().unwrap().enc_bits_proofs.clone(),
        };

        self.publish("BidAnnouncement", bid_announcement)
            .map_err(|_| AuctionError::BroadcastError)?;

        self.bidders_bid_map.blocking_write().push(self.bid_vector.as_ref().unwrap().enc_bits.clone());

        *self.bid_state.blocking_lock() = BidState::BidSubmitted;

        Ok(())
    }

    pub fn bid_vector(&self) -> Option<&BidderVector> {
        self.bid_vector.as_ref()
    }

    pub fn public_key(&self) -> &ProjectivePoint {
        &self.public_key
    }

    pub fn secret_key(&self) -> &Scalar {
        &self.secret_key
    }

    /// Sends a labeled payload over the broadcast channel.
    pub fn publish<L, T>(&self, label: L, payload: T) -> Result<(), SendEnvelopeError>
    where
        L: Into<String>,
        T: Serialize,
    {
        send_envelope(&self.sender, label, payload)
    }

    /// Receives the next envelope addressed on the broadcast channel.
    pub async fn receive_envelope(&mut self) -> Result<MessageEnvelope, tokio::sync::broadcast::error::RecvError> {
        receive_envelope(&mut self.inbox).await
    }

    /// Returns a new independent subscription to the broadcast channel.
    pub fn subscribe(&self) -> EnvelopeReceiver {
        self.sender.subscribe()
    }

    /// Returns a stream of envelopes received on the broadcast channel.
    pub fn stream(&self) -> tokio_stream::wrappers::BroadcastStream<MessageEnvelope> {
        crate::broadcast::stream_envelopes(self.sender.subscribe())
    }
}


