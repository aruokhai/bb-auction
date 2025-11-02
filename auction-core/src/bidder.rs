use core::num;
use std::{collections::{BTreeMap, BTreeSet, HashSet}, env, marker::PhantomData, sync::Arc};

use elastic_elgamal::{group::{self, ElementOps}, Ciphertext, PublicKey};
use k256::{
    elliptic_curve::{ops::MulByGenerator, Field},
    ProjectivePoint, Scalar,
};
use rand::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};
use tokio::{sync::{self, Mutex}, task};
use crate::{bidder, brandt::{add_blinding_scalars, compute_partial_winning_vector, determine_winner, make_onehot_bid, partially_decrypt, AuctionParams, Delta, EncBidVector, Gamma, Phi}, channel::{self, create_envelope, BidChannel}, elgamal::K256Group, error::AuctionError, proof::SecretKeyProof, seller::BidCollationFinalization, serde::projective_point};

use crate::{
    brandt::BidderVector,
    channel::{
        MessageEnvelope,
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

#[derive(Clone, Serialize, Deserialize)]
pub struct PartialDecryptMessage {
    #[serde(with = "projective_point")]
    pub phi: Phi 
}

#[derive(Clone, Serialize, Deserialize)]
pub struct BidCollationAnnoucement {
    #[serde(with = "projective_point")]
    pub public_key: ProjectivePoint,
    #[serde(with = "projective_point::vec")]
    pub blinded_gamma: Gamma,
    #[serde(with = "projective_point::vec")]
    pub blinded_delta: Delta
}




/// Represents a bidder participating in the auction protocol.
pub struct Bidder<Channel: BidChannel<K> + Clone, K: Copy> {
    secret_key: Scalar,
    public_key: ProjectivePoint,
    group_public_key: Arc<Mutex<PublicKey<K256Group>>>,
    bid_vector: Option<BidderVector>,
    bid_range: BidParams,
    bid_channel: Channel,
    bidders_keys: Arc<sync::RwLock<Vec<ProjectivePoint>>>,
    bidders_bid_list: Arc<sync::RwLock<Vec<EncBidVector>>>,
    bid_state: Arc<Mutex<BidState>>,
    blinded_gamma_list: Arc<sync::RwLock<Vec<Gamma>>>,
    blinded_delta_list: Arc<sync::RwLock<Vec<Delta>>>,
    seller_key: K,
}

#[derive(Clone, PartialEq, PartialOrd)]
pub enum BidState {
    NotStarted,
    DKGInProgress,
    DKGCompleted,
    BidSubmitted,
    BidsAcknowledged,
    BidsCollated,
    BidsPartiallyDecrypted,
    AuctionEnded,
}

pub struct BidParams {
    pub min: u64,
    pub max: u64,
    pub step: u64,
    pub winners_size: usize,
}


impl<Channel: BidChannel<K> + Clone, K> Bidder<Channel, K> {
    pub fn new<R: RngCore + CryptoRng>(rng: &mut R, bid_channel: Channel, bid_range: BidParams, seller_key: K ) -> Self {
        let secret_key = Scalar::random(rng);
        let public_key = ProjectivePoint::mul_by_generator(&secret_key);
        let group_public_key = K256Group::to_public_key(&ProjectivePoint::IDENTITY);

        Self {
            secret_key,
            public_key,
            group_public_key: Arc::new(Mutex::new(group_public_key)),
            bid_vector: None,
            bid_range,
            bid_channel,
            bidders_keys: Arc::new(sync::RwLock::new(Vec::new())),
            bidders_bid_list: Arc::new(sync::RwLock::new(Vec::new())),
            bid_state: Arc::new(Mutex::new(BidState::NotStarted)),
            blinded_gamma_list: Arc::new(sync::RwLock::new(Vec::new())),
            blinded_delta_list: Arc::new(sync::RwLock::new(Vec::new())),
            seller_key,
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
            let blinded_gamma_list = self.blinded_gamma_list.clone();
            let blinded_delta_list = self.blinded_delta_list.clone();
            let bidders_bid_map = self.bidders_bid_list.clone();
            let group_public_key = self.group_public_key.clone();
            let cloned_channel = self.bid_channel.clone();
            let bid_state = self.bid_state.clone();
            let bid_vector = self.bid_vector.clone();
            let auction_params = AuctionParams {
                n_prices: self.bid_range.step as usize,
                m_winners: self.bid_range.winners_size,
            };
            let bidder_pubkey = self.public_key.clone();
            let secret_share= self.secret_key;
            let seller_key= self.seller_key;

            async move {
                while let Ok(msg) = cloned_channel.receive_broadcast_message().await {
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

                            let (gamma, delta) = compute_partial_winning_vector(
                                &bid_vector.clone().unwrap(),
                                &bid_map.clone(),
                                &auction_params,
                                &*group_public_key.lock().await,
                            ); 

                            let (gamma_blinded, delta_blinded) = add_blinding_scalars(&bid_vector.clone().unwrap(), gamma, delta, &auction_params);

                            blinded_gamma_list.write().await.push(gamma_blinded.clone());
                            blinded_delta_list.write().await.push(delta_blinded.clone());

                            let bid_collation_announcement = BidCollationAnnoucement {
                                public_key: bidder_pubkey.clone(),
                                blinded_gamma: gamma_blinded,
                                blinded_delta: delta_blinded,
                            };

                            let envelope = create_envelope("BidCollationAnnouncement", bid_collation_announcement).unwrap();

                            let res = cloned_channel.send_broadcast_message(&envelope).await;

                            if !res.is_ok() {
                                println!("Bid Collation Error")
                            }

                            *bid_state.lock().await = BidState::BidsCollated;

                        }
                    }

                    if let Ok(bid_collation_announcement) = msg.decode::<BidCollationAnnoucement>() {
                        let mut gamma_list = blinded_gamma_list.write().await; 
                        if gamma_list.len() >= num_bidders {
                            println!("All bidders' bid collation have been received.");
                            continue;
                        }

                        gamma_list.push(bid_collation_announcement.blinded_gamma);
                        let mut delta_list = blinded_delta_list.write(). await;
                        delta_list.push(bid_collation_announcement.blinded_delta);

                        if gamma_list.len() == num_bidders {
                            let all_deltas = delta_list.as_array().unwrap();

                            let phi = partially_decrypt(secret_share, all_deltas, &auction_params);

                            let phi_message = PartialDecryptMessage {
                                phi
                            };

                            let envelope = create_envelope("PhiMessage", phi_message).unwrap();

                            let res = cloned_channel.send_direct_message(&envelope, seller_key).await;

                            if !res.is_ok() {
                                println!("Direct Message Error")
                            }
                        }
                    }

                    if let Ok(bid_collation_finalization) =  msg.decode::<BidCollationFinalization>() {
                        let mut gamma_list = blinded_gamma_list.read().await; 
                        let is_winner = determine_winner(&bid_collation_finalization.collated_phi, gamma_list, &auction_params);

                        if is_winner {
                            println!("I am a fucking winner")
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

    pub async fn publish_bid(&self) -> Result<(), AuctionError> {
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

        let envelope = create_envelope("BidAnnouncement", bid_announcement).unwrap();

        self.bid_channel.send_broadcast_message(envelope).await.map_err(|err| AuctionError::BidPublishErr(err))?;

        self.bidders_bid_list.blocking_write().push(self.bid_vector.as_ref().unwrap().enc_bits.clone());

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

}


