use std::cmp;

use crate::elgamal::*;
use crate::serde::projective_point;
use elastic_elgamal::{Ciphertext, PublicKey, RingProof, group::ElementOps};
use k256::{ProjectivePoint, Scalar, elliptic_curve::{Field, Group, PrimeField}};
use rand::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};

const N_PRICES: u64 = 10; // K in many notations
const WINNERS_M: u64 = 1; // M (usually 1 for single-w inner example)

#[derive(Clone, Serialize, Deserialize)]
pub struct AuctionParams {
    pub k: u64, // K in many notations
    pub min: u64,
    pub max: u64,
    pub m: u64, // M (usually 1 for single-winner example)
    pub num_bidders: u64,
}

impl Default for AuctionParams {
    fn default() -> Self {
        Self {
            k: N_PRICES,
            m: WINNERS_M,
            min: 0,
            max: 100,
            num_bidders: 2,
        }
    }
}

pub type EncBidVector = Vec<Ciphertext<K256Group>>; // length = K
pub type Gamma = Vec<ProjectivePoint>;
pub type Delta = Vec<ProjectivePoint>;
pub type Phi = Vec<ProjectivePoint>;

#[derive(Clone, Serialize, Deserialize)]
pub struct BidderShare {
    #[serde(with = "projective_point::vec")]
    pub gamma: Gamma,
    #[serde(with = "projective_point::vec")]
    pub delta: Delta,
}

#[derive(Clone, Serialize, Deserialize)]
/// A bidder’s unit-bid vector: encryptions of [0,...,0,1,0,...0]
pub struct BidVector {
    pub secret_key: Scalar,
    #[serde(with = "projective_point")]
    pub public_key: ProjectivePoint,
    pub enc_bits: EncBidVector,                     // length = K
    pub blinding_scalars: Vec<Scalar>,              // length = K
    pub vector_size: usize,
    pub winner_size: usize,
}

/// Build an encrypted one-hot vector for price index j* (0..K-1)
pub fn make_onehot_bid<R: RngCore + CryptoRng>(
    mut rng: R,
    secret_key: Scalar,
    public_key: ProjectivePoint,
    group_pk: &PublicKey<K256Group>,
    auction_params: &AuctionParams,
    bid_amount: u64,
) -> BidVector {
    let vector_size = auction_params.k as usize;
    let marker_projective = ProjectivePoint::GENERATOR * Scalar::from_u128(1024);
    let mut ciphertext_v = Vec::with_capacity(vector_size);
    let mut blinding_scalars = Vec::with_capacity(vector_size);
    let bid_index = find_bid_index(bid_amount, auction_params).expect(format!("Bid amount out of range {}", bid_amount).as_str());

    println!("Bid amount {} mapped to index {}", bid_amount, bid_index);
    for j in 0..vector_size {
        let cipher_text = if j == bid_index {
            group_pk.encrypt_element(marker_projective, &mut rng)
        } else {
            group_pk.encrypt_element(ProjectivePoint::IDENTITY, &mut rng)
        };
        ciphertext_v.push(cipher_text);

        blinding_scalars.push(Scalar::random(&mut rng));
    }
    BidVector {
        secret_key: secret_key,
        public_key: public_key,
        enc_bits: ciphertext_v,
        blinding_scalars,
        vector_size: vector_size,
        winner_size: auction_params.m as usize,
    }
}

impl BidVector {
    /// Step 6 : Compute γij for a participant for all i, j  and step 7
    pub fn compute_bidder_share(
        &self,
        all_bids: &[EncBidVector],
    ) -> BidderShare {
        let n_bidders = all_bids.len();

        let mut gamma_vector = Vec::with_capacity(self.vector_size);
        let mut delta_vector = Vec::with_capacity(self.vector_size);

        let two_m_plus_two = Scalar::from((2 * self.winner_size + 2) as u64);
        let two_m_plus_one = Scalar::from((2 * self.winner_size + 1) as u64);


        let marker_projective = ProjectivePoint::GENERATOR * Scalar::from_u128(1024);
        let bid_vector_finder = marker_projective * two_m_plus_one;

        for j in 0..self.vector_size {
            let mut acc_a = K256Group::identity();
            let mut acc_b = K256Group::identity();

            let mut bid_vector_alpha_blinder = K256Group::identity();
            let mut bid_vector_beta_blinder = K256Group::identity();

            for d in 0..=j {
                bid_vector_alpha_blinder =
                    bid_vector_alpha_blinder + self.enc_bits[d].blinded_element();
                bid_vector_beta_blinder = bid_vector_beta_blinder + self.enc_bits[d].random_element();
            }

            bid_vector_alpha_blinder = bid_vector_alpha_blinder * two_m_plus_two;
            bid_vector_beta_blinder = bid_vector_beta_blinder * two_m_plus_two;

            for h in 0..n_bidders {
                for d in j..self.vector_size {
                    let d_plus_1 = all_bids[h].get(d + 1);
                    if let Some(dp1) = d_plus_1 {
                         acc_a = acc_a + all_bids[h][d].blinded_element() + dp1.blinded_element();
                        acc_b = acc_b + all_bids[h][d].random_element() + dp1.random_element();
                    } else {
                        acc_a = acc_a + all_bids[h][d].blinded_element();
                        acc_b = acc_b + all_bids[h][d].random_element();
                    }
               
                }
            }

            acc_a = (acc_a + bid_vector_alpha_blinder) - bid_vector_finder;
            acc_b = acc_b + bid_vector_beta_blinder;

            gamma_vector.push(acc_a);
            delta_vector.push(acc_b);
        }

        let mut gamma_blinded = Vec::with_capacity(self.vector_size);
        let mut delta_blinded = Vec::with_capacity(self.vector_size);

        for j in 0..self.vector_size {
            let gamma_j_blinded = &gamma_vector[j] * &self.blinding_scalars[j];
            let delta_j_blinded = &delta_vector[j] * &self.blinding_scalars[j];

            gamma_blinded.push(gamma_j_blinded);
            delta_blinded.push(delta_j_blinded);
        }

        BidderShare {
            gamma: gamma_blinded,
            delta: delta_blinded,
        }
    }

    // step 8 add partial secret keys to beta
    // TODO: Add proofs
    pub fn derive_phi(&self, all_blinded_delta: &[Vec<ProjectivePoint>]) -> Phi {
        let mut phi_v = Vec::with_capacity(self.vector_size);

        for j in 0..self.vector_size {
            let mut phi = K256Group::identity();
            for h in 0..all_blinded_delta.len() {
                phi = phi + (all_blinded_delta[h][j].clone());
            }

            phi_v.push(phi  * self.secret_key);
        }

        phi_v
    }

    // step 9 and 10, final decryption and winner determination
    pub fn is_winner(&self, phi_list: &[Phi], gamma_all: &[Vec<ProjectivePoint>]) -> bool {
        let n_bidders = phi_list.len();
        let mut winning_vector = vec![K256Group::identity(); self.vector_size];

        for j in 0..self.vector_size {
            let mut acc_gamma = K256Group::identity();
            let mut acc_phi = K256Group::identity();

            for h in 0..n_bidders {
                acc_gamma = &acc_gamma + &gamma_all[h][j];
                acc_phi = &acc_phi + &phi_list[h][j];
            }
            let final_decryption = &acc_gamma - &acc_phi;

            winning_vector[j] = final_decryption;
        }

        for j in 0..self.vector_size {
            if winning_vector[j] == K256Group::identity() {
                return true;
            }
        }

        return false;
    }
}

pub fn find_bid_index(bid_amount: u64, auction_params: &AuctionParams) -> Option<usize> {
    let min = auction_params.min;
    let slot_width = auction_params.k;
    let max = auction_params.max;

    if slot_width == 0 {
        return None;
    }
    if bid_amount < min || bid_amount > max {
        return None;
    }

    // total number of slots (inclusive range)
    let total_slots = ((max - min) / slot_width) as usize  + 1;

    // reverse index: high bids map to low indices
    let diff = max - bid_amount;
    let idx = (diff / slot_width) as usize;
    if idx >= total_slots {
       
        return None;
    }
    Some(idx)
}
