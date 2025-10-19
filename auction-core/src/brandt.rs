use core::borrow;

use crate::elgamal::*;
use elastic_elgamal::{group::ElementOps, Ciphertext, PublicKey, RingProof};
use k256::{elliptic_curve::Field, ProjectivePoint, Scalar};
use rand::{rngs::OsRng, seq::index, CryptoRng, RngCore};
use serde::{Deserialize, Serialize};

const N_PRICES: usize = 10; // K in many notations
const WINNERS_M: usize = 1; // M (usually 1 for single-w inner example)

/// Auction parameters
pub struct AuctionParams {
    pub n_prices: usize, // K in many notations
    pub m_winners: usize, // M (usually 1 for single-winner example)
}

impl Default for AuctionParams {
    fn default() -> Self {
        Self { n_prices: N_PRICES, m_winners: WINNERS_M }
    }
}

pub type EncBidVector = Vec<Ciphertext<K256Group>>; // length = K
pub type Gamma = Vec<ProjectivePoint>;
pub type Delta = Vec<ProjectivePoint>;
pub type Phi = Vec<ProjectivePoint>;

#[derive(Clone, Serialize, Deserialize)]
/// A bidder’s unit-bid vector: encryptions of [0,...,0,1,0,...0]
pub struct BidderVector {
    pub enc_bits: EncBidVector, // length = K
    pub enc_bits_proofs: Vec<RingProof<K256Group>>, // length = K
    pub blinding_scalars: Vec<Scalar>, // length = K
}

/// Build an encrypted one-hot vector for price index j* (0..K-1)
pub fn make_onehot_bid<R: RngCore + CryptoRng>(
    mut rng: R,
    pk: &PublicKey<K256Group>,
    k: usize,
    bid_index: usize,
) -> BidderVector {
    let mut ciphertext_v = Vec::with_capacity(k);
    let mut ring_proof_v = Vec::with_capacity(k);
    let mut blinding_scalars = Vec::with_capacity(k);
    for j in 0..k {
        let (cipher_text, ring_proof) = if j == bid_index { pk.encrypt_bool(true, &mut rng) } else { pk.encrypt_bool(false, &mut rng) };
        ciphertext_v.push(cipher_text);
        ring_proof_v.push(ring_proof);

        blinding_scalars.push(Scalar::random(&mut rng));
    }
    BidderVector { enc_bits: ciphertext_v, enc_bits_proofs: ring_proof_v, blinding_scalars }
}


/// Step 6 : Compute γij for a participant for all i, j 
pub fn compute_partial_winning_vector(
    my_bid_vector : &BidderVector,
    all_bids: &[EncBidVector],
    params: &AuctionParams,
    y_group : &PublicKey<K256Group>,
) -> (Gamma, Delta) {
    let n_bidders = all_bids.len();

    let mut gamma_vector = Vec::with_capacity(params.n_prices);
    let mut delta_vector = Vec::with_capacity(params.n_prices);

    let two_m_plus_two = Scalar::from((2 * params.m_winners + 2) as u64);
    let two_m_minus_one = Scalar::from((2 * params.m_winners - 1) as u64);

    let vector_size = params.n_prices;

    let mut bid_vector_alpha_blinder = K256Group::identity();
    let mut bid_vector_beta_blinder = K256Group::identity();

    for d in 0..vector_size {
        bid_vector_alpha_blinder = bid_vector_alpha_blinder + my_bid_vector.enc_bits[d].blinded_element();
        bid_vector_beta_blinder = bid_vector_beta_blinder + my_bid_vector.enc_bits[d].random_element();
    }


    bid_vector_alpha_blinder = &bid_vector_alpha_blinder * &two_m_plus_two;
    bid_vector_beta_blinder = &bid_vector_beta_blinder * &two_m_plus_two;

    let bid_vector_finder = y_group.as_element() * &two_m_minus_one;

    for j in 0..params.n_prices {
         let mut acc_a = K256Group::identity();
         let mut acc_b = K256Group::identity();

        for h in 0..n_bidders {
           
            for d in j..vector_size {
                acc_a = acc_a + all_bids[h][d].blinded_element();
                acc_b = acc_b + all_bids[h][d].random_element();
            }
        }

        acc_a = (&acc_a + &bid_vector_alpha_blinder) -  &bid_vector_finder;
        acc_b = &acc_b + &bid_vector_beta_blinder;

        gamma_vector.push(acc_a);
        delta_vector.push(acc_b);

    }

    (gamma_vector, delta_vector)
}

// step 7
pub fn add_blinding_scalars(my_bid_vector : &BidderVector, gamma: Gamma, delta: Delta, params: &AuctionParams) -> (Gamma, Delta) {
    let mut gamma_blinded = Vec::with_capacity(params.n_prices);
    let mut delta_blinded = Vec::with_capacity(params.n_prices);

    for j in 0..params.n_prices {
        let gamma_j_blinded = &gamma[j] * &my_bid_vector.blinding_scalars[j];
        let delta_j_blinded = &delta[j]  * &my_bid_vector.blinding_scalars[j];

        gamma_blinded.push(gamma_j_blinded);
        delta_blinded.push(delta_j_blinded);
    }

    (gamma_blinded, delta_blinded)
}

// step 8 add partial secret keys to beta 
// TODO: Add proofs
pub fn partially_decrypt(secret_share: Scalar, all_delta: &[Vec<ProjectivePoint>], params: &AuctionParams) -> Phi {
    let mut phi_v = Vec::with_capacity(params.n_prices);

    for j in 0..params.n_prices {
        let mut phi = K256Group::identity();
        for h in 0..all_delta.len() {
             phi = phi + (all_delta[h][j].clone() * &secret_share);
        }
        
        phi_v.push(phi);
    }

   phi_v
}

// step 9 and 10, final decryption and winner determination
pub fn determine_winner(
    phi_list: &[Vec<ProjectivePoint>],
    gamma_all: &[Vec<ProjectivePoint>],
    params: &AuctionParams,
) -> bool {
    let n_bidders = phi_list.len();
    let mut winning_vector = vec![K256Group::identity(); params.n_prices];
    

    for j in 0..params.n_prices {
        let mut acc_gamma = K256Group::identity();
        let mut acc_phi = K256Group::identity();
        for h in 0..n_bidders {
            acc_gamma = &acc_gamma + &gamma_all[h][j];
            acc_phi = &acc_phi + &phi_list[h][j];
        }
        let final_decryption = &acc_gamma - &acc_phi;
    
        winning_vector.push(final_decryption);

    }

    for j in 0..params.n_prices {
        if winning_vector[j] == K256Group::identity() {
            return true;
        } 
    }

    return false;
}