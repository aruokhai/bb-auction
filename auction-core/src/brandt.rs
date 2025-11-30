use std::{cmp, collections::{BTreeMap, BTreeSet, HashSet}};

use crate::{elgamal::*, error::AuctionError, proof::{PlainCase, prove_dleq, prove_enc_bid, verify_dleq, verify_or_dleq}, rate::{self, RateParams}, types::*};
use crate::serde::projective_point;
use k256::{ProjectivePoint, Scalar, elliptic_curve::{Field, Group, PrimeField}};
use rand::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};
use crate::serde::projective_point::vec::serialize;
use k256::elliptic_curve::sec1::ToEncodedPoint;

const N_PRICES: u64 = 10; // K in many notations
const WINNERS_M: u64 = 1; // M (usually 1 for single-w inner example)

fn marker_point() -> ProjectivePoint {
    ProjectivePoint::GENERATOR * Scalar::from_u128(1024)
}

#[derive(Clone, Serialize, Deserialize)]
pub struct AuctionParams {
    pub rate: RateParams,
    pub m: u64, // M (usually 1 for single-winner example)
    pub num_bidders: u64,
}

impl Default for AuctionParams {
    fn default() -> Self {
        Self {
            rate: RateParams {
                min_bps: 100,  // 1.00%
                max_bps: 1000, // 10.00%
                step_bps: 1,   // 1 bp
            },
            m: WINNERS_M,
            num_bidders: 2,
        }
    }
}





#[derive(Clone, Serialize, Deserialize)]
/// A bidder’s unit-bid vector: encryptions of [0,...,0,1,0,...0]
pub struct BidVector {
    pub secret_key: Scalar,
    pub enc_bits: EncBidVector,                     // length = K
    pub blinding_scalars: Vec<Vec<Scalar>>,              // length = K
    pub vector_size: usize,
    pub winner_size: usize,
    pub bid_amount: u64,
}

/// Build an encrypted one-hot vector for price index j* (0..K-1)
pub fn make_onehot_bid<R: RngCore + CryptoRng>(
    mut rng: R,
    secret_key: Scalar,
    public_key: ProjectivePoint,
    group_pk: &PublicKey,
    auction_params: &AuctionParams,
    rate_bps: u64,
) -> BidVector {
    let vector_size = auction_params.rate.total_slots();
    let marker_projective = marker_point();
    let group_pk_element = group_pk.as_element();
    let mut ciphertext_v = Vec::with_capacity(vector_size);
    let mut blinding_scalars = Vec::with_capacity(auction_params.num_bidders as usize);
    let bid_index = auction_params.rate.find_rate_index(rate_bps).expect(format!("Bid amount out of range {}", rate_bps).as_str());

    for j in 0..vector_size {
        let cipher_text = if j == bid_index {
            group_pk.encrypt_element(marker_projective, &mut rng)
        } else {
            group_pk.encrypt_element(ProjectivePoint::IDENTITY, &mut rng)
        };
        let proof = prove_enc_bid(
            &mut rng,
            &ProjectivePoint::GENERATOR,
            &group_pk_element,
            &marker_projective,
            &cipher_text.random_element,
            &cipher_text.blinded_element,
            &cipher_text.random_scalar,
            if j == bid_index {
                PlainCase::IsY
            } else {
                PlainCase::IsOne
            },
        );
        ciphertext_v.push(EncBid {
            inner: cipher_text,
            proof,
        });

    }

    for _ in 0..auction_params.num_bidders {
        let mut row_vec = Vec::with_capacity(vector_size);
        for _ in 0..vector_size {
            let blinder = Scalar::random(&mut rng);
            row_vec.push(blinder);
        }
        blinding_scalars.push(row_vec);
    }

    let h1 = ciphertext_v.iter().map(|ct| ct.inner.random_element).fold(ProjectivePoint::IDENTITY, |a, b| a + b);
    let h2 = ciphertext_v.iter().map(|ct| ct.inner.blinded_element).fold(ProjectivePoint::IDENTITY, |a, b| a + b) - marker_projective;
    let randomness_sum = ciphertext_v
        .iter()
        .fold(Scalar::ZERO, |acc, ct| acc + ct.inner.random_scalar);

    let encoded_proof = prove_dleq(
        &mut rng,
        &ProjectivePoint::GENERATOR,
        &h1,
        &group_pk_element,
        &h2,
        &randomness_sum,
    );

    let encoded_vec = EncBidVector {
        public_key: public_key,
        encoded_bid: ciphertext_v.clone(),
        proof: encoded_proof,
    };

    BidVector {
        secret_key: secret_key,
        enc_bits: encoded_vec,
        blinding_scalars,
        vector_size: vector_size,
        winner_size: auction_params.m as usize,
        bid_amount: rate_bps,
    }
}

impl BidVector {

    pub fn compute_bidder_share_constant(&self, all_bids: BTreeSet<EncBidVector>) -> Result<(Vec<Vec<ProjectivePoint>>, Vec<Vec<ProjectivePoint>>), AuctionError> {

        let n_bidders = all_bids.len();
        let marker_projective = marker_point();

        let sorted_bids: Vec<EncBidVector> = all_bids.clone().into_iter().collect();

        let two_m_plus_two = Scalar::from((2 * self.winner_size + 2) as u64);
        let two_m_plus_one = Scalar::from((2 * self.winner_size + 1) as u64);

        let mut gamma_list = Vec::new();
        let mut delta_list = Vec::new();

        let bid_vector_finder = marker_projective * two_m_plus_one;

        for (_, bid_v) in all_bids.iter().enumerate() {

                let bid = &bid_v.encoded_bid;

                let mut gamma_vector = Vec::with_capacity(self.vector_size);
                let mut delta_vector = Vec::with_capacity(self.vector_size);

                for j in 0..self.vector_size {
                    let mut acc_a = K256Group::identity();
                    let mut acc_b = K256Group::identity();

                    let mut bid_vector_alpha_blinder = K256Group::identity();
                    let mut bid_vector_beta_blinder = K256Group::identity();

                    for d in 0..=j {
                        bid_vector_alpha_blinder =
                            bid_vector_alpha_blinder + bid[d].inner.blinded_element;
                        bid_vector_beta_blinder = bid_vector_beta_blinder + bid[d].inner.random_element;
                    }

                    bid_vector_alpha_blinder = bid_vector_alpha_blinder * two_m_plus_two;
                    bid_vector_beta_blinder = bid_vector_beta_blinder * two_m_plus_two;

                    for h in 0..n_bidders {
                        for d in j..self.vector_size {
                            let d_plus_1 = sorted_bids[h].encoded_bid.get(d + 1);
                            if let Some(dp1) = d_plus_1 {
                                 acc_a = acc_a + sorted_bids[h].encoded_bid[d].inner.blinded_element + dp1.inner.blinded_element;
                                acc_b = acc_b + sorted_bids[h].encoded_bid[d].inner.random_element + dp1.inner.random_element;
                            } else {
                                acc_a = acc_a + sorted_bids[h].encoded_bid[d].inner.blinded_element;
                                acc_b = acc_b + sorted_bids[h].encoded_bid[d].inner.random_element;
                            }
                        
                        }
                    }

                    acc_a = (acc_a + bid_vector_alpha_blinder) - bid_vector_finder;
                    acc_b = acc_b + bid_vector_beta_blinder;

                    gamma_vector.push(acc_a);
                    delta_vector.push(acc_b);
                }

                gamma_list.push(gamma_vector);
                delta_list.push(delta_vector);
            }

        return Ok((gamma_list, delta_list)); 
        
    }

    /// Step 6 : Compute γij for a participant for all i, j  and step 7
    pub fn compute_bidder_share<R: RngCore + CryptoRng>(
        &self,
        mut rng: R,
        all_bids: BTreeSet<EncBidVector>,
    ) -> Result<BidderShareMatrix, AuctionError> {
        let n_bidders = all_bids.len();

        let aggregated_pk = aggregate_public_key(&all_bids);
        let marker_projective = marker_point();
        for bid in &all_bids {
            verify_bid_vector(bid, &aggregated_pk, &marker_projective)?;
        }

        let sorted_bids: Vec<EncBidVector> = all_bids.clone().into_iter().collect();

        let mut blinded_share = BTreeSet::new();

        let two_m_plus_two = Scalar::from((2 * self.winner_size + 2) as u64);
        let two_m_plus_one = Scalar::from((2 * self.winner_size + 1) as u64);


        let bid_vector_finder = marker_projective * two_m_plus_one;

        for (i, bid_v) in all_bids.iter().enumerate() {

            let bid = &bid_v.encoded_bid;

            let mut gamma_vector = Vec::with_capacity(self.vector_size);
            let mut delta_vector = Vec::with_capacity(self.vector_size);

            for j in 0..self.vector_size {
                let mut acc_a = K256Group::identity();
                let mut acc_b = K256Group::identity();

                let mut bid_vector_alpha_blinder = K256Group::identity();
                let mut bid_vector_beta_blinder = K256Group::identity();

                for d in 0..=j {
                    bid_vector_alpha_blinder =
                        bid_vector_alpha_blinder + bid[d].inner.blinded_element;
                    bid_vector_beta_blinder = bid_vector_beta_blinder + bid[d].inner.random_element;
                }

                bid_vector_alpha_blinder = bid_vector_alpha_blinder * two_m_plus_two;
                bid_vector_beta_blinder = bid_vector_beta_blinder * two_m_plus_two;

                for h in 0..n_bidders {
                    for d in j..self.vector_size {
                        let d_plus_1 = sorted_bids[h].encoded_bid.get(d + 1);
                        if let Some(dp1) = d_plus_1 {
                             acc_a = acc_a + sorted_bids[h].encoded_bid[d].inner.blinded_element + dp1.inner.blinded_element;
                            acc_b = acc_b + sorted_bids[h].encoded_bid[d].inner.random_element + dp1.inner.random_element;
                        } else {
                            acc_a = acc_a + sorted_bids[h].encoded_bid[d].inner.blinded_element;
                            acc_b = acc_b + sorted_bids[h].encoded_bid[d].inner.random_element;
                        }
                    
                    }
                }

                acc_a = (acc_a + bid_vector_alpha_blinder) - bid_vector_finder;
                acc_b = acc_b + bid_vector_beta_blinder;

                gamma_vector.push(acc_a);
                delta_vector.push(acc_b);
            }

            let mut share_column = Vec::with_capacity(self.vector_size);

            for j in 0..self.vector_size {
                let gamma_j_blinded = &gamma_vector[j] * &self.blinding_scalars[i][j];
                let delta_j_blinded = &delta_vector[j] * &self.blinding_scalars[i][j];

                let proof = prove_dleq(& mut rng, &gamma_vector[j], &gamma_j_blinded, &delta_vector[j], &delta_j_blinded, &self.blinding_scalars[i][j]);

                share_column.push(BidShareColumn {
                    gamma: gamma_j_blinded,
                    delta: delta_j_blinded,
                    proof,
                });
        
            }

            blinded_share.insert(BidderShareRow {
                public_key: bid_v.public_key,
                share_column,
            });


        }

       


        return Ok(BidderShareMatrix {
            public_key: self.enc_bits.public_key,
            rows: blinded_share,
        });
    }

    // step 8 add partial secret keys to beta
    pub fn derive_phi<R: RngCore + CryptoRng>(&self, mut rng: R, bidder_share: BTreeSet<BidderShareMatrix>, all_bids: BTreeSet<EncBidVector>) -> BidderPhiMatrix {
        // TODO: Proofs Doesnt work
        let (gammas, deltas)= self.compute_bidder_share_constant(all_bids).expect("Should compute bidder share constant");
        for share in &bidder_share {
            for (i, row) in share.rows.iter().enumerate() {
                for (j, column) in row.share_column.iter().enumerate() {
                    if !verify_dleq(
                        &gammas[i][j],
                        &column.gamma,
                        &deltas[i][j],
                        &column.delta,
                        &column.proof,
                    ) {
                        panic!("Bidder share proof verification failed");
                    }
                }
            }
        }
        let all_deltas = bidder_share
            .iter()
            .map(|share| share.rows.clone().iter().map(|row| row.share_column.clone().iter().map(|m| m.delta).collect::<Vec<_>>()).collect::<Vec<_>>()).collect::<Vec<_>>();

        let mut phi_rows= Vec::new();

        //row by row
        for h in 0..all_deltas.len() {
            let mut phi_row = Vec::new();
           for j in 0..self.vector_size {
                let mut phi = K256Group::identity();
                for i in 0..all_deltas.len() {
                    phi = phi + (all_deltas[i][h][j].clone());
                }
                let phi_secret = phi * &self.secret_key;
                let proof = prove_dleq(
                    &mut rng,
                    &ProjectivePoint::GENERATOR,
                    &(ProjectivePoint::GENERATOR * self.secret_key),
                    &phi,
                    &phi_secret,
                    &self.secret_key,
                );
                phi_row.push(Phi {
                    inner: phi_secret,
                    proof,
                });
           }
           phi_rows.push(BidderPhiRow {
                public_key: bidder_share.iter().nth(0).unwrap().rows.iter().nth(h).unwrap().public_key,
                phi_vector: phi_row,
           });
        }
        

        BidderPhiMatrix {
            public_key: self.enc_bits.public_key,
            inner: phi_rows.into_iter().collect(),
        }
    }

    // step 9 and 10, final decryption and winner determination
   
}

pub fn derive_bidder_phi_matrix(
    bidders_phi_list: Vec<BidderPhiMatrix>,
    auction_params: &AuctionParams,
    bidder_public_key: ProjectivePoint,
    bidder_share_list: Vec<BidderShareMatrix>,
) -> Vec<Vec<ProjectivePoint>> {
    let n_bidders = bidders_phi_list.len();
    let vector_size = auction_params.rate.total_slots();

    let aggregated_deltas  =  get_all_deltas(bidder_share_list, auction_params);

    // Verify proofs
    for bidder_phi in &bidders_phi_list {
        let phi_creator_pk = bidder_phi.public_key;
        for (i, row) in bidder_phi.inner.iter().enumerate() {
            for (j, phi)in row.phi_vector.iter().enumerate() {
                if !verify_dleq(
                    &ProjectivePoint::GENERATOR,
                    &phi_creator_pk, 
                    &aggregated_deltas[i][j],
                    &phi.inner,
                    &phi.proof,
                ) {
                    panic!("Phi proof verification failed");
                }
            }
        }
    }

    let mut winning_matrix: Vec<Vec<ProjectivePoint>> = vec![vec![K256Group::identity(); vector_size]; n_bidders];

    for (i, bidder_phi) in bidders_phi_list.iter().enumerate() {
        for phi_row in bidder_phi.inner.iter() {
            if phi_row.public_key == bidder_public_key {
                for j in 0..vector_size {
                    winning_matrix[i][j] = phi_row.phi_vector[j].inner.clone();
                }
            }
        }
    }

    winning_matrix
}

 pub fn is_winner(phi_matrix: &Vec<Vec<ProjectivePoint>>, gamma_matrix: Vec<Vec<ProjectivePoint>>) -> bool {
        let n_bidders = phi_matrix.len();
        let mut winning_vector: Vec<ProjectivePoint> = vec![K256Group::identity(); phi_matrix[0].len()];

        for j in 0..phi_matrix[0].len() {
            let mut acc_gamma = K256Group::identity();
            let mut acc_phi = K256Group::identity();

            for h in 0..n_bidders {
                acc_gamma = &acc_gamma + &gamma_matrix[h][j];
                acc_phi = &acc_phi + &phi_matrix[h][j];
            }
            let final_decryption = &acc_gamma - &acc_phi;

            winning_vector[j] = final_decryption;
        }

        for j in 0..phi_matrix[0].len() {
            if winning_vector[j] == K256Group::identity() {
                return true;
            }
        }

        return false;
    }

pub fn derive_bidder_gamma_matrix(
    bidder_share_list: Vec<BidderShareMatrix>,
    auction_params: &AuctionParams,
    bidder_public_key: ProjectivePoint,
) -> Vec<Vec<ProjectivePoint>> {
    let n_bidders = bidder_share_list.len();
    let vector_size = auction_params.rate.total_slots() as usize;

    let mut gamma_matrix: Vec<Vec<ProjectivePoint>> = vec![vec![K256Group::identity(); vector_size]; n_bidders];

    for (i, bidder_share) in bidder_share_list.iter().enumerate() {
        for share_row in bidder_share.rows.iter() {
            if share_row.public_key == bidder_public_key {
                for j in 0..vector_size {
                    gamma_matrix[i][j] = share_row.share_column[j].gamma.clone();
                }
            }
        }
    }

    gamma_matrix
}

fn get_all_deltas(
    bidder_share_list: Vec<BidderShareMatrix>,
    auction_params: &AuctionParams,
) -> Vec<Vec<ProjectivePoint>> {
    let n_bidders = bidder_share_list.len();
    let vector_size = auction_params.rate.total_slots() as usize;

    let all_deltas = bidder_share_list
            .iter()
            .map(|share| share.rows.clone().iter().map(|row| row.share_column.clone().iter().map(|m| m.delta).collect::<Vec<_>>()).collect::<Vec<_>>()).collect::<Vec<_>>();

    let mut aggregated_deltas: Vec<Vec<ProjectivePoint>> = vec![vec![K256Group::identity(); vector_size]; n_bidders];
    // sum all columns of all bidders into the pre-allocated rows
    for h in 0..all_deltas.len() {
        for j in 0..vector_size {
            let mut delta_aggregated_column = K256Group::identity();
            for i in 0..all_deltas.len() {
                delta_aggregated_column = delta_aggregated_column + (all_deltas[i][h][j].clone());
            }
            aggregated_deltas[h][j] = delta_aggregated_column;
        }
    }

    aggregated_deltas
}

fn aggregate_public_key(bids: &BTreeSet<EncBidVector>) -> ProjectivePoint {
    bids.iter()
        .fold(ProjectivePoint::IDENTITY, |acc, bid| acc + bid.public_key)
}

fn verify_bid_vector(
    bid_vector: &EncBidVector,
    aggregated_pk: &ProjectivePoint,
    marker_projective: &ProjectivePoint,
) -> Result<(), AuctionError> {
    let generator = ProjectivePoint::GENERATOR;

    for enc_bid in &bid_vector.encoded_bid {
        let ciphertext = &enc_bid.inner;
        if !verify_or_dleq(
            &generator,
            aggregated_pk,
            marker_projective,
            &ciphertext.random_element,
            &ciphertext.blinded_element,
            &enc_bid.proof,
        ) {
            return Err(AuctionError::ProofVerificationFailed);
        }
    }

    let h1 = bid_vector
        .encoded_bid
        .iter()
        .map(|ct| ct.inner.random_element)
        .fold(ProjectivePoint::IDENTITY, |a, b| a + b);
    let h2 = bid_vector
        .encoded_bid
        .iter()
        .map(|ct| ct.inner.blinded_element)
        .fold(ProjectivePoint::IDENTITY, |a, b| a + b)
        - *marker_projective;

    if !verify_dleq(&generator, &h1, aggregated_pk, &h2, &bid_vector.proof) {
        return Err(AuctionError::ProofVerificationFailed);
    }

    Ok(())
}




#[cfg(test)]
mod tests {
    use super::*;
    use crate::elgamal::K256Group;
    use k256::{
        ProjectivePoint, Scalar,
        elliptic_curve::ops::MulByGenerator,
    };
    use rand::{rngs::StdRng, SeedableRng};

    #[test]
    fn linear_bidding_flow_selects_highest_bidder() {
        let auction_params = AuctionParams {
            rate: rate::RateParams {
                min_bps: 100,
                max_bps: 1000,
                step_bps: 100,
            },
            m: 1,
            num_bidders: 10,
        };
        let num_bidders = auction_params.num_bidders as usize;

        let mut secret_keys = Vec::with_capacity(num_bidders);
        let mut public_keys = Vec::with_capacity(num_bidders);
        for idx in 0..num_bidders {
            let mut key_rng = StdRng::seed_from_u64(1_000 + idx as u64);
            let sk = Scalar::random(&mut key_rng);
            let pk = ProjectivePoint::mul_by_generator(&sk);
            secret_keys.push(sk);
            public_keys.push(pk);
        }

        let aggregated_pk =
            public_keys
                .iter()
                .fold(ProjectivePoint::IDENTITY, |acc, pk| acc + pk);
        let group_pk = K256Group::to_public_key(&aggregated_pk);

        let mut bid_vectors = Vec::with_capacity(num_bidders);
        for idx in 0..num_bidders {
            let mut bid_rng = StdRng::seed_from_u64(10_000 + idx as u64);
            let rate_bps =
            auction_params.rate.min_bps + (idx as u64) * auction_params.rate.step_bps;
            assert!(
                rate_bps >= auction_params.rate.min_bps
                    && rate_bps <= auction_params.rate.max_bps
            );

            let bid_vector = make_onehot_bid(
                &mut bid_rng,
                secret_keys[idx],
                public_keys[idx],
                &group_pk,
                &auction_params,
                rate_bps,
            );
            bid_vectors.push(bid_vector);
        }

        let enc_bid_vectors: BTreeSet<EncBidVector> = bid_vectors
            .iter()
            .map(|bv| bv.enc_bits.clone())
            .collect();

        let mut key_rng = StdRng::seed_from_u64(1000);
        let bidder_shares: BTreeSet<BidderShareMatrix> = bid_vectors
            .iter()
            .map(|bv| {
                bv.compute_bidder_share(&mut key_rng, enc_bid_vectors.clone())
                    .expect("proof verification should succeed")
            })
            .collect();

        let mut key_rng = StdRng::seed_from_u64(1_000);

        let phi_list: BTreeSet<BidderPhiMatrix> = bid_vectors
            .iter()
            .map(|bv| bv.derive_phi(& mut key_rng,bidder_shares.clone(), enc_bid_vectors.clone()))
            .collect();

        let users_sets: Vec<(ProjectivePoint, Vec<Vec<ProjectivePoint>>, Vec<Vec<ProjectivePoint>>)> = bid_vectors
            .iter()
            .map(|bv| {
                let bidder_public_key = bv.enc_bits.public_key;
                let phi_matrix = derive_bidder_phi_matrix(
                    phi_list.clone().into_iter().collect(),
                    &auction_params,
                    bidder_public_key,
                    bidder_shares.clone().into_iter().collect()
                );
                let gamma_matrix = derive_bidder_gamma_matrix(
                    bidder_shares.clone().into_iter().collect(),
                    &auction_params,
                    bidder_public_key,
                );
                (bidder_public_key, phi_matrix, gamma_matrix)
            })
            .collect();

        let winners: Vec<(ProjectivePoint, bool)> = users_sets.into_iter()
            .map(|(pk, phi_matrix, gamma_matrix)| {
                (pk,is_winner(&phi_matrix, gamma_matrix))
            })
            .collect();


        let winner_count = winners.iter().filter(|flag| flag.1).count();
        assert_eq!(winner_count, 1, "there should be exactly one winner");

        let winner = winners[0].0;
        let wiiner_rate_bps = bid_vectors.iter().find(|bv| bv.enc_bits.public_key == winner).unwrap().bid_amount;
         assert_eq!(
        wiiner_rate_bps, auction_params.rate.min_bps,
        "bidder with lowest interest rate should win"
    );
       

    }
}
