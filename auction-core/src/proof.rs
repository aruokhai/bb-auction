use crate::serde::projective_point;
use k256::elliptic_curve::sec1::ToEncodedPoint;
use k256::{
    ProjectivePoint, Scalar,
    elliptic_curve::{Field, PrimeField, ops::MulByGenerator},
};
use rand::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};
use sha2::Digest;
use sha2::Sha256;

#[derive(Clone, Serialize, Deserialize)]

pub struct SecretKeyProof {
    #[serde(with = "projective_point")]
    pub commitment: ProjectivePoint,
    pub response: Scalar,
}

impl SecretKeyProof {
    pub fn new<R: RngCore + CryptoRng>(
        secret_key: &Scalar,
        public_key: &ProjectivePoint,
        rng: &mut R,
    ) -> Self {
        let nonce = Scalar::random(rng);
        let commitment = ProjectivePoint::mul_by_generator(&nonce);
        let challenge = compute_challenge(&commitment, public_key);
        let response = nonce + (challenge * secret_key);

        Self {
            commitment,
            response,
        }
    }
}

fn compute_challenge(commitment: &ProjectivePoint, public_key: &ProjectivePoint) -> Scalar {
    let commitment_bytes = commitment
        .to_affine()
        .to_encoded_point(true)
        .as_bytes()
        .to_vec();
    let public_key_bytes = public_key
        .to_affine()
        .to_encoded_point(true)
        .as_bytes()
        .to_vec();

    let mut hasher = Sha256::new();
    hasher.update(commitment_bytes);
    hasher.update(public_key_bytes);

    let challenge_bytes = hasher.finalize();

    // Convert the hash output to a Scalar, defaulting to zero if invalid
    Scalar::from_repr(challenge_bytes.into()).unwrap_or_else(|| Scalar::ZERO)
}


#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct OrDleqProof {
    #[serde(with = "projective_point")]
    // T0_*: commitments for branch "M = 1"
    pub t0_1: ProjectivePoint,
    #[serde(with = "projective_point")]
    pub t0_2: ProjectivePoint,
    // T1_*: commitments for branch "M = Y"
    #[serde(with = "projective_point")]
    pub t1_1: ProjectivePoint,
    #[serde(with = "projective_point")]
    pub t1_2: ProjectivePoint,
    // challenges and responses for each branch
    pub c0: Scalar,
    pub c1: Scalar,
    pub s0: Scalar,
    pub s1: Scalar,
}

/// Which plaintext case this ciphertext actually uses.
pub enum PlainCase {
    IsOne, // M = 1 (identity)
    IsY,   // M = marker Y
}

/// Prove that ciphertext (C1, C2) encrypts either O or marker_y
/// under public key Y_pub, with randomness r.
///
/// G     : base generator
/// Y_pub : ElGamal public key (group element)
/// marker_y : point Y representing "bid mark"
/// C1    : r*G
/// C2    : M + r*Y_pub    (M is O or marker_y)
pub fn prove_enc_bid<R: RngCore + CryptoRng>(
    rng: &mut R,
    g: &ProjectivePoint,
    y_pub: &ProjectivePoint,
    marker_y: &ProjectivePoint,
    c1: &ProjectivePoint,
    c2: &ProjectivePoint,
    r: &Scalar,        // encryption randomness (witness for the true branch)
    case: PlainCase,   // which plaintext was used
) -> OrDleqProof {
    // Branch 0: M = O, relation: log_G(C1) = log_{Y_pub}(C2)
    let h1_0 = *c1;
    let h2_0 = *c2;

    // Branch 1: M = Y, relation: log_G(C1) = log_{Y_pub}(C2 - Y)
    let h1_1 = *c1;
    let h2_1 = *c2 - *marker_y;

    // Choose which branch is true
    match case {
        PlainCase::IsOne => {
            // True branch = 0, false branch = 1

            // --- Simulate branch 1 ---
            let c1_fake = Scalar::random(&mut *rng);
            let s1_fake = Scalar::random(&mut  *rng);
            let t1_1 = *g * s1_fake - (h1_1 * c1_fake);
            let t1_2 = *y_pub * s1_fake - (h2_1 * c1_fake);

            // --- Real DLEQ for branch 0 with witness r ---
            let w = Scalar::random(rng);
            let t0_1 = *g * w;
            let t0_2 = *y_pub * w;

            // Fiat–Shamir global challenge
            let c = hash_to_scalar(&[
                *g, *y_pub, *marker_y, *c1, *c2,
                t0_1, t0_2, t1_1, t1_2,
            ]);

            let c0 = c - c1_fake;
            let s0 = w + c0 * r;

            OrDleqProof {
                t0_1, t0_2,
                t1_1, t1_2,
                c0,
                c1: c1_fake,
                s0,
                s1: s1_fake,
            }
        }
        PlainCase::IsY => {
            // True branch = 1, false branch = 0

            // --- Simulate branch 0 ---
            let c0_fake = Scalar::random(&mut *rng);
            let s0_fake = Scalar::random(&mut *rng);
            let t0_1 = *g * s0_fake - (h1_0 * c0_fake);
            let t0_2 = *y_pub * s0_fake - (h2_0 * c0_fake);

            // --- Real DLEQ for branch 1 with witness r ---
            let w = Scalar::random(rng);
            let t1_1 = *g * w;
            let t1_2 = *y_pub * w;

            // Fiat–Shamir global challenge
            let c = hash_to_scalar(&[
                *g, *y_pub, *marker_y, *c1, *c2,
                t0_1, t0_2, t1_1, t1_2,
            ]);

            let c1 = c - c0_fake;
            let s1 = w + c1 * r;

            OrDleqProof {
                t0_1, t0_2,
                t1_1, t1_2,
                c0: c0_fake,
                c1,
                s0: s0_fake,
                s1,
            }
        }
    }
}

/// Verify an OR-DLEQ proof used for ciphertext validity checks.
pub fn verify_or_dleq(
    g: &ProjectivePoint,
    y_pub: &ProjectivePoint,
    marker_y: &ProjectivePoint,
    c1: &ProjectivePoint,
    c2: &ProjectivePoint,
    proof: &OrDleqProof,
) -> bool {
    let OrDleqProof {
        t0_1,
        t0_2,
        t1_1,
        t1_2,
        c0,
        c1: c1_branch,
        s0,
        s1,
    } = proof;

    let h1_0 = *c1;
    let h2_0 = *c2;
    let h1_1 = *c1;
    let h2_1 = *c2 - *marker_y;

    // Global challenge must equal c0 + c1 in the field.
    let challenge = hash_to_scalar(&[*g, *y_pub, *marker_y, *c1, *c2, *t0_1, *t0_2, *t1_1, *t1_2]);
    if (*c0 + *c1_branch) != challenge {
        return false;
    }

    let branch0_ok =
        (*g * *s0 == *t0_1 + (h1_0 * *c0)) && (*y_pub * *s0 == *t0_2 + (h2_0 * *c0));
    let branch1_ok =
        (*g * *s1 == *t1_1 + (h1_1 * *c1_branch)) && (*y_pub * *s1 == *t1_2 + (h2_1 * *c1_branch));

    branch0_ok && branch1_ok
}


/// Hash a bunch of curve points into a scalar (Fiat–Shamir challenge).
fn hash_to_scalar(points: &[ProjectivePoint]) -> Scalar {
    let mut hasher = Sha256::new();
    for p in points {
        let affine = p.to_affine();
        let enc = affine.to_encoded_point(true);
        hasher.update(enc.as_bytes());
    }
    let bytes = hasher.finalize();
    // Reduce 256-bit hash mod curve order
    Scalar::from_repr(bytes.into()).unwrap()
}

/// Simple DLEQ proof: log_{g1}(h1) = log_{g2}(h2)
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DleqProof {
    #[serde(with = "projective_point")]
    pub t1: ProjectivePoint,
    #[serde(with = "projective_point")] 
    pub t2: ProjectivePoint,
    pub c: Scalar,
    pub s: Scalar,
}


/// Prover: given x such that h1 = x*g1 and h2 = x*g2, prove DLEQ.
pub fn prove_dleq<R: RngCore + CryptoRng>(
    rng: &mut R,
    g1: &ProjectivePoint,
    h1: &ProjectivePoint,
    g2: &ProjectivePoint,
    h2: &ProjectivePoint,
    x: &Scalar,
) -> DleqProof {
    // 1. Pick random w
    let w = Scalar::random(rng);

    // 2. Commitments T1 = w*g1, T2 = w*g2
    let t1 = *g1 * w;
    let t2 = *g2 * w;

    // 3. Fiat–Shamir: c = H(g1,h1,g2,h2,t1,t2)
    let c = hash_to_scalar(&[*g1, *h1, *g2, *h2, t1, t2]);

    // 4. Response s = w + c*x
    let s = w + c * x;

    DleqProof { t1, t2, c, s }
}


/// Verifier: check DLEQ
pub fn verify_dleq(
    g1: &ProjectivePoint,
    h1: &ProjectivePoint,
    g2: &ProjectivePoint,
    h2: &ProjectivePoint,
    proof: &DleqProof,
) -> bool {
    let DleqProof { t1, t2, c, s } = proof;

    // Recompute challenge
    let c_check = hash_to_scalar(&[*g1, *h1, *g2, *h2, *t1, *t2]);
    if *c != c_check {
        return false;
    }

    // Check s*g1 == T1 + c*h1
    let lhs1 = *g1 * *s;
    let rhs1 = *t1 + (*h1 * *c);

    // Check s*g2 == T2 + c*h2
    let lhs2 = *g2 * *s;
    let rhs2 = *t2 + (*h2 * *c);

    lhs1 == rhs1 && lhs2 == rhs2
}
