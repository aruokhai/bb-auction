use k256::{elliptic_curve::{ops::MulByGenerator, Field, PrimeField}, ProjectivePoint, Scalar};
use rand::{CryptoRng, RngCore};
use k256::elliptic_curve::sec1::ToEncodedPoint;
use serde::{Deserialize, Serialize};
use crate::serde::projective_point;
use sha2::Sha256;
use sha2::Digest;

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