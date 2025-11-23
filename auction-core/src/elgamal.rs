use elastic_elgamal::{
    group::{ElementOps, Group as ElGroup, ScalarOps},
};
use k256::{
    EncodedPoint, ProjectivePoint, Scalar as S,
    elliptic_curve::{
        Field,
        ff::PrimeField,
        group::Group as _,
        sec1::{FromEncodedPoint, ToEncodedPoint},
    },
};
use rand::{CryptoRng, RngCore};

use crate::serde::projective_point;
use serde::{Deserialize, Serialize};

pub type Element = ProjectivePoint;
pub type Scalar = S;

const SCALAR_SIZE: usize = 32;
 const ELEMENT_SIZE: usize = 33;

 #[derive(Debug, Clone)]
#[non_exhaustive]
pub enum PublicKeyConversionError {
    /// Invalid size of the byte buffer.
    InvalidByteSize,
    /// Byte buffer has correct size, but does not represent a group element.
    InvalidGroupElement,
    /// Underlying group element is the group identity.
    IdentityKey,
}

#[derive(Clone, Serialize, Deserialize)]

pub struct Ciphertext {
    #[serde(with = "projective_point")]
    pub random_element: Element,
    #[serde(with = "projective_point")]
    pub blinded_element: Element,
    pub random_scalar: Scalar,
}

#[derive(Clone, Debug)]
pub struct PublicKey{
    bytes: Vec<u8>,
    element: Element,
}

impl PublicKey {
    /// Deserializes a public key from bytes.
    ///
    /// # Errors
    ///
    /// Returns an error if `bytes` has invalid byte size, does not represent a valid group element
    /// or represents the group identity.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, PublicKeyConversionError> {
        if bytes.len() != ELEMENT_SIZE {
            return Err(PublicKeyConversionError::InvalidByteSize);
        }

        let element =
            K256Group::deserialize_element(bytes).ok_or(PublicKeyConversionError::InvalidGroupElement)?;
        if K256Group::is_identity(&element) {
            Err(PublicKeyConversionError::IdentityKey)
        } else {
            Ok(Self {
                bytes: bytes.to_vec(),
                element,
            })
        }
    }

    pub(crate) fn from_element(element: Element) -> Self {
        let mut element_bytes = vec![0_u8; ELEMENT_SIZE];
        K256Group::serialize_element(&element, &mut element_bytes);
        PublicKey {
            element,
            bytes: element_bytes,
        }
    }

    /// Returns bytes representing the group element corresponding to this key.
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Returns the group element equivalent to this key.
    pub fn as_element(&self) -> Element {
        self.element
    }

    pub fn encrypt_element<R: CryptoRng + RngCore>(
        &self,
        value: Element,
        rng: &mut R,
    ) -> Ciphertext {
        let random_scalar = K256Group::generate_scalar(rng);
        let random_element = K256Group::mul_generator(&random_scalar);
        let dh_element = self.as_element() * random_scalar;
        let blinded_element = value + dh_element;

        return Ciphertext {
            random_element,
            blinded_element,
            random_scalar,
        };
    }

}

// impl From<&SecretKey> for PublicKey {
//     fn from(secret_key: &SecretKey) -> Self {
//         let element = G::mul_generator(&secret_key.0);
//         Self::from_element(element)
//     }
// }

#[derive(Clone, Copy, Debug, Default)]
pub struct K256Group;

impl  K256Group {

    fn generate_scalar<R: rand_core::CryptoRng + rand_core::RngCore>(rng: &mut R) -> Scalar {
        Scalar::random(rng)
    }

    fn invert_scalar(scalar: Scalar) -> Scalar {
        scalar.invert().unwrap()
    }

    fn serialize_scalar(scalar: &Scalar, buffer: &mut [u8]) {
        buffer.copy_from_slice(scalar.to_bytes().as_slice());
    }

    fn deserialize_scalar(buffer: &[u8]) -> Option<Scalar> {
        if buffer.len() != SCALAR_SIZE {
            return None;
        }

        let mut bytes = [0u8; SCALAR_SIZE];
        bytes.copy_from_slice(buffer);

        Scalar::from_repr(bytes.into()).into()
    }
}

impl  K256Group {

   

    #[inline]
    pub fn identity() -> Element {
        ProjectivePoint::IDENTITY
    }

    #[inline]
    fn is_identity(element: &Element) -> bool {
        element.is_identity().into()
    }

    #[inline]
    fn generator() -> Element {
        ProjectivePoint::GENERATOR
    }

    fn serialize_element(element: &Element, buffer: &mut [u8]) {
        let encoded = element.to_encoded_point(true);
        buffer.copy_from_slice(encoded.as_bytes());
    }

    fn deserialize_element(buffer: &[u8]) -> Option<Element> {
        let encoded = EncodedPoint::from_bytes(buffer).ok()?;
        ProjectivePoint::from_encoded_point(&encoded).into()
    }
}

impl K256Group {
    #[inline]
    fn mul_generator(k: &Scalar) -> Element {
        ProjectivePoint::GENERATOR * *k
    }

    #[inline]
    fn vartime_mul_generator(k: &Scalar) -> Element {
        // k256's scalar mul is already variable-time in arithmetic mode.
        ProjectivePoint::GENERATOR * *k
    }

    fn multi_mul<'a, I, J>(scalars: I, elements: J) -> Element
    where
        I: IntoIterator<Item = &'a Scalar>,
        J: IntoIterator<Item = Element>,
    {
        // Collect to slices for potential MSM optimization
        let s_vec: Vec<Scalar> = scalars.into_iter().copied().collect();
        let p_vec: Vec<ProjectivePoint> = elements.into_iter().collect();

        p_vec
            .iter()
            .zip(s_vec.iter())
            .fold(ProjectivePoint::IDENTITY, |acc, (p, s)| acc + (*p * *s))
    }

    #[inline]
    fn vartime_double_mul_generator(
        k: &Scalar,         // scalar for G
        k_element: Element, // point P
        r: &Scalar,         // scalar for P
    ) -> Element {
        // Compute k·G + r·P
        (ProjectivePoint::GENERATOR * *k) + (k_element * *r)
    }

    fn vartime_multi_mul<'a, I, J>(scalars: I, elements: J) -> Element
    where
        I: IntoIterator<Item = &'a Scalar>,
        J: IntoIterator<Item = Element>,
    {
        // For variable-time we can use the same fold; if you later wire a var-time MSM,
        // swap it in here.
        let s_vec: Vec<Scalar> = scalars.into_iter().copied().collect();
        let p_vec: Vec<ProjectivePoint> = elements.into_iter().collect();

        p_vec
            .iter()
            .zip(s_vec.iter())
            .fold(ProjectivePoint::IDENTITY, |acc, (p, s)| acc + (*p * *s))
    }
}

impl K256Group {
    pub fn to_public_key(element: &ProjectivePoint) -> PublicKey {
        let bytes = element.to_encoded_point(true).as_bytes().to_vec();
        PublicKey::from_bytes(bytes.as_ref()).unwrap()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use elastic_elgamal::SecretKey;
    use k256::{
        ProjectivePoint, Scalar,
        elliptic_curve::{ops::MulByGenerator, Field},
    };
    use rand::{rngs::StdRng, SeedableRng};

    #[test]
    fn group_public_key_encrypts_and_decrypts_elements() {
        let secret_scalars = [
            Scalar::from(5u64),
            Scalar::from(9u64),
            Scalar::from(13u64),
        ];
        let public_points: Vec<ProjectivePoint> = secret_scalars
            .iter()
            .map(|sk| ProjectivePoint::mul_by_generator(sk))
            .collect();

        let aggregated_point =
            public_points
                .iter()
                .fold(ProjectivePoint::IDENTITY, |acc, pk| acc + pk);
        let group_public_key = K256Group::to_public_key(&aggregated_point);

        let aggregated_secret = secret_scalars
            .iter()
            .copied()
            .fold(Scalar::ZERO, |acc, sk| acc + sk);
        assert_eq!(
            aggregated_point,
            ProjectivePoint::mul_by_generator(&aggregated_secret),
            "group key should correspond to summed secret"
        );

        let mut rng = StdRng::seed_from_u64(7);
        let message = ProjectivePoint::GENERATOR * Scalar::from(42u64);
        let ciphertext = group_public_key.encrypt_element(message, &mut rng);


        let decrypted = ciphertext.blinded_element.clone() - (ciphertext.random_element * &aggregated_secret);
        assert_eq!(
            decrypted,
            ProjectivePoint::GENERATOR * Scalar::from(42u64),
            "group key should decrypt marker element"
        );
    }
}
