use elastic_elgamal::{group::{ElementOps, Group as ElGroup, ScalarOps}, PublicKey};
use k256::{
    elliptic_curve::{
        ff::PrimeField,
        group::Group as _,
        sec1::{FromEncodedPoint, ToEncodedPoint},
        Field,
    },
    EncodedPoint, ProjectivePoint, Scalar,
};

#[derive(Clone, Copy, Debug, Default)]
pub struct K256Group;

impl ScalarOps for K256Group {
    type Scalar = Scalar;

    const SCALAR_SIZE: usize = 32;

    fn generate_scalar<R: rand_core::CryptoRng + rand_core::RngCore>(rng: &mut R) -> Self::Scalar {
        Scalar::random(rng)
    }

    fn invert_scalar(scalar: Self::Scalar) -> Self::Scalar {
        scalar.invert().unwrap()
    }

    fn serialize_scalar(scalar: &Self::Scalar, buffer: &mut [u8]) {
        buffer.copy_from_slice(scalar.to_bytes().as_slice());
    }

    fn deserialize_scalar(buffer: &[u8]) -> Option<Self::Scalar> {
        if buffer.len() != Self::SCALAR_SIZE {
            return None;
        }

        let mut bytes = [0u8; Self::SCALAR_SIZE];
        bytes.copy_from_slice(buffer);

        Scalar::from_repr(bytes.into()).into()
    }
}

impl ElementOps for K256Group {
    type Element = ProjectivePoint;

    const ELEMENT_SIZE: usize = 33;

    #[inline]
    fn identity() -> Self::Element {
        ProjectivePoint::IDENTITY
    }

    #[inline]
    fn is_identity(element: &Self::Element) -> bool {
        element.is_identity().into()
    }

    #[inline]
    fn generator() -> Self::Element {
        ProjectivePoint::GENERATOR
    }

    fn serialize_element(element: &Self::Element, buffer: &mut [u8]) {
        let encoded = element.to_encoded_point(true);
        buffer.copy_from_slice(encoded.as_bytes());
    }

    fn deserialize_element(buffer: &[u8]) -> Option<Self::Element> {
        let encoded = EncodedPoint::from_bytes(buffer).ok()?;
        ProjectivePoint::from_encoded_point(&encoded).into()
    }
}

impl ElGroup for K256Group {
    #[inline]
    fn mul_generator(k: &Self::Scalar) -> Self::Element {
        ProjectivePoint::GENERATOR * *k
    }

    #[inline]
    fn vartime_mul_generator(k: &Self::Scalar) -> Self::Element {
        // k256's scalar mul is already variable-time in arithmetic mode.
        ProjectivePoint::GENERATOR * *k
    }

    fn multi_mul<'a, I, J>(scalars: I, elements: J) -> Self::Element
    where
        I: IntoIterator<Item = &'a Self::Scalar>,
        J: IntoIterator<Item = Self::Element>,
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
        k: &Self::Scalar,        // scalar for G
        k_element: Self::Element, // point P
        r: &Self::Scalar,        // scalar for P
    ) -> Self::Element {
        // Compute k·G + r·P
        (ProjectivePoint::GENERATOR * *k) + (k_element * *r)
    }

    fn vartime_multi_mul<'a, I, J>(scalars: I, elements: J) -> Self::Element
    where
        I: IntoIterator<Item = &'a Self::Scalar>,
        J: IntoIterator<Item = Self::Element>,
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
    pub fn to_public_key(element: &ProjectivePoint) -> PublicKey<K256Group> {
        let bytes = element.to_encoded_point(true).as_bytes().to_vec();
        PublicKey::from_bytes(bytes.as_ref()).unwrap()
    }
}