use std::{cmp, collections::{BTreeMap, BTreeSet, HashSet}};

use k256::{ProjectivePoint, Scalar, elliptic_curve::{Field, Group, PrimeField}};
use rand::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};
use crate::{proof::{DleqProof, OrDleqProof}, serde::projective_point::vec::serialize};
use k256::elliptic_curve::sec1::ToEncodedPoint;
use crate::serde::projective_point;
use crate::serde::bid_share_column_vec;
use crate::elgamal::*;

pub struct Phi {
    pub inner: ProjectivePoint,
    pub proof: DleqProof,
}

#[derive(Clone, Serialize, Deserialize)]

pub struct EncBid {
    pub inner: Ciphertext,
    pub proof: OrDleqProof,
}


#[derive(Clone, Serialize, Deserialize)]

pub struct EncBidVector {
    #[serde(with = "projective_point")]
    pub public_key: ProjectivePoint,
    pub encoded_bid: Vec<EncBid>,
    pub proof: DleqProof,
} // length = K


impl PartialEq for  EncBidVector {
    fn eq(&self, other: &Self) -> bool {
        self.public_key
            .to_affine()
            .to_encoded_point(true)
            .as_bytes()
            ==
        other.public_key
            .to_affine()
            .to_encoded_point(true)
            .as_bytes()
    }
}

impl Eq for EncBidVector {}

impl Ord for EncBidVector {
    fn cmp(&self, other: &Self) -> cmp::Ordering {
        let a_ep = self
            .public_key
            .to_affine()
            .to_encoded_point(true);
        let b_ep = other
            .public_key
            .to_affine()
            .to_encoded_point(true);
        a_ep.as_bytes().cmp(b_ep.as_bytes())
    }
}

impl PartialOrd for EncBidVector {
    fn partial_cmp(&self, other: &Self) -> Option<cmp::Ordering> {
        Some(self.cmp(other))
    }
}


#[derive(Clone, Serialize, Deserialize)]

pub struct BidderPhiMatrix {
    #[serde(with = "projective_point")]
    pub public_key: ProjectivePoint,
    pub inner: BTreeSet<BidderPhiRow>

}

impl PartialEq for  BidderPhiMatrix {
    fn eq(&self, other: &Self) -> bool {
        self.public_key
            .to_affine()
            .to_encoded_point(true)
            .as_bytes()
            ==
        other.public_key
            .to_affine()
            .to_encoded_point(true)
            .as_bytes()
    }
}

impl Eq for BidderPhiMatrix {}

impl Ord for BidderPhiMatrix {
    fn cmp(&self, other: &Self) -> cmp::Ordering {
        let a_ep = self
            .public_key
            .to_affine()
            .to_encoded_point(true);
        let b_ep = other
            .public_key
            .to_affine()
            .to_encoded_point(true);
        a_ep.as_bytes().cmp(b_ep.as_bytes())
    }
}

impl PartialOrd for BidderPhiMatrix {
    fn partial_cmp(&self, other: &Self) -> Option<cmp::Ordering> {
        Some(self.cmp(other))
    }
}

#[derive(Clone, Serialize, Deserialize)]
pub struct  BidderPhiRow {
     #[serde(with = "projective_point")]
    pub public_key: ProjectivePoint,

    #[serde(with = "projective_point::vec")]
    pub phi_vector: Vec<Phi>,

}



impl PartialEq for  BidderPhiRow {
    fn eq(&self, other: &Self) -> bool {
        self.public_key
            .to_affine()
            .to_encoded_point(true)
            .as_bytes()
            ==
        other.public_key
            .to_affine()
            .to_encoded_point(true)
            .as_bytes()
    }
}

impl Eq for BidderPhiRow {}

impl Ord for BidderPhiRow {
    fn cmp(&self, other: &Self) -> cmp::Ordering {
        let a_ep = self
            .public_key
            .to_affine()
            .to_encoded_point(true);
        let b_ep = other
            .public_key
            .to_affine()
            .to_encoded_point(true);
        a_ep.as_bytes().cmp(b_ep.as_bytes())
    }
}

impl PartialOrd for BidderPhiRow {
    fn partial_cmp(&self, other: &Self) -> Option<cmp::Ordering> {
        Some(self.cmp(other))
    }
}

pub type Gamma = ProjectivePoint;
pub type Delta = ProjectivePoint;

#[derive(Clone, Serialize, Deserialize)]
pub struct BidderShareRow {
    #[serde(with = "projective_point")]
    pub public_key: ProjectivePoint,

    #[serde(with = "bid_share_column_vec")]
    pub share_column: Vec<BidShareColumn>,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct BidShareColumn {
    #[serde(with = "projective_point")]
    pub gamma: Gamma,
    #[serde(with = "projective_point")]
    pub delta: Delta,
    pub proof: DleqProof,
}



impl PartialEq for BidderShareRow {
    fn eq(&self, other: &Self) -> bool {
        self.public_key
            .to_affine()
            .to_encoded_point(true)
            .as_bytes()
            ==
        other.public_key
            .to_affine()
            .to_encoded_point(true)
            .as_bytes()
    }
}

impl Eq for BidderShareRow {}

impl Ord for BidderShareRow {
    fn cmp(&self, other: &Self) -> cmp::Ordering {
        let a_ep = self
            .public_key
            .to_affine()
            .to_encoded_point(true);
        let b_ep = other
            .public_key
            .to_affine()
            .to_encoded_point(true);
        a_ep.as_bytes().cmp(b_ep.as_bytes())
    }
}

impl PartialOrd for BidderShareRow {
    fn partial_cmp(&self, other: &Self) -> Option<cmp::Ordering> {
        Some(self.cmp(other))
    }
}

#[derive(Clone, Serialize, Deserialize)]
pub struct  BidderShareMatrix {
    #[serde(with = "projective_point")]
    pub public_key: ProjectivePoint,
    pub rows: BTreeSet<BidderShareRow>,
}  

impl PartialEq for BidderShareMatrix {
    fn eq(&self, other: &Self) -> bool {
        self.public_key
            .to_affine()
            .to_encoded_point(true)
            .as_bytes()
            ==
        other.public_key
            .to_affine()
            .to_encoded_point(true)
            .as_bytes()
    }
}

impl Eq for BidderShareMatrix {}

impl Ord for BidderShareMatrix {
    fn cmp(&self, other: &Self) -> cmp::Ordering {
        let a_ep = self
            .public_key
            .to_affine()
            .to_encoded_point(true);
        let b_ep = other
            .public_key
            .to_affine()
            .to_encoded_point(true);
        a_ep.as_bytes().cmp(b_ep.as_bytes())
    }
}

impl PartialOrd for BidderShareMatrix {
    fn partial_cmp(&self, other: &Self) -> Option<cmp::Ordering> {
        Some(self.cmp(other))
    }
}


