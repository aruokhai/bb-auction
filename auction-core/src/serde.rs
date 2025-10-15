use core::fmt;

use k256::{CompressedPoint, ProjectivePoint};
use serde::{
    de::{self, SeqAccess, Visitor},
    Deserializer, Serializer,
};

const COMPRESSED_POINT_LEN: usize = 33;

/// Serde helpers for `k256::ProjectivePoint`.
pub mod projective_point {
    use k256::AffinePoint;
    use serde::{Deserialize, Serialize};

    use super::*;

    pub fn serialize<S>(point: &ProjectivePoint, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {   
        let affine_point = point.to_affine();
        
        affine_point.serialize(serializer)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<ProjectivePoint, D::Error>
    where
        D: Deserializer<'de>,
    {
        
        let affine_point = AffinePoint::deserialize(deserializer)?;
        Ok(ProjectivePoint::from(affine_point))
    }
}
