use core::fmt;

use k256::{CompressedPoint, ProjectivePoint};
use serde::{
    Deserializer, Serializer,
    de::{self, SeqAccess, Visitor},
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

    pub mod vec {
        use k256::{AffinePoint, ProjectivePoint};
        use serde::{Deserialize, Deserializer, Serialize, Serializer};

        // Serialize Vec<ProjectivePoint> by converting each element to AffinePoint
        // and delegating to AffinePoint's Serde implementation.
        pub fn serialize<S>(points: &Vec<ProjectivePoint>, serializer: S) -> Result<S::Ok, S::Error>
        where
            S: Serializer,
        {
            let affines = points.iter().map(|p| p.to_affine()).collect::<Vec<_>>();
            affines.serialize(serializer)
        }

        // Deserialize Vec<ProjectivePoint> by reading a Vec<AffinePoint>
        // and converting each element back to ProjectivePoint.
        pub fn deserialize<'de, D>(deserializer: D) -> Result<Vec<ProjectivePoint>, D::Error>
        where
            D: Deserializer<'de>,
        {
            let affines = Vec::<AffinePoint>::deserialize(deserializer)?;
            Ok(affines
                .into_iter()
                .map(ProjectivePoint::from)
                .collect::<Vec<_>>())
        }
    }

    pub mod vec_vec {
        use k256::{AffinePoint, ProjectivePoint};
        use serde::{Deserialize, Deserializer, Serialize, Serializer};

        // Serialize Vec<Vec<ProjectivePoint>> by converting each inner ProjectivePoint to AffinePoint.
        pub fn serialize<S>(
            points: &Vec<Vec<ProjectivePoint>>,
            serializer: S,
        ) -> Result<S::Ok, S::Error>
        where
            S: Serializer,
        {
            // Convert Vec<Vec<ProjectivePoint>> → Vec<Vec<AffinePoint>>
            let affines: Vec<Vec<AffinePoint>> = points
                .iter()
                .map(|inner| inner.iter().map(|p| p.to_affine()).collect())
                .collect();

            affines.serialize(serializer)
        }

        // Deserialize Vec<Vec<ProjectivePoint>> by reading Vec<Vec<AffinePoint>>
        // and converting each inner element back to ProjectivePoint.
        pub fn deserialize<'de, D>(deserializer: D) -> Result<Vec<Vec<ProjectivePoint>>, D::Error>
        where
            D: Deserializer<'de>,
        {
            let affines: Vec<Vec<AffinePoint>> =
                Vec::<Vec<AffinePoint>>::deserialize(deserializer)?;
            Ok(affines
                .into_iter()
                .map(|inner| inner.into_iter().map(ProjectivePoint::from).collect())
                .collect())
        }
    }
}


pub mod bid_share_column_vec {
    use serde::{Deserialize, Serialize};

    use crate::types::BidShareColumn;

    use super::*;

    pub fn serialize<S>(cols: &Vec<BidShareColumn>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        // BidShareColumn already implements Serialize (and its fields use
        // #[serde(with = "projective_point")]), so we can just delegate.
        cols.serialize(serializer)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Vec<BidShareColumn>, D::Error>
    where
        D: Deserializer<'de>,
    {
        // Same idea on the way back.
        Vec::<BidShareColumn>::deserialize(deserializer)
    }
}