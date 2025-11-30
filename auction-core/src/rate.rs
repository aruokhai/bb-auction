use serde::{Deserialize, Serialize};


#[derive(Clone, Serialize, Deserialize)]
pub struct RateParams {
    pub min_bps: u64,  // e.g. 100 = 1.00%
    pub max_bps: u64,  // e.g. 1000 = 10.00%
    pub step_bps: u64, // granularity, e.g. 1 = 0.01% = 1 bp
}

impl RateParams {
    /// Computes the total number of discrete rate slots defined by these parameters.
    pub fn total_slots(&self) -> usize {
        if self.step_bps == 0 || self.max_bps < self.min_bps {
            0
        } else {
            ((self.max_bps - self.min_bps) / self.step_bps) as usize + 1
        }
    }
    pub fn  find_rate_index(&self, rate_bps: u64) -> Option<usize> {
        let min: u64 = self.min_bps;
        let max = self.max_bps;
        let step = self.step_bps;

        if step == 0 {
            return None;
        }
        if rate_bps < min || rate_bps > max {
            return None;
        }

        // total number of slots in [min, max] inclusive
        let total_slots = ((max - min) / step) as usize + 1;

        // forward index: min -> 0, max -> total_slots - 1
        let forward_idx = ((rate_bps - min) / step) as usize;

        // reverse: high index for low rates, low index for high rates
        let idx = total_slots - 1 - forward_idx;

        if idx >= total_slots {
            return None;
        }

        Some(idx)
    }

}



#[cfg(test)]
mod tests {
    use super::{RateParams};

    fn params() -> RateParams {
        RateParams {
            min_bps: 100,   // 1.00%
            max_bps: 1000,  // 10.00%
            step_bps: 1,    // 1 bp
        }
    }

    #[test]
    fn max_rate_maps_to_zero_index() {
        let p = params();
        let idx = p.find_rate_index(1000, );
        assert_eq!(idx, Some(0));
    }

    #[test]
    fn min_rate_maps_to_last_index() {
        let p = params();
        let total_slots = p.total_slots();
        let idx = p.find_rate_index(100);
        assert_eq!(idx, Some(total_slots - 1));
    }

    #[test]
    fn middle_rate_maps_to_middle_index() {
        let p = params();
        // 100..=1000 with step 1 → 901 slots, so middle is around 550 bps
        let total_slots = p.total_slots();
        let idx = p.find_rate_index(550).unwrap();

        // sanity: index is within bounds
        assert!(idx < total_slots);

        // symmetry check: distance from both ends roughly the same
        let dist_from_low = total_slots - 1 - idx;
        let dist_from_high = idx;
        assert!((dist_from_low as isize - dist_from_high as isize).abs() <= 1);
    }

    #[test]
    fn rate_below_min_is_rejected() {
        let p = params();
        let idx = p.find_rate_index(50);
        assert_eq!(idx, None);
    }

    #[test]
    fn rate_above_max_is_rejected() {
        let p = params();
        let idx = p.find_rate_index(1200);
        assert_eq!(idx, None);
    }

    #[test]
    fn zero_step_is_rejected() {
        let p = RateParams {
            min_bps: 100,
            max_bps: 200,
            step_bps: 0,
        };
        let idx = p.find_rate_index(150);
        assert_eq!(idx, None);
    }

    #[test]
    fn indices_are_monotone_in_rate() {
        let p = params();
        let total_slots = ((p.max_bps - p.min_bps) / p.step_bps) as usize + 1;

        // as rate increases, index must not increase
        let mut prev_idx = p.find_rate_index(p.min_bps).unwrap();
        assert!(prev_idx < total_slots);

        let mut rate = p.min_bps + p.step_bps;
        while rate <= p.max_bps {
            let idx = p.find_rate_index(rate).unwrap();
            assert!(idx <= prev_idx, "idx should be non-increasing as rate increases");
            prev_idx = idx;
            rate += p.step_bps;
        }
    }
}