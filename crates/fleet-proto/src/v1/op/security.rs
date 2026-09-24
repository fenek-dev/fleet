//! `security` group argument types (tags 200–299).

use crate::v1::args::{ArgError, Cidr, at_most, ensure};
use serde::{Deserialize, Serialize};

/// Intrusion blocking settings (design §4.7).
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct BanConfig {
    /// Failures within `window_s` that trigger a ban (1..=1000).
    pub threshold: u16,
    /// 10..=86400 seconds.
    pub window_s: u32,
    /// Ban durations for the first, second, … offence (1–4 steps, each
    /// 60 s ..= 30 days, non-decreasing).
    pub ban_steps_s: Vec<u32>,
    /// Never-banned ranges in addition to the learned Mac addresses (≤ 64).
    pub exempt: Vec<Cidr>,
    /// Ban web scanners seen in access logs.
    pub web_scanners: bool,
}

impl BanConfig {
    pub fn validate(&self) -> Result<(), ArgError> {
        ensure((1..=1000).contains(&self.threshold), "ban threshold")?;
        ensure((10..=86_400).contains(&self.window_s), "ban window")?;
        ensure(
            (1..=4).contains(&self.ban_steps_s.len())
                && self
                    .ban_steps_s
                    .iter()
                    .all(|s| (60..=30 * 86_400).contains(s))
                && self.ban_steps_s.windows(2).all(|w| w[0] <= w[1]),
            "ban steps",
        )?;
        at_most(&self.exempt, 64, "ban exemptions")
    }
}
