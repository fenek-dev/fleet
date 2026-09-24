//! `cron` group argument types (tags 700–799).

use crate::v1::args::{CronCommand, CronSpec, Label};
use serde::{Deserialize, Serialize};

/// One line of a user's crontab. `cron.set` replaces the whole crontab.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct CronEntry {
    pub schedule: CronSpec,
    pub command: CronCommand,
    /// Written as a `#` comment line above the entry.
    pub comment: Label,
}
