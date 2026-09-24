use super::BoundedString;
use serde::{Deserialize, Serialize};

/// Who initiated a command, as asserted by the Mac app (design §5.4), or
/// `System` for actions the agent takes on its own.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Actor {
    Human,
    Ai {
        client: BoundedString<64>,
        session: [u8; 16],
    },
    Runbook {
        id: [u8; 16],
    },
    /// Required on (and only on) recovery-key commands.
    Recovery,
    /// Agent-originated (auto-revert, startup cleanup). Never valid in a
    /// signed command; appears only in audit entries written by exec.
    System,
}
