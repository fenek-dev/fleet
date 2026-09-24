//! Domain-separation prefixes for every signature in the protocol.
//!
//! A signed message is always `DOMAIN ‖ payload`. No prefix is a prefix of
//! another, so a signature for one purpose never verifies for another.

pub const CMD: &[u8] = b"fleet/cmd/v1";
pub const AUTH: &[u8] = b"fleet/auth/v1";
pub const APPROVE: &[u8] = b"fleet/approve/v1";
pub const ROSTER: &[u8] = b"fleet/roster/v1";
pub const RECEIPT: &[u8] = b"fleet/receipt/v1";
pub const CHECKPOINT: &[u8] = b"fleet/checkpoint/v1";
pub const RELEASE: &[u8] = b"fleet/release/v1";
pub const EVENT: &[u8] = b"fleet/event/v1";

pub(crate) fn concat(domain: &[u8], parts: &[&[u8]]) -> Vec<u8> {
    let len = domain.len() + parts.iter().map(|p| p.len()).sum::<usize>();
    let mut out = Vec::with_capacity(len);
    out.extend_from_slice(domain);
    for p in parts {
        out.extend_from_slice(p);
    }
    out
}

#[cfg(test)]
mod tests {
    #[test]
    fn no_domain_is_prefix_of_another() {
        let all = [
            super::CMD,
            super::AUTH,
            super::APPROVE,
            super::ROSTER,
            super::RECEIPT,
            super::CHECKPOINT,
            super::RELEASE,
            super::EVENT,
        ];
        for (i, a) in all.iter().enumerate() {
            for (j, b) in all.iter().enumerate() {
                assert!(i == j || !b.starts_with(a), "{a:?} prefixes {b:?}");
            }
        }
    }
}
