//! Content versions (`expected_version`, `new_version`, design §4.2): the
//! one definition both the agent (`fleet_ops::fswrite`) and the Mac core
//! (`fleet_core::versions`) use, so they can't drift apart.

/// First 8 bytes (little-endian) of the BLAKE3 of `bytes`: the version of
/// a replaced file or section.
pub fn content_version(bytes: &[u8]) -> u64 {
    let h = blake3::hash(bytes);
    let mut b = [0u8; 8];
    b.copy_from_slice(&h.as_bytes()[..8]);
    u64::from_le_bytes(b)
}

#[cfg(test)]
mod tests {
    #[test]
    fn known_value() {
        // BLAKE3("") = af1349b9 f5f9a1a6 …
        assert_eq!(super::content_version(b""), 0xa6a1_f9f5_b949_13af);
    }
}
