//! Compose files for `compose.deploy` (design §4.2, §9.6).
//!
//! Only size and encoding are checked here (`fleet-proto` stays free of a
//! YAML parser, and a textual scan can't be trusted: quoted keys, escapes,
//! anchors and merge keys all hide a key from it). The structural deny-list
//! check (`fleet_ops::compose::validate`)
//! (`privileged`, `cap_add` beyond the allow-list, `pid`/`ipc`/`network_mode`/
//! `userns_mode: host`, `devices`, `security_opt` disabling AppArmor or
//! seccomp, bind mounts outside `/srv/<project>/`) belongs to `fleet-ops`,
//! run by exec (and by the Mac to know whether to ask for Touch ID) on the
//! fully parsed and merged document. See `Op::may_escalate`.

use super::validated_string;

validated_string!(
    /// `compose.yaml` text: UTF-8, at most 256 KiB, no control characters
    /// but `\n`, `\r` and `\t`.
    ComposeFile,
    "compose file",
    |s| s.len() <= ComposeFile::MAX_BYTES
        && !s
            .chars()
            .any(|c| c.is_control() && !matches!(c, '\n' | '\r' | '\t'))
);

impl ComposeFile {
    pub const MAX_BYTES: usize = 256 * 1024;
}

#[cfg(test)]
mod tests {
    use super::super::testutil::{roundtrip, wire_rejects};
    use super::*;
    use proptest::prelude::*;

    #[test]
    fn examples() {
        let yaml = "services:\n  web:\n    image: nginx:1.27\n    ports: [\"127.0.0.1:8080:80\"]\n";
        roundtrip(&ComposeFile::new(yaml).unwrap());
        assert!(ComposeFile::new("a\0b").is_err());
        assert!(ComposeFile::new("x".repeat(ComposeFile::MAX_BYTES)).is_ok());
        assert!(ComposeFile::new("x".repeat(ComposeFile::MAX_BYTES + 1)).is_err());
        assert!(wire_rejects::<ComposeFile>("\u{1b}[2J"));
    }

    proptest! {
        #[test]
        fn accepts_printable(s in "[ -~\\n\\t]{0,400}") {
            prop_assert!(ComposeFile::new(s).is_ok());
        }
    }
}
