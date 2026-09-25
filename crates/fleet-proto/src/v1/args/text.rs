//! Bounded free-text and slug arguments.

use super::{line_ok, slug_ok, text_ok, validated_string};

validated_string!(
    /// Operator comment or label: at most 128 bytes, one line.
    Label,
    "label",
    |s| line_ok(s, 0, 128)
);

validated_string!(
    /// nftables rule comment. It lands inside an nft script, so the
    /// character set is closed: `[A-Za-z0-9 ._:/-]{0,64}`.
    FwComment,
    "firewall comment",
    |s| s.len() <= 64
        && s.bytes()
            .all(|c| c.is_ascii_alphanumeric() || b" ._:/-".contains(&c))
);

validated_string!(
    /// Fleet search term: 1–128 bytes, one line. Matched literally.
    SearchTerm,
    "search term",
    |s| line_ok(s, 1, 128)
);

validated_string!(
    /// Journal message filter: 1–256 bytes, one line. A literal substring
    /// match done by the agent, never passed to `journalctl --grep` (PCRE).
    GrepPattern,
    "grep pattern",
    |s| line_ok(s, 1, 256)
);

validated_string!(
    /// Opaque journald cursor: 1–512 printable ASCII bytes.
    JournalCursor,
    "journal cursor",
    |s| (1..=512).contains(&s.len()) && s.bytes().all(|c| c.is_ascii_graphic())
);

validated_string!(
    /// Crontab command field: 1–1024 bytes, one line (a newline would start
    /// a new crontab entry). It is shell text by nature: `cron.set` is
    /// therefore Elevated for privileged users.
    CronCommand,
    "cron command",
    |s| line_ok(s, 1, 1024) && !s.starts_with(char::is_whitespace)
);

validated_string!(
    /// `shell.exec` script text: 1–16384 bytes, no control characters but
    /// `\n` and `\t`. Stored verbatim in the audit log.
    ShellCommand,
    "shell command",
    |s| text_ok(s, 1, 16 * 1024)
);

validated_string!(
    /// RCON console command: 1–512 bytes, one line.
    RconCommand,
    "rcon command",
    |s| line_ok(s, 1, 512)
);

validated_string!(
    @no_debug
    /// Provisioning profile TOML (design §9.2): at most 64 KiB, no control
    /// characters but `\n`, `\r` and `\t`. Parsed by `fleet-hardening`.
    /// `Debug` prints only its length and BLAKE3, never the content.
    ProfileToml,
    "profile toml",
    |s| s.len() <= 64 * 1024
        && !s
            .chars()
            .any(|c| c.is_control() && !matches!(c, '\n' | '\r' | '\t'))
);

impl core::fmt::Debug for ProfileToml {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let h = blake3::hash(self.0.as_bytes());
        f.debug_struct("ProfileToml")
            .field("len", &self.0.len())
            .field("blake3", &hex::encode(&h.as_bytes()[..8]))
            .finish()
    }
}

validated_string!(
    /// HTTP probe path: starts with `/`, 1–256 printable ASCII bytes, no
    /// spaces.
    HttpPath,
    "http path",
    |s| s.starts_with('/') && s.len() <= 256 && s.bytes().all(|c| c.is_ascii_graphic())
);

validated_string!(
    /// Provisioning module id, e.g. `ssh.hardening`: `^[a-z0-9][a-z0-9._-]{0,63}$`.
    ModuleId,
    "module id",
    |s| slug_ok(s, 64)
);

validated_string!(
    /// Alert rule id: `^[a-z0-9][a-z0-9._-]{0,63}$`.
    RuleId,
    "rule id",
    |s| slug_ok(s, 64)
);

validated_string!(
    /// Health check id: `^[a-z0-9][a-z0-9._-]{0,63}$`.
    CheckId,
    "check id",
    |s| slug_ok(s, 64)
);

#[cfg(test)]
mod tests {
    use super::super::testutil::{roundtrip, wire_rejects};
    use super::*;
    use proptest::prelude::*;

    #[test]
    fn examples() {
        assert!(Label::new("").is_ok());
        assert!(Label::new("a\nb").is_err());
        assert!(FwComment::new("allow ssh: office/v4").is_ok());
        assert!(FwComment::new("x\" ; flush ruleset").is_err());
        assert!(SearchTerm::new("").is_err());
        assert!(GrepPattern::new("a".repeat(257)).is_err());
        assert!(JournalCursor::new("s=abc;i=1").is_ok());
        assert!(JournalCursor::new("a b").is_err());
        assert!(CronCommand::new("/usr/bin/true").is_ok());
        assert!(CronCommand::new("a\n* * * * * root evil").is_err());
        assert!(CronCommand::new(" leading").is_err());
        assert!(ShellCommand::new("echo a\necho b").is_ok());
        assert!(ShellCommand::new("a\0b").is_err());
        let toml = ProfileToml::new("[profile]\r\nname = \"secret-x\"\n").unwrap();
        let dbg = format!("{toml:?}");
        assert!(!dbg.contains("secret-x") && dbg.contains("len"), "{dbg}");
        assert!(HttpPath::new("/health?x=1").is_ok());
        assert!(HttpPath::new("health").is_err());
        assert!(HttpPath::new("/a b").is_err());
        assert!(ModuleId::new("kernel.modules.usb-storage").is_ok());
        assert!(ModuleId::new("Kernel").is_err());
        assert!(RuleId::new("-x").is_err());
        assert!(wire_rejects::<CheckId>("A"));
        roundtrip(&CheckId::new("http.api").unwrap());
    }

    proptest! {
        #[test]
        fn slug_accepts(s in "[a-z0-9][a-z0-9._-]{0,63}") {
            prop_assert!(ModuleId::new(s.clone()).is_ok());
            roundtrip(&RuleId::new(s).unwrap());
        }

        #[test]
        fn slug_rejects(s in "[a-z0-9]{0,8}[A-Z /\\n\\x00][a-z]{0,8}") {
            prop_assert!(RuleId::new(s.clone()).is_err());
            prop_assert!(wire_rejects::<RuleId>(&s));
        }

        #[test]
        fn line_rejects_controls(a in "[a-z]{0,10}", c in "[\\x00-\\x1f\\x7f]", b in "[a-z]{0,10}") {
            let s = format!("{a}{c}{b}");
            let prefixed = format!("x{s}");
            prop_assert!(Label::new(s).is_err());
            prop_assert!(CronCommand::new(prefixed.clone()).is_err());
            prop_assert!(RconCommand::new(prefixed).is_err());
        }

        #[test]
        fn fw_comment_charset(s in "[A-Za-z0-9 ._:/-]{0,64}") {
            prop_assert!(FwComment::new(s).is_ok());
        }

        #[test]
        fn fw_comment_rejects(s in "[a-z]{0,5}[\"';{}\\\\\\n$`#][a-z]{0,5}") {
            prop_assert!(FwComment::new(s).is_err());
        }
    }
}
