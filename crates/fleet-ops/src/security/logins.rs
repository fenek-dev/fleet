//! `logins.query` (design §2.4, §4.6): SSH authentication events from
//! journald (method, key fingerprint, failures) joined with sessions from
//! `wtmpdb` or `wtmp` (session end), plus console logins and `btmp`
//! failures that journald did not already report.
//!
//! Country stays `None`: the Mac fills it in (GeoIP is an open question).

use super::authlog::{AuthKind, parse_sshd};
use super::utmp::{self, Session};
use crate::ctx::SysCtx;
use crate::handler::{LocalBoxFuture, OpError, OpHandler, OpMeta, OpOutput};
use crate::logs::journal::{self, JOURNALCTL, parse_line};
use crate::logs::lines::LineSpawner;
use crate::runner::CommandSpec;
use fleet_proto::args::TimeRange;
use fleet_proto::payload::{LoginMethod, LoginRecord, Logins};
use fleet_proto::{DeviceId, ErrorCode, Op, Payload};
use std::ffi::OsString;
use std::rc::Rc;
use std::time::Instant;

pub const MAX_LIMIT: u32 = 10_000;
/// Journal lines scanned for auth events per query.
const MAX_JOURNAL: usize = 200_000;
/// A journal `Accepted` and a wtmp session this close are the same login.
const JOIN_WINDOW_MS: u64 = 10_000;

/// Maps an SSH key fingerprint (`SHA256:…`) to the enrolled Mac it belongs
/// to. Exec implements it from the roster's SSH keys.
pub trait FingerprintResolver {
    fn device_for(&self, fingerprint: &str) -> Option<DeviceId>;
}

/// OpenSSH's `SHA256:<base64, no padding>` fingerprint of a public key
/// blob (the base64-decoded middle field of an `authorized_keys` line), as
/// `sshd` logs it under `LogLevel VERBOSE`.
pub fn ssh_fingerprint(blob: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    const A: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let d = Sha256::digest(blob);
    let mut out = String::from("SHA256:");
    for c in d.chunks(3) {
        let n = (u32::from(c[0]) << 16)
            | (u32::from(*c.get(1).unwrap_or(&0)) << 8)
            | u32::from(*c.get(2).unwrap_or(&0));
        let chars = c.len() + 1;
        for i in 0..chars {
            out.push(A[(n >> (18 - 6 * i)) as usize & 63] as char);
        }
    }
    out
}

/// Resolves nothing (no roster wired in).
pub struct NoResolver;

impl FingerprintResolver for NoResolver {
    fn device_for(&self, _fingerprint: &str) -> Option<DeviceId> {
        None
    }
}

/// `journalctl` argv for sshd messages in a range (both the classic `sshd`
/// identifier and OpenSSH 9.8+'s `sshd-session`; same-field matches OR).
pub fn sshd_journal_args(range: &TimeRange) -> Vec<OsString> {
    let mut a: Vec<OsString> = [
        "-o",
        "json",
        "--no-pager",
        "--quiet",
        "--output-fields=MESSAGE,PRIORITY,_SYSTEMD_UNIT,SYSLOG_IDENTIFIER,_PID",
        "--reverse",
    ]
    .into_iter()
    .map(Into::into)
    .collect();
    if let Some(s) = range.since_ms {
        a.push(format!("--since=@{}", s / 1000).into());
    }
    if let Some(u) = range.until_ms {
        a.push(format!("--until=@{}", u.div_ceil(1000)).into());
    }
    a.push("SYSLOG_IDENTIFIER=sshd".into());
    a.push("SYSLOG_IDENTIFIER=sshd-session".into());
    a
}

fn in_range(r: &TimeRange, ms: u64) -> bool {
    r.since_ms.is_none_or(|s| ms >= s) && r.until_ms.is_none_or(|u| ms < u)
}

/// Login records from journal SSH auth events (newest first as read).
pub fn records_from_messages(
    msgs: impl IntoIterator<Item = (u64, String)>,
    resolver: &dyn FingerprintResolver,
) -> Vec<LoginRecord> {
    msgs.into_iter()
        .filter_map(|(time_ms, m)| {
            let e = parse_sshd(&m)?;
            let (success, method, fp) = match e.kind {
                AuthKind::Accepted {
                    method,
                    fingerprint,
                } => (true, method, fingerprint),
                AuthKind::Failed { method, .. } => (false, method, None),
                AuthKind::InvalidUser => (false, LoginMethod::Other, None),
                // Pre-auth noise feeds bans, not the login history.
                AuthKind::Preauth => return None,
            };
            Some(LoginRecord {
                time_ms,
                user: e.user.unwrap_or_default(),
                source: Some(e.addr),
                country: None,
                success,
                method,
                device_id: fp.as_deref().and_then(|f| resolver.device_for(f)),
                key_fingerprint: fp,
                session_end_ms: None,
            })
        })
        .collect()
}

/// Joins sessions onto journal logins (session end) and appends sessions
/// journald didn't report (console, `su`-less local logins, or a journal
/// that was vacuumed). `failed` are `btmp` entries, added when journald had
/// no failures at all (rsyslog-only or journal lost).
pub fn merge(
    mut records: Vec<LoginRecord>,
    sessions: &[Session],
    failed: &[Session],
) -> Vec<LoginRecord> {
    let mut used = vec![false; sessions.len()];
    for r in records.iter_mut().filter(|r| r.success) {
        let hit = sessions.iter().enumerate().find(|(i, s)| {
            !used[*i]
                && s.user == r.user
                && s.source == r.source
                && s.start_ms.abs_diff(r.time_ms) <= JOIN_WINDOW_MS
        });
        if let Some((i, s)) = hit {
            used[i] = true;
            r.session_end_ms = s.end_ms;
        }
    }
    let as_record = |s: &Session, success: bool| LoginRecord {
        time_ms: s.start_ms,
        user: s.user.clone(),
        source: s.source,
        country: None,
        success,
        method: LoginMethod::Other,
        key_fingerprint: None,
        device_id: None,
        session_end_ms: s.end_ms,
    };
    let extra: Vec<LoginRecord> = sessions
        .iter()
        .zip(&used)
        .filter(|(_, u)| !**u)
        .map(|(s, _)| as_record(s, true))
        .collect();
    records.extend(extra);
    if !records.iter().any(|r| !r.success) {
        records.extend(failed.iter().map(|s| as_record(s, false)));
    }
    records
}

/// Filters, sorts newest first and cuts to `limit`.
pub fn finish(
    mut records: Vec<LoginRecord>,
    range: &TimeRange,
    failed_only: bool,
    limit: u32,
) -> Logins {
    records.retain(|r| in_range(range, r.time_ms) && !(failed_only && r.success));
    records.sort_by_key(|r| std::cmp::Reverse(r.time_ms));
    let limit = usize::try_from(limit).unwrap_or(usize::MAX);
    let truncated = records.len() > limit;
    records.truncate(limit);
    Logins {
        logins: records,
        truncated,
    }
}

pub struct LoginsHandler {
    spawner: Rc<dyn LineSpawner>,
    resolver: Rc<dyn FingerprintResolver>,
}

impl LoginsHandler {
    pub fn new(spawner: Rc<dyn LineSpawner>, resolver: Rc<dyn FingerprintResolver>) -> Self {
        Self { spawner, resolver }
    }

    async fn journal_messages(&self, range: &TimeRange, limit: usize) -> Vec<(u64, String)> {
        let spec = CommandSpec::new(JOURNALCTL).args(sshd_journal_args(range));
        let Ok(mut src) = self.spawner.spawn(spec) else {
            return Vec::new();
        };
        let deadline = Instant::now() + journal::QUERY_DEADLINE;
        let mut out = Vec::new();
        let mut scanned = 0;
        let mut auth = 0;
        while scanned < MAX_JOURNAL && auth < limit {
            let left = deadline.saturating_duration_since(Instant::now());
            let Ok(Some(Ok(line))) = tokio::time::timeout(left, src.next_line()).await else {
                break;
            };
            scanned += 1;
            if let Some(p) = parse_line(&line) {
                let m = p.entry.message;
                if m.starts_with("Accepted ")
                    || m.starts_with("Failed ")
                    || m.starts_with("Invalid user ")
                {
                    auth += 1;
                }
                out.push((p.entry.time_us / 1000, m));
            }
        }
        out
    }
}

impl OpHandler for LoginsHandler {
    fn validate(&self, _ctx: &SysCtx, op: &Op, _meta: &OpMeta) -> Result<(), OpError> {
        let Op::LoginsQuery { range, limit, .. } = op else {
            return Err(ErrorCode::Unsupported.into());
        };
        range.validate().map_err(ErrorCode::from)?;
        if !(1..=MAX_LIMIT).contains(limit) {
            return Err(ErrorCode::InvalidArgument.into());
        }
        Ok(())
    }

    fn handle<'a>(
        &'a self,
        ctx: &'a SysCtx,
        op: &'a Op,
        _meta: &'a OpMeta,
    ) -> LocalBoxFuture<'a, Result<OpOutput, OpError>> {
        Box::pin(async move {
            let Op::LoginsQuery {
                range,
                failed_only,
                limit,
            } = op
            else {
                return Err(ErrorCode::Unsupported.into());
            };
            // Read a little past `limit`: some auth lines are filtered later.
            let want = usize::try_from(*limit)
                .unwrap_or(usize::MAX)
                .saturating_mul(2);
            let msgs = self.journal_messages(range, want).await;
            let records = records_from_messages(msgs, self.resolver.as_ref());
            let sessions = match utmp::read_wtmpdb(ctx).await {
                Some(s) => s,
                None => utmp::sessions(&utmp::read_file(ctx, utmp::WTMP)),
            };
            let failed = utmp::failures(&utmp::read_file(ctx, utmp::BTMP));
            let all = merge(records, &sessions, &failed);
            Ok(OpOutput::Payload(Payload::Logins(finish(
                all,
                range,
                *failed_only,
                *limit,
            ))))
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::FakeRunner;
    use crate::logs::lines::FakeLineSpawner;
    use crate::security::utmp::tests::record;
    use crate::testutil::{T0, block, ctx_at, meta_at};

    #[test]
    fn fingerprint_matches_ssh_keygen() {
        fn b64(s: &str) -> Vec<u8> {
            const A: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
            let v: Vec<u32> = s
                .bytes()
                .filter(|b| *b != b'=')
                .map(|b| A.iter().position(|a| *a == b).unwrap() as u32)
                .collect();
            let mut out = Vec::new();
            for c in v.chunks(4) {
                let n = c
                    .iter()
                    .enumerate()
                    .fold(0, |n, (i, x)| n | x << (18 - 6 * i));
                out.extend(&n.to_be_bytes()[1..c.len()]);
            }
            out
        }
        // `ssh-keygen -lf` of this key.
        let blob = b64(
            "AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBKJE7MGhV1KRwnWX0sGPhHyDcjpkFm7dBLnegSSB6SW3jzWmf8ex4lMVdhSUowGHJRebrBdsBmQjBM3uxWyDIwk=",
        );
        assert_eq!(
            ssh_fingerprint(&blob),
            "SHA256:PZ/ADm/POhDW0tGKvk5poaPYtYCyQz2o+/H764kvHMw"
        );
    }

    struct OneMac;
    impl FingerprintResolver for OneMac {
        fn device_for(&self, fp: &str) -> Option<DeviceId> {
            (fp == "SHA256:macmacmac").then_some(DeviceId([9; 16]))
        }
    }

    fn jline(sec: u64, msg: &str) -> String {
        serde_json::json!({
            "__REALTIME_TIMESTAMP": (sec * 1_000_000).to_string(),
            "SYSLOG_IDENTIFIER": "sshd",
            "MESSAGE": msg,
        })
        .to_string()
    }

    #[test]
    fn logins_query_joins_sources() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(dir.path().join("var/log")).unwrap();
        let mut wtmp = Vec::new();
        let mut a = [0u8; 16];
        a[..4].copy_from_slice(&[203, 0, 113, 9]);
        wtmp.extend(record(7, "pts/0", "alice", "203.0.113.9", 1_000_002, a));
        wtmp.extend(record(8, "pts/0", "", "", 1_000_600, [0; 16]));
        wtmp.extend(record(7, "tty1", "root", "", 1_000_700, [0; 16]));
        std::fs::write(dir.path().join("var/log/wtmp"), wtmp).unwrap();
        std::fs::write(
            dir.path().join("var/log/btmp"),
            record(6, "ssh:notty", "admin", "198.51.100.1", 1_000_010, [0; 16]),
        )
        .unwrap();

        let lines = [
            jline(1_000_900, "Connection closed by 192.0.2.1 port 1 [preauth]"),
            jline(
                1_000_800,
                "Failed password for invalid user admin from 198.51.100.1 port 2 ssh2",
            ),
            jline(
                1_000_001,
                "Accepted publickey for alice from 203.0.113.9 port 3 ssh2: ED25519 SHA256:macmacmac",
            ),
            jline(1_000_000, "Server listening on 0.0.0.0 port 22."),
        ];
        let lines: Vec<&str> = lines.iter().map(String::as_str).collect();
        let sp = Rc::new(FakeLineSpawner::new());
        let range = TimeRange::default();
        let args: Vec<String> = sshd_journal_args(&range)
            .into_iter()
            .map(|s| s.into_string().unwrap())
            .collect();
        let args: Vec<&str> = args.iter().map(String::as_str).collect();
        sp.expect(JOURNALCTL, &args, &lines, false);
        let h = LoginsHandler::new(sp, Rc::new(OneMac));
        let c = ctx_at(dir.path(), Rc::new(FakeRunner::new()), T0);
        let op = Op::LoginsQuery {
            range,
            failed_only: false,
            limit: 10,
        };
        h.validate(&c, &op, &meta_at(Op::SystemInfo, Some(1), T0))
            .unwrap();
        let OpOutput::Payload(Payload::Logins(l)) =
            block(h.handle(&c, &op, &meta_at(Op::SystemInfo, Some(1), T0))).unwrap()
        else {
            panic!()
        };
        // failed (journal), root console (wtmp only), alice (joined). btmp
        // is skipped because journald reported failures.
        assert_eq!(l.logins.len(), 3);
        assert!(!l.truncated);
        assert!(!l.logins[0].success);
        assert_eq!(l.logins[0].user, "admin");
        assert_eq!(l.logins[1].user, "root");
        let alice = &l.logins[2];
        assert_eq!(alice.device_id, Some(DeviceId([9; 16])));
        assert_eq!(alice.key_fingerprint.as_deref(), Some("SHA256:macmacmac"));
        assert_eq!(alice.session_end_ms, Some(1_000_600_500));
        assert_eq!(alice.method, LoginMethod::PublicKey);
        assert_eq!(alice.country, None);
    }

    #[test]
    fn btmp_fallback_filters_and_limit() {
        let failed = [Session {
            user: "x".into(),
            line: "ssh:notty".into(),
            source: None,
            start_ms: 5,
            end_ms: None,
        }];
        let all = merge(Vec::new(), &[], &failed);
        assert_eq!(all.len(), 1);
        let recs: Vec<LoginRecord> = (0..5)
            .map(|i| LoginRecord {
                time_ms: i,
                success: i % 2 == 0,
                ..all[0].clone()
            })
            .collect();
        let l = finish(recs.clone(), &TimeRange::default(), true, 1);
        assert_eq!(
            (l.logins.len(), l.logins[0].time_ms, l.truncated),
            (1, 3, true)
        );
        let r = TimeRange {
            since_ms: Some(1),
            until_ms: Some(3),
        };
        assert_eq!(finish(recs, &r, false, 10).logins.len(), 2);
        let h = LoginsHandler::new(Rc::new(FakeLineSpawner::new()), Rc::new(NoResolver));
        let bad = Op::LoginsQuery {
            range: TimeRange::default(),
            failed_only: false,
            limit: 0,
        };
        assert!(
            h.validate(
                &crate::testutil::ctx_empty(),
                &bad,
                &meta_at(Op::SystemInfo, Some(1), T0)
            )
            .is_err()
        );
    }
}
