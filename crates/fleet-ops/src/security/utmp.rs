//! Session sources (design §4.6): legacy glibc `wtmp`/`btmp` records and
//! `wtmpdb` (Debian 13+, year-2038 safe) via `wtmpdb last --json`.
//!
//! `lastlog2` is not read: it only holds each user's latest login, which
//! `wtmpdb` already has with the full history.

use crate::ctx::SysCtx;
use crate::runner::{CommandSpec, RunError};
use serde_json::Value;
use std::io::{Read, Seek, SeekFrom};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::time::Duration;

/// `sizeof(struct utmp)` on x86_64 and aarch64 glibc.
pub const RECORD: usize = 384;
/// Newest records read from each file (~16 MiB).
pub const MAX_RECORDS: u64 = 43_690;
pub const WTMP: &str = "/var/log/wtmp";
pub const BTMP: &str = "/var/log/btmp";
pub const WTMPDB_DB: &str = "/var/lib/wtmpdb/wtmp.db";
pub const WTMPDB: &str = "/usr/bin/wtmpdb";

const BOOT_TIME: i16 = 2;
const LOGIN_PROCESS: i16 = 6;
const USER_PROCESS: i16 = 7;
const DEAD_PROCESS: i16 = 8;

/// One raw record, fields decoded, text lossy and NUL-trimmed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UtmpRecord {
    pub kind: i16,
    pub pid: i32,
    pub line: String,
    pub user: String,
    pub host: String,
    pub time_ms: u64,
    pub addr: Option<IpAddr>,
}

fn cstr(b: &[u8]) -> String {
    let end = b.iter().position(|&c| c == 0).unwrap_or(b.len());
    String::from_utf8_lossy(&b[..end]).into_owned()
}

fn le_i16(b: &[u8], at: usize) -> i16 {
    i16::from_le_bytes([b[at], b[at + 1]])
}

fn le_i32(b: &[u8], at: usize) -> i32 {
    i32::from_le_bytes([b[at], b[at + 1], b[at + 2], b[at + 3]])
}

/// Decodes one 384-byte record; `None` for a short slice.
///
/// Layout: `ut_type` i16 @0, `ut_pid` i32 @4, `ut_line[32]` @8,
/// `ut_id[4]` @40, `ut_user[32]` @44, `ut_host[256]` @76, `ut_exit` @332,
/// `ut_session` i32 @336, `ut_tv` {i32 sec, i32 usec} @340,
/// `ut_addr_v6[4]` @348 (network order), unused @364.
pub fn parse_record(b: &[u8]) -> Option<UtmpRecord> {
    let b = b.get(..RECORD)?;
    let sec = le_i32(b, 340);
    let usec = le_i32(b, 344).clamp(0, 999_999);
    let time_ms = u64::try_from(sec)
        .unwrap_or(0)
        .saturating_mul(1000)
        .saturating_add(u64::try_from(usec / 1000).unwrap_or(0));
    let a: [u8; 16] = b[348..364].try_into().ok()?;
    let addr = if a == [0; 16] {
        None
    } else if a[4..] == [0; 12] {
        Some(IpAddr::V4(Ipv4Addr::new(a[0], a[1], a[2], a[3])))
    } else {
        Some(IpAddr::V6(Ipv6Addr::from(a)))
    };
    let host = cstr(&b[76..332]);
    Some(UtmpRecord {
        kind: le_i16(b, 0),
        pid: le_i32(b, 4),
        line: cstr(&b[8..40]),
        user: cstr(&b[44..76]),
        addr: addr.or_else(|| host.parse().ok()),
        host,
        time_ms,
    })
}

/// Reads up to [`MAX_RECORDS`] newest records of a utmp-format file under
/// the context root. Missing file → empty.
pub fn read_file(ctx: &SysCtx, abs: &str) -> Vec<UtmpRecord> {
    let Ok((mut f, _)) = crate::logs::logfile::open_nofollow(ctx, abs) else {
        return Vec::new();
    };
    let Ok(len) = f.metadata().map(|m| m.len()) else {
        return Vec::new();
    };
    let whole = len - len % RECORD as u64;
    let start = whole.saturating_sub(MAX_RECORDS * RECORD as u64);
    let mut buf = Vec::new();
    if f.seek(SeekFrom::Start(start)).is_err()
        || f.take(whole - start).read_to_end(&mut buf).is_err()
    {
        return Vec::new();
    }
    buf.chunks_exact(RECORD).filter_map(parse_record).collect()
}

/// A login session (success) or failed attempt (btmp).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Session {
    pub user: String,
    pub line: String,
    pub source: Option<IpAddr>,
    pub start_ms: u64,
    pub end_ms: Option<u64>,
}

/// Pairs `USER_PROCESS` with the `DEAD_PROCESS` on the same line; a reboot
/// closes everything still open.
pub fn sessions(records: &[UtmpRecord]) -> Vec<Session> {
    let mut out: Vec<Session> = Vec::new();
    let mut open: Vec<usize> = Vec::new();
    for r in records {
        match r.kind {
            USER_PROCESS => {
                open.push(out.len());
                out.push(Session {
                    user: r.user.clone(),
                    line: r.line.clone(),
                    source: r.addr,
                    start_ms: r.time_ms,
                    end_ms: None,
                });
            }
            DEAD_PROCESS => {
                if let Some(pos) = open.iter().rposition(|&i| out[i].line == r.line) {
                    let i = open.remove(pos);
                    out[i].end_ms = Some(r.time_ms);
                }
            }
            BOOT_TIME => {
                for i in open.drain(..) {
                    out[i].end_ms = Some(r.time_ms);
                }
            }
            _ => {}
        }
    }
    out
}

/// Failed attempts from `btmp` (sshd writes `LOGIN_PROCESS`, some tools
/// `USER_PROCESS`).
pub fn failures(records: &[UtmpRecord]) -> Vec<Session> {
    records
        .iter()
        .filter(|r| matches!(r.kind, LOGIN_PROCESS | USER_PROCESS))
        .map(|r| Session {
            user: r.user.clone(),
            line: r.line.clone(),
            source: r.addr,
            start_ms: r.time_ms,
            end_ms: None,
        })
        .collect()
}

/// `wtmpdb last` argv. `--time-format=iso` makes login/logout parseable.
pub fn wtmpdb_spec() -> CommandSpec {
    CommandSpec::new(WTMPDB)
        .args(["last", "--json", "--time-format=iso"])
        .timeout(Duration::from_secs(20))
        .output_cap(16 << 20)
}

/// Sessions from `wtmpdb`, or `None` when the database is absent or the
/// tool fails (older wtmpdb without `--json`): the caller then falls back
/// to `wtmp`.
pub async fn read_wtmpdb(ctx: &SysCtx) -> Option<Vec<Session>> {
    if !ctx.path(WTMPDB_DB).is_some_and(|p| p.exists()) {
        return None;
    }
    let out: Result<_, RunError> = ctx.runner.run(wtmpdb_spec()).await;
    let out = out.ok().filter(|o| o.success())?;
    parse_wtmpdb_json(&out.stdout)
}

/// Tolerant parse of `wtmpdb last --json`: entries under `entries` (or a
/// top-level array), `user`, `hostname`/`host`, `tty`, `login`, `logout`
/// as ISO-8601 text or Unix seconds/ms/µs. Unparseable logout ("still
/// logged in", "crash") → open session.
pub fn parse_wtmpdb_json(b: &[u8]) -> Option<Vec<Session>> {
    let v: Value = serde_json::from_slice(b).ok()?;
    let items = match &v {
        Value::Array(a) => a,
        Value::Object(o) => o.get("entries").and_then(Value::as_array)?,
        _ => return None,
    };
    let s = |o: &serde_json::Map<String, Value>, k: &str| {
        o.get(k)
            .and_then(Value::as_str)
            .map(|s| s.chars().take(256).collect::<String>())
    };
    Some(
        items
            .iter()
            .filter_map(Value::as_object)
            .filter_map(|o| {
                let start_ms = o.get("login").and_then(time_value)?;
                let host = s(o, "hostname")
                    .or_else(|| s(o, "host"))
                    .unwrap_or_default();
                Some(Session {
                    user: s(o, "user").unwrap_or_default(),
                    line: s(o, "tty").unwrap_or_default(),
                    source: host.parse().ok(),
                    start_ms,
                    end_ms: o.get("logout").and_then(time_value),
                })
            })
            .collect(),
    )
}

fn time_value(v: &Value) -> Option<u64> {
    match v {
        Value::Number(n) => {
            let n = n.as_u64()?;
            Some(match n {
                n if n >= 100_000_000_000_000 => n / 1000,
                n if n >= 100_000_000_000 => n,
                n => n.saturating_mul(1000),
            })
        }
        Value::String(s) => parse_iso8601_ms(s),
        _ => None,
    }
}

/// `YYYY-MM-DD[T ]HH:MM:SS[.frac][Z|±HH:MM|±HHMM]` → Unix ms (no offset =
/// UTC).
pub fn parse_iso8601_ms(s: &str) -> Option<u64> {
    let s = s.trim();
    let b = s.as_bytes();
    if b.len() < 19 || b[4] != b'-' || b[7] != b'-' || !matches!(b[10], b'T' | b' ') {
        return None;
    }
    let num = |r: std::ops::Range<usize>| -> Option<i64> {
        let t = s.get(r)?;
        t.bytes()
            .all(|c| c.is_ascii_digit())
            .then(|| t.parse().ok())?
    };
    let (y, mo, d) = (num(0..4)?, num(5..7)?, num(8..10)?);
    let (h, mi, se) = (num(11..13)?, num(14..16)?, num(17..19)?);
    if !(1..=12).contains(&mo) || !(1..=31).contains(&d) || h > 23 || mi > 59 || se > 60 {
        return None;
    }
    let mut rest = &s[19..];
    let mut frac_ms = 0i64;
    if let Some(r) = rest.strip_prefix('.') {
        let digits: String = r.chars().take_while(char::is_ascii_digit).collect();
        rest = &r[digits.len()..];
        let ms: String = digits.chars().chain("000".chars()).take(3).collect();
        frac_ms = ms.parse().ok()?;
    }
    let offset_s = match rest {
        "" | "Z" => 0,
        r => {
            let sign = match r.as_bytes()[0] {
                b'+' => 1,
                b'-' => -1,
                _ => return None,
            };
            let digits: String = r[1..].chars().filter(|c| *c != ':').collect();
            if digits.len() != 4 || !digits.bytes().all(|c| c.is_ascii_digit()) {
                return None;
            }
            let oh: i64 = digits[..2].parse().ok()?;
            let om: i64 = digits[2..].parse().ok()?;
            sign * (oh * 3600 + om * 60)
        }
    };
    // Days from civil (Howard Hinnant).
    let y = if mo <= 2 { y - 1 } else { y };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let mp = (mo + 9) % 12;
    let doy = (153 * mp + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = era * 146_097 + doe - 719_468;
    let secs = days * 86_400 + h * 3600 + mi * 60 + se - offset_s;
    u64::try_from(secs * 1000 + frac_ms).ok()
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    /// Builds a glibc utmp record (the fixture generator).
    pub fn record(
        kind: i16,
        line: &str,
        user: &str,
        host: &str,
        sec: i32,
        addr: [u8; 16],
    ) -> Vec<u8> {
        let mut b = vec![0u8; RECORD];
        b[0..2].copy_from_slice(&kind.to_le_bytes());
        b[4..8].copy_from_slice(&1234i32.to_le_bytes());
        b[8..8 + line.len()].copy_from_slice(line.as_bytes());
        b[44..44 + user.len()].copy_from_slice(user.as_bytes());
        b[76..76 + host.len()].copy_from_slice(host.as_bytes());
        b[340..344].copy_from_slice(&sec.to_le_bytes());
        b[344..348].copy_from_slice(&500_000i32.to_le_bytes());
        b[348..364].copy_from_slice(&addr);
        b
    }

    fn v4(a: [u8; 4]) -> [u8; 16] {
        let mut x = [0; 16];
        x[..4].copy_from_slice(&a);
        x
    }

    #[test]
    fn utmp_records_and_sessions() {
        let v6: [u8; 16] = "2001:db8::7".parse::<Ipv6Addr>().unwrap().octets();
        let mut data = Vec::new();
        data.extend(record(BOOT_TIME, "~", "reboot", "6.1.0", 1_000, [0; 16]));
        data.extend(record(
            USER_PROCESS,
            "pts/0",
            "alice",
            "203.0.113.9",
            1_100,
            v4([203, 0, 113, 9]),
        ));
        data.extend(record(
            USER_PROCESS,
            "pts/1",
            "bob",
            "2001:db8::7",
            1_200,
            v6,
        ));
        data.extend(record(DEAD_PROCESS, "pts/0", "", "", 1_300, [0; 16]));
        data.extend(record(USER_PROCESS, "tty1", "root", "", 1_400, [0; 16]));
        data.extend(record(BOOT_TIME, "~", "reboot", "6.1.0", 2_000, [0; 16]));
        data.extend_from_slice(&[0xff; 100]); // torn final write

        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(dir.path().join("var/log")).unwrap();
        std::fs::write(dir.path().join("var/log/wtmp"), &data).unwrap();
        let ctx = crate::test_util::ctx_at(dir.path(), std::rc::Rc::new(crate::FakeRunner::new()));
        let recs = read_file(&ctx, WTMP);
        assert_eq!(recs.len(), 6);
        assert_eq!(recs[1].time_ms, 1_100_500);
        let s = sessions(&recs);
        assert_eq!(s.len(), 3);
        assert_eq!(
            (
                s[0].user.as_str(),
                s[0].source.unwrap().to_string(),
                s[0].end_ms
            ),
            ("alice", "203.0.113.9".into(), Some(1_300_500))
        );
        assert_eq!(s[1].source.unwrap().to_string(), "2001:db8::7");
        assert_eq!(s[1].end_ms, Some(2_000_500)); // closed by reboot
        assert_eq!((s[2].source, s[2].end_ms), (None, Some(2_000_500)));
        assert!(read_file(&ctx, BTMP).is_empty());
        assert!(parse_record(&[0; 10]).is_none());
        assert_eq!(
            failures(&[parse_record(&record(
                LOGIN_PROCESS,
                "ssh:notty",
                "admin",
                "198.51.100.1",
                5,
                [0; 16]
            ))
            .unwrap()])[0]
                .source
                .unwrap()
                .to_string(),
            "198.51.100.1"
        );
    }

    #[test]
    fn iso8601() {
        assert_eq!(parse_iso8601_ms("1970-01-01T00:00:00Z"), Some(0));
        assert_eq!(
            parse_iso8601_ms("2023-11-14T22:13:20+00:00"),
            Some(1_700_000_000_000)
        );
        assert_eq!(
            parse_iso8601_ms("2023-11-15T00:13:20.250+02:00"),
            Some(1_700_000_000_250)
        );
        assert_eq!(
            parse_iso8601_ms("2023-11-14 17:13:20-0500"),
            Some(1_700_000_000_000)
        );
        assert_eq!(parse_iso8601_ms("still logged in"), None);
        assert_eq!(parse_iso8601_ms("2023-13-14T22:13:20Z"), None);
        assert_eq!(parse_iso8601_ms("2023-11-14T22:13:20+0x:00"), None);
    }

    #[test]
    fn wtmpdb_json() {
        let j = br#"{"entries":[
            {"user":"alice","tty":"pts/0","hostname":"203.0.113.9","login":"2023-11-14T22:13:20+00:00","logout":"2023-11-14T23:13:20+00:00"},
            {"user":"bob","tty":"pts/1","hostname":"","login":1700000000,"logout":"still logged in"},
            {"user":"x","login":"garbage"}, 7
        ]}"#;
        let s = parse_wtmpdb_json(j).unwrap();
        assert_eq!(s.len(), 2);
        assert_eq!(s[0].end_ms, Some(1_700_003_600_000));
        assert_eq!(
            (s[1].start_ms, s[1].end_ms, s[1].source),
            (1_700_000_000_000, None, None)
        );
        assert!(parse_wtmpdb_json(b"not json").is_none());
    }
}
