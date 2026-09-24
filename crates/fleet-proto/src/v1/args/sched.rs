//! Scheduling and process-control arguments.

use super::{ArgError, ensure};
use core::fmt;
use core::str::FromStr;
use serde::{Deserialize, Serialize};

/// Signals `process.signal` may send. No real-time or core-dumping signals
/// beyond `QUIT`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Signal {
    Hup,
    Int,
    Quit,
    Kill,
    Usr1,
    Usr2,
    Term,
    Cont,
    Stop,
}

impl Signal {
    /// Linux signal number (x86_64 and aarch64 agree on these).
    pub fn number(self) -> i32 {
        match self {
            Signal::Hup => 1,
            Signal::Int => 2,
            Signal::Quit => 3,
            Signal::Kill => 9,
            Signal::Usr1 => 10,
            Signal::Usr2 => 12,
            Signal::Term => 15,
            Signal::Cont => 18,
            Signal::Stop => 19,
        }
    }
}

/// Niceness, -20..=19.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(try_from = "i8", into = "i8")]
pub struct Nice(i8);

impl Nice {
    pub fn new(n: i8) -> Result<Self, ArgError> {
        ensure((-20..=19).contains(&n), "nice")?;
        Ok(Self(n))
    }

    pub fn get(self) -> i8 {
        self.0
    }
}

impl TryFrom<i8> for Nice {
    type Error = ArgError;
    fn try_from(n: i8) -> Result<Self, ArgError> {
        Self::new(n)
    }
}

impl From<Nice> for i8 {
    fn from(n: Nice) -> i8 {
        n.0
    }
}

/// Target process id, at least 2 (never init). Exec additionally refuses
/// kernel threads and Fleet's own processes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(try_from = "u32", into = "u32")]
pub struct Pid(u32);

impl Pid {
    pub fn new(p: u32) -> Result<Self, ArgError> {
        ensure((2..=1 << 22).contains(&p), "pid")?;
        Ok(Self(p))
    }

    pub fn get(self) -> u32 {
        self.0
    }
}

impl TryFrom<u32> for Pid {
    type Error = ArgError;
    fn try_from(p: u32) -> Result<Self, ArgError> {
        Self::new(p)
    }
}

impl From<Pid> for u32 {
    fn from(p: Pid) -> u32 {
        p.0
    }
}

/// Five-field crontab schedule (`min hour dom month dow`), normalized to
/// single spaces, at most 128 bytes. Each field is `*` or a comma list of
/// `N`, `N-M`, `*/S` or `N-M/S` within the field's bounds; month and weekday
/// also accept a single three-letter name (`jan`, `mon`) as the whole field.
/// `@reboot`-style macros are not accepted.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct CronSpec(String);

const FIELDS: [(u8, u8, &[&str]); 5] = [
    (0, 59, &[]),
    (0, 23, &[]),
    (1, 31, &[]),
    (
        1,
        12,
        &[
            "jan", "feb", "mar", "apr", "may", "jun", "jul", "aug", "sep", "oct", "nov", "dec",
        ],
    ),
    (0, 7, &["sun", "mon", "tue", "wed", "thu", "fri", "sat"]),
];

fn num(s: &str, min: u8, max: u8) -> Option<u8> {
    if s.is_empty() || s.len() > 2 || !s.bytes().all(|c| c.is_ascii_digit()) {
        return None;
    }
    let n: u8 = s.parse().ok()?;
    (min..=max).contains(&n).then_some(n)
}

fn field_ok(f: &str, min: u8, max: u8, names: &[&str]) -> bool {
    if names.iter().any(|n| f.eq_ignore_ascii_case(n)) {
        return true;
    }
    f.split(',').all(|item| {
        let (range, step) = match item.split_once('/') {
            Some((r, s)) => match num(s, 1, max.max(1)) {
                Some(_) => (r, true),
                None => return false,
            },
            None => (item, false),
        };
        if range == "*" {
            return true;
        }
        match range.split_once('-') {
            Some((a, b)) => {
                matches!((num(a, min, max), num(b, min, max)), (Some(a), Some(b)) if a <= b)
            }
            // `N/S` has different meanings across cron implementations.
            None => !step && num(range, min, max).is_some(),
        }
    })
}

impl CronSpec {
    pub fn new(s: &str) -> Result<Self, ArgError> {
        let fields: Vec<&str> = s.split_whitespace().collect();
        let ok = s.len() <= 128
            && fields.len() == 5
            && fields
                .iter()
                .zip(FIELDS)
                .all(|(f, (min, max, names))| field_ok(f, min, max, names));
        ensure(ok, "cron schedule")?;
        Ok(Self(fields.join(" ")))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl TryFrom<String> for CronSpec {
    type Error = ArgError;
    fn try_from(s: String) -> Result<Self, ArgError> {
        // The wire form must already be normalized.
        let spec = Self::new(&s)?;
        ensure(spec.0 == s, "cron schedule")?;
        Ok(spec)
    }
}

impl From<CronSpec> for String {
    fn from(c: CronSpec) -> String {
        c.0
    }
}

impl FromStr for CronSpec {
    type Err = ArgError;
    fn from_str(s: &str) -> Result<Self, ArgError> {
        Self::new(s)
    }
}

impl fmt::Display for CronSpec {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str(&self.0)
    }
}

#[cfg(test)]
mod tests {
    use super::super::testutil::{roundtrip, wire_rejects};
    use super::*;
    use proptest::prelude::*;

    #[test]
    fn examples() {
        for ok in [
            "* * * * *",
            "*/5 * * * *",
            "0 4 * * sun",
            "0 4 1 jan *",
            "0,30 8-18 * * 1-5",
            "0 0-23/2 1-31 1-12 0-7",
        ] {
            assert!(CronSpec::new(ok).is_ok(), "{ok}");
        }
        for bad in [
            "",
            "* * * *",
            "* * * * * *",
            "60 * * * *",
            "* 24 * * *",
            "* * 0 * *",
            "* * * 13 *",
            "* * * * 8",
            "*/0 * * * *",
            "5/10 * * * *",
            "10-5 * * * *",
            "@reboot",
            "* * * jan-mar *",
            "* * * * mon,tue",
            "1,,2 * * * *",
            "* * * * * ; rm",
        ] {
            assert!(CronSpec::new(bad).is_err(), "{bad}");
        }
        assert_eq!(
            CronSpec::new("  0\t4 * *  * ").unwrap().as_str(),
            "0 4 * * *"
        );
        assert!(wire_rejects::<CronSpec>("0  4 * * *"));
        roundtrip(&CronSpec::new("0 4 * * *").unwrap());

        assert!(Nice::new(-21).is_err() && Nice::new(20).is_err());
        assert!(crate::decode::<Nice>(&crate::encode(&20i8)).is_err());
        assert!(Pid::new(1).is_err() && Pid::new(2).is_ok());
        assert_eq!(Signal::Term.number(), 15);
    }

    proptest! {
        #[test]
        fn cron_accepts(
            m in 0u8..60, h in 0u8..24, d in 1u8..32, mo in 1u8..13, w in 0u8..8, step in 1u8..60,
        ) {
            let s = format!("*/{step} {h} {d}-31 {mo} {w}");
            let spec = CronSpec::new(&s).unwrap();
            roundtrip(&spec);
            let s2 = format!("{m},{} * * * *", (m + 1) % 60);
            prop_assert!(CronSpec::new(&s2).is_ok());
        }

        #[test]
        fn cron_rejects_out_of_range(m in 60u8..100) {
            let s = format!("{m} * * * *");
            prop_assert!(CronSpec::new(&s).is_err());
        }

        #[test]
        fn nice_range(n in any::<i8>()) {
            prop_assert_eq!(Nice::new(n).is_ok(), (-20..=19).contains(&n));
        }
    }
}
