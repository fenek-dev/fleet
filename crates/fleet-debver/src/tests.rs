use super::*;
use Ordering::{Equal, Greater, Less};
use proptest::prelude::*;

/// Known orderings: Debian Policy §5.6.12 examples, dpkg's own test suite
/// (`t_verrevcmp`), and real security-update version shapes.
const TABLE: &[(&str, &str, Ordering)] = &[
    // Policy: `~~ < ~~a < ~ < (empty) < a`.
    ("1.0~~", "1.0~~a", Less),
    ("1.0~~a", "1.0~", Less),
    ("1.0~", "1.0", Less),
    ("1.0", "1.0a", Less),
    ("1.0~rc1", "1.0", Less),
    ("1.0~rc1", "1.0~rc2", Less),
    ("1.0~beta1~svn1245", "1.0~beta1", Less),
    // Letters sort before non-letters.
    ("1.0a", "1.0+", Less),
    ("1.0a", "1.0.", Less),
    ("1.0+", "1.0.", Less),
    ("1.0z", "1.0A", Greater),
    // Numbers compare as integers.
    ("1.10", "1.9", Greater),
    ("1.001", "1.1", Equal),
    ("001", "1", Equal),
    ("1.0", "1.0.0", Less),
    (
        "99999999999999999999999",
        "99999999999999999999998",
        Greater,
    ),
    ("1.18446744073709551616", "1.18446744073709551615", Greater),
    // Epochs dominate.
    ("1:0.9", "2.0", Greater),
    ("1:1.0", "0:9.9", Greater),
    ("0:1.0", "1.0", Equal),
    ("2:1.0", "10:0.1", Less),
    // Revisions.
    ("1.0", "1.0-1", Less),
    ("1.0-0", "1.0", Equal),
    ("1.0-1", "1.0-2", Less),
    ("1.0-1", "1.0-1+b1", Less),
    ("1.0-1", "1.0-1ubuntu1", Less),
    ("1.0-1ubuntu1", "1.0-1ubuntu1.1", Less),
    ("1.0-1ubuntu0.1", "1.0-1ubuntu1", Less),
    ("1.0-1~bpo12+1", "1.0-1", Less),
    // Hyphens in upstream: the revision starts after the last one.
    ("1.0-2-3", "1.0-2-4", Less),
    ("1.0-2-3", "1.0-3-1", Less),
    // Real security updates.
    ("3.0.11-1~deb12u2", "3.0.13-1~deb12u1", Less),
    ("7.88.1-10+deb12u5", "7.88.1-10+deb12u12", Less),
    ("2.36-9+deb12u7", "2.36-9+deb12u10", Less),
    ("1:9.2p1-2+deb12u3", "1:9.2p1-2+deb12u2", Greater),
    ("2025b-0+deb12u1", "2024a-0+deb12u1", Greater),
    ("3.0.2-0ubuntu1.10", "3.0.2-0ubuntu1.9", Greater),
    ("2.35-0ubuntu3.8", "2.35-0ubuntu3.10", Less),
    ("5.15.0-100.110", "5.15.0-99.109", Greater),
    ("1:8.9p1-3ubuntu0.10", "1:8.9p1-3ubuntu0.6", Greater),
    ("2.30-0ubuntu1~22.04", "2.30-0ubuntu1", Less),
];

#[test]
fn known_orderings() {
    for &(a, b, o) in TABLE {
        assert_eq!(compare(a, b), o, "{a} vs {b}");
        assert_eq!(compare(b, a), o.reverse(), "{b} vs {a}");
        let (pa, pb) = (Version::parse(a).unwrap(), Version::parse(b).unwrap());
        assert_eq!(pa.cmp(&pb), o, "parsed {a} vs {b}");
    }
}

#[test]
fn parse_parts() {
    let v = Version::parse("1:2.3-4-5ubuntu1").unwrap();
    assert_eq!((v.epoch, v.upstream, v.revision), (1, "2.3-4", "5ubuntu1"));
    assert_eq!(v.to_string(), "1:2.3-4-5ubuntu1");
    let v = Version::parse("0:1.0").unwrap();
    assert_eq!((v.epoch, v.upstream, v.revision), (0, "1.0", ""));
    assert_eq!(v.to_string(), "1.0");
}

#[test]
fn parse_rejects() {
    use VersionError::*;
    for (s, e) in [
        ("", Empty),
        ("a1.0", BadUpstream),
        (":1.0", BadEpoch),
        ("x:1.0", BadEpoch),
        ("99999999999:1.0", BadEpoch),
        ("1.0-", EmptyRevision),
        ("1:", BadUpstream),
        ("1.0 beta", BadChar),
        ("1.0_1", BadChar),
        // The epoch ends at the first colon.
        ("1.0-1:2", BadEpoch),
        ("1.0-a_b", BadChar),
    ] {
        assert_eq!(Version::parse(s).err(), Some(e), "{s:?}");
    }
    assert_eq!(
        Version::parse(&"1".repeat(Version::MAX_LEN + 1)).err(),
        Some(TooLong)
    );
}

/// Independent model of Policy §5.6.12, written as the text describes it
/// (tokenize into non-digit / digit runs) rather than as dpkg's loop.
fn policy_part(a: &str, b: &str) -> Ordering {
    fn weight(c: Option<char>) -> i32 {
        match c {
            None => 0,
            Some('~') => -1,
            Some(c) if c.is_ascii_alphabetic() => c as i32,
            Some(c) => c as i32 + 256,
        }
    }
    fn take(s: &str, digits: bool) -> (&str, &str) {
        let n = s
            .find(|c: char| c.is_ascii_digit() != digits)
            .unwrap_or(s.len());
        s.split_at(n)
    }
    let (mut a, mut b) = (a, b);
    while !a.is_empty() || !b.is_empty() {
        let (na, ra) = take(a, false);
        let (nb, rb) = take(b, false);
        let n = na.len().max(nb.len());
        for k in 0..n {
            let o = weight(na[k..].chars().next()).cmp(&weight(nb[k..].chars().next()));
            if o != Equal {
                return o;
            }
        }
        let (da, ra) = take(ra, true);
        let (db, rb) = take(rb, true);
        let (da, db) = (da.trim_start_matches('0'), db.trim_start_matches('0'));
        let o = da.len().cmp(&db.len()).then_with(|| da.cmp(db));
        if o != Equal {
            return o;
        }
        (a, b) = (ra, rb);
    }
    Equal
}

fn policy(a: &str, b: &str) -> Ordering {
    let (ea, ua, ra) = split(a);
    let (eb, ub, rb) = split(b);
    ea.cmp(&eb)
        .then_with(|| policy_part(ua, ub))
        .then_with(|| policy_part(ra, rb))
}

fn version() -> impl Strategy<Value = String> {
    (
        proptest::option::of(0u32..4),
        "[0-9][0-9a-zA-Z.+~]{0,10}",
        proptest::option::of("[0-9a-z.+~]{1,8}"),
    )
        .prop_map(|(e, u, r)| {
            let mut s = e.map(|e| format!("{e}:")).unwrap_or_default();
            s.push_str(&u);
            if let Some(r) = r {
                s.push('-');
                s.push_str(&r);
            }
            s
        })
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(2000))]

    #[test]
    fn matches_policy_model(a in version(), b in version()) {
        prop_assert_eq!(compare(&a, &b), policy(&a, &b));
    }

    #[test]
    fn any_input_matches_model(a in "[0-9a-z:~.+\\-]{0,24}", b in "[0-9a-z:~.+\\-]{0,24}") {
        prop_assert_eq!(compare(&a, &b), policy(&a, &b));
    }

    #[test]
    fn total_order(a in version(), b in version(), c in version()) {
        prop_assert_eq!(compare(&a, &a), Equal);
        prop_assert_eq!(compare(&a, &b), compare(&b, &a).reverse());
        if compare(&a, &b) != Greater && compare(&b, &c) != Greater {
            prop_assert_ne!(compare(&a, &c), Greater, "{} {} {}", a, b, c);
        }
    }

    #[test]
    fn generated_versions_parse(v in version()) {
        let p = Version::parse(&v).unwrap();
        prop_assert_eq!(compare(&p.to_string(), &v), Equal);
    }

    #[test]
    fn tilde_suffix_sorts_first(u in "[0-9][0-9a-z.+]{0,10}", s in "[0-9a-z.+~]{0,6}") {
        let pre = format!("{u}~{s}");
        prop_assert_eq!(compare(&pre, &u), Less);
    }

    #[test]
    fn epoch_dominates(a in version(), b in version()) {
        let (a1, b0) = (format!("5:{}", a.rsplit(':').next().unwrap_or("")), b.rsplit(':').next().unwrap_or("").to_string());
        if Version::parse(&a1).is_ok() {
            prop_assert_eq!(compare(&a1, &b0), Greater);
        }
    }

    #[test]
    fn never_panics(a in "\\PC{0,40}", b in "\\PC{0,40}") {
        let _ = compare(&a, &b);
        let _ = Version::parse(&a);
    }
}
