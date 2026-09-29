//! The one path glob matcher shared by the agent (config history rules,
//! secret and deny lists, search) and the Mac (MCP secret-file refusal).
//!
//! `*` and `?` match within one path component (`?` one character, `*` any
//! run, including none); a component that is exactly `**` matches any
//! number of components, none included. Everything else is literal, and a
//! literal `*` or `?` in the *text* is just a character (the wildcard is
//! decided by the pattern only). Matching is a dynamic program, so cost is
//! bounded by pattern size times text size whatever the pattern looks like;
//! inputs over [`MAX_LEN`] bytes never match (callers that use a match to
//! *deny* must check [`within_limits`] and fail closed).

/// Longest pattern or text (bytes) that is matched.
pub const MAX_LEN: usize = 4096;

/// Whether both inputs are short enough to be matched.
pub fn within_limits(pattern: &str, text: &str) -> bool {
    pattern.len() <= MAX_LEN && text.len() <= MAX_LEN
}

/// Whether `s` has glob metacharacters.
pub fn is_glob(s: &str) -> bool {
    s.contains(['*', '?'])
}

/// `*`/`?` wildcard match of one component (iterative, linear backtrack;
/// a `*` in the pattern is always a wildcard, checked before any literal
/// comparison).
pub fn component_match(pattern: &str, s: &str) -> bool {
    let (p, s): (Vec<char>, Vec<char>) = (pattern.chars().collect(), s.chars().collect());
    let (mut pi, mut si) = (0usize, 0usize);
    let mut star: Option<(usize, usize)> = None;
    while si < s.len() {
        if pi < p.len() && p[pi] == '*' {
            star = Some((pi, si));
            pi += 1;
        } else if pi < p.len() && (p[pi] == '?' || p[pi] == s[si]) {
            pi += 1;
            si += 1;
        } else if let Some((sp, ss)) = star {
            pi = sp + 1;
            si = ss + 1;
            star = Some((sp, ss + 1));
        } else {
            return false;
        }
    }
    p[pi..].iter().all(|c| *c == '*')
}

/// `row[j]`: the whole pattern matches the first `j` components of `text`.
fn prefix_row(pattern: &str, text: &str) -> Option<Vec<bool>> {
    if !within_limits(pattern, text) {
        return None;
    }
    let s: Vec<&str> = text.split('/').collect();
    let n = s.len();
    let mut row = vec![false; n + 1];
    row[0] = true;
    for comp in pattern.split('/') {
        let mut next = vec![false; n + 1];
        if comp == "**" {
            next[0] = row[0];
            for j in 1..=n {
                next[j] = row[j] || next[j - 1];
            }
        } else {
            for j in 1..=n {
                next[j] = row[j - 1] && component_match(comp, s[j - 1]);
            }
        }
        row = next;
    }
    Some(row)
}

/// Whether `pattern` matches all of `text`.
pub fn glob_match(pattern: &str, text: &str) -> bool {
    prefix_row(pattern, text).is_some_and(|r| r[r.len() - 1])
}

/// Whether `pattern` matches `text` or a leading run of its components
/// (a directory above it): a glob covers what is below a match.
pub fn glob_covers(pattern: &str, text: &str) -> bool {
    prefix_row(pattern, text).is_some_and(|r| r[1..].iter().any(|b| *b))
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    /// Obvious exponential reference (small inputs only).
    fn ref_comp(p: &[char], s: &[char]) -> bool {
        match p.split_first() {
            None => s.is_empty(),
            Some(('*', rest)) => (0..=s.len()).any(|i| ref_comp(rest, &s[i..])),
            Some((c, rest)) => match s.split_first() {
                Some((d, srest)) => (*c == '?' || c == d) && ref_comp(rest, srest),
                None => false,
            },
        }
    }

    fn ref_path(p: &[&str], s: &[&str]) -> bool {
        match p.split_first() {
            None => s.is_empty(),
            Some((&"**", rest)) => (0..=s.len()).any(|i| ref_path(rest, &s[i..])),
            Some((c, rest)) => match s.split_first() {
                Some((d, srest)) => {
                    let (cc, dd): (Vec<char>, Vec<char>) = (c.chars().collect(), d.chars().collect());
                    ref_comp(&cc, &dd) && ref_path(rest, srest)
                }
                None => false,
            },
        }
    }

    fn ref_match(p: &str, s: &str) -> bool {
        let (p, s): (Vec<&str>, Vec<&str>) = (p.split('/').collect(), s.split('/').collect());
        ref_path(&p, &s)
    }

    fn ref_covers(p: &str, s: &str) -> bool {
        let comps: Vec<&str> = s.split('/').collect();
        let p: Vec<&str> = p.split('/').collect();
        (1..=comps.len()).any(|n| ref_path(&p, &comps[..n]))
    }

    #[test]
    fn literal_star_in_text_does_not_hide_the_wildcard() {
        assert!(glob_match(
            "/etc/postfix/sasl_passwd*",
            "/etc/postfix/sasl_passwd*backup"
        ));
        assert!(component_match("a*b", "a*xb"));
        assert!(component_match("*", "*"));
        assert!(component_match("a*", "a*"));
        assert!(glob_covers("/etc/*shadow*", "/etc/*shadow*/x"));
    }

    #[test]
    fn repeated_globstars_are_cheap() {
        let pat = format!("/{}x", "**/".repeat(200));
        let text = format!("/{}y", "a/".repeat(200));
        assert!(!glob_match(&pat, &text));
        let stars = format!("/{}b", "*a".repeat(500));
        let t = format!("/{}", "a".repeat(1000));
        assert!(!glob_match(&stars, &t));
    }

    #[test]
    fn oversized_inputs_never_match() {
        let big = "a".repeat(MAX_LEN + 1);
        assert!(!glob_match("/**", &big));
        assert!(!within_limits("/**", &big));
    }

    proptest! {
        #[test]
        fn matches_the_reference(p in "[ab*?/.]{0,12}", s in "[ab*?/.]{0,12}") {
            prop_assert_eq!(glob_match(&p, &s), ref_match(&p, &s), "{} {}", p, s);
            prop_assert_eq!(glob_covers(&p, &s), ref_covers(&p, &s), "{} {}", p, s);
        }

        #[test]
        fn component_matches_the_reference(p in "[ab*?]{0,8}", s in "[ab*?.]{0,8}") {
            let (pc, sc): (Vec<char>, Vec<char>) = (p.chars().collect(), s.chars().collect());
            prop_assert_eq!(component_match(&p, &s), ref_comp(&pc, &sc));
        }
    }
}
