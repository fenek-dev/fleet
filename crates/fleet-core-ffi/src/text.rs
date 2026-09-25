//! Display-safe server text (rule 6).
//!
//! Strings from a server (file names, log lines, unit names, stderr…) go
//! to SwiftUI labels and tables. Control characters there can fake line
//! breaks or hide text, and bidi overrides (U+202A–202E, U+2066–2069) can
//! make `evil<U+202E>txt.sh` read as `evilhs.txt`. Row conversion escapes them
//! visibly instead:
//!
//! - C0 controls (U+0000–U+001F), DEL (U+007F) and C1 controls
//!   (U+0080–U+009F) become `\xNN`;
//! - bidi embeddings, overrides and isolates become `\u{NNNN}`;
//! - a literal backslash stays as is (the escape is for reading, not a
//!   reversible encoding).
//!
//! [`line`] escapes every control; [`text`] keeps `\n` and `\t` for
//! multi-line blocks (a ruleset dump).

fn is_bidi(c: char) -> bool {
    matches!(c, '\u{202A}'..='\u{202E}' | '\u{2066}'..='\u{2069}')
}

fn escape(s: &str, keep_newlines: bool) -> String {
    let clean =
        |c: char| !(c.is_control() || is_bidi(c)) || (keep_newlines && matches!(c, '\n' | '\t'));
    if s.chars().all(clean) {
        return s.to_string();
    }
    let mut out = String::with_capacity(s.len() + 8);
    for c in s.chars() {
        if clean(c) {
            out.push(c);
        } else if is_bidi(c) {
            out.push_str(&format!("\\u{{{:04X}}}", c as u32));
        } else {
            out.push_str(&format!("\\x{:02X}", c as u32));
        }
    }
    out
}

/// One line: every control and bidi character escaped.
pub fn line(s: String) -> String {
    escape(&s, false)
}

/// [`line`] for optional fields.
pub fn opt(s: Option<String>) -> Option<String> {
    s.map(line)
}

/// [`line`] for each entry.
pub fn lines(v: Vec<String>) -> Vec<String> {
    v.into_iter().map(line).collect()
}

/// Multi-line block: like [`line`] but `\n` and `\t` stay.
pub fn text(s: String) -> String {
    escape(&s, true)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn escapes_controls_and_bidi() {
        assert_eq!(line("nginx.service".into()), "nginx.service");
        assert_eq!(line("a\x1b[31mb".into()), "a\\x1B[31mb");
        assert_eq!(line("x\ny\r".into()), "x\\x0Ay\\x0D");
        assert_eq!(line("evil\u{202E}txt.sh".into()), "evil\\u{202E}txt.sh");
        assert_eq!(line("\u{2066}a\u{2069}".into()), "\\u{2066}a\\u{2069}");
        assert_eq!(line("c1\u{85}".into()), "c1\\x85");
        assert_eq!(line("del\x7f".into()), "del\\x7F");
        assert_eq!(line("Ünïcödé 日本".into()), "Ünïcödé 日本");
        assert_eq!(text("a\n\tb\x07".into()), "a\n\tb\\x07");
    }
}
