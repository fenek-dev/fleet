//! Human-readable operation details for the AI approval sheet.
//!
//! Turns an op's `Debug` form into `field: value` lines: newtype wrappers
//! (`AbsPath("/etc/x")`) collapse to their value and strings are shown
//! unescaped (multi-line text stays multi-line). Complete, never cut. The
//! caller escapes control characters. If the text does not parse, the raw
//! `Debug` text is returned, so nothing is ever left out.

#[derive(Debug)]
enum Node {
    Str(String),
    Atom(String),
    /// `Name { k: v, .. }`, or an anonymous map `{ k: v }`.
    Struct(String, Vec<(String, Node)>),
    /// `Name(a, b)`; an empty name is a plain tuple.
    Tuple(String, Vec<Node>),
    List(Vec<Node>),
}

struct P<'a> {
    s: &'a [u8],
    src: &'a str,
    i: usize,
}

impl P<'_> {
    fn ws(&mut self) {
        while self.s.get(self.i) == Some(&b' ') {
            self.i += 1;
        }
    }

    fn eat(&mut self, c: u8) -> bool {
        self.ws();
        if self.s.get(self.i) == Some(&c) {
            self.i += 1;
            true
        } else {
            false
        }
    }

    fn peek(&mut self) -> Option<u8> {
        self.ws();
        self.s.get(self.i).copied()
    }

    fn string(&mut self) -> Option<String> {
        // At the opening quote.
        self.i += 1;
        let mut out = String::new();
        loop {
            let c = self.src.get(self.i..)?.chars().next()?;
            self.i += c.len_utf8();
            match c {
                '"' => return Some(out),
                '\\' => {
                    let e = self.src.get(self.i..)?.chars().next()?;
                    self.i += e.len_utf8();
                    match e {
                        'n' => out.push('\n'),
                        't' => out.push('\t'),
                        'r' => out.push('\r'),
                        '0' => out.push('\0'),
                        '"' | '\'' | '\\' => out.push(e),
                        'u' => {
                            let rest = self.src.get(self.i..)?;
                            let close = rest.find('}')?;
                            let hex = rest.get(1..close)?;
                            out.push(char::from_u32(u32::from_str_radix(hex, 16).ok()?)?);
                            self.i += close + 1;
                        }
                        _ => return None,
                    }
                }
                c => out.push(c),
            }
        }
    }

    fn atom(&mut self) -> Option<String> {
        let start = self.i;
        while let Some(&b) = self.s.get(self.i) {
            if matches!(
                b,
                b',' | b')' | b']' | b'}' | b'(' | b'{' | b'[' | b':' | b' '
            ) {
                break;
            }
            self.i += 1;
        }
        (self.i > start).then(|| self.src[start..self.i].to_string())
    }

    fn list(&mut self, close: u8) -> Option<Vec<Node>> {
        let mut v = Vec::new();
        while !self.eat(close) {
            v.push(self.value()?);
            if !self.eat(b',') && self.peek() != Some(close) {
                return None;
            }
        }
        Some(v)
    }

    fn fields(&mut self) -> Option<Vec<(String, Node)>> {
        let mut v = Vec::new();
        while !self.eat(b'}') {
            let k = match self.peek()? {
                b'"' => self.string()?,
                _ => self.atom()?,
            };
            if !self.eat(b':') {
                return None;
            }
            v.push((k, self.value()?));
            if !self.eat(b',') && self.peek() != Some(b'}') {
                return None;
            }
        }
        Some(v)
    }

    fn value(&mut self) -> Option<Node> {
        match self.peek()? {
            b'"' => self.string().map(Node::Str),
            b'[' => {
                self.i += 1;
                self.list(b']').map(Node::List)
            }
            b'(' => {
                self.i += 1;
                self.list(b')').map(|v| Node::Tuple(String::new(), v))
            }
            b'{' => {
                self.i += 1;
                self.fields().map(|f| Node::Struct(String::new(), f))
            }
            _ => {
                let name = self.atom()?;
                match self.s.get(self.i) {
                    Some(b'(') => {
                        self.i += 1;
                        self.list(b')').map(|v| Node::Tuple(name, v))
                    }
                    Some(b' ') if self.s.get(self.i + 1) == Some(&b'{') => {
                        self.i += 2;
                        self.fields().map(|f| Node::Struct(name, f))
                    }
                    _ => Some(Node::Atom(name)),
                }
            }
        }
    }
}

fn scalar(n: &Node) -> Option<String> {
    match n {
        Node::Atom(a) => Some(a.clone()),
        Node::Str(s) if !s.contains('\n') => Some(quote(s)),
        // `Some(x)` / newtype of a scalar: the value itself.
        Node::Tuple(_, v) if v.len() == 1 => scalar(&v[0]),
        Node::List(v) if v.is_empty() => Some("[]".into()),
        _ => None,
    }
}

/// A string value shown between quotes with `"` and `\` escaped, so its
/// text can neither end the value early nor pass for a field.
fn quote(s: &str) -> String {
    format!("\"{}\"", s.replace('\\', "\\\\").replace('"', "\\\""))
}

fn pad(out: &mut String, indent: usize) {
    for _ in 0..indent {
        out.push_str("  ");
    }
}

/// Multi-line text: every line starts with `| `, so no line of it can pass
/// for a field of the operation.
fn block(out: &mut String, text: &str, indent: usize) {
    for line in text.split('\n') {
        pad(out, indent);
        out.push_str("| ");
        out.push_str(line);
        out.push('\n');
    }
}

/// One value on its own lines at `indent`.
fn value(out: &mut String, n: &Node, indent: usize) {
    if let Some(s) = scalar(n) {
        pad(out, indent);
        out.push_str(&s);
        out.push('\n');
        return;
    }
    match n {
        Node::Str(s) => block(out, s, indent),
        Node::Struct(name, f) => {
            if !name.is_empty() {
                pad(out, indent);
                out.push_str(name);
                out.push('\n');
            }
            fields(out, f, indent + usize::from(!name.is_empty()));
        }
        Node::Tuple(name, v) => {
            // A variant with data keeps its name (the name is meaning).
            if v.len() == 1 && !name.is_empty() {
                pad(out, indent);
                out.push_str(name);
                out.push('\n');
                value(out, &v[0], indent + 1);
            } else {
                for x in v {
                    value(out, x, indent);
                }
            }
        }
        Node::List(v) => {
            for x in v {
                let mut item = String::new();
                value(&mut item, x, 0);
                for (k, line) in item.lines().enumerate() {
                    pad(out, indent);
                    out.push_str(if k == 0 { "- " } else { "  " });
                    out.push_str(line);
                    out.push('\n');
                }
            }
        }
        Node::Atom(_) => {}
    }
}

fn fields(out: &mut String, f: &[(String, Node)], indent: usize) {
    for (k, v) in f {
        pad(out, indent);
        out.push_str(k);
        out.push(':');
        if let Some(s) = scalar(v) {
            out.push(' ');
            out.push_str(&s);
            out.push('\n');
        } else {
            out.push('\n');
            value(out, v, indent + 1);
        }
    }
}

/// `Debug` text of an op as readable lines; the raw text if it does not
/// parse.
pub fn humanize(debug: &str) -> String {
    let mut p = P {
        s: debug.as_bytes(),
        src: debug,
        i: 0,
    };
    let Some(node) = p.value() else {
        return debug.to_string();
    };
    if p.peek().is_some() {
        return debug.to_string();
    }
    let mut out = String::new();
    match &node {
        Node::Struct(_, f) => fields(&mut out, f, 0),
        n => value(&mut out, n, 0),
    }
    let out = out.trim_end().to_string();
    if out.is_empty() {
        "(no arguments)".into()
    } else {
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn newtypes_collapse() {
        let d = r#"ConfigRollback { path: AbsPath("/etc/ssh/sshd_config"), version: 1 }"#;
        assert_eq!(humanize(d), "path: \"/etc/ssh/sshd_config\"\nversion: 1");
        assert_eq!(
            humanize(r#"UnitRestart { unit: UnitName("cron.service") }"#),
            "unit: \"cron.service\""
        );
    }

    #[test]
    fn values_cannot_forge_fields() {
        // A value with a quote and a fake field stays inside its quotes.
        let h = humanize(r#"X { a: "v\", b: 1", c: "l1\nb: 2" }"#);
        assert_eq!(h, "a: \"v\\\", b: 1\"\nc:\n  | l1\n  | b: 2");
    }

    #[test]
    fn multiline_strings_and_lists() {
        let d = r#"ComposeDeploy { project: "app", yaml: "a: 1\nb: \"x\"\n", ports: [80, 443] }"#;
        let h = humanize(d);
        assert!(h.contains("yaml:\n  | a: 1\n  | b: \"x\""), "{h}");
        assert!(h.contains("ports:\n  - 80\n  - 443"), "{h}");
        assert!(!h.contains("\\n"));
    }

    #[test]
    fn unit_and_unparsable() {
        assert_eq!(humanize("SystemReboot"), "SystemReboot");
        assert_eq!(humanize("Foo { bar: "), "Foo { bar: ");
    }
}
