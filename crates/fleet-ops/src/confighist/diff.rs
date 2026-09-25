//! Unified diff of two texts (Myers, 3 lines of context).
//!
//! Bounded work: common prefix and suffix are trimmed first; the Myers
//! search keeps one `V` slice per edit distance (`O(D²)` memory) and gives
//! up past [`MAX_EDITS`], answering the middle as one replace hunk (still
//! a valid diff, just not minimal). Output stops at [`MAX_DIFF_BYTES`]
//! with a `\ diff truncated` marker line.

use std::fmt::Write as _;

pub const CONTEXT: usize = 3;
/// Edit distance searched before falling back to replace-all.
pub const MAX_EDITS: usize = 600;
/// Output cap (the reply frame is 1 MiB).
pub const MAX_DIFF_BYTES: usize = 512 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Op {
    Keep,
    Del,
    Ins,
}

/// Edit script for the middle part `a`/`b`, or `None` past `MAX_EDITS`.
fn myers(a: &[&str], b: &[&str]) -> Option<Vec<Op>> {
    let (n, m) = (a.len() as isize, b.len() as isize);
    let max = (n + m) as usize;
    let limit = max.min(MAX_EDITS);
    let off = max as isize + 1;
    let mut v = vec![0isize; 2 * max + 3];
    let mut trace: Vec<Vec<isize>> = Vec::new();
    let idx = |k: isize| (k + off) as usize;
    let mut found = None;
    'outer: for d in 0..=limit as isize {
        trace.push(v[idx(-d)..=idx(d)].to_vec());
        let mut k = -d;
        while k <= d {
            let mut x = if k == -d || (k != d && v[idx(k - 1)] < v[idx(k + 1)]) {
                v[idx(k + 1)]
            } else {
                v[idx(k - 1)] + 1
            };
            let mut y = x - k;
            while x < n && y < m && a[x as usize] == b[y as usize] {
                x += 1;
                y += 1;
            }
            v[idx(k)] = x;
            if x >= n && y >= m {
                found = Some(d);
                break 'outer;
            }
            k += 2;
        }
    }
    let dmax = found?;
    let mut ops = Vec::with_capacity((n + m) as usize);
    let (mut x, mut y) = (n, m);
    for d in (1..=dmax).rev() {
        let vd = &trace[d as usize];
        let at = |k: isize| vd[(k + d) as usize];
        let k = x - y;
        let prev_k = if k == -d || (k != d && at(k - 1) < at(k + 1)) {
            k + 1
        } else {
            k - 1
        };
        let prev_x = at(prev_k);
        let prev_y = prev_x - prev_k;
        while x > prev_x && y > prev_y {
            ops.push(Op::Keep);
            x -= 1;
            y -= 1;
        }
        ops.push(if x == prev_x { Op::Ins } else { Op::Del });
        x = prev_x;
        y = prev_y;
    }
    while x > 0 && y > 0 {
        ops.push(Op::Keep);
        x -= 1;
        y -= 1;
    }
    ops.reverse();
    Some(ops)
}

fn edit_script(a: &[&str], b: &[&str]) -> Vec<Op> {
    let pre = a.iter().zip(b).take_while(|(x, y)| x == y).count();
    let suf = a[pre..]
        .iter()
        .rev()
        .zip(b[pre..].iter().rev())
        .take_while(|(x, y)| x == y)
        .count();
    let (am, bm) = (&a[pre..a.len() - suf], &b[pre..b.len() - suf]);
    let middle = myers(am, bm).unwrap_or_else(|| {
        let mut v = vec![Op::Del; am.len()];
        v.extend(std::iter::repeat_n(Op::Ins, bm.len()));
        v
    });
    let mut ops = vec![Op::Keep; pre];
    ops.extend(middle);
    ops.extend(std::iter::repeat_n(Op::Keep, suf));
    ops
}

fn push_line(out: &mut String, mark: char, line: &str) {
    out.push(mark);
    out.push_str(line);
    if !line.ends_with('\n') {
        out.push_str("\n\\ No newline at end of file\n");
    }
}

/// Unified diff of `old` → `new` with `---`/`+++` labels; empty when equal.
pub fn unified(old: &str, new: &str, label_old: &str, label_new: &str) -> String {
    let a: Vec<&str> = old.split_inclusive('\n').collect();
    let b: Vec<&str> = new.split_inclusive('\n').collect();
    let ops = edit_script(&a, &b);
    // Position in a/b before each op.
    let mut pos = Vec::with_capacity(ops.len() + 1);
    let (mut ia, mut ib) = (0usize, 0usize);
    for op in &ops {
        pos.push((ia, ib));
        match op {
            Op::Keep => {
                ia += 1;
                ib += 1;
            }
            Op::Del => ia += 1,
            Op::Ins => ib += 1,
        }
    }
    pos.push((ia, ib));
    let changes: Vec<usize> = (0..ops.len()).filter(|&i| ops[i] != Op::Keep).collect();
    if changes.is_empty() {
        return String::new();
    }
    let mut out = format!("--- {label_old}\n+++ {label_new}\n");
    let mut ci = 0;
    while ci < changes.len() {
        let start = changes[ci].saturating_sub(CONTEXT);
        let mut last = changes[ci];
        while ci + 1 < changes.len() && changes[ci + 1] <= last + 2 * CONTEXT + 1 {
            ci += 1;
            last = changes[ci];
        }
        ci += 1;
        let end = (last + CONTEXT + 1).min(ops.len());
        let (a0, b0) = pos[start];
        let (a1, b1) = pos[end];
        let (alen, blen) = (a1 - a0, b1 - b0);
        let astart = if alen == 0 { a0 } else { a0 + 1 };
        let bstart = if blen == 0 { b0 } else { b0 + 1 };
        let _ = writeln!(out, "@@ -{astart},{alen} +{bstart},{blen} @@");
        for i in start..end {
            let (pa, pb) = pos[i];
            match ops[i] {
                Op::Keep => push_line(&mut out, ' ', a[pa]),
                Op::Del => push_line(&mut out, '-', a[pa]),
                Op::Ins => push_line(&mut out, '+', b[pb]),
            }
            if out.len() > MAX_DIFF_BYTES {
                let mut cut = MAX_DIFF_BYTES;
                while !out.is_char_boundary(cut) {
                    cut -= 1;
                }
                out.truncate(cut);
                if !out.ends_with('\n') {
                    out.push('\n');
                }
                out.push_str("\\ diff truncated\n");
                return out;
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    #[test]
    fn simple_change() {
        let old = "a\nb\nc\nd\ne\nf\ng\nh\n";
        let new = "a\nb\nc\nD\ne\nf\ng\nh\n";
        let d = unified(old, new, "a/x@v1", "b/x@v2");
        assert_eq!(
            d,
            "--- a/x@v1\n+++ b/x@v2\n@@ -1,7 +1,7 @@\n a\n b\n c\n-d\n+D\n e\n f\n g\n"
        );
        assert_eq!(unified(old, old, "a", "b"), "");
    }

    #[test]
    fn separate_hunks_and_edges() {
        let old: String = (1..=20).map(|i| format!("{i}\n")).collect();
        let new = old.replace("2\n", "two\n").replace("19\n", "");
        let d = unified(&old, &new, "a", "b");
        assert_eq!(d.matches("@@ ").count(), 2, "{d}");
        assert!(d.contains("-2\n+two\n"));
        assert!(d.contains("-19\n"));
        // Additions to an empty file; no newline at end.
        let d = unified("", "x", "a", "b");
        assert_eq!(
            d,
            "--- a\n+++ b\n@@ -0,0 +1,1 @@\n+x\n\\ No newline at end of file\n"
        );
    }

    #[test]
    fn fallback_and_cap() {
        let old: String = (0..2000).map(|i| format!("a{i}\n")).collect();
        let new: String = (0..2000).map(|i| format!("b{i}\n")).collect();
        let d = unified(&old, &new, "a", "b");
        assert!(d.starts_with("--- a\n+++ b\n@@ -1,2000 +1,2000 @@\n"));
        let big_old = "x\n".repeat(10);
        let big_new = format!("{}\n", "y".repeat(MAX_DIFF_BYTES + 10));
        let d = unified(&big_old, &big_new, "a", "b");
        assert!(d.len() <= MAX_DIFF_BYTES + 32);
        assert!(d.ends_with("\\ diff truncated\n"));
    }

    /// Applies a unified diff with full context to `old` (test oracle).
    fn apply(old: &str, diff: &str) -> String {
        let a: Vec<&str> = old.split_inclusive('\n').collect();
        let mut out = String::new();
        let mut ia = 0usize;
        let mut lines = diff.split_inclusive('\n').skip(2).peekable();
        while let Some(h) = lines.next() {
            let astart: usize = h[4..].split(',').next().unwrap().parse().unwrap();
            let alen: usize = h
                .split(',')
                .nth(1)
                .unwrap()
                .split(' ')
                .next()
                .unwrap()
                .parse()
                .unwrap();
            let target = if alen == 0 { astart } else { astart - 1 };
            while ia < target {
                out.push_str(a[ia]);
                ia += 1;
            }
            while let Some(l) = lines.peek() {
                if l.starts_with("@@") {
                    break;
                }
                let l = lines.next().unwrap();
                let body = &l[1..];
                let no_nl = lines.peek().is_some_and(|n| n.starts_with('\\'));
                let body = if no_nl {
                    body.strip_suffix('\n').unwrap()
                } else {
                    body
                };
                if no_nl {
                    lines.next();
                }
                match &l[..1] {
                    " " => {
                        out.push_str(body);
                        ia += 1;
                    }
                    "-" => ia += 1,
                    "+" => out.push_str(body),
                    _ => unreachable!(),
                }
            }
        }
        while ia < a.len() {
            out.push_str(a[ia]);
            ia += 1;
        }
        out
    }

    proptest! {
        #[test]
        fn diff_applies(a in proptest::collection::vec(0u8..4, 0..40), b in proptest::collection::vec(0u8..4, 0..40), nl in any::<bool>()) {
            let mut old: String = a.iter().map(|c| format!("{c}\n")).collect();
            let mut new: String = b.iter().map(|c| format!("{c}\n")).collect();
            if nl { old.push('z'); } else { new.push('z'); }
            let d = unified(&old, &new, "a", "b");
            prop_assert_eq!(apply(&old, &d), new);
        }
    }
}
