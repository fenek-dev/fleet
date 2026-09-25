//! Reading a tracked file: hash, secret detection, bounded content, and
//! the blob codec (DEFLATE via `miniz_oxide`, pure Rust).

use crate::files::walk::FileMeta;
use fleet_proto::Hash32;
use std::io::{self, Read};

/// Content kept per version (larger files are tracked by hash only).
pub const MAX_BLOB: u64 = 1 << 20;
/// Read chunk.
const CHUNK: usize = 64 * 1024;
/// A PEM private key of any kind (`RSA`, `EC`, `OPENSSH`, `ENCRYPTED`, …).
pub const KEY_MARKER: &[u8] = b"PRIVATE KEY-----";
/// Content that makes any file a secret: PEM keys, WireGuard/networkd
/// and netplan private keys, age and PuTTY keys, crypt(3) hashes in
/// `name:$id$…` form (yescrypt, SHA-512, SHA-256, bcrypt).
pub const SECRET_MARKERS: &[&[u8]] = &[
    KEY_MARKER,
    b"PrivateKey=",
    b"PrivateKey =",
    b"private-key:",
    b"AGE-SECRET-KEY-1",
    b"PuTTY-User-Key-File-",
    b":$y$",
    b":$6$",
    b":$5$",
    b":$2a$",
    b":$2b$",
    b":$2x$",
    b":$2y$",
];
/// Netplan files are secrets too when they configure Wi-Fi or hold a
/// password.
pub const NETPLAN_MARKERS: &[&[u8]] = &[b"wifis:", b"password"];
const DEFLATE_LEVEL: u8 = 6;

/// The content markers that make `path` a secret.
pub fn markers_for(path: &str) -> Vec<&'static [u8]> {
    let mut m = SECRET_MARKERS.to_vec();
    if super::rules::is_netplan(path) {
        m.extend_from_slice(NETPLAN_MARKERS);
    }
    m
}

/// One read of a file.
#[derive(Debug, Clone)]
pub struct Observed {
    pub meta: FileMeta,
    pub hash: Hash32,
    /// Holds a secret marker, or has more than one hard link (another name
    /// could be a secret path): hash only.
    pub secret: bool,
    /// Plain content, when `keep` was asked, the file is at most
    /// [`MAX_BLOB`] and isn't `secret`. `None` otherwise.
    pub data: Option<Vec<u8>>,
    /// Bytes read.
    pub read: u64,
}

fn find(hay: &[u8], needle: &[u8]) -> bool {
    hay.windows(needle.len()).any(|w| w == needle)
}

/// Hashes `file` (at `path`) to its end (streamed), looking for
/// [`markers_for`] across chunk boundaries. Content is buffered only when
/// `keep`, small enough and singly linked; it is dropped again if a marker
/// turns up.
pub fn observe(
    mut file: std::fs::File,
    meta: FileMeta,
    keep: bool,
    path: &str,
) -> io::Result<Observed> {
    let markers = markers_for(path);
    let mut hasher = blake3::Hasher::new();
    let linked = meta.nlink > 1;
    let mut data = (keep && !linked && meta.size <= MAX_BLOB).then(Vec::new);
    let mut buf = vec![0u8; CHUNK];
    let mut tail: Vec<u8> = Vec::new();
    let overlap = markers.iter().map(|m| m.len()).max().unwrap_or(1).max(1) - 1;
    let mut has_key = false;
    let mut read = 0u64;
    loop {
        let n = match file.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => n,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e),
        };
        let chunk = &buf[..n];
        read += n as u64;
        hasher.update(chunk);
        if !has_key {
            tail.extend_from_slice(chunk);
            has_key = markers.iter().any(|m| find(&tail, m));
            let keep_from = tail.len().saturating_sub(overlap);
            tail.drain(..keep_from);
        }
        if let Some(d) = data.as_mut() {
            if read > MAX_BLOB {
                data = None;
            } else {
                d.extend_from_slice(chunk);
            }
        }
    }
    let secret = has_key || linked;
    if secret {
        data = None;
    }
    Ok(Observed {
        meta,
        hash: *hasher.finalize().as_bytes(),
        secret,
        data,
        read,
    })
}

pub fn compress(data: &[u8]) -> Vec<u8> {
    miniz_oxide::deflate::compress_to_vec(data, DEFLATE_LEVEL)
}

/// Inflates a blob (bounded by [`MAX_BLOB`]) and checks it against the
/// version's hash, so a corrupted blob is never restored or shown.
pub fn decompress(blob: &[u8], hash: &Hash32) -> Option<Vec<u8>> {
    let usize_max = usize::try_from(MAX_BLOB).unwrap_or(usize::MAX);
    let data = miniz_oxide::inflate::decompress_to_vec_with_limit(blob, usize_max).ok()?;
    (blake3::hash(&data).as_bytes() == hash).then_some(data)
}

/// Text for diffing: valid UTF-8 without NUL bytes.
pub fn as_text(data: &[u8]) -> Option<&str> {
    if data.contains(&0) {
        return None;
    }
    std::str::from_utf8(data).ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::files::walk::{Kind, open_file};
    use crate::testutil::ctx;
    use std::rc::Rc;

    fn read_at(path: &str, content: &[u8], keep: bool) -> Observed {
        let d = tempfile::tempdir().unwrap();
        let real = d.path().join(path.trim_start_matches('/'));
        std::fs::create_dir_all(real.parent().unwrap()).unwrap();
        std::fs::write(&real, content).unwrap();
        let c = ctx(d.path(), Rc::new(crate::FakeRunner::new()));
        let (f, m) = open_file(&c, path).unwrap();
        assert_eq!(m.kind, Kind::File);
        observe(f, m, keep, path).unwrap()
    }

    fn read(content: &[u8], keep: bool) -> Observed {
        read_at("/f", content, keep)
    }

    #[test]
    fn hashes_and_keeps_small_text() {
        let o = read(b"hello\n", true);
        assert_eq!(o.hash, *blake3::hash(b"hello\n").as_bytes());
        assert_eq!(o.data.as_deref(), Some(&b"hello\n"[..]));
        assert!(!o.secret);
        let o = read(b"hello\n", false);
        assert!(o.data.is_none());
    }

    #[test]
    fn detects_keys_across_chunks() {
        let mut big = vec![b'a'; CHUNK - 5];
        big.extend_from_slice(b"-----BEGIN OPENSSH PRIVATE KEY-----\nxxx\n");
        let o = read(&big, true);
        assert!(o.secret);
        assert!(o.data.is_none());
        let o = read(b"-----BEGIN PUBLIC KEY-----\n", true);
        assert!(!o.secret);
    }

    #[test]
    fn secret_markers() {
        for (path, text, secret) in [
            (
                "/etc/systemd/network/wg.netdev",
                "[WireGuard]\nPrivateKey=abc\n",
                true,
            ),
            ("/etc/wg.conf", "[Interface]\nPrivateKey = abc\n", true),
            ("/etc/x.yaml", "wireguard:\n  private-key: abc\n", true),
            ("/etc/age.txt", "AGE-SECRET-KEY-1QQQ\n", true),
            ("/etc/k.ppk", "PuTTY-User-Key-File-3: ssh-ed25519\n", true),
            ("/etc/p", "bob:$y$j9T$salt$hash:19000::\n", true),
            ("/etc/p", "bob:$6$salt$hash:19000::\n", true),
            ("/etc/p", "bob:$5$salt$hash\n", true),
            ("/etc/p", "bob:$2b$12$hash\n", true),
            ("/etc/p", "bob:x:1000:1000::/home/bob:/bin/bash\n", false),
            ("/etc/p", "PrivateKeyFile=/etc/k\n", false),
            (
                "/etc/netplan/01.yaml",
                "network:\n  wifis:\n    wlan0: {}\n",
                true,
            ),
            ("/etc/netplan/01.yaml", "      password: hunter2\n", true),
            ("/etc/netplan/01.yaml", "network:\n  ethernets: {}\n", false),
            ("/etc/app.conf", "password = x\n", false),
        ] {
            let o = read_at(path, text.as_bytes(), true);
            assert_eq!(o.secret, secret, "{path}: {text}");
            assert_eq!(o.data.is_none(), secret, "{path}: {text}");
        }
    }

    #[test]
    fn hard_linked_files_are_hash_only() {
        let d = tempfile::tempdir().unwrap();
        std::fs::write(d.path().join("a"), b"plain\n").unwrap();
        std::fs::hard_link(d.path().join("a"), d.path().join("b")).unwrap();
        let c = ctx(d.path(), Rc::new(crate::FakeRunner::new()));
        let (f, m) = open_file(&c, "/b").unwrap();
        let o = observe(f, m, true, "/b").unwrap();
        assert!(o.secret);
        assert!(o.data.is_none());
        assert_eq!(o.hash, *blake3::hash(b"plain\n").as_bytes());
    }

    #[test]
    fn large_files_are_hash_only() {
        let big = vec![b'x'; (MAX_BLOB + 1) as usize];
        let o = read(&big, true);
        assert!(o.data.is_none());
        assert_eq!(o.hash, *blake3::hash(&big).as_bytes());
    }

    #[test]
    fn codec_roundtrip_and_integrity() {
        let data = b"a = 1\nb = 2\n".repeat(100);
        let h = *blake3::hash(&data).as_bytes();
        let z = compress(&data);
        assert!(z.len() < data.len());
        assert_eq!(decompress(&z, &h).unwrap(), data);
        assert!(decompress(&z, &[0; 32]).is_none());
        assert!(decompress(b"junk", &h).is_none());
        assert_eq!(as_text(b"ok\n"), Some("ok\n"));
        assert_eq!(as_text(b"a\0b"), None);
        assert_eq!(as_text(&[0xff, 0xfe]), None);
    }
}
