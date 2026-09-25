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
const DEFLATE_LEVEL: u8 = 6;

/// One read of a file.
#[derive(Debug, Clone)]
pub struct Observed {
    pub meta: FileMeta,
    pub hash: Hash32,
    /// Holds a PEM private key block.
    pub has_key: bool,
    /// Plain content, when `keep` was asked, the file is at most
    /// [`MAX_BLOB`] and holds no key. `None` otherwise.
    pub data: Option<Vec<u8>>,
    /// Bytes read.
    pub read: u64,
}

fn find(hay: &[u8], needle: &[u8]) -> bool {
    hay.windows(needle.len()).any(|w| w == needle)
}

/// Hashes `file` to its end (streamed), looking for [`KEY_MARKER`] across
/// chunk boundaries. Content is buffered only when `keep` and small
/// enough; it is dropped again if a key turns up.
pub fn observe(mut file: std::fs::File, meta: FileMeta, keep: bool) -> io::Result<Observed> {
    let mut hasher = blake3::Hasher::new();
    let mut data = (keep && meta.size <= MAX_BLOB).then(Vec::new);
    let mut buf = vec![0u8; CHUNK];
    let mut tail: Vec<u8> = Vec::new();
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
            has_key = find(&tail, KEY_MARKER);
            let keep_from = tail.len().saturating_sub(KEY_MARKER.len() - 1);
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
    if has_key {
        data = None;
    }
    Ok(Observed {
        meta,
        hash: *hasher.finalize().as_bytes(),
        has_key,
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

    fn read(content: &[u8], keep: bool) -> Observed {
        let d = tempfile::tempdir().unwrap();
        std::fs::write(d.path().join("f"), content).unwrap();
        let c = ctx(d.path(), Rc::new(crate::FakeRunner::new()));
        let (f, m) = open_file(&c, "/f").unwrap();
        assert_eq!(m.kind, Kind::File);
        observe(f, m, keep).unwrap()
    }

    #[test]
    fn hashes_and_keeps_small_text() {
        let o = read(b"hello\n", true);
        assert_eq!(o.hash, *blake3::hash(b"hello\n").as_bytes());
        assert_eq!(o.data.as_deref(), Some(&b"hello\n"[..]));
        assert!(!o.has_key);
        let o = read(b"hello\n", false);
        assert!(o.data.is_none());
    }

    #[test]
    fn detects_keys_across_chunks() {
        let mut big = vec![b'a'; CHUNK - 5];
        big.extend_from_slice(b"-----BEGIN OPENSSH PRIVATE KEY-----\nxxx\n");
        let o = read(&big, true);
        assert!(o.has_key);
        assert!(o.data.is_none());
        let o = read(b"-----BEGIN PUBLIC KEY-----\n", true);
        assert!(!o.has_key);
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
