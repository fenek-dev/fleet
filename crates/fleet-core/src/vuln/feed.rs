//! Feed sources and ingest: decompress, stream-parse, replace the feed's
//! rows in [`VulnDb`] in one transaction. No network here (see `fetch`).

use super::db::{DbError, VulnDb};
use super::{Distro, debian, ubuntu};
use serde::de::{DeserializeOwned, Error as _, MapAccess, Visitor};
use std::cell::Cell;
use std::fmt;
use std::io::{BufReader, Read};
use std::marker::PhantomData;
use std::path::Path;
use std::rc::Rc;

/// Largest download accepted (compressed bytes).
pub const MAX_DOWNLOAD: u64 = 256 << 20;
/// Largest decompressed feed parsed (the USN database is ~0.5 GB of JSON).
pub const MAX_DECOMPRESSED: u64 = 2 << 30;
/// Largest top-level entry (one source package, one USN) parsed.
pub const MAX_ENTRY: u64 = 64 << 20;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Source {
    DebianTracker,
    UbuntuUsn,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Compression {
    None,
    Gzip,
    Bzip2,
}

impl Source {
    pub const ALL: [Source; 2] = [Source::DebianTracker, Source::UbuntuUsn];

    /// Key in the `feeds` table.
    pub fn key(self) -> &'static str {
        match self {
            Self::DebianTracker => "debian-tracker",
            Self::UbuntuUsn => "ubuntu-usn",
        }
    }

    pub fn url(self) -> &'static str {
        match self {
            Self::DebianTracker => "https://security-tracker.debian.org/tracker/data/json",
            Self::UbuntuUsn => "https://usn.ubuntu.com/usn-db/database.json.bz2",
        }
    }

    pub fn distro(self) -> Distro {
        match self {
            Self::DebianTracker => Distro::Debian,
            Self::UbuntuUsn => Distro::Ubuntu,
        }
    }

    /// Compression of the body. The tracker serves plain JSON, gzip when
    /// asked (`Content-Encoding`); the USN database is a `.bz2` file.
    pub fn compression(self, content_encoding: Option<&str>) -> Compression {
        match self {
            Self::UbuntuUsn => Compression::Bzip2,
            Self::DebianTracker => match content_encoding.map(str::trim) {
                Some(e) if e.eq_ignore_ascii_case("gzip") => Compression::Gzip,
                _ => Compression::None,
            },
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum FeedError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("parse: {0}")]
    Parse(String),
    #[error("unsupported content encoding")]
    Encoding,
    #[error(transparent)]
    Db(#[from] DbError),
    /// No advisory at all: refuse to replace good data with an empty set.
    #[error("feed has no advisories")]
    Empty,
    /// Advisory count fell by more than half since the last successful
    /// import: likely a broken or truncated feed, so the previous data stays.
    #[error("feed shrank from {previous} to {new} advisories; kept the previous data")]
    Shrunk { previous: u64, new: u64 },
    /// One top-level entry is over [`MAX_ENTRY`] bytes.
    #[error("feed entry larger than 64 MiB")]
    EntryTooLarge,
}

impl From<serde_json::Error> for FeedError {
    fn from(e: serde_json::Error) -> Self {
        if e.is_io() {
            FeedError::Parse(format!("truncated or unreadable: {e}"))
        } else {
            FeedError::Parse(e.to_string())
        }
    }
}

/// Parse counters.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct Stats {
    /// Top-level entries (source packages, USNs).
    pub entries: u64,
    pub advisories: u64,
    /// Rows dropped for failing validation.
    pub invalid: u64,
}

struct EachEntry<'f, T, F> {
    f: &'f mut F,
    budget: &'f EntryBudget,
    _t: PhantomData<T>,
}

impl<'de, T, F> Visitor<'de> for EachEntry<'_, T, F>
where
    T: DeserializeOwned,
    F: FnMut(String, T) -> Result<(), String>,
{
    type Value = u64;

    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("a JSON object")
    }

    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<u64, A::Error> {
        let mut n = 0u64;
        // The counter sits above the `BufReader`, so it sees what the parser
        // consumed (plus at most one peeked byte).
        self.budget.used.set(0);
        while let Some(k) = map.next_key::<String>()? {
            let v: T = map.next_value()?;
            self.budget.used.set(0);
            (self.f)(k, v).map_err(A::Error::custom)?;
            n += 1;
        }
        Ok(n)
    }
}

/// Byte budget of one top-level entry (key and value), shared between the
/// reader and the visitor, which resets it at each entry.
#[derive(Default)]
struct EntryBudget {
    used: Cell<u64>,
    exceeded: Cell<bool>,
}

/// Counts bytes handed to the parser; fails once the current entry is over
/// `limit`, so one huge entry can't grow memory without bound.
struct EntryLimit<R> {
    inner: R,
    budget: Rc<EntryBudget>,
    limit: u64,
}

impl<R: Read> Read for EntryLimit<R> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let n = self.inner.read(buf)?;
        let used = self.budget.used.get().saturating_add(n as u64);
        self.budget.used.set(used);
        if used > self.limit {
            self.budget.exceeded.set(true);
            return Err(std::io::Error::other("feed entry too large"));
        }
        Ok(n)
    }
}

/// Streams a top-level JSON object, deserializing one value at a time:
/// memory is bounded by the largest entry ([`MAX_ENTRY`]), not the document.
pub(crate) fn for_each_entry<R, T, F>(reader: R, f: F) -> Result<u64, FeedError>
where
    R: Read,
    T: DeserializeOwned,
    F: FnMut(String, T) -> Result<(), String>,
{
    for_each_entry_limited(reader, MAX_ENTRY, f)
}

pub(crate) fn for_each_entry_limited<R, T, F>(
    reader: R,
    limit: u64,
    mut f: F,
) -> Result<u64, FeedError>
where
    R: Read,
    T: DeserializeOwned,
    F: FnMut(String, T) -> Result<(), String>,
{
    use serde::Deserializer as _;
    let budget = Rc::new(EntryBudget::default());
    let counted = EntryLimit {
        inner: BufReader::with_capacity(1 << 16, reader),
        budget: budget.clone(),
        limit,
    };
    let mut de = serde_json::Deserializer::from_reader(counted);
    let result = de
        .deserialize_map(EachEntry {
            f: &mut f,
            budget: &budget,
            _t: PhantomData,
        })
        .and_then(|n| de.end().map(|()| n));
    match result {
        Ok(n) => Ok(n),
        Err(_) if budget.exceeded.get() => Err(FeedError::EntryTooLarge),
        Err(e) => Err(e.into()),
    }
}

/// The decompressed, size-capped body.
pub fn decoder<'a, R: Read + 'a>(r: R, c: Compression) -> Box<dyn Read + 'a> {
    let r: Box<dyn Read + 'a> = match c {
        Compression::None => Box::new(r),
        Compression::Gzip => Box::new(flate2::read::MultiGzDecoder::new(BufReader::new(r))),
        Compression::Bzip2 => Box::new(bzip2::read::MultiBzDecoder::new(BufReader::new(r))),
    };
    Box::new(r.take(MAX_DECOMPRESSED))
}

/// Parses `reader` (already decompressed) as `source`, into `sink`.
pub fn parse<R: Read>(
    source: Source,
    reader: R,
    sink: &mut dyn FnMut(super::Advisory) -> Result<(), String>,
) -> Result<Stats, FeedError> {
    match source {
        Source::DebianTracker => debian::parse(reader, sink),
        Source::UbuntuUsn => ubuntu::parse(reader, sink),
    }
}

/// Replaces `source`'s rows with the feed in `path`. On any error the
/// previous rows stay.
pub fn ingest_file(
    db: &mut VulnDb,
    source: Source,
    path: &Path,
    compression: Compression,
) -> Result<Stats, FeedError> {
    let file = std::fs::File::open(path)?;
    ingest(db, source, decoder(file, compression))
}

/// Feeds are checked this often while the app runs.
pub const REFRESH_MS: u64 = 24 * 3600 * 1000;
/// A failed or interrupted attempt is retried after this long.
pub const RETRY_MS: u64 = 3600 * 1000;

/// Whether `meta`'s feed should be fetched at `now_ms`: never fetched, or
/// last successful check a day old, and no attempt in the last hour. A
/// clock that went backwards makes it due.
pub fn due(meta: &super::db::FeedMeta, now_ms: u64) -> bool {
    let recent =
        |t: Option<u64>, window: u64| t.is_some_and(|t| t <= now_ms && now_ms - t < window);
    !recent(meta.attempted_ms, RETRY_MS) && !recent(meta.fetched_ms, REFRESH_MS)
}

/// Whether a feed going from `previous` to `new` advisories dropped by
/// more than half (a first import, `previous == 0`, never has).
pub fn shrank_too_much(previous: u64, new: u64) -> bool {
    new.saturating_mul(2) < previous
}

/// Replaces `source`'s rows with the feed read from `reader`. Refuses an
/// empty feed and one that lost more than half its advisories since the
/// last successful import; on any error the previous rows stay.
pub fn ingest<R: Read>(db: &mut VulnDb, source: Source, reader: R) -> Result<Stats, FeedError> {
    let previous = db.count(source.distro())?;
    db.replace_feed(source.distro(), |sink| {
        let stats = parse(source, reader, sink)?;
        if stats.advisories == 0 {
            return Err(FeedError::Empty);
        }
        if shrank_too_much(previous, stats.advisories) {
            return Err(FeedError::Shrunk {
                previous,
                new: stats.advisories,
            });
        }
        Ok(stats)
    })
}
