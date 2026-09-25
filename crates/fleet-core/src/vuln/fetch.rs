//! HTTPS download of the feeds (feature `fetch`): `reqwest` on rustls
//! with the `ring` provider, the macOS trust store
//! (`rustls-platform-verifier`), HTTPS only (redirects too), conditional
//! GET (`If-None-Match` / `If-Modified-Since`), a size cap enforced on
//! both `Content-Length` and the bytes actually received, and a
//! temporary file so the parse streams from disk.

use super::db::{FeedMeta, VulnDb};
use super::feed::{self, FeedError, MAX_DOWNLOAD, Source, Stats};
use reqwest::StatusCode;
use reqwest::header::{
    ACCEPT_ENCODING, CONTENT_ENCODING, ETAG, HeaderMap, IF_MODIFIED_SINCE, IF_NONE_MATCH,
    LAST_MODIFIED,
};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::Duration;

#[derive(Debug, thiserror::Error)]
pub enum FetchError {
    #[error("http client: {0}")]
    Client(String),
    #[error("request failed: {0}")]
    Request(String),
    #[error("server answered {0}")]
    Status(u16),
    #[error("download larger than {0} bytes")]
    TooLarge(u64),
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error(transparent)]
    Feed(#[from] FeedError),
}

fn req(e: reqwest::Error) -> FetchError {
    FetchError::Request(e.without_url().to_string())
}

/// The shared client. Installs the `ring` provider as rustls' process
/// default (a no-op if one is installed already).
pub fn client() -> Result<reqwest::Client, FetchError> {
    let _ = rustls::crypto::ring::default_provider().install_default();
    reqwest::Client::builder()
        .https_only(true)
        .connect_timeout(Duration::from_secs(20))
        .read_timeout(Duration::from_secs(60))
        .timeout(Duration::from_secs(20 * 60))
        .redirect(reqwest::redirect::Policy::limited(5))
        .user_agent(concat!("fleet/", env!("CARGO_PKG_VERSION")))
        .build()
        .map_err(|e| FetchError::Client(e.to_string()))
}

/// Result of a conditional GET.
#[derive(Debug)]
pub enum Fetched {
    NotModified,
    Downloaded {
        path: PathBuf,
        etag: Option<String>,
        last_modified: Option<String>,
        content_encoding: Option<String>,
    },
}

fn header(h: &HeaderMap, name: reqwest::header::HeaderName) -> Option<String> {
    h.get(name)
        .and_then(|v| v.to_str().ok())
        .filter(|v| v.len() <= 256)
        .map(str::to_string)
}

/// Downloads `url` to `dest` unless it is unchanged since `prev`.
pub async fn download(
    client: &reqwest::Client,
    url: &str,
    prev: &FeedMeta,
    gzip: bool,
    max_bytes: u64,
    dest: &Path,
) -> Result<Fetched, FetchError> {
    let mut rq = client.get(url);
    if let Some(e) = &prev.etag {
        rq = rq.header(IF_NONE_MATCH, e.as_str());
    }
    if let Some(m) = &prev.last_modified {
        rq = rq.header(IF_MODIFIED_SINCE, m.as_str());
    }
    if gzip {
        rq = rq.header(ACCEPT_ENCODING, "gzip");
    }
    let mut resp = rq.send().await.map_err(req)?;
    match resp.status() {
        StatusCode::NOT_MODIFIED => return Ok(Fetched::NotModified),
        StatusCode::OK => {}
        s => return Err(FetchError::Status(s.as_u16())),
    }
    if resp.content_length().is_some_and(|n| n > max_bytes) {
        return Err(FetchError::TooLarge(max_bytes));
    }
    let h = resp.headers();
    let (etag, last_modified, content_encoding) = (
        header(h, ETAG),
        header(h, LAST_MODIFIED),
        header(h, CONTENT_ENCODING),
    );
    let mut file = std::fs::File::create(dest)?;
    let mut total = 0u64;
    while let Some(chunk) = resp.chunk().await.map_err(req)? {
        total += chunk.len() as u64;
        if total > max_bytes {
            drop(file);
            let _ = std::fs::remove_file(dest);
            return Err(FetchError::TooLarge(max_bytes));
        }
        file.write_all(&chunk)?;
    }
    file.sync_all()?;
    Ok(Fetched::Downloaded {
        path: dest.to_path_buf(),
        etag,
        last_modified,
        content_encoding,
    })
}

/// What one feed update did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outcome {
    NotModified,
    Updated(Stats),
}

/// Checks `source` and loads new data into `db`. Records the attempt,
/// the validators and any error in the feed's metadata.
pub async fn update(
    client: &reqwest::Client,
    db: &mut VulnDb,
    source: Source,
    tmp_dir: &Path,
    now_ms: u64,
) -> Result<Outcome, FetchError> {
    let mut meta = db.meta(source).map_err(FeedError::from)?;
    meta.attempted_ms = Some(now_ms);
    db.set_meta(source, &meta).map_err(FeedError::from)?;
    let dest = tmp_dir.join(format!("{}.download", source.key()));
    type Validators = (Option<String>, Option<String>);
    let result: Result<(Outcome, Option<Validators>), FetchError> = async {
        let gzip = source == Source::DebianTracker;
        match download(client, source.url(), &meta, gzip, MAX_DOWNLOAD, &dest).await? {
            Fetched::NotModified => Ok((Outcome::NotModified, None)),
            Fetched::Downloaded {
                path,
                etag,
                last_modified,
                content_encoding,
            } => {
                let c = source.compression(content_encoding.as_deref());
                let stats = feed::ingest_file(db, source, &path, c)?;
                Ok((Outcome::Updated(stats), Some((etag, last_modified))))
            }
        }
    }
    .await;
    let _ = std::fs::remove_file(&dest);
    match result {
        Ok((outcome, validators)) => {
            meta.fetched_ms = Some(now_ms);
            meta.last_error = None;
            if let Some((etag, lm)) = validators {
                meta.etag = etag;
                meta.last_modified = lm;
                meta.updated_ms = Some(now_ms);
            }
            meta.rows = db.count(source.distro()).map_err(FeedError::from)?;
            db.set_meta(source, &meta).map_err(FeedError::from)?;
            Ok(outcome)
        }
        Err(e) => {
            meta.last_error = Some(e.to_string());
            let _ = db.set_meta(source, &meta);
            Err(e)
        }
    }
}
