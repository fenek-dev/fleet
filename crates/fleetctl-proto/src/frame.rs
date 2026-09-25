//! Frames: a 4-byte big-endian body length, then a JSON body of at most
//! [`MAX_FRAME`] bytes. Both sides read the header first and refuse a
//! length over the limit before reading the body.

use serde::Serialize;
use serde::de::DeserializeOwned;

/// Largest frame body. Tool results cap untrusted text well below this.
pub const MAX_FRAME: usize = 4 * 1024 * 1024;

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum FrameError {
    #[error("frame too large ({0} bytes)")]
    TooLarge(usize),
    #[error("empty frame")]
    Empty,
    #[error("malformed frame: {0}")]
    Malformed(String),
}

/// Header + JSON body.
pub fn encode_frame<T: Serialize>(msg: &T) -> Result<Vec<u8>, FrameError> {
    let body = serde_json::to_vec(msg).map_err(|e| FrameError::Malformed(e.to_string()))?;
    if body.len() > MAX_FRAME {
        return Err(FrameError::TooLarge(body.len()));
    }
    let mut out = Vec::with_capacity(4 + body.len());
    out.extend_from_slice(&(body.len() as u32).to_be_bytes());
    out.extend_from_slice(&body);
    Ok(out)
}

/// Body length from a header, checked against [`MAX_FRAME`].
pub fn frame_len(header: [u8; 4]) -> Result<usize, FrameError> {
    let n = u32::from_be_bytes(header) as usize;
    if n == 0 {
        return Err(FrameError::Empty);
    }
    if n > MAX_FRAME {
        return Err(FrameError::TooLarge(n));
    }
    Ok(n)
}

pub fn decode_body<T: DeserializeOwned>(body: &[u8]) -> Result<T, FrameError> {
    if body.len() > MAX_FRAME {
        return Err(FrameError::TooLarge(body.len()));
    }
    serde_json::from_slice(body).map_err(|e| FrameError::Malformed(e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::msg::{Hello, Request, RequestBody};

    #[test]
    fn round_trip_and_limits() {
        let req = Request {
            v: crate::PROTO_VERSION,
            id: 7,
            body: RequestBody::Hello(Hello {
                client_name: "claude-code".into(),
                client_version: "1.0".into(),
                session: "00112233445566778899aabbccddeeff".into(),
            }),
        };
        let f = encode_frame(&req).unwrap();
        let n = frame_len(f[..4].try_into().unwrap()).unwrap();
        assert_eq!(n, f.len() - 4);
        let back: Request = decode_body(&f[4..]).unwrap();
        assert_eq!(back, req);
        assert_eq!(frame_len([0, 0, 0, 0]), Err(FrameError::Empty));
        assert!(matches!(
            frame_len(((MAX_FRAME + 1) as u32).to_be_bytes()),
            Err(FrameError::TooLarge(_))
        ));
        assert!(decode_body::<Request>(b"{\"v\":1}").is_err());
    }
}
