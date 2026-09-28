//! Shared fixtures: the golden-vector roster and command (fleet-proto).
#![allow(dead_code)]

use fleet_proto::{SignedCommand, SignedRoster, decode};
use serde::de::DeserializeOwned;

fn vector<T: DeserializeOwned>(hex_text: &str) -> T {
    let bytes = hex::decode(hex_text.trim()).expect("vector hex");
    decode(&bytes).expect("vector decodes")
}

/// The golden `signed_roster` vector (a fixed test fleet).
pub fn roster() -> SignedRoster {
    vector(include_str!(
        "../../crates/fleet-proto/tests/vectors/v1/signed_roster.hex"
    ))
}

/// The golden `signed_command` vector.
pub fn command() -> SignedCommand {
    vector(include_str!(
        "../../crates/fleet-proto/tests/vectors/v1/signed_command.hex"
    ))
}

/// Lossy text view of fuzz input for the line/TOML/YAML parsers.
pub fn text(data: &[u8]) -> std::borrow::Cow<'_, str> {
    String::from_utf8_lossy(data)
}
