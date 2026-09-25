#!/usr/bin/env bash
# Builds `fleetctl` (the MCP server, design §8) and, when run from Xcode,
# copies it into the app bundle as Contents/MacOS/fleetctl, next to the
# app binary. The app's MCP socket accepts only this binary (signed as
# `dev.fleet.fleetctl` with the app's team; unsigned debug builds: this
# exact bundled path).
set -euo pipefail

export PATH="$HOME/.cargo/bin:/opt/homebrew/bin:/usr/local/bin:$PATH"

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
target="aarch64-apple-darwin"
bin="$root/target/$target/release/fleetctl"

cd "$root"
cargo build -p fleetctl --release --locked --target "$target"

if [[ -n "${TARGET_BUILD_DIR:-}" && -n "${EXECUTABLE_FOLDER_PATH:-}" ]]; then
    dest="$TARGET_BUILD_DIR/$EXECUTABLE_FOLDER_PATH"
    mkdir -p "$dest"
    install -m 0755 "$bin" "$dest/fleetctl"
fi
