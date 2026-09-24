#!/usr/bin/env bash
# Builds the Rust core static library for the Mac app and generates its
# Swift bindings (design §7.1).
#
#   target/aarch64-apple-darwin/release/libfleet_core_ffi.a
#   apple/Fleet/Generated/fleet_core.swift
#   apple/Fleet/Generated/include/{fleet_coreFFI.h,module.modulemap}
#
# Run by hand or by the Xcode pre-build phase. Takes no arguments; every
# path is derived from this script's location.
set -euo pipefail

# Xcode runs build phases with a minimal PATH.
export PATH="$HOME/.cargo/bin:/opt/homebrew/bin:/usr/local/bin:$PATH"

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
target="aarch64-apple-darwin"
lib="$root/target/$target/release/libfleet_core_ffi.a"
out="$root/apple/Fleet/Generated"

cd "$root"

cargo build -p fleet-core-ffi --release --locked --target "$target"

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

cargo run -q -p fleet-core-ffi --features bindgen --release --locked \
    --bin uniffi-bindgen -- \
    generate --library "$lib" --language swift --out-dir "$tmp"

mkdir -p "$out/include"
# Only replace files whose content changed, so Xcode doesn't recompile
# the bindings on every build.
install_if_changed() {
    if ! cmp -s "$1" "$2"; then
        cp "$1" "$2"
    fi
}
install_if_changed "$tmp/fleet_core.swift" "$out/fleet_core.swift"
install_if_changed "$tmp/fleet_coreFFI.h" "$out/include/fleet_coreFFI.h"
install_if_changed "$tmp/fleet_coreFFI.modulemap" "$out/include/module.modulemap"

echo "fleet-core: $lib"
