#!/usr/bin/env bash
# Builds `fleetctl` (the MCP server, design §8) and embeds it in the app
# bundle as Contents/MacOS/fleetctl, next to the app binary. The app's MCP
# socket accepts only this binary: team builds check "signed as
# `dev.fleet.fleetctl` with the app's team"; ad-hoc builds check that its
# cdhash equals the one compiled into the app executable.
#
#   scripts/build-fleetctl.sh [stage|embed]     (default: both)
#
# stage: cargo build, ad-hoc sign a copy with identifier dev.fleet.fleetctl
#        (hardened runtime) into build/embed/fleetctl and write its cdhash
#        (hex) to build/embed/fleetctl.cdhash. Runs before the app compiles
#        (scripts/gen-bundled-artifacts.sh) so the cdhash can be compiled in.
# embed: copy the staged, signed copy into $TARGET_BUILD_DIR (Xcode phase).
#        Release builds with a team re-sign it afterwards
#        (scripts/build-release-app.sh).
set -euo pipefail

export PATH="$HOME/.cargo/bin:/opt/homebrew/bin:/usr/local/bin:$PATH"

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
target="aarch64-apple-darwin"
bin="$root/target/$target/release/fleetctl"
staged="$root/build/embed/fleetctl"
mode="${1:-both}"

if [[ "$mode" == stage || "$mode" == both ]]; then
    cd "$root"
    cargo build -p fleetctl --release --locked --target "$target"
    mkdir -p "$root/build/embed"
    rm -f "$staged"
    cp "$bin" "$staged"
    codesign --force --sign - --identifier dev.fleet.fleetctl --options runtime "$staged"
    codesign -d -vvv "$staged" 2>&1 | sed -n 's/^CDHash=//p' | head -n1 >"$root/build/embed/fleetctl.cdhash"
    [[ -s "$root/build/embed/fleetctl.cdhash" ]] || { echo "no cdhash for fleetctl" >&2; exit 1; }
fi

if [[ "$mode" == embed || "$mode" == both ]]; then
    if [[ -n "${TARGET_BUILD_DIR:-}" && -n "${EXECUTABLE_FOLDER_PATH:-}" ]]; then
        dest="$TARGET_BUILD_DIR/$EXECUTABLE_FOLDER_PATH"
        mkdir -p "$dest"
        install -m 0755 "$staged" "$dest/fleetctl"
    fi
fi
