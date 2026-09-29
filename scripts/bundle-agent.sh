#!/usr/bin/env bash
# Builds the agent .deb for arm64 and amd64 (scripts/build-deb.sh, Docker)
# and copies them into a directory, by default the app bundle being built:
# Fleet.app/Contents/Resources/agent/fleet-agent_<ver>_<arm64|amd64>.deb.
# The app's install flow picks the one matching the server (design §10.1).
#
#   scripts/bundle-agent.sh [dest-dir]
#
# From Xcode (post-build phase) the destination is
# $TARGET_BUILD_DIR/$UNLOCALIZED_RESOURCES_FOLDER_PATH/agent.
#
# FLEET_SKIP_AGENT_BUNDLE=1 skips everything (fast Debug/test builds: the
# test hook FLEET_TEST_AGENT_ARTIFACT supplies the agent instead; the app
# then offers only "Choose…").
# FLEET_AGENT_VERSION (major.minor.patch) is passed through to the builds.
# The first amd64 build runs under emulation and takes many minutes;
# later builds reuse the Docker volumes.
set -euo pipefail
export PATH="$HOME/.cargo/bin:/opt/homebrew/bin:/usr/local/bin:$PATH"

if [[ "${FLEET_SKIP_AGENT_BUNDLE:-}" == "1" ]]; then
    echo "bundle-agent: FLEET_SKIP_AGENT_BUNDLE=1, skipping" >&2
    exit 0
fi

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
if [[ -n "${1:-}" ]]; then
    dest="$1"
elif [[ -n "${TARGET_BUILD_DIR:-}" && -n "${UNLOCALIZED_RESOURCES_FOLDER_PATH:-}" ]]; then
    dest="$TARGET_BUILD_DIR/$UNLOCALIZED_RESOURCES_FOLDER_PATH/agent"
else
    echo "usage: $0 <dest-dir>" >&2
    exit 2
fi

stage="$(mktemp -d)"
trap 'rm -rf "$stage"' EXIT
rm -rf "$dest"
mkdir -p "$dest"
for arch in aarch64 x86_64; do
    FLEET_AGENT_OUT="$stage/$arch" "$root/scripts/build-deb.sh" "$arch" >&2
    cp "$stage/$arch"/fleet-agent_*.deb "$dest/"
done
ls -l "$dest" >&2
