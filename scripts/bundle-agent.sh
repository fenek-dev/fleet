#!/usr/bin/env bash
# Agent .deb packages (arm64 + amd64) for the app bundle (design §10.1).
#
#   scripts/bundle-agent.sh stage   # build into build/embed/agent/ + agent-pins.txt
#   scripts/bundle-agent.sh embed [dest-dir]   # copy the staged packages
#
# stage runs BEFORE the app compiles (scripts/gen-bundled-artifacts.sh): it
# builds both packages with scripts/build-deb.sh (Docker) and writes
# `<file name> <sha256 of the whole .deb>` lines to agent-pins.txt, which
# get compiled into the app executable. embed (Xcode post-build phase)
# copies exactly those files to
# $TARGET_BUILD_DIR/$UNLOCALIZED_RESOURCES_FOLDER_PATH/agent; the install
# flow refuses a package whose hash differs from its pin.
#
# FLEET_SKIP_AGENT_BUNDLE=1 skips both (fast Debug/test builds: the test
# hook FLEET_TEST_AGENT_ARTIFACT supplies the agent instead; the app then
# offers only "Choose…"). FLEET_AGENT_VERSION (major.minor.patch) is passed
# through. The first amd64 build runs under emulation and takes many
# minutes; later builds reuse the Docker volumes.
set -euo pipefail
export PATH="$HOME/.cargo/bin:/opt/homebrew/bin:/usr/local/bin:$PATH"

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
out="$root/build/embed"
mode="${1:-}"

case "$mode" in
    stage)
        rm -rf "$out/agent" "$out/agent-pins.txt"
        mkdir -p "$out"
        if [[ "${FLEET_SKIP_AGENT_BUNDLE:-}" == "1" ]]; then
            echo "bundle-agent: FLEET_SKIP_AGENT_BUNDLE=1, skipping" >&2
            : >"$out/agent-pins.txt"
            exit 0
        fi
        mkdir -p "$out/agent"
        tmp="$(mktemp -d)"
        trap 'rm -rf "$tmp"' EXIT
        for arch in aarch64 x86_64; do
            FLEET_AGENT_OUT="$tmp/$arch" "$root/scripts/build-deb.sh" "$arch" >&2
            cp "$tmp/$arch"/fleet-agent_*.deb "$out/agent/"
        done
        for f in "$out"/agent/*.deb; do
            echo "$(basename "$f") $(shasum -a 256 "$f" | cut -d' ' -f1)"
        done >"$out/agent-pins.txt"
        cat "$out/agent-pins.txt" >&2
        ;;
    embed)
        if [[ -n "${2:-}" ]]; then
            dest="$2"
        elif [[ -n "${TARGET_BUILD_DIR:-}" && -n "${UNLOCALIZED_RESOURCES_FOLDER_PATH:-}" ]]; then
            dest="$TARGET_BUILD_DIR/$UNLOCALIZED_RESOURCES_FOLDER_PATH/agent"
        else
            echo "usage: $0 embed <dest-dir>" >&2
            exit 2
        fi
        rm -rf "$dest"
        if [[ "${FLEET_SKIP_AGENT_BUNDLE:-}" == "1" ]]; then
            exit 0
        fi
        # The staged files are what the pins were computed from.
        [[ -s "$out/agent-pins.txt" ]] || { echo "bundle-agent: nothing staged" >&2; exit 1; }
        mkdir -p "$dest"
        while read -r name sum; do
            got="$(shasum -a 256 "$out/agent/$name" | cut -d' ' -f1)"
            [[ "$got" == "$sum" ]] || { echo "bundle-agent: $name changed since staging" >&2; exit 1; }
            cp "$out/agent/$name" "$dest/$name"
        done <"$out/agent-pins.txt"
        ls -l "$dest" >&2
        ;;
    *)
        echo "usage: $0 stage | embed [dest-dir]" >&2
        exit 2
        ;;
esac
