#!/usr/bin/env bash
# Builds a fresh static fleet-agent (and its .deb) for the Mac app's
# "Choose…" install picker, and prints their paths:
#
#   tests/vm/agent-artifact.sh [aarch64|x86_64] [--deb-only|--bin-only]
#
# Output (stdout, nothing else):
#   /tmp/fleet-artifacts/<arch>/fleet-agent
#   /tmp/fleet-artifacts/<arch>/fleet-agent_<ver>_<debarch>.deb
#
# The arch defaults to the host's (the pool's containers match it). Build
# logs go to stderr. Debug app builds can preselect the file with
# FLEET_TEST_AGENT_ARTIFACT (see apple/Fleet/TESTING.md).
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
arch=""
want_bin=1
want_deb=1
for a in "$@"; do
    case "$a" in
        aarch64 | x86_64) arch="$a" ;;
        --deb-only) want_bin=0 ;;
        --bin-only) want_deb=0 ;;
        *) echo "usage: $0 [aarch64|x86_64] [--deb-only|--bin-only]" >&2; exit 2 ;;
    esac
done
if [ -z "$arch" ]; then
    case "$(uname -m)" in
        arm64 | aarch64) arch="aarch64" ;;
        x86_64 | amd64) arch="x86_64" ;;
        *) echo "unsupported host architecture: $(uname -m)" >&2; exit 1 ;;
    esac
fi

# The app must not read files under ~/Documents (the repo usually lives
# there): that raises a TCC prompt which blocks unattended UI tests. So the
# artifacts are copied to /tmp/fleet-artifacts/<arch>/ and those paths are
# printed.
out="/tmp/fleet-artifacts/$arch"
mkdir -p "$out"
"$root/scripts/build-agent-linux.sh" "$arch" >&2
if [ "$want_bin" = 1 ]; then
    cp "$root/target/linux/$arch/fleet-agent" "$out/fleet-agent"
    echo "$out/fleet-agent"
fi
if [ "$want_deb" = 1 ]; then
    FLEET_AGENT_OUT="$root/target/linux/$arch/deb" "$root/scripts/build-deb.sh" "$arch" >&2
    deb="$(ls "$root/target/linux/$arch/deb/"fleet-agent_*.deb | head -n1)"
    cp "$deb" "$out/"
    echo "$out/$(basename "$deb")"
fi
