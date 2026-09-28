#!/usr/bin/env bash
# Linux integration run (design §13): cross-builds the agent, builds the
# systemd test image and runs crates/fleet-it against one container.
#
#   tests/vm/run.sh [debian12|ubuntu24] [extra cargo test filter args...]
#
# Environment: FLEET_IT_KEEP=1 keeps the container afterwards.
set -euo pipefail

distro="${1:-debian12}"
case "$distro" in
    debian12 | ubuntu24) ;;
    *)
        echo "usage: $0 [debian12|ubuntu24] [test filter...]" >&2
        exit 2
        ;;
esac
shift || true

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
case "$(uname -m)" in
    arm64 | aarch64) arch="aarch64" ;;
    x86_64 | amd64) arch="x86_64" ;;
    *)
        echo "unsupported host architecture: $(uname -m)" >&2
        exit 1
        ;;
esac

"$root/scripts/build-agent-linux.sh" "$arch"
# Build B for the update test: same source, higher version.
next_out="$root/target/linux/$arch/next"
FLEET_AGENT_OUT="$next_out" FLEET_AGENT_VERSION=0.2.0 \
    "$root/scripts/build-agent-linux.sh" "$arch"
export FLEET_IT_AGENT_NEXT="$next_out/fleet-agent"
# FLEET_IT_DEB=1: install through the .deb (dpkg -i) instead of files.
if [ -n "${FLEET_IT_DEB:-}" ]; then
    FLEET_AGENT_OUT="$root/target/linux/$arch/deb" "$root/scripts/build-deb.sh" "$arch"
    FLEET_IT_DEB="$(ls "$root/target/linux/$arch/deb/"fleet-agent_*.deb | head -n1)"
    export FLEET_IT_DEB
fi

image="fleet-it:$distro"
docker build -q -t "$image" \
    -f "$root/tests/vm/docker/Dockerfile.$distro" "$root/tests/vm/docker" >/dev/null
echo "image $image ready"

cleanup() {
    if [ -z "${FLEET_IT_KEEP:-}" ]; then
        # The harness reaps its own container; this catches anything left
        # by an interrupted run.
        docker ps -aq --filter label=fleet-it=1 | while read -r id; do
            docker rm -f "$id" >/dev/null 2>&1 || true
        done
    fi
}
trap cleanup EXIT

cd "$root"
FLEET_IT_IMAGE="$image" \
    FLEET_IT_AGENT="$root/target/linux/$arch/fleet-agent" \
    cargo test --locked -p fleet-it --test linux -- \
    --ignored --test-threads=1 --nocapture "$@"
