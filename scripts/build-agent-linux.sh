#!/usr/bin/env bash
# Builds fleet-agent as a static musl binary for Linux inside a Docker
# `rust` container (design §13). No host toolchain changes: rustup, the
# cargo registry and the target dir live in named Docker volumes, so
# rebuilds are incremental.
#
#   scripts/build-agent-linux.sh [aarch64|x86_64]    (default: aarch64)
#
# Output: target/linux/<arch>/fleet-agent, or $FLEET_AGENT_OUT/fleet-agent.
#
# FLEET_AGENT_VERSION (optional, `major.minor.patch`) overrides the version
# the agent reports and checks updates against (release builds; the update
# harness builds the same source twice with different versions).
#
# FLEET_TARGET_VOLUME=<name> uses its own target volume: parallel
# worktrees sharing one would see each other's (mtime-fresh) artifacts
# for the same /src paths and skip rebuilding changed crates.
#
# aarch64 builds natively on Apple Silicon (linux/arm64 container).
# x86_64 runs the container as linux/amd64 (Rosetta/QEMU emulation in
# Docker Desktop): it works, but expect it to be several times slower.
set -euo pipefail

arch="${1:-aarch64}"
case "$arch" in
    aarch64) platform="linux/arm64" ;;
    x86_64) platform="linux/amd64" ;;
    *)
        echo "usage: $0 [aarch64|x86_64]" >&2
        exit 2
        ;;
esac
target="${arch}-unknown-linux-musl"

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
out="${FLEET_AGENT_OUT:-$root/target/linux/$arch}"
mkdir -p "$out"
version_env=()
if [ -n "${FLEET_AGENT_VERSION:-}" ]; then
    case "$FLEET_AGENT_VERSION" in
        *[!0-9.]* | "")
            echo "FLEET_AGENT_VERSION must be major.minor.patch" >&2
            exit 2
            ;;
    esac
    version_env=(-e "FLEET_AGENT_VERSION=$FLEET_AGENT_VERSION")
fi

# Toolchain image (rust + musl-gcc for ring's C code); rust-toolchain.toml
# pins the exact release, which rustup installs into the (persistent)
# rustup volume on first use.
image="fleet-agent-builder:$arch"
suffix="${arch}"
# One target volume per checkout: worktrees building concurrently into a
# shared one see each other's artifacts (all mounted at /src, so cargo's
# mtime fingerprints can't tell the sources apart).
tree="$(printf '%s' "$root" | cksum | cut -d' ' -f1)"
docker build -q --platform "$platform" -t "$image" \
    -f "$root/scripts/Dockerfile.agent-builder" "$root/scripts" >/dev/null

# musl-gcc is the native musl wrapper inside the (same-arch) container.
cc_var="CC_${arch}_unknown_linux_musl"

docker run --rm \
    --platform "$platform" \
    -v "$root:/src:ro" \
    -v "$out:/out" \
    -v "fleet-rustup-$suffix:/usr/local/rustup" \
    -v "fleet-cargo-registry-$suffix:/usr/local/cargo/registry" \
    -v "fleet-target-linux-${FLEET_TARGET_VOLUME:-$suffix-$tree}:/target" \
    -w /src \
    -e CARGO_TARGET_DIR=/target \
    -e CARGO_PROFILE_RELEASE_STRIP=symbols \
    -e TARGET="$target" \
    -e "$cc_var=musl-gcc" \
    ${version_env[@]+"${version_env[@]}"} \
    "$image" \
    bash -euo pipefail -c '
        rustup target add "$TARGET" >/dev/null
        cargo build --release --locked -p fleet-agent --bin fleet-agent --target "$TARGET"
        install -m 0755 "/target/$TARGET/release/fleet-agent" /out/fleet-agent
    '

bin="$out/fleet-agent"
size="$(wc -c <"$bin" | tr -d " ")"
echo "built $bin ($size bytes, budget 10485760)"
file "$bin"
if [ "$size" -ge 10485760 ]; then
    echo "warning: binary exceeds the 10 MB budget" >&2
fi
