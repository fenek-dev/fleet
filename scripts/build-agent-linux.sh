#!/usr/bin/env bash
# Builds fleet-agent as a static musl binary for Linux inside a Docker
# `rust` container (design §13). No host toolchain changes: rustup, the
# cargo registry and the target dir live in named Docker volumes, so
# rebuilds are incremental.
#
#   scripts/build-agent-linux.sh [aarch64|x86_64]    (default: aarch64)
#
# Output: target/linux/<arch>/fleet-agent
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
out="$root/target/linux/$arch"
mkdir -p "$out"

# Toolchain image (rust + musl-gcc for ring's C code); rust-toolchain.toml
# pins the exact release, which rustup installs into the (persistent)
# rustup volume on first use.
image="fleet-agent-builder:$arch"
suffix="${arch}"
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
    -v "fleet-target-linux-$suffix:/target" \
    -w /src \
    -e CARGO_TARGET_DIR=/target \
    -e CARGO_PROFILE_RELEASE_STRIP=symbols \
    -e TARGET="$target" \
    -e "$cc_var=musl-gcc" \
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
