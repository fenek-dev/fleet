#!/usr/bin/env bash
# Packages fleet-agent as a Debian package (design §10.1, §5.7), inside the
# agent builder Docker image (dpkg-deb comes with it).
#
#   scripts/build-deb.sh [aarch64|x86_64]    (default: aarch64)
#
# Builds the static binary first (scripts/build-agent-linux.sh; honours
# FLEET_AGENT_VERSION), then:
#   /usr/lib/fleet/fleet-agent                    0755
#   /usr/lib/systemd/system/fleet-{exec,gate}.service
#   /usr/lib/tmpfiles.d/fleet.conf
#   /etc/needrestart/conf.d/fleet.conf            (conffile)
#   DEBIAN/{control,conffiles,postinst,prerm,postrm}
#
# data.tar is stored uncompressed (-Znone) so the Mac app can read the
# binary out of the package to hash and sign it (release import) without a
# decompressor; the package is a few MB larger for it.
#
# Output: target/linux/<arch>/fleet-agent_<version>_<debarch>.deb
set -euo pipefail

arch="${1:-aarch64}"
case "$arch" in
    aarch64) platform="linux/arm64" debarch="arm64" ;;
    x86_64) platform="linux/amd64" debarch="amd64" ;;
    *)
        echo "usage: $0 [aarch64|x86_64]" >&2
        exit 2
        ;;
esac

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
out="${FLEET_AGENT_OUT:-$root/target/linux/$arch}"
version="${FLEET_AGENT_VERSION:-$(sed -n 's/^version = "\([0-9.]*\)"$/\1/p' "$root/Cargo.toml" | head -n1)}"
case "$version" in
    *[!0-9.]* | "")
        echo "bad version: $version" >&2
        exit 2
        ;;
esac

FLEET_AGENT_OUT="$out" FLEET_AGENT_VERSION="$version" \
    "$root/scripts/build-agent-linux.sh" "$arch"

image="fleet-agent-builder:$arch"
deb="fleet-agent_${version}_${debarch}.deb"

docker run --rm \
    --platform "$platform" \
    -v "$root:/src:ro" \
    -v "$out:/out" \
    -e VERSION="$version" \
    -e DEBARCH="$debarch" \
    -e DEB="$deb" \
    "$image" \
    bash -euo pipefail -c '
        pkg="$(mktemp -d)"
        install -d -m 0755 "$pkg/DEBIAN" "$pkg/usr/lib/fleet" \
            "$pkg/usr/lib/systemd/system" "$pkg/usr/lib/tmpfiles.d" \
            "$pkg/etc/needrestart/conf.d"
        install -m 0755 /out/fleet-agent "$pkg/usr/lib/fleet/fleet-agent"
        install -m 0644 /src/packaging/systemd/fleet-exec.service /src/packaging/systemd/fleet-gate.service \
            "$pkg/usr/lib/systemd/system/"
        install -m 0644 /src/packaging/systemd/tmpfiles.d/fleet.conf "$pkg/usr/lib/tmpfiles.d/fleet.conf"
        install -m 0644 /src/packaging/needrestart/fleet.conf "$pkg/etc/needrestart/conf.d/fleet.conf"
        for s in postinst prerm postrm; do
            install -m 0755 "/src/packaging/deb/$s" "$pkg/DEBIAN/$s"
        done
        echo /etc/needrestart/conf.d/fleet.conf >"$pkg/DEBIAN/conffiles"
        size="$(du -sk --exclude=DEBIAN "$pkg" | cut -f1)"
        cat >"$pkg/DEBIAN/control" <<EOF
Package: fleet-agent
Version: $VERSION
Architecture: $DEBARCH
Maintainer: Fleet <fleet@localhost>
Section: admin
Priority: optional
Installed-Size: $size
Depends: systemd, passwd, util-linux
Description: Fleet server agent
 Static agent for the Fleet macOS control plane: fleet-gate (unprivileged,
 no network) and fleet-exec (root, verifies every signed operation).
 Reached only through SSH; opens no network ports.
EOF
        SOURCE_DATE_EPOCH=0 dpkg-deb --root-owner-group -Znone --build "$pkg" "/out/$DEB" >/dev/null
        dpkg-deb --info "/out/$DEB" | sed -n "s/^ \(Package\|Version\|Architecture\):/\1:/p"
    '
echo "built $out/$deb"
