#!/usr/bin/env bash
# Renders apple/Fleet/Icon/AppIcon.svg into apple/Fleet/Fleet/Resources/AppIcon.icns
# (checked in; rerun only when the SVG changes). Needs rsvg-convert and
# iconutil.
set -euo pipefail
export PATH="/opt/homebrew/bin:/usr/local/bin:$PATH"

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
svg="$root/apple/Fleet/Icon/AppIcon.svg"
out="$root/apple/Fleet/Fleet/Resources/AppIcon.icns"
set="$(mktemp -d)/AppIcon.iconset"
mkdir -p "$set" "$(dirname "$out")"

for size in 16 32 128 256 512; do
    rsvg-convert -w "$size" -h "$size" "$svg" -o "$set/icon_${size}x${size}.png"
    rsvg-convert -w "$((size * 2))" -h "$((size * 2))" "$svg" -o "$set/icon_${size}x${size}@2x.png"
done
iconutil -c icns "$set" -o "$out"
echo "wrote $out"
