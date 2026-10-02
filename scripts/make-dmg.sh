#!/usr/bin/env bash
# Packs dist/Fleet.app (from scripts/build-release-app.sh) into
# dist/Fleet-<version>.dmg with an /Applications shortcut.
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
app="$root/dist/Fleet.app"
[ -d "$app" ] || { echo "missing $app: run scripts/build-release-app.sh first" >&2; exit 1; }

version="$(/usr/libexec/PlistBuddy -c 'Print :CFBundleShortVersionString' "$app/Contents/Info.plist")"
dmg="$root/dist/Fleet-$version.dmg"
stage="$(mktemp -d)"
trap 'rm -rf "$stage"' EXIT

cp -R "$app" "$stage/Fleet.app"
ln -s /Applications "$stage/Applications"
rm -f "$dmg"
hdiutil create -volname "Fleet" -srcfolder "$stage" -fs HFS+ -format UDZO -ov "$dmg" >/dev/null
echo "built $dmg"
