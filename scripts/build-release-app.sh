#!/usr/bin/env bash
# Release build of the Mac app: fleetctl and both agent packages embedded,
# test hooks verified absent, output dist/Fleet.app + dist/Fleet-<ver>.zip.
#
#   scripts/build-release-app.sh
#
# Signed (needs an Apple Developer team with a provisioning profile for
# keychain-access-groups; iCloud sync additionally needs the iCloud
# capability/container):
#   FLEET_TEAM_ID=ABCDE12345 [FLEET_SIGN_IDENTITY="Apple Development"] \
#   [FLEET_ICLOUD=1] scripts/build-release-app.sh
#     FLEET_ICLOUD=1 uses Fleet/Fleet-iCloud.entitlements (else
#     Fleet/Fleet.entitlements: Keychain, no iCloud).
#
# Without FLEET_TEAM_ID the app is signed ad hoc with
# Fleet/Fleet-AdHoc.entitlements and a warning says what is limited.
#
# The first run builds the agent for amd64 under emulation (many minutes).
# FLEET_SKIP_AGENT_BUNDLE=1 skips the agent packages (the app then only
# installs from a file chosen with "Choose…").
set -euo pipefail
export PATH="$HOME/.cargo/bin:/opt/homebrew/bin:/usr/local/bin:$PATH"

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
derived="$root/build/DerivedDataRelease"
built="$derived/Build/Products/Release/Fleet.app"
version="$(sed -n 's/^version = "\([0-9.]*\)"$/\1/p' "$root/Cargo.toml" | head -n1)"
dist="$root/dist"

# No get-task-allow (debugger attach) in a release app.
sign_args=(CODE_SIGN_INJECT_BASE_ENTITLEMENTS=NO)
if [[ -n "${FLEET_TEAM_ID:-}" ]]; then
    identity="${FLEET_SIGN_IDENTITY:-Apple Development}"
    ent="Fleet/Fleet.entitlements"
    [[ "${FLEET_ICLOUD:-}" == "1" ]] && ent="Fleet/Fleet-iCloud.entitlements"
    sign_args+=(DEVELOPMENT_TEAM="$FLEET_TEAM_ID" CODE_SIGN_STYLE=Automatic
        CODE_SIGN_IDENTITY="$identity" FLEET_ENTITLEMENTS="$ent"
        -allowProvisioningUpdates)
    echo "signing: team $FLEET_TEAM_ID, identity '$identity', entitlements $ent"
else
    sign_args+=(CODE_SIGN_IDENTITY=- CODE_SIGNING_REQUIRED=NO
        FLEET_ENTITLEMENTS=Fleet/Fleet-AdHoc.entitlements
        # The file key store fallback exists only in ad-hoc builds (and
        # even then only when the runtime code signature is ad hoc).
        'SWIFT_ACTIVE_COMPILATION_CONDITIONS=$(inherited) FLEET_ADHOC_KEYSTORE')
    cat >&2 <<'EOF'
WARNING: FLEET_TEAM_ID not set: ad-hoc signed build. Works: Secure Enclave
keys (kept in a 0600 file under Application Support, enclave-wrapped), SSH,
provisioning, everything local. Does NOT work without a team signature:
  - Keychain-only secrets: per-server sudo passwords, the sync key
  - iCloud sync, recovery escrow
  - Gatekeeper trust on other Macs (right-click > Open, or xattr -cr)
EOF
fi

mkdir -p "$root/build"
"$root/scripts/gen-bundled-artifacts.sh" --stub
cd "$root/apple/Fleet"
xcodegen generate >/dev/null
rm -rf "$built"
xcodebuild -project Fleet.xcodeproj -scheme Fleet -configuration Release \
    -destination 'platform=macOS,arch=arm64' \
    -derivedDataPath "$derived" -skipPackagePluginValidation \
    ${sign_args[@]+"${sign_args[@]}"} build >"$derived.log" 2>&1 || {
    grep -E "error:|BUILD" "$derived.log" | cut -c1-300 | tail -20 >&2
    echo "Release build failed (log: $derived.log)" >&2
    exit 1
}

[[ -x "$built/Contents/MacOS/fleetctl" ]] || { echo "fleetctl not embedded" >&2; exit 1; }
if [[ "${FLEET_SKIP_AGENT_BUNDLE:-}" != "1" ]]; then
    n="$(ls "$built"/Contents/Resources/agent/fleet-agent_*.deb 2>/dev/null | wc -l | tr -d ' ')"
    [[ "$n" == 2 ]] || { echo "expected 2 bundled agent packages, found $n" >&2; exit 1; }
fi

"$root/scripts/check-release-hooks.sh" --no-build

# The embedded fleetctl must be the staged, ad-hoc signed one whose cdhash
# is compiled into the executable (the MCP socket compares them).
if [[ -z "${FLEET_TEAM_ID:-}" ]]; then
    want="$(cat "$root/build/embed/fleetctl.cdhash")"
    got="$(codesign -d -vvv "$built/Contents/MacOS/fleetctl" 2>&1 | sed -n 's/^CDHash=//p' | head -n1)"
    [[ -n "$want" && "$want" == "$got" ]] || { echo "embedded fleetctl cdhash $got != staged $want" >&2; exit 1; }
    grep -aq "$want" "$built/Contents/MacOS/Fleet" || { echo "cdhash $want not compiled into the app" >&2; exit 1; }
fi

if [[ -n "${FLEET_TEAM_ID:-}" ]]; then
    # The socket accepts only a fleetctl signed as dev.fleet.fleetctl with
    # the app's team; re-sign the app afterwards keeping its entitlements.
    codesign --force --options runtime --identifier dev.fleet.fleetctl \
        --sign "${FLEET_SIGN_IDENTITY:-Apple Development}" "$built/Contents/MacOS/fleetctl"
    codesign --force --options runtime --preserve-metadata=entitlements,requirements,flags \
        --sign "${FLEET_SIGN_IDENTITY:-Apple Development}" "$built"
fi
codesign --verify --deep --strict "$built"

rm -rf "$dist"
mkdir -p "$dist"
ditto "$built" "$dist/Fleet.app"
ditto -c -k --keepParent "$dist/Fleet.app" "$dist/Fleet-$version.zip"
echo "built $dist/Fleet.app"
echo "built $dist/Fleet-$version.zip"
