#!/usr/bin/env bash
# Builds the Mac app in Release (unsigned) and fails if the binary contains
# any test-hook string. Guards `#if FLEET_TEST_HOOKS` (Debug only).
#
#   scripts/check-release-hooks.sh [--no-build]
set -euo pipefail
export PATH="$HOME/.cargo/bin:/opt/homebrew/bin:/usr/local/bin:$PATH"

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
derived="$root/build/DerivedDataRelease"
app="$derived/Build/Products/Release/Fleet.app"
bin="$app/Contents/MacOS/Fleet"

if [[ "${1:-}" != "--no-build" ]]; then
    cd "$root/apple/Fleet"
    xcodegen generate >/dev/null
    xcodebuild -project Fleet.xcodeproj -scheme Fleet -configuration Release \
        -destination 'platform=macOS,arch=arm64' \
        -derivedDataPath "$derived" -skipPackagePluginValidation \
        CODE_SIGNING_ALLOWED=NO CODE_SIGNING_REQUIRED=NO CODE_SIGN_IDENTITY= \
        FLEET_ENTITLEMENTS=Fleet/Fleet-Test.entitlements \
        build >"$derived.log" 2>&1 || {
        grep -E "error:|BUILD" "$derived.log" | cut -c1-300 | tail -20 >&2
        echo "Release build failed (log: $derived.log)" >&2
        exit 1
    }
fi

[ -f "$bin" ] || { echo "missing $bin" >&2; exit 1; }

# The markers are assembled here so this script's own text is not what
# matches; `strings -a` covers every section, and the raw grep catches
# UTF-16 or oddly-sectioned literals.
markers=(FLEET_TEST_SIGNER FLEET_DATA_DIR TEST-APPROVE FLEET_TEST_AGENT_ARTIFACT FLEET_TEST_AUTO_PAIR approvals.log ssh_pubkey)
fail=0
for m in "${markers[@]}"; do
    if strings -a "$bin" | grep -q -- "$m" || grep -aq -- "$m" "$bin"; then
        echo "FAIL: Release binary contains \"$m\"" >&2
        fail=1
    fi
done
if [ "$fail" = 1 ]; then exit 1; fi
echo "OK: no test-hook strings in $bin"
