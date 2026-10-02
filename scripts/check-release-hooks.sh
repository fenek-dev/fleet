#!/usr/bin/env bash
# Builds the Mac app in Release (unsigned) and fails if the binary contains
# any test-hook string. Guards `#if FLEET_TEST_HOOKS` (Debug only).
#
#   scripts/check-release-hooks.sh [--no-build]
set -euo pipefail
export PATH="$HOME/.cargo/bin:/opt/homebrew/bin:/usr/local/bin:$PATH"

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# The scan only needs the binary, not the agent packages (slow to build).
export FLEET_SKIP_AGENT_BUNDLE=1
derived="$root/build/DerivedDataRelease"
app="$derived/Build/Products/Release/Fleet.app"
bin="$app/Contents/MacOS/Fleet"

if [[ "${1:-}" != "--no-build" ]]; then
    "$root/scripts/gen-bundled-artifacts.sh" --stub
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

# Heuristic: absence of these strings is evidence, not proof, that the hooks
# are compiled out (obfuscated or computed literals would not match). Each
# marker is scanned as ASCII (`strings -a` and raw grep) and UTF-16LE (raw
# bytes with NULs stripped via `tr -d '\000'`, portable to macOS grep).
# A scanner error (not just "no match") fails the check.
markers=(FLEET_TEST_SIGNER FLEET_DATA_DIR TEST-APPROVE FLEET_TEST_AGENT_ARTIFACT FLEET_TEST_AUTO_PAIR FLEET_TEST_SERVER_PASSWORD approvals.log ssh_pubkey)

scan_err() { echo "FAIL: scanner error ($1) on $bin" >&2; exit 1; }

# grep -c: 0 matches => rc 1 (fine); rc >=2 => error. Prints the count.
count_grep() { # count_grep <marker> ; reads stdin
    local c rc=0
    c="$(LC_ALL=C grep -aFc -- "$1")" || rc=$?
    [ "$rc" -le 1 ] || scan_err "grep rc=$rc"
    echo "$c"
}

strings_out="$(strings -a "$bin")" || scan_err "strings rc=$?"
[ -n "$strings_out" ] || scan_err "strings produced no output"

fail=0
for m in "${markers[@]}"; do
    hits="$(count_grep "$m" <<<"$strings_out")"
    raw="$(count_grep "$m" <"$bin")"
    u16="$(LC_ALL=C tr -d '\000' <"$bin" | count_grep "$m")"
    if [ "$hits" != 0 ] || [ "$raw" != 0 ] || [ "$u16" != 0 ]; then
        echo "FAIL: Release binary contains \"$m\"" >&2
        fail=1
    fi
done
if [ "$fail" = 1 ]; then exit 1; fi
echo "OK: no test-hook strings in $bin"
