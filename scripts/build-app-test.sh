#!/usr/bin/env bash
# Ad-hoc signed Debug build of the Mac app for automated end-to-end tests
# (no team, no provisioning profile, no Keychain). Test hooks are compiled
# in (Debug only); see apple/Fleet/TESTING.md.
#
#   scripts/build-app-test.sh            # build
#   scripts/build-app-test.sh test [xcodebuild args...]   # run UI tests
#                                   (serialized machine-wide, see below)
#
# App: build/DerivedData/Build/Products/Debug/Fleet.app
set -euo pipefail
export PATH="$HOME/.cargo/bin:/opt/homebrew/bin:/usr/local/bin:$PATH"

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root/apple/Fleet"
xcodegen generate >/dev/null

action=build
if [[ "${1:-}" == "test" ]]; then
    action=test
    shift
fi

# UI tests drive the one shared desktop (focus, keyboard), so only one
# XCUITest run at a time machine-wide, across all worktrees. Waits for the
# lock; a lock whose owner died is taken over.
if [[ "$action" == "test" ]]; then
    lock=/tmp/fleet-uitest.lock
    while ! mkdir "$lock" 2>/dev/null; do
        owner="$(cat "$lock/pid" 2>/dev/null || true)"
        if [[ -n "$owner" ]] && ! kill -0 "$owner" 2>/dev/null; then
            rm -rf "$lock"
            continue
        fi
        echo "waiting for UI test lock (held by pid ${owner:-?})" >&2
        sleep 15
    done
    echo $$ >"$lock/pid"
    trap 'rm -rf "$lock"' EXIT
    # A hung test must not hold the shared lock for long: 10 min per test.
    set -- -test-timeouts-enabled YES -default-test-execution-time-allowance 600 \
        -maximum-test-execution-time-allowance 600 "$@"
fi

xcodebuild -project Fleet.xcodeproj -scheme Fleet -configuration Debug \
    -destination 'platform=macOS,arch=arm64' \
    -derivedDataPath "$root/build/DerivedData" \
    -skipPackagePluginValidation \
    CODE_SIGN_IDENTITY=- CODE_SIGNING_REQUIRED=NO \
    FLEET_ENTITLEMENTS=Fleet/Fleet-Test.entitlements \
    "$@" "$action"
