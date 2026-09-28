#!/usr/bin/env bash
# Ad-hoc signed Debug build of the Mac app for automated end-to-end tests
# (no team, no provisioning profile, no Keychain). Test hooks are compiled
# in (Debug only); see apple/Fleet/TESTING.md.
#
#   scripts/build-app-test.sh            # build
#   scripts/build-app-test.sh test [xcodebuild args...]   # run UI tests
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

exec xcodebuild -project Fleet.xcodeproj -scheme Fleet -configuration Debug \
    -destination 'platform=macOS,arch=arm64' \
    -derivedDataPath "$root/build/DerivedData" \
    -skipPackagePluginValidation \
    CODE_SIGN_IDENTITY=- CODE_SIGNING_REQUIRED=NO \
    FLEET_ENTITLEMENTS=Fleet/Fleet-Test.entitlements \
    "$@" "$action"
