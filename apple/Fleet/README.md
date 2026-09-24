# Fleet (macOS app)

SwiftUI app over the Rust core (`crates/fleet-core-ffi`, design §7.1).

## Build

Needs Xcode 26+, xcodegen, and the Rust toolchain with the `aarch64-apple-darwin` target (arm64 only for now).

```sh
scripts/build-core.sh              # Rust static lib + Swift bindings → apple/Fleet/Generated/
cd apple/Fleet && xcodegen generate
xcodebuild -project Fleet.xcodeproj -scheme Fleet -destination 'platform=macOS,arch=arm64' build
```

`Fleet.xcodeproj` and `Generated/` are gitignored. The `Fleet` target runs `scripts/build-core.sh` as a pre-build phase, so after the first `xcodegen generate` a normal Xcode build keeps the core and bindings current.

## Notes

- **Signing:** keys live in the data protection keychain, which needs a signed build with the `keychain-access-groups` entitlement (set a development team). Unsigned builds (`CODE_SIGNING_ALLOWED=NO`) compile but can't store keys.
- **No Secure Enclave** (VMs, CI): launch with `FLEET_SOFTWARE_KEYS=1` to use Keychain-stored software keys. The UI shows a warning. Development only.
- **App Sandbox is off** for now (Hardened Runtime is on). The core opens outbound SSH itself; sandboxing waits until the MCP socket and file transfer paths are settled.
- **Enrollment:** until `fleet_id` and `device_id` exist in the cache, servers are listed but nothing connects.
- Fonts: Geist isn't bundled yet; the UI uses system fonts at the spec's sizes.
