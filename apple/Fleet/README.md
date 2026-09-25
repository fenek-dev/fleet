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
- **Enrollment:** on first launch the app shows onboarding (fleet name, 24-word recovery code shown once, re-type 4 words, optional passphrase, Touch ID signs the genesis roster). Until then nothing connects.
- **Adding a server:** authorize the Mac's SSH key (shown in the Add server sheet) for the admin user, confirm the host key fingerprint, then pick the agent `.deb` (or a bare `fleet-agent` binary for development) to install. Passwordless `sudo` is required.
- **Packages:** SwiftTerm (Swift Package, resolved by Xcode) for terminals. It ships a build-info plugin: trust it once in Xcode, or pass `-skipPackagePluginValidation` to command-line `xcodebuild`.
- Fonts: Geist isn't bundled yet; the UI uses system fonts at the spec's sizes.
- **iCloud sync** (design §7.6) needs a team-signed build with the iCloud → CloudKit capability, container `iCloud.dev.fleet.Fleet`, and `CODE_SIGN_ENTITLEMENTS = Fleet/Fleet-iCloud.entitlements` (the default `Fleet.entitlements` has no iCloud keys, so unsigned and ad-hoc builds still build and run). The app checks for the entitlement at runtime and otherwise keeps sync local-only; joining a fleet and "Recover fleet" need iCloud. Sync polls every 60 s (no push subscription yet).
- **Adding a Mac:** the new Mac chooses "Join an existing fleet" and shows a QR code / pairing code; an enrolled Mac scans it (camera: `NSCameraUsageDescription` + `com.apple.security.device.camera`) or pastes it in Settings → Devices → Add Mac, both compare six digits, and Touch ID approves.
- **Sudo passwords** are Keychain items with user-presence access control; "Sudo password…" in a server's header reveals one behind Touch ID.
