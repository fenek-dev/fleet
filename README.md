# Fleet

A native macOS control plane for a personal fleet of 10–100 Debian/Ubuntu servers, used by one operator from several Macs.

- **`fleet-agent`** (Rust, static musl) runs on each server. It opens no ports and is reached only through SSH: an exec channel runs `fleet-agent bridge`, a Noise session ends at the sandboxed `fleet-gate`, and the root `fleet-exec` re-verifies every signed, typed command.
- **The Mac app** (SwiftUI over a Rust core via UniFFI) holds its keys in the Secure Enclave, signs commands, and provides dashboard, terminal, files, administration, provisioning, and `fleetctl mcp` for AI agents.

Status: every roadmap phase has code; nothing is validated on real Macs or VMs yet. Remaining work: [design §14](docs/design.md#14-roadmap).

## Layout

```
crates/
  fleet-proto        wire types, Op catalog (op/mod.rs), tiers (op/meta.rs)
  fleet-crypto       Noise, signing/verification, recovery derivation
  fleet-agent        agent binary: gate | exec | bridge | install | revert
  fleet-ops          typed operation handlers
  fleet-hardening    provisioning modules, profiles, audit score
  fleet-compose      compose.deploy validator (agent and Mac)
  fleet-cloudinit    cloud-init YAML generation
  fleet-debver       dpkg version ordering
  fleet-core         Mac core: sessions, cache, bulk engine, sync, recovery, MCP host
  fleet-core-ffi     UniFFI bindings for the Swift app
  fleetctl-proto     fleetctl <-> app socket protocol
  fleetctl           MCP server (stdio) and CLI
  fleet-it           Linux integration tests (Docker harness)
apple/Fleet          SwiftUI app (XcodeGen)
packaging/           systemd units, tmpfiles, needrestart config
profiles/            baseline, strict, roles, game templates
scripts/             build scripts
tests/vm/            Linux harness runner
docs/                design.md, ui-design.md, ui-reference/
```

## Build

```sh
scripts/build-agent-linux.sh [aarch64|x86_64]   # static agent in Docker → target/linux/<arch>/fleet-agent
scripts/build-core.sh                           # libfleet_core_ffi.a + Swift bindings → apple/Fleet/Generated/
scripts/build-fleetctl.sh                       # fleetctl (copied into the app bundle when run from Xcode)
cd apple/Fleet && xcodegen generate
xcodebuild -project Fleet.xcodeproj -scheme Fleet -destination 'platform=macOS,arch=arm64' build
```

**Release app:** `scripts/build-release-app.sh` → `dist/Fleet.app` + `dist/Fleet-<version>.zip`, with `fleetctl` and both agent `.deb`s (arm64, amd64) embedded so Add server needs no file. `FLEET_TEAM_ID=<team>` signs with the real entitlements; without it the app is ad hoc signed and works except for Keychain-only features (sync key, sudo passwords, iCloud). Details in [apple/Fleet/README.md](apple/Fleet/README.md).

Unsigned builds keep Secure Enclave keys in an enclave-bound file store (design §5.2); the data-protection keychain needs the `keychain-access-groups` entitlement, which needs team signing (sync key, sudo passwords and iCloud sync likewise). Without a Secure Enclave, `FLEET_SOFTWARE_KEYS=1` uses software keys (development only). See [apple/Fleet/README.md](apple/Fleet/README.md).

## Test

```sh
cargo test -p <crate> --locked                  # unit and property tests
cargo test -p fleet-agent --test e2e --locked   # agent pipeline over real sockets
tests/vm/run.sh [debian12|ubuntu24] [filter]    # real agent under systemd in Docker, over SSH
```

The harness needs Docker Desktop; see [tests/vm/README.md](tests/vm/README.md).

## Docs

- [docs/design.md](docs/design.md): architecture, security model, protocol, operations (authoritative design; the code wins where they differ).
- [docs/ui-design.md](docs/ui-design.md) and `docs/ui-reference/`: UI spec and mockups.
- [CLAUDE.md](CLAUDE.md): decisions and rules for contributors and agents.
