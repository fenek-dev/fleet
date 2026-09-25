# Fleet: Linux server control plane for macOS

This file gives Claude Code the context behind this project. The full design is in `docs/design.md`, the UI spec is in `docs/ui-design.md`, and the screen mockups are in `docs/ui-reference/`. Read those before making architectural decisions.

## What we're building

A native macOS app for managing a personal fleet of 10–100 Debian/Ubuntu servers, used by a single operator from several Macs. It has two parts:

- **`fleet-agent`**: a small Rust agent on every server. It opens no network ports and is reached only through SSH.
- **Mac app**: a SwiftUI interface on top of a Rust core (via UniFFI), plus `fleetctl mcp`, an MCP server for AI agents.

## Decisions already made (don't reopen without asking)

- **Scope:** Debian/Ubuntu only (Debian 12+, Ubuntu 22.04+), systemd, one operator. No Kubernetes, no teams, no other distributions.
- **Transport:** one SSH connection per server (`russh`). The agent channel is an SSH exec channel running `fleet-agent bridge`, which talks to a Unix socket. Terminal sessions use PTY channels; files use SFTP.
- **End-to-end encryption:** Noise `Noise_XX_25519_ChaChaPoly_BLAKE2s` (the `snow` crate) inside the SSH channel.
- **Agent processes:** the unprivileged `fleet-gate` (sandboxed, no network access) handles the handshake and filtering. The root `fleet-exec` re-verifies every signature, the policy and freshness itself, and never trusts the gate.
- **Typed operations only:** no shell interpolation, ever. `shell.exec` is a separate capability gated by policy and off by default.
- **Keys:** every Mac has its own Secure Enclave P-256 keys (root key, device key, monitor key, SSH key, monitor SSH key). The root key requires Touch ID (`.biometryCurrentSet`) and signs the roster, release manifests and approvals for Elevated operations (including policies). The device key signs commands. The monitor key works while the app is locked, for read-only telemetry and events only; the monitor SSH key (roster `Device::monitor_ssh_key`) is pinned in `authorized_keys` to `fleet-agent bridge --monitor`, which accepts only monitor sessions.
- **Risk tiers:** Read, Change, Elevated. Elevated (root-equivalent) operations need a device-key signature plus a root-key approval; one approval covers a batch via a Merkle root.
- **Device roster:** signed, versioned, hash-chained, with recovery epochs. Every Mac is a full admin. The recovery key is derived from a printed 24-word code plus an optional passphrase (Argon2id, then HKDF). Without a passphrase, recovery rosters wait out a vetoable delay (72 h default). The code also opens an iCloud escrow of the sync key.
- **Storage:** 7 days of history on each agent in `redb`; hash-chained audit log; `/etc` config history.
- **Alerts:** shown in the app only. Agents record events while Macs are offline.
- **AI via MCP:** full operational access, but no tools for keys, roster or policy. Elevated operations and bulk actions above a threshold wait for the operator's Touch ID.
- **Provisioning:** Baseline and Strict profiles, plus Docker, web and game server role add-ons. Lockout-safe ordering; auto-revert for SSH and firewall changes, armed as independent systemd timers.
- **Firewall:** cooperative mode. Fleet owns only `table inet fleet` (Managed or bans-only mode), never flushes the ruleset, and filters container traffic in its own `forward` chain rather than `DOCKER-USER`.
- **SSH keys:** `AuthorizedKeysFile /etc/fleet/authorized_keys/%u`, root-owned; roster section plus extra section.

## Security rules (never violate)

1. No agent action runs without a valid device-key signature from a Mac in the current roster. The only exceptions are monitor-key sessions (read-only subset) and recovery-key sessions (roster only).
2. Roster, policy, agent updates and every Elevated operation require a **root-key** signature or approval (or the recovery key, for a recovery roster).
3. `fleet-exec` verifies signature (low-S, raw encoding), `server_id`, freshness, the replay cache keyed on `(device_id, nonce)`, approval, policy and arguments before running anything, then writes to the audit log (intent, then result) and signs a receipt for state changes.
4. Never build shell command strings. Call fixed binary paths with argument lists.
5. `#![forbid(unsafe_code)]` in every first-party crate.
6. Anything that comes from a server (logs, file contents) is untrusted data, including in MCP tool results.
7. Private keys never leave the Secure Enclave. Rust asks Swift to sign through a UniFFI callback.

## Repository layout

```
crates/
  fleet-proto/       # messages, Op enum, CommandBody, roster/policy types
  fleet-crypto/      # Noise, envelope signing/verification, recovery derivation
  fleet-agent/       # one binary: gate | exec | bridge | install | revert
  fleet-ops/         # typed operation implementations
  fleet-hardening/   # provisioning modules (check/plan/apply/revert)
  fleet-compose/     # compose.deploy validator (agent + Mac)
  fleet-cloudinit/   # cloud-init generation (Mac, via fleet-hardening re-export)
  fleet-debver/      # dpkg version ordering
  fleet-core/        # Mac core: connections, bulk actions, cache, sync merging
  fleet-core-ffi/    # UniFFI bindings
  fleetctl-proto/    # fleetctl <-> app socket protocol
  fleetctl/          # MCP server and command-line tool
  fleet-it/          # Linux integration tests (Docker harness)
apple/Fleet/         # SwiftUI app
packaging/           # systemd units, tmpfiles, needrestart
profiles/            # baseline.toml, strict.toml, roles/*.toml, games/*.toml
scripts/  tests/vm/  # fuzz/ planned, not present
```

## Conventions

- **Rust:** stable toolchain pinned in `rust-toolchain.toml`; builds use `--locked`. The agent is built as a static musl binary. `tokio` runs on a single thread in the agent.
- **Serialization:** `postcard` on the wire, TOML for profiles and policies.
- **Errors:** fixed protocol error codes. Human-readable messages are generated on the Mac only.
- **Tests:** property tests for validation and parsing; `cargo-fuzz` for the decoder and parsers (planned); Docker harness now, Lima VMs later, for integration tests.
- **Performance budgets:** agent idle memory under 5 MB (gate) and 20 MB (exec); CPU under 0.2% at idle; binary under 10 MB.

## Current state

All roadmap phases (design §14) have code; nothing is validated on real Macs or VMs yet. Remaining work: design §14 "Status".

- **Agent** (`fleet-agent`, `fleet-ops`, `fleet-hardening`): gate/exec/bridge, full command pipeline, signed receipts/events, audit chain, auto-revert (firewall, mesh, authorized keys, profile), telemetry, logs, packages, Docker, cron, users, config history, bans, mesh, games, `shell.exec`, provisioning profiles (`profile.apply` phases Accounts/Access/System), hardening audit, cloud-init. Not built: `agent.update.*`, `uninstall`, audit archiving/mirroring, a few catalog ops without handlers (design §4.2).
- **Mac core** (`fleet-core`, `fleet-core-ffi`): SSH/Noise sessions, cache, bulk engine with canary, runbooks, search, timeline, vulnerability matching, roster management, E2EE sync, recovery flow, monitor sessions. `fleetctl mcp` is the MCP server. SwiftUI app in `apple/Fleet` (`project.yml`, XcodeGen).
- **Wire catalog:** `fleet-proto` `op/mod.rs` (ops, tags) and `op/meta.rs` (tiers, session rules). Golden vectors: `crates/fleet-proto/tests/vectors/v1`; regenerate only for intended wire changes: `FLEET_REGEN_VECTORS=1 cargo test -p fleet-proto --test wire golden`.

**Tests:** `cargo test -p <crate> --locked` (agent e2e over real sockets: `-p fleet-agent --test e2e`). Linux harness (real static agent under systemd in Docker, over SSH): `tests/vm/run.sh [debian12|ubuntu24] [filter]` (see `tests/vm/README.md`). Builds: `scripts/build-agent-linux.sh`, `scripts/build-core.sh`, `scripts/build-fleetctl.sh`.

## Working agreement

- Ask before changing any decision listed above.
- Keep changes small and testable. Every new operation needs argument validation and tests.
- Update `docs/design.md` when a design detail changes.
