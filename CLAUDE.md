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
- **Keys:** every Mac has its own Secure Enclave P-256 keys (root key, device key, monitor key, SSH key). The root key requires Touch ID (`.biometryCurrentSet`) and signs the roster, release manifests and approvals for Elevated operations (including policies). The device key signs commands. The monitor key works while the app is locked, for read-only telemetry and events only.
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

## Repository layout (target)

```
crates/
  fleet-proto/       # messages, Op enum, CommandBody, roster/policy types
  fleet-crypto/      # Noise, envelope signing/verification, recovery derivation
  fleet-agent/       # one binary: gate | exec | bridge | install
  fleet-ops/         # typed operation implementations
  fleet-hardening/   # provisioning modules (check/plan/apply/revert)
  fleet-core/        # Mac core: connections, bulk actions, cache, sync merging
  fleet-core-ffi/    # UniFFI bindings
  fleetctl/          # MCP server and command-line tool
apple/Fleet/         # SwiftUI app
profiles/            # baseline.toml, strict.toml, roles/*.toml
fuzz/  tests/vm/
```

## Conventions

- **Rust:** stable toolchain pinned in `rust-toolchain.toml`; builds use `--locked`. The agent is built as a static musl binary. `tokio` runs on a single thread in the agent.
- **Serialization:** `postcard` on the wire, TOML for profiles and policies.
- **Errors:** fixed protocol error codes. Human-readable messages are generated on the Mac only.
- **Tests:** property tests for validation and parsing; `cargo-fuzz` for the decoder and parsers; Lima VMs for integration tests.
- **Performance budgets:** agent idle memory under 5 MB (gate) and 20 MB (exec); CPU under 0.2% at idle; binary under 10 MB.

## Where to start (Phase 0: security foundation)

1. Cargo workspace plus `fleet-proto` (the `CommandBody`, `SignedCommand`, `Roster` and `Policy` types).
2. `fleet-crypto`: signing and verification of envelopes, and recovery key derivation, with test vectors.
3. `fleet-agent`: split into gate and exec, with the bridge, Noise handshake and signed `system.info` round-trip.
4. Rejection tests: tampered, replayed, stale, wrong-server and revoked-device commands must all fail.

Status: steps 1–4 are done (`crates/fleet-agent/tests/e2e.rs` runs Mac client → gate → exec over real sockets; `crates/fleet-core` holds the Mac session client). Still stubbed: ending `sshd` sessions of removed devices (`exec::SessionTerminator`), real snapshot restore (`revert::Revert`), streams (`StreamOpen` answers `Unsupported`). Next work follows `docs/design.md` section 14.

See `docs/design.md` section 14 for later phases.

## Working agreement

- Ask before changing any decision listed above.
- Keep changes small and testable. Every new operation needs argument validation and tests.
- Update `docs/design.md` when a design detail changes.
