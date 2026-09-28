# Fuzzing

`cargo-fuzz` (libFuzzer) targets for the wire decoder, crypto verification
and the parsers that read server output. Separate crate, excluded from the
root workspace; it pins a nightly in `rust-toolchain.toml` (the workspace
stays on stable).

## Setup

```sh
rustup toolchain install nightly-2026-09-20 --profile minimal   # once
cargo install cargo-fuzz --locked                               # once
```

Use rustup's `cargo` (`~/.cargo/bin` first in `PATH`), not a Homebrew one,
so `rust-toolchain.toml` takes effect. If `cargo fuzz` builds for the wrong
host (`can't find crate for core`, x86_64 on Apple Silicon), pass
`--target aarch64-apple-darwin`.

## Run

From `fuzz/`:

```sh
cargo fuzz list
# Scratch corpus first (new inputs land there), committed seeds second:
cargo fuzz run wire_message /tmp/fz/wire_message corpus/wire_message -- -max_total_time=60
```

Running with only `corpus/<target>` also works but writes every new input
into the committed seeds; keep that directory small (hand-picked seeds from
fixtures and golden vectors). Crashes go to `artifacts/<target>/`
(git-ignored). Reproduce and minimize:

```sh
cargo fuzz run <target> artifacts/<target>/crash-...
cargo fuzz tmin <target> artifacts/<target>/crash-...
```

A fix belongs in the owning crate with a regression unit test built from
the minimized input.

## Targets

| Target | Code under test | Checks |
|---|---|---|
| `wire_message` | `fleet_proto::decode` of `Message`, `CommandBody`, `SignedCommand`, `SignedRoster` | decode → encode → decode equal, encoding stable |
| `signed_command` | `verify_command` against the golden roster/command context | no panic |
| `merkle_approval` | `MerkleTree`/`verify_proof`, `verify_approval` | honest proofs verify only for their leaf; no panic on arbitrary proofs/approvals |
| `chunk_reassembler` | `chunk::Reassembler` (records `len:u8 ‖ chunk`) | frame and buffer limits; `split_frame` round trip |
| `noise_frames` | Noise transport after a fixed XX handshake | forged ciphertext rejected without desync; honest records round-trip |
| `roster_eval` | `roster::evaluate`, `verify_genesis` | no panic, both directions, extreme clocks |
| `policy_toml` | `Policy::from_toml` | no panic |
| `profile_toml` | `profile::parse_custom`, `RebootWindow::parse` | no panic |
| `compose_yaml` | `fleet_compose::validate` | no panic |
| `sshd_log` | `authlog::parse_sshd`, sshd_config / `sshd -T` parsers | no panic |
| `access_log` | web access-log JSON (`webscan`) | no panic |
| `journal_json` | `logs::journal::parse_line` | no panic |
| `nft_json` | `firewall::parse::parse_table`, `parse_ufw` | no panic |
| `dpkg_status` | dpkg-query, dpkg status, extended_states, dpkg.log, history.log | no panic |
| `apt_sim` | `parse_apt_sim` | no panic |
| `utmp` | wtmp records, wtmpdb JSON | no panic |
| `sudoers` | `escalation::parse_sudoers` | no panic |
| `cron` | crontab (user/system), systemd timer listings | no panic |
| `debver` | `fleet_debver::compare`, `Version` (input `a\0b`) | reflexive, antisymmetric |
| `sync_record` | `SignedRecord` decode + `verify_record`, `SyncKey::open_record` | seal → open round trip |
| `fleetctl_frame` | fleetctl socket frames (`Request`, `Response`) | JSON round trip |
| `vuln_feed` | Debian tracker and Ubuntu USN feed parsers | no panic |

Signatures can't be forged by the fuzzer, so `signed_command`,
`merkle_approval` and `sync_record` exercise decoding and the checks before
the signature; the checks after it are covered by unit tests.
