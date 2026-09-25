# Linux integration harness (Docker)

Stand-in for the Lima VM matrix (design §13). Needs Docker Desktop.

```sh
tests/vm/run.sh              # Debian 12
tests/vm/run.sh ubuntu24     # Ubuntu 24.04
tests/vm/run.sh debian12 metrics   # only tests matching "metrics"
FLEET_IT_KEEP=1 tests/vm/run.sh    # keep the container for debugging
```

`run.sh` does three things:

1. `scripts/build-agent-linux.sh <arch>` builds `target/linux/<arch>/fleet-agent`
   (static musl, stripped) in a `rust` container with `musl-gcc`. Cargo
   registry, rustup and the target dir live in named volumes
   (`fleet-*-<arch>`), so rebuilds are incremental. `x86_64` works on Apple
   Silicon through emulation, slowly.
2. Builds `fleet-it:<distro>` from `docker/Dockerfile.<distro>`: systemd as
   PID 1, sshd (key-only), D-Bus, journald (volatile), sudo, nftables, tmux,
   and an `ops` user in `sudo` (password `fleet-it-password`, never used for
   SSH).
3. `cargo test -p fleet-it --test linux -- --ignored --test-threads=1`.

The tests start one container (`--privileged --cgroupns=private`, tmpfs
`/run`, `/run/lock`, `/tmp`, SSH on a random `127.0.0.1` port), generate two
test Macs, install the agent with `docker/install-agent.sh` and talk to it
through fleet-core over SSH. The container is removed when the test process
exits (a reaper shell watches it), and `run.sh` removes anything labelled
`fleet-it=1` on exit.

Notes:

- Docker Desktop (cgroup v2): `--privileged` plus a private cgroup
  namespace is enough for systemd, `PrivateNetwork=`, seccomp filters and
  `MemoryMax=`. No `/sys/fs/cgroup` bind mount is needed.
- A fresh network namespace lists the kernel's fallback tunnel devices
  (`sit0`, `gre0`, …); the sandbox test checks the gate's namespace differs
  from PID 1's and has no `eth*`.
- If `docker pull` hangs in `docker-credential-desktop get` (keychain not
  reachable from a non-interactive shell), run with a config without a
  credential store: `DOCKER_CONFIG=$(mktemp -d) tests/vm/run.sh`
  (anonymous pulls; copy `~/.docker/contexts` in if you use a non-default
  context).
