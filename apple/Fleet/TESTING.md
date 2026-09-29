# Testing the Mac app end to end

Automated agents can drive the real app against local Linux servers, several instances in parallel, without Touch ID, the Secure Enclave, the Keychain or team signing. All of it is **Debug only**: the hooks sit behind the `FLEET_TEST_HOOKS` compilation condition, which project.yml defines for the Debug configuration alone.

## Build

```sh
scripts/build-app-test.sh        # ad-hoc signed Debug build, no team needed
```

Output: `build/DerivedData/Build/Products/Debug/Fleet.app` (binary: `Contents/MacOS/Fleet`). The script overrides the entitlements with `Fleet/Fleet-Test.entitlements` (no `keychain-access-groups`, which needs a provisioning profile). A normal team-signed Debug build from Xcode also has the hooks.

## Launch an instance

Every instance needs its own `FLEET_DATA_DIR`; instances with different dirs are fully isolated.

```sh
APP=build/DerivedData/Build/Products/Debug/Fleet.app
# direct binary (one process per instance, env is per process):
FLEET_DATA_DIR=/tmp/fleet-a FLEET_TEST_SIGNER=1 $APP/Contents/MacOS/Fleet &
FLEET_DATA_DIR=/tmp/fleet-b FLEET_TEST_SIGNER=1 $APP/Contents/MacOS/Fleet &
# or through LaunchServices:
open -n $APP --env FLEET_DATA_DIR=/tmp/fleet-c --env FLEET_TEST_SIGNER=1
```

Keep the dir path short (under about 60 characters): it holds `mcp.sock`, and Unix socket paths are limited to about 100 bytes.

| Variable | Effect |
| --- | --- |
| `FLEET_DATA_DIR=<dir>` | Every app file (`cache.sqlite`, `vulns.sqlite`, `mcp.sock`, the core's download dirs) lives under it. UserDefaults/`@AppStorage` go to `<dir>/defaults.plist`. Keychain items (keys, Noise key, sync key, sudo passwords) are files in `<dir>/keys/` (0600). |
| `FLEET_TEST_SIGNER=1` | Software P-256 keys. App lock, root-key signatures, sudo-password reveal and AI/MCP approval prompts skip Touch ID and append `TEST-APPROVE <kind>: <reason>` to `<dir>/approvals.log`. Assert on that file to prove Touch ID would have been asked. |
| `FLEET_TEST_AUTO_PAIR=0` | With the signer on, MCP pairing prompts are answered automatically (approval logged). `0` keeps the pairing sheet (`aiPrompt.approve` / `aiPrompt.deny`). |
| `FLEET_TEST_AGENT_ARTIFACT=<path>` | "Choose…" in the install step picks this file (no file panel). Use the `.deb` (`agent-artifact.sh --deb-only`): a bare binary is refused on a fresh pool server (no fleet-gate user/units). |

Once the keys exist (after onboarding, and on every later launch) the app writes `<dir>/ssh_pubkey` and `<dir>/monitor_ssh_pubkey` (OpenSSH lines). Authorize `ssh_pubkey` on a server before "Add and connect". The monitor key is pinned by the agent install itself.

Notes: `approvals.log` lines are `TEST-APPROVE app-unlock: ...`, `root-sign: ...`, `mcp-approval: ...`, `sudo-reveal: ...`, `sudo-store: ...`. Elevated MCP approvals still show their sheet; only the Touch ID part is automatic.

## Servers

```sh
tests/vm/agent-artifact.sh          # builds static agent + .deb, prints both paths
tests/vm/pool.sh up 3 debian12 --key /tmp/fleet-a/ssh_pubkey --key /tmp/fleet-b/ssh_pubkey
# name host port distro      (add --json for a JSON array)
tests/vm/pool.sh list [--json]
tests/vm/pool.sh down [name...]     # no names: whole pool
```

Servers are systemd containers from the `fleet-it:<distro>` image (built if missing), user `ops` with passwordless sudo and key-only SSH on `127.0.0.1:<port>`; no agent installed. Add server in the app with host `127.0.0.1`, that port, user `ops`, then pick the agent file. The Add Server sheet's SSH key can also be read from the sheet (`addServer.sshKey`).

## MCP / fleetctl

Each instance's socket is `<FLEET_DATA_DIR>/mcp.sock`:

```sh
FLEET_MCP_SOCKET=/tmp/fleet-a/mcp.sock $APP/Contents/MacOS/fleetctl mcp
```

The Debug app accepts the `fleetctl` bundled in the same `.app`. A shell parent is "ask every time", so each connection raises a pairing prompt; with `FLEET_TEST_SIGNER=1` it is approved automatically.

## UI tests

```sh
scripts/build-app-test.sh test -only-testing:FleetUITests
# equivalent: xcodebuild test -scheme Fleet -only-testing:FleetUITests <the flags in the script>
```

`FleetUITests/FleetUITestCase.swift` is the base class: fresh `FLEET_DATA_DIR` (`/tmp/fleet-ui-<id>`) per test, signer on, helpers `wait`, `tap`, `type`, `sidebar("fleet")`, `serverTab("firewall")`, `createFleet()`, `snap("name")` (XCTAttachment, kept always), `approvalsLog`, `waitForFile("ssh_pubkey")`. Environment for the runner: `FLEET_UI_KEEP_DATA=1` keeps the data dir; `FLEET_UI_ENV_<NAME>=v` is forwarded to the app as `<NAME>=v` (e.g. `FLEET_UI_ENV_FLEET_TEST_AGENT_ARTIFACT`). The runner is sandboxed: it can read the data dir but not create it (the app does).

Settings is an in-window screen: `sidebar.settings` or ⌘, opens it, `settings.nav.<section>` (`devices`, `recovery`, `ai`, `sync`, `releases`, `alertRules`, `profiles`, `appearance`, `general`) switches sections, and each page keeps its `settings.<section>` identifier.

Accessibility identifiers are `area.element`: `sidebar.*`, `serverTab.*`, `server.*`, `fleet.*`, `onboarding.*`, `addServer.*`, `provision.*`, `bulk.*`, `settings.*`, `devices.*`, `addMac.*`, `recovery.*`, `sync.*`, `releases.*`, `cloudInit.*`, `ai.*`, `aiPrompt.*`, `alerts.*`, `palette.*`. List them: `grep -rhoE 'accessibilityIdentifier\("[^"]+' apple/Fleet/Fleet | sort -u`.

## Release safety

`scripts/check-release-hooks.sh` builds Release (unsigned) and fails if the binary contains `FLEET_TEST_SIGNER`, `FLEET_DATA_DIR`, `TEST-APPROVE` or the other hook strings. Run it after touching anything under `#if FLEET_TEST_HOOKS`.
