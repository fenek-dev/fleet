#!/usr/bin/env bash
# Minimal agent install inside a test container, standing in for the
# package + app install flow (design §10.1) until fleet-core has one.
# Runs as root via `docker exec`. The staging directory (copied in with
# `docker cp`) holds:
#   fleet-agent            static binary
#   systemd/               packaging/systemd (units + tmpfiles.d)
#   genesis.hex policy.toml authorized_keys
#
#   install-agent.sh <staging-dir> <server-id> <admin-user>
#
# Prints the `fleet-agent install` output (noise_static=…, signing_key=…).
set -euo pipefail

if [ "$#" -ne 3 ]; then
    echo "usage: $0 <staging-dir> <server-id> <admin-user>" >&2
    exit 2
fi
stage="$1"
server_id="$2"
admin="$3"

if [ -f "$stage/fleet-agent.deb" ]; then
    # The package (scripts/build-deb.sh): users, groups, binary, units,
    # tmpfiles, needrestart config.
    dpkg -i "$stage/fleet-agent.deb" >/dev/null
    echo "installed $(dpkg-query -W -f='${Package} ${Version} ${Status}' fleet-agent)" >&2
else
    # What the package does: users, groups, binary, units, tmpfiles.
    getent group fleet >/dev/null || groupadd --system fleet
    getent passwd fleet-gate >/dev/null ||
        useradd --system --user-group --no-create-home --home-dir /nonexistent \
            --shell /usr/sbin/nologin fleet-gate
    install -d -m 0755 /usr/lib/fleet
    install -m 0755 "$stage/fleet-agent" /usr/lib/fleet/fleet-agent
    install -m 0644 "$stage/systemd/fleet-exec.service" /etc/systemd/system/fleet-exec.service
    install -m 0644 "$stage/systemd/fleet-gate.service" /etc/systemd/system/fleet-gate.service
    install -m 0644 "$stage/systemd/tmpfiles.d/fleet.conf" /usr/lib/tmpfiles.d/fleet.conf
fi

# The admin's membership in `fleet` is `fleet-agent install --admin-user`'s
# job (design §10.1), deliberately not done here.

# The test Macs' SSH keys (plain ~/.ssh; moving keys to /etc/fleet is a
# separate step, design §10.1 step 5).
install -m 0600 -o "$admin" -g "$admin" "$stage/authorized_keys" "/home/$admin/.ssh/authorized_keys"

# What the app does over SSH: fleet-agent install.
/usr/lib/fleet/fleet-agent install \
    --genesis "$stage/genesis.hex" \
    --policy "$stage/policy.toml" \
    --server-id "$server_id" \
    --admin-user "$admin"

systemd-tmpfiles --create /usr/lib/tmpfiles.d/fleet.conf
systemctl daemon-reload
systemctl enable --now fleet-exec.service fleet-gate.service >/dev/null 2>&1

for _ in $(seq 1 100); do
    if [ -S /run/fleet/agent.sock ]; then
        exit 0
    fi
    sleep 0.1
done
echo "agent.sock did not appear" >&2
systemctl --no-pager status fleet-exec.service fleet-gate.service >&2 || true
exit 1
