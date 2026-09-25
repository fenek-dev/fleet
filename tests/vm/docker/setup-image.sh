#!/usr/bin/env bash
# Image build step shared by the Debian and Ubuntu test images. Runs once,
# as root, at `docker build` time.
set -euo pipefail

# Units that make no sense (or touch the host) in a container.
systemctl mask \
    systemd-udevd.service systemd-udevd-kernel.socket systemd-udevd-control.socket \
    systemd-firstboot.service systemd-remount-fs.service \
    getty.target console-getty.service serial-getty@.service \
    sys-kernel-debug.mount sys-kernel-tracing.mount \
    apt-daily.timer apt-daily-upgrade.timer >/dev/null 2>&1 || true

# Admin user: sudo with a password (the password is a test fixture, never
# used for SSH). Its authorized_keys is written per test run, since the
# test Macs' keys are generated fresh each run.
useradd --create-home --shell /bin/bash --groups sudo ops
echo 'ops:fleet-it-password' | chpasswd
install -d -m 0700 -o ops -g ops /home/ops/.ssh

# Key-only SSH. Ubuntu 24.04 uses socket activation (ssh.socket); either
# way sshd listens on 22.
cat >/etc/ssh/sshd_config.d/fleet-it.conf <<'EOF'
PasswordAuthentication no
KbdInteractiveAuthentication no
PermitRootLogin no
EOF
systemctl enable ssh.service >/dev/null 2>&1 || true

# Persistent journal is irrelevant here; keep journald in memory.
mkdir -p /etc/systemd/journald.conf.d
cat >/etc/systemd/journald.conf.d/fleet-it.conf <<'EOF'
[Journal]
Storage=volatile
EOF
