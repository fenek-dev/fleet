#!/usr/bin/env bash
# Pool of local Linux servers (systemd containers from the fleet-it image)
# for end-to-end tests of the Mac app. No agent is installed: the app
# installs it (see tests/vm/agent-artifact.sh).
#
#   tests/vm/pool.sh up <n> [debian12|ubuntu24] --key <pubkey-file>... [--json]
#   tests/vm/pool.sh up <n> [debian12|ubuntu24] --password-auth [--json]
#   tests/vm/pool.sh list [--json]
#   tests/vm/pool.sh down [name...]        (no names: the whole pool)
#
# `up` prints one `name host port distro` line per server (or a JSON array
# with --json; nothing else goes to stdout). Each server has user `ops`
# (passwordless sudo, key-only SSH) whose ~/.ssh/authorized_keys gets the
# given public keys. Containers are labelled fleet-pool=1.
# `--password-auth` (one-time password setup, design §10.1): no authorized
# key, `PasswordAuthentication yes`, and sudo that asks for the password
# (`fleet-it-password`, the image's fixture); JSON gets "password".
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
export PATH="/opt/homebrew/bin:/usr/local/bin:$HOME/.docker/bin:$PATH"

usage() {
    sed -n '2,14p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//' >&2
    exit 2
}

cmd="${1:-}"
[ -n "$cmd" ] || usage
shift

json=0
password_auth=0
keys=()
distro="debian12"
count=""
names=()

case "$cmd" in
    up)
        while [ $# -gt 0 ]; do
            case "$1" in
                --json) json=1 ;;
                --password-auth) password_auth=1 ;;
                --key)
                    [ $# -ge 2 ] || usage
                    keys+=("$2")
                    shift
                    ;;
                debian12 | ubuntu24) distro="$1" ;;
                [0-9]*) count="$1" ;;
                *) usage ;;
            esac
            shift
        done
        case "$count" in '' | *[!0-9]*) usage ;; esac
        ;;
    list)
        while [ $# -gt 0 ]; do
            case "$1" in
                --json) json=1 ;;
                *) usage ;;
            esac
            shift
        done
        ;;
    down)
        names=("$@")
        ;;
    *) usage ;;
esac

info() { docker inspect -f '{{index .Config.Labels "fleet-pool-distro"}}' "$1"; }

port_of() {
    docker port "$1" 22/tcp | sed -n 's/.*:\([0-9][0-9]*\)$/\1/p' | head -n1
}

emit() { # emit <name>...   (prints lines or JSON for the given containers)
    local first=1 n port d pw
    [ "$json" = 1 ] && printf '['
    for n in "$@"; do
        port="$(port_of "$n")"
        d="$(info "$n")"
        pw=""
        if [ "$(docker inspect -f '{{index .Config.Labels "fleet-pool-password"}}' "$n")" = "1" ]; then
            pw="fleet-it-password"
        fi
        if [ "$json" = 1 ]; then
            [ "$first" = 1 ] || printf ','
            printf '{"name":"%s","host":"127.0.0.1","port":%s,"distro":"%s","user":"ops"' "$n" "$port" "$d"
            [ -z "$pw" ] || printf ',"password":"%s"' "$pw"
            printf '}'
        else
            echo "$n 127.0.0.1 $port $d"
        fi
        first=0
    done
    if [ "$json" = 1 ]; then printf ']\n'; fi
}

pool_names() { docker ps -a --filter label=fleet-pool=1 --format '{{.Names}}' | sort; }

case "$cmd" in
    up)
        [ -n "$count" ] && [ "$count" -ge 1 ] || usage
        for k in ${keys[@]+"${keys[@]}"}; do
            [ -r "$k" ] || { echo "cannot read key file: $k" >&2; exit 2; }
        done
        image="fleet-it:$distro"
        if ! docker image inspect "$image" >/dev/null 2>&1; then
            echo "building $image ..." >&2
            docker build -q -t "$image" \
                -f "$root/tests/vm/docker/Dockerfile.$distro" "$root/tests/vm/docker" >/dev/null
        fi
        stamp="$(($(date +%s) % 100000))"
        started=()
        i=1
        while [ "$i" -le "$count" ]; do
            name="fleet-pool-$stamp-$i"
            # Same flags as fleet-it's Container::start.
            docker run -d --privileged --cgroupns=private \
                --tmpfs /run --tmpfs /run/lock --tmpfs /tmp \
                --label fleet-pool=1 --label "fleet-pool-distro=$distro" \
                --label "fleet-pool-password=$password_auth" \
                -p 127.0.0.1::22 --name "$name" "$image" >/dev/null
            started+=("$name")
            i=$((i + 1))
        done
        for name in "${started[@]}"; do
            # Right after `docker run`, systemd may not answer yet (ubuntu24
            # returns nothing): retry until it prints a state, then wait.
            state=""
            for _ in $(seq 1 60); do
                state="$(docker exec "$name" systemctl is-system-running --wait 2>/dev/null || true)"
                state="$(echo "$state" | tail -n1)"
                case "$state" in
                    running | degraded) break ;;
                esac
                sleep 1
            done
            case "$state" in
                running | degraded) ;;
                *)
                    echo "$name: systemd did not boot ($state)" >&2
                    docker rm -f "${started[@]}" >/dev/null 2>&1 || true
                    exit 1
                    ;;
            esac
            if [ "$password_auth" = 1 ]; then
                # Same setup as fleet-it's Container::password_login.
                docker exec "$name" bash -c \
                    "printf 'PasswordAuthentication yes\nKbdInteractiveAuthentication no\nUsePAM yes\n' >/etc/ssh/sshd_config.d/00-fleet-it-password.conf && sshd -t && (systemctl reload ssh 2>/dev/null || true)"
            else
                docker exec "$name" bash -c \
                    'echo "ops ALL=(ALL) NOPASSWD:ALL" >/etc/sudoers.d/fleet-pool && chmod 0440 /etc/sudoers.d/fleet-pool'
            fi
            if [ "${#keys[@]}" -gt 0 ] && [ "$password_auth" = 0 ]; then
                cat "${keys[@]}" | docker exec -i "$name" bash -c \
                    'cat >>/home/ops/.ssh/authorized_keys && chown ops:ops /home/ops/.ssh/authorized_keys && chmod 0600 /home/ops/.ssh/authorized_keys'
            fi
        done
        emit "${started[@]}"
        ;;
    list)
        all=()
        while IFS= read -r n; do [ -n "$n" ] && all+=("$n"); done < <(pool_names)
        if [ "${#all[@]}" -eq 0 ]; then
            [ "$json" = 1 ] && echo '[]'
            exit 0
        fi
        emit "${all[@]}"
        ;;
    down)
        if [ "${#names[@]}" -eq 0 ]; then
            while IFS= read -r n; do [ -n "$n" ] && names+=("$n"); done < <(pool_names)
        fi
        ids=()
        refused=0
        for n in ${names[@]+"${names[@]}"}; do
            label="$(docker inspect --type container -f '{{index .Config.Labels "fleet-pool"}}' "$n" 2>/dev/null || true)"
            if [ "$label" != "1" ]; then
                echo "refusing $n: not a fleet-pool container (label fleet-pool=1 missing)" >&2
                refused=$((refused + 1))
                continue
            fi
            cid="$(docker inspect --type container -f '{{.Id}}' "$n" 2>/dev/null || true)"
            if [ -z "$cid" ]; then
                echo "refusing $n: cannot resolve container id" >&2
                refused=$((refused + 1))
                continue
            fi
            ids+=("$cid")
        done
        if [ "${#ids[@]}" -gt 0 ]; then
            docker rm -f "${ids[@]}" >/dev/null
        fi
        echo "removed ${#ids[@]} container(s), refused $refused" >&2
        [ "$refused" -eq 0 ] || exit 1
        ;;
    *) usage ;;
esac
