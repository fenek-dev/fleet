#!/usr/bin/env bash
# Pool of local Linux servers (systemd containers from the fleet-it image)
# for end-to-end tests of the Mac app. No agent is installed: the app
# installs it (see tests/vm/agent-artifact.sh).
#
#   tests/vm/pool.sh up <n> [debian12|ubuntu24] --key <pubkey-file>... [--json]
#   tests/vm/pool.sh list [--json]
#   tests/vm/pool.sh down [name...]        (no names: the whole pool)
#
# `up` prints one `name host port distro` line per server (or a JSON array
# with --json; nothing else goes to stdout). Each server has user `ops`
# (passwordless sudo, key-only SSH) whose ~/.ssh/authorized_keys gets the
# given public keys. Containers are labelled fleet-pool=1.
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
keys=()
distro="debian12"
count=""
names=()

while [ $# -gt 0 ]; do
    case "$1" in
        --json) json=1 ;;
        --key)
            [ $# -ge 2 ] || usage
            keys+=("$2")
            shift
            ;;
        debian12 | ubuntu24) distro="$1" ;;
        [0-9]*) count="$1" ;;
        *) names+=("$1") ;;
    esac
    shift
done

info() { docker inspect -f '{{index .Config.Labels "fleet-pool-distro"}}' "$1"; }

port_of() {
    docker port "$1" 22/tcp | sed -n 's/.*:\([0-9][0-9]*\)$/\1/p' | head -n1
}

emit() { # emit <name>...   (prints lines or JSON for the given containers)
    local first=1 n port d
    [ "$json" = 1 ] && printf '['
    for n in "$@"; do
        port="$(port_of "$n")"
        d="$(info "$n")"
        if [ "$json" = 1 ]; then
            [ "$first" = 1 ] || printf ','
            printf '{"name":"%s","host":"127.0.0.1","port":%s,"distro":"%s","user":"ops"}' "$n" "$port" "$d"
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
                -p 127.0.0.1::22 --name "$name" "$image" >/dev/null
            started+=("$name")
            i=$((i + 1))
        done
        for name in "${started[@]}"; do
            state="$(docker exec "$name" systemctl is-system-running --wait 2>/dev/null || true)"
            state="$(echo "$state" | tail -n1)"
            case "$state" in
                running | degraded) ;;
                *)
                    echo "$name: systemd did not boot ($state)" >&2
                    docker rm -f "${started[@]}" >/dev/null 2>&1 || true
                    exit 1
                    ;;
            esac
            docker exec "$name" bash -c \
                'echo "ops ALL=(ALL) NOPASSWD:ALL" >/etc/sudoers.d/fleet-pool && chmod 0440 /etc/sudoers.d/fleet-pool'
            if [ "${#keys[@]}" -gt 0 ]; then
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
        if [ "${#names[@]}" -gt 0 ]; then
            docker rm -f "${names[@]}" >/dev/null
        fi
        echo "removed ${#names[@]} container(s)" >&2
        ;;
    *) usage ;;
esac
