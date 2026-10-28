#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Boot a complete disposable Ubuntu system: real system bus, logind, polkit and
# PAM. A shell-only container cannot exercise desktop-session authorization.
set -Eeuo pipefail
cd "$(dirname "$0")/.."
[[ ${OCTOVAULT_DISPOSABLE_TEST:-} == 1 ]] || {
    printf 'Set OCTOVAULT_DISPOSABLE_TEST=1 only on a disposable integration runner.\n' >&2
    exit 2
}
command -v docker >/dev/null || { printf 'Docker is required for this integration runner.\n' >&2; exit 2; }
context=$(mktemp -d)
container=octovault-authorization-${GITHUB_RUN_ID:-$$}
image=octovault-authorization-ci:${GITHUB_RUN_ID:-local}
cleanup() {
    local status=$?
    if ((status != 0)); then
        docker logs "$container" >&2 || true
        docker exec "$container" journalctl --no-pager -n 120 \
            -u polkit.service -u systemd-logind.service -u octovault.service >&2 || true
    fi
    docker rm -f "$container" >/dev/null 2>&1 || true
    rm -rf -- "$context"
}
trap cleanup EXIT
cat >"$context/Dockerfile" <<'DOCKERFILE'
FROM ubuntu:26.04
ENV container=docker
RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install --yes --no-install-recommends \
    systemd systemd-sysv dbus dbus-user-session polkitd libpam-systemd login passwd util-linux \
    build-essential pkg-config libglib2.0-dev libjson-glib-dev libfido2-dev libssl-dev libpolkit-agent-1-dev \
    libgtk-4-dev libadwaita-1-dev jq restic tomb cryptsetup-bin gnupg scdaemon \
    pinentry-gnome3 rsync lsof ca-certificates \
    && rm -rf /var/lib/apt/lists/*
STOPSIGNAL SIGRTMIN+3
# --privileged exposes host virtual-console device nodes in Docker's private
# /dev. Remove this one node before logind starts so its real container seat
# has no VTs; the test must never switch the hosted runner's virtual consoles.
CMD ["/bin/sh", "-c", "rm -f /dev/tty0; exec /sbin/init"]
DOCKERFILE
docker build --tag "$image" "$context"
# This writable cgroup mount belongs to the disposable hosted runner. It lets
# systemd create genuine user login sessions instead of replacing logind.
docker run --detach --name "$container" --privileged --cgroupns=host \
    --tmpfs /run --tmpfs /run/lock \
    --volume /sys/fs/cgroup:/sys/fs/cgroup:rw \
    --mount "type=bind,src=$PWD,dst=/source,readonly" "$image" >/dev/null
ready=false
for _ in {1..60}; do
    if docker exec "$container" systemctl start dbus.service systemd-logind.service polkit.service >/dev/null 2>&1 &&
        docker exec "$container" systemctl is-active --quiet dbus.service systemd-logind.service polkit.service; then
        ready=true; break
    fi
    sleep 1
done
[[ $ready == true ]] || { printf 'The real authorization services did not start.\n' >&2; exit 1; }
docker exec --env CI=true --env OCTOVAULT_DISPOSABLE_TEST=1 "$container" bash -c \
    'mkdir /workspace && cp -a /source/. /workspace/ && cd /workspace && bash tests/test-authorization-integration.sh --disposable-system'
