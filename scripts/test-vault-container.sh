#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# This script installs dependencies only in an explicitly disposable CI image.
set -Eeuo pipefail
[[ ${OCTOVAULT_DISPOSABLE_TEST:-} == 1 && ${CI:-} == true && $EUID == 0 ]] || {
    printf 'Requires root in a disposable CI container.\n' >&2
    exit 2
}
[[ $(awk 'END {print NR}' /proc/swaps) -eq 1 ]] || {
    printf 'Disable swap on the disposable host before running the vault container.\n' >&2
    exit 2
}
apt-get update
DEBIAN_FRONTEND=noninteractive apt-get install --yes --no-install-recommends \
    ca-certificates build-essential pkg-config libglib2.0-dev tomb cryptsetup-bin jq rsync pinentry-curses \
    gnupg scdaemon steghide qrencode lsof systemd util-linux procps
mkdir -p build
cc -std=c11 -O2 -Wall -Wextra src/service/pinentry.c -o build/pinentry-octovault
cc -std=c11 -O2 -Wall -Wextra src/service/steghide.c -o build/steghide -lutil
read -r -a glib_cflags <<<"$(pkg-config --cflags glib-2.0)"
read -r -a glib_libs <<<"$(pkg-config --libs glib-2.0)"
cc -std=c11 -O2 -Wall -Wextra "${glib_cflags[@]}" src/service/text-carrier.c -o build/text-carrier "${glib_libs[@]}"
install -d /usr/libexec/octovault /usr/share/octovault/cloak-ciphers /dev/mapper
install -m 0755 build/pinentry-octovault /usr/bin/pinentry-octovault
install -m 0755 build/steghide /usr/libexec/octovault/steghide
install -m 0755 build/text-carrier /usr/libexec/octovault/text-carrier
install -m 0644 data/cloak-ciphers/words /usr/share/octovault/cloak-ciphers/words
test -c /dev/mapper/control || mknod /dev/mapper/control c 10 236
bash scripts/test-tomb-capabilities.sh
bash tests/test-vault.sh --integration
