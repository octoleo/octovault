#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Test the distribution's installed Tomb and OctoVault's carrier adapter.
set -Eeuo pipefail
trap 'printf "Tomb package capability check failed at line %s: %s\n" "$LINENO" "$BASH_COMMAND" >&2' ERR
version=$(dpkg-query -W -f='${Version}' tomb)
dpkg --compare-versions "$version" ge 2.9
# The sourced interface is used for protected metadata and native lifecycle
# operations. Check the real packaged functions; privileged mount integration
# verifies their behavior separately on each supported Ubuntu release.
# shellcheck disable=SC2016
zsh -f -c '
    source /usr/bin/tomb source || exit
    for capability in forge_key lock_tomb_with_key mount_tomb umount_tomb change_tomb_key resize_tomb; do
        (( $+functions[$capability] )) || exit 1
    done
'
project=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)
helper="$project/build/text-carrier"
test -x "$helper"
cipher="$project/data/cloak-ciphers/words"
test -r "$cipher"
[[ $(wc -l <"$cipher") -eq 66 ]]
[[ $(sort -u "$cipher" | wc -l) -eq 66 ]]
command -v qrencode >/dev/null
work=$(mktemp -d)
trap 'rm -rf -- "$work"' EXIT
printf 'Synthetic encrypted-key test bytes\n\000\001\377\n' >"$work/key"
"$helper" encode "$work/key" "$cipher" "$work/cloaked.txt"
"$helper" decode "$work/cloaked.txt" "$cipher" "$work/recovered.key"
cmp "$work/key" "$work/recovered.key"
if [[ -x /usr/libexec/tomb/cloakify && -x /usr/libexec/tomb/decloakify ]]; then
    # Newer Tomb provides its own helpers. Cross-read both formats so Ubuntu
    # 24.04 and 26.04 retain interoperable existing text-key carriers.
    /usr/libexec/tomb/decloakify -i "$work/cloaked.txt" -c "$cipher" -o "$work/tomb-recovered.key"
    cmp "$work/key" "$work/tomb-recovered.key"
    /usr/libexec/tomb/cloakify -i "$work/key" -c "$cipher" -o "$work/tomb-cloaked.txt"
    "$helper" decode "$work/tomb-cloaked.txt" "$cipher" "$work/native-recovered.key"
    cmp "$work/key" "$work/native-recovered.key"
fi
printf 'OctoVault QR capability test' | qrencode -o "$work/recovery.png"
test -s "$work/recovery.png"
printf 'Distribution Tomb %s: sourced lifecycle, text-carrier round-trip, cipher, and QR export passed\n' "$version"
