#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Test the distribution's installed package, never a downloaded replacement.
set -Eeuo pipefail
trap 'printf "Tomb package capability check failed at line %s: %s\n" "$LINENO" "$BASH_COMMAND" >&2; dpkg-query -L tomb | grep -E "cloak|cipher" >&2 || true' ERR
version=$(dpkg-query -W -f='${Version}' tomb)
dpkg --compare-versions "$version" ge 2.13
for helper in cloakify decloakify; do
    test -x "/usr/libexec/tomb/$helper"
    dpkg-query -S "/usr/libexec/tomb/$helper" >/dev/null
done
cipher=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)/data/cloak-ciphers/words
test -r "$cipher"
[[ $(wc -l <"$cipher") -eq 66 ]]
[[ $(sort -u "$cipher" | wc -l) -eq 66 ]]
command -v qrencode >/dev/null
work=$(mktemp -d)
trap 'rm -rf -- "$work"' EXIT
printf 'Synthetic encrypted-key test bytes\n\000\001\377\n' >"$work/key"
/usr/libexec/tomb/cloakify -i "$work/key" -c "$cipher" -o "$work/cloaked.txt"
/usr/libexec/tomb/decloakify -i "$work/cloaked.txt" -c "$cipher" -o "$work/recovered.key"
cmp "$work/key" "$work/recovered.key"
printf 'OctoVault QR capability test' | qrencode -o "$work/recovery.png"
test -s "$work/recovery.png"
printf 'Distribution Tomb %s: native text helpers, binary round-trip, cipher, and QR export passed\n' "$version"
