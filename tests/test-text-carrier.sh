#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
set -Eeuo pipefail
cd "$(dirname -- "$0")/.."
work=$(mktemp -d)
trap 'rm -rf -- "$work"' EXIT
read -r -a cflags <<<"$(pkg-config --cflags glib-2.0)"
read -r -a libs <<<"$(pkg-config --libs glib-2.0)"
cc -std=c11 -Wall -Wextra -Werror -O2 "${cflags[@]}" src/service/text-carrier.c -o "$work/text-carrier" "${libs[@]}"
carrier="$work/text-carrier"
cipher=data/cloak-ciphers/words
reject() {
    printf 'preserve existing output\n' >"$work/rejected-output"
    if "$carrier" "$@" "$work/rejected-output" >"$work/stdout" 2>"$work/stderr"; then
        printf 'Invalid text-carrier input was accepted: %s\n' "$*" >&2
        exit 1
    fi
    [[ $(cat "$work/rejected-output") == 'preserve existing output' ]]
    [[ ! -s $work/stdout && -s $work/stderr ]]
}

# Known Tomb fixture: byte M -> standard base64 TQ== -> alphabet indices
# 45, 42, 64, 64 in Tomb's lowercase-first word map.
printf M >"$work/known"
printf 'tulip\nquail\nmoss\nmoss\n' >"$work/known.expected"
"$carrier" encode "$work/known" "$cipher" "$work/known.txt"
cmp "$work/known.expected" "$work/known.txt"
"$carrier" decode "$work/known.txt" "$cipher" "$work/known.key"
cmp "$work/known" "$work/known.key"
[[ $(stat -c %a "$work/known.key") == 600 ]]

# Include every byte, NULs and line endings without involving shell strings.
for ((i=0; i<256; i++)); do printf '%b' "\\$(printf '%03o' "$i")"; done >"$work/binary"
printf '\000\n\r\377encrypted key\n' >>"$work/binary"
"$carrier" encode "$work/binary" "$cipher" "$work/binary.txt"
"$carrier" decode "$work/binary.txt" "$cipher" "$work/binary.key"
cmp "$work/binary" "$work/binary.key"
touch "$work/empty"
"$carrier" encode "$work/empty" "$cipher" "$work/empty.txt"
"$carrier" decode "$work/empty.txt" "$cipher" "$work/empty.key"
[[ ! -s $work/empty.txt && ! -s $work/empty.key ]]

# Custom UTF-8 maps and CRLF carriers preserve exact token contents.
sed 's/^/🌿 /' "$cipher" >"$work/unicode-cipher"
"$carrier" encode "$work/binary" "$work/unicode-cipher" "$work/unicode.txt"
sed 's/$/\r/' "$work/unicode.txt" >"$work/crlf.txt"
"$carrier" decode "$work/crlf.txt" "$work/unicode-cipher" "$work/unicode.key"
cmp "$work/binary" "$work/unicode.key"
sed 's/$/\r/' "$work/unicode-cipher" >"$work/crlf-cipher"
"$carrier" decode "$work/crlf.txt" "$work/crlf-cipher" "$work/crlf.key"
cmp "$work/binary" "$work/crlf.key"

head -n 65 "$cipher" >"$work/short-cipher"
reject encode "$work/binary" "$work/short-cipher"
sed '2s/.*/amber/' "$cipher" >"$work/duplicate-cipher"
reject encode "$work/binary" "$work/duplicate-cipher"
sed '2s/.*//' "$cipher" >"$work/blank-cipher"
reject encode "$work/binary" "$work/blank-cipher"
printf '\377\n' >"$work/invalid-utf8"
reject decode "$work/invalid-utf8" "$cipher"
printf 'unknown-word\n' >"$work/unknown-word"
reject decode "$work/unknown-word" "$cipher"
printf 'oasis\n' >"$work/unused-symbol"
reject decode "$work/unused-symbol" "$cipher"
head -n 3 "$work/known.txt" >"$work/truncated"
reject decode "$work/truncated" "$cipher"
printf 'moss\ntulip\nquail\nmoss\n' >"$work/bad-padding"
reject decode "$work/bad-padding" "$cipher"
printf 'tulip\nreed\nmoss\nmoss\n' >"$work/noncanonical"
reject decode "$work/noncanonical" "$cipher"
ln -s "$work/binary" "$work/input-link"
reject encode "$work/input-link" "$cipher"
truncate -s 1048577 "$work/oversize"
reject encode "$work/oversize" "$cipher"

if [[ -x /usr/libexec/tomb/cloakify && -x /usr/libexec/tomb/decloakify ]]; then
    /usr/libexec/tomb/cloakify -i "$work/binary" -c "$cipher" -o "$work/tomb.txt"
    cmp "$work/binary.txt" "$work/tomb.txt"
    "$carrier" decode "$work/tomb.txt" "$cipher" "$work/from-tomb.key"
    cmp "$work/binary" "$work/from-tomb.key"
    /usr/libexec/tomb/decloakify -i "$work/binary.txt" -c "$cipher" -o "$work/from-native.key"
    cmp "$work/binary" "$work/from-native.key"
    printf 'ok - real distribution Tomb text-carrier interoperability\n'
fi
printf 'ok - Tomb-compatible binary text carriers, Unicode, strict validation and atomic output\n'
