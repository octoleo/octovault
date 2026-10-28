#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
set -euo pipefail
cd "$(dirname "$0")/.."
work=$(mktemp -d)
trap 'rm -rf -- "$work"' EXIT
read -r -a flags <<<"$(pkg-config --cflags gio-2.0 json-glib-1.0 libfido2 openssl)"
read -r -a libs <<<"$(pkg-config --libs gio-2.0 json-glib-1.0 libfido2 openssl)"
cc -std=c11 -Wall -Wextra -Werror "${flags[@]}" tests/service/test_fido2.c -o "$work/test-fido2" "${libs[@]}"
G_DEBUG=fatal-criticals "$work/test-fido2"
cc -std=c11 -Wall -Wextra -Werror "${flags[@]}" src/service/fido2.c -o "$work/fido2" "${libs[@]}"
if printf '%s' '{}' | "$work/fido2" enroll > "$work/result"; then exit 1; fi
jq -e '.error == "pin_required" and (has("password")|not)' "$work/result" >/dev/null
if printf '%s' '{"pin":"123456","enrollment":{}}' | "$work/fido2" unlock > "$work/result"; then exit 1; fi
jq -e '.error == "invalid_enrollment" and (has("password")|not)' "$work/result" >/dev/null
printf 'FIDO2 protocol-object, cryptography and input-boundary tests passed.\n'
