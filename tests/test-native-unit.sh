#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
set -euo pipefail
cd "$(dirname "$0")/.."
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
read -r -a cflags <<<"$(pkg-config --cflags gio-2.0 gio-unix-2.0 json-glib-1.0)"
read -r -a libs <<<"$(pkg-config --libs gio-2.0 gio-unix-2.0 json-glib-1.0)"
for target in cli daemon access_store access_recovery; do
    cc -std=c11 -Wall -Wextra -Werror -Isrc/service "${cflags[@]}" \
        "tests/service/test_$target.c" src/service/client.c -o "$work/test-$target" "${libs[@]}"
    "$work/test-$target"
done
