#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# GUI request-contract tests run without a display; CI separately renders every
# native form through octovault-gtk --smoke-test under Xvfb.
set -euo pipefail
cd "$(dirname "$0")/.."
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
read -r -a cflags <<<"$(pkg-config --cflags gtk4 libadwaita-1 json-glib-1.0 gio-2.0)"
read -r -a libs <<<"$(pkg-config --libs gtk4 libadwaita-1 json-glib-1.0 gio-2.0)"
cc -std=c11 -Wall -Wextra -Werror -Isrc/ui "${cflags[@]}" src/ui/test-contract.c src/service/client.c -o "$work/test-ui" "${libs[@]}"
G_DEBUG=fatal-criticals "$work/test-ui"
