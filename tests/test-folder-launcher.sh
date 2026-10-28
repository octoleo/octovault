#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
set -euo pipefail
cd "$(dirname "$0")/.."
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
read -r -a cflags <<<"$(pkg-config --cflags gio-2.0 gio-unix-2.0)"
read -r -a libs <<<"$(pkg-config --libs gio-2.0 gio-unix-2.0)"
cc -std=c11 -Wall -Wextra -Werror "${cflags[@]}" src/ui/test-folder-launcher.c -o "$work/test-folder-launcher" "${libs[@]}"
TMPDIR="$work" DBUS_SESSION_BUS_ADDRESS="unix:path=$work/no-session-bus" G_DEBUG=fatal-criticals "$work/test-folder-launcher"
