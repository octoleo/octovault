#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Compilation always runs with normal unit tests. Native interaction is an
# explicit CI gate, invoked as the unprivileged desktop user under D-Bus/Xvfb.
set -euo pipefail
cd "$(dirname "$0")/.."
if [[ $# -gt 1 || ${1:-} != '' && ${1:-} != --native ]]; then
    printf 'Usage: %s [--native]\n' "$0" >&2
    exit 2
fi
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
read -r -a cflags <<<"$(pkg-config --cflags gtk4 libadwaita-1 json-glib-1.0 gio-2.0)"
read -r -a libs <<<"$(pkg-config --libs gtk4 libadwaita-1 json-glib-1.0 gio-2.0)"
cc -std=c11 -Wall -Wextra -Werror -Isrc/ui "${cflags[@]}" src/ui/test-picker.c -o "$work/test-picker" "${libs[@]}"
if [[ ${1:-} != --native ]]; then
    printf 'Native picker regression compiled; CI runs tests/test-picker.sh --native under D-Bus/Xvfb.\n'
    exit 0
fi
if [[ -z ${DISPLAY:-} && -z ${WAYLAND_DISPLAY:-} ]]; then
    printf 'Native picker tests require a display (run under xvfb-run in CI).\n' >&2
    exit 1
fi
# Force an actual working desktop FileChooser portal for the regression gate.
# Merely installing its packages can silently leave GTK using a fallback when
# D-Bus activation did not inherit the Xvfb display.
if [[ ${GDK_DEBUG:-} == *portals* || ${OCTOVAULT_TEST_PORTAL:-0} == 1 ]]; then
    printf 'Verifying the desktop FileChooser portal is available...\n'
    gdbus call --session --dest org.freedesktop.portal.Desktop \
        --object-path /org/freedesktop/portal/desktop \
        --method org.freedesktop.DBus.Properties.Get \
        org.freedesktop.portal.FileChooser version
fi
mkdir -p "$work/config" "$work/cache" "$work/data"
G_DEBUG=fatal-criticals GTK_A11Y=none GSK_RENDERER=cairo GSETTINGS_BACKEND=memory \
    XDG_CONFIG_HOME="$work/config" XDG_CACHE_HOME="$work/cache" XDG_DATA_HOME="$work/data" \
    "$work/test-picker"
