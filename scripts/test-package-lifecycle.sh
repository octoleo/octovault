#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Mutates only an explicitly designated disposable CI container.
set -Eeuo pipefail
[[ ${1:-} == --disposable-system && $# == 2 && ${OCTOVAULT_DISPOSABLE_TEST:-} == 1 && $EUID == 0 ]] || {
    printf 'Requires --disposable-system PACKAGE, root, and OCTOVAULT_DISPOSABLE_TEST=1 in disposable CI.\n' >&2
    exit 2
}
package=$(realpath -- "$2")
temp=$(mktemp -d)
trap 'rm -rf -- "$temp"' EXIT
dpkg-deb --raw-extract "$package" "$temp/prior"
# Exercise Debian upgrade semantics without pretending an earlier release exists.
sed -i 's/^Version: .*/Version: 0.0.0~lifecycle/' "$temp/prior/DEBIAN/control"
dpkg-deb --root-owner-group --build "$temp/prior" "$temp/prior.deb" >/dev/null
apt-get install --yes "$temp/prior.deb"
install -d -m 0700 /var/lib/octovault/users/12345/plans
printf '{"id":"lifecycle","schema_version":1}\n' >/var/lib/octovault/users/12345/plans/lifecycle.json
chmod 0600 /var/lib/octovault/users/12345/plans/lifecycle.json
cp /var/lib/octovault/users/12345/plans/lifecycle.json "$temp/expected"
apt-get install --yes "$package"
apt-get install --yes --reinstall "$package"
/usr/bin/octovault --version
test -x /usr/bin/octovault-gtk
test -x /usr/libexec/octovault/daemon
test -f /usr/share/applications/io.vdm.OctoVault.desktop
cmp "$temp/expected" /var/lib/octovault/users/12345/plans/lifecycle.json
test "$(stat -c %a /var/lib/octovault/users/12345/plans/lifecycle.json)" = 600
apt-get remove --yes octovault
cmp "$temp/expected" /var/lib/octovault/users/12345/plans/lifecycle.json
apt-get purge --yes octovault
cmp "$temp/expected" /var/lib/octovault/users/12345/plans/lifecycle.json
printf 'Install, upgrade, reinstall, remove, and purge retain user data\n'
