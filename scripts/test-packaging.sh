#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
set -Eeuo pipefail
root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)
cd "$root"
bash scripts/version.sh --check
desktop-file-validate data/io.vdm.OctoVault.desktop data/io.vdm.OctoVault.Session.desktop
xmllint --noout data/io.vdm.OctoVault.metainfo.xml data/io.vdm.octovault.policy data/io.vdm.OctoVault1.conf
appstreamcli validate --no-net data/io.vdm.OctoVault.metainfo.xml
[[ $(xmllint --xpath 'string(/component/id)' data/io.vdm.OctoVault.metainfo.xml) == io.vdm.OctoVault ]]
for action in manage recovery; do
    [[ $(xmllint --xpath "count(/policyconfig/action[@id='io.vdm.octovault.$action'])" data/io.vdm.octovault.policy) == 1 ]]
done
if [[ $# == 1 ]]; then
    package=$(realpath -- "$1")
    [[ $(dpkg-deb -f "$package" Package) == octovault ]]
    [[ $(dpkg-deb -f "$package" Version) == "$(cat VERSION)" ]]
    contents=$(dpkg-deb --contents "$package")
    for path in usr/bin/octovault usr/bin/octovault-gtk usr/bin/octovault-session usr/bin/pinentry-octovault usr/libexec/octovault/backend usr/libexec/octovault/daemon usr/libexec/octovault/fido2 usr/libexec/octovault/text-carrier usr/libexec/octovault/run-plan usr/libexec/octovault/event-system usr/libexec/octovault/priority-backend usr/share/octovault/cloak-ciphers/words usr/share/polkit-1/actions/io.vdm.octovault.policy usr/share/dbus-1/system.d/io.vdm.OctoVault1.conf; do
        [[ $contents == *"./$path"* ]] || { printf 'Package missing %s\n' "$path" >&2; exit 1; }
    done
    dependencies=$(dpkg-deb -f "$package" Depends)
    [[ $dependencies == *tomb* && $dependencies == *restic* && $dependencies == *systemd* ]]
fi
printf 'Package metadata checks passed\n'
