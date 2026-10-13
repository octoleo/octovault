#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
set -Eeuo pipefail
root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)
version=$(cat "$root/VERSION")
[[ $version =~ ^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$ ]] || { printf 'Invalid VERSION\n' >&2; exit 1; }
case ${1:-} in
    '') printf '%s\n' "$version" ;;
    --check)
        [[ $(dpkg-parsechangelog -l "$root/debian/changelog" -S Version) == "$version" ]] || { printf 'VERSION and Debian changelog disagree\n' >&2; exit 1; }
        [[ $(xmllint --xpath 'string(/component/releases/release[1]/@version)' "$root/data/io.vdm.OctoVault.metainfo.xml") == "$version" ]] || { printf 'VERSION and AppStream release disagree\n' >&2; exit 1; }
        [[ -z ${2:-} || $2 == "v$version" ]] || { printf 'Release tag does not match VERSION\n' >&2; exit 1; }
        printf 'Version %s is consistent\n' "$version"
        ;;
    *) printf 'Usage: scripts/version.sh [--check [vX.Y.Z]]\n' >&2; exit 2 ;;
esac
