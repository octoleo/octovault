#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Build against the target Ubuntu release's libraries, then name its downloads.
set -Eeuo pipefail
root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)
cd "$root"
# shellcheck source=/dev/null
. /etc/os-release
architecture=$(dpkg --print-architecture)
[[ ${ID:-} == ubuntu && ( ${VERSION_ID:-} == 24.04 || ${VERSION_ID:-} == 26.04 ) && $architecture == amd64 ]] || {
    printf 'Build the release package on Ubuntu 24.04 or 26.04 amd64.\n' >&2
    exit 2
}
ubuntu_version=$VERSION_ID
bash scripts/version.sh --check
version=$(cat VERSION)
dpkg-buildpackage -us -uc -b
package="../octovault_${version}_${architecture}.deb"
bash scripts/test-packaging.sh "$package"
mkdir -p dist
filename="octovault_${version}_ubuntu${ubuntu_version}_${architecture}.deb"
cp -- "$package" "dist/$filename"
(
    cd dist
    sha256sum "$filename" >"SHA256SUMS-ubuntu${ubuntu_version}"
)
printf 'Built dist/%s and its Ubuntu %s checksum manifest.\n' "$filename" "$ubuntu_version"
