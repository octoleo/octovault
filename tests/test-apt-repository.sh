#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
set +x +a
set -Eeuo pipefail
umask 077
unset APT_SIGNING_KEY APT_SIGNING_PASSPHRASE APT_SIGNING_KEY_FINGERPRINT APT_REPOSITORY_URL
cd "$(dirname -- "${BASH_SOURCE[0]}")/.."
for tool in apt-ftparchive dpkg-deb appstreamcli xmllint gpg gpgv gpgconf; do
    command -v "$tool" >/dev/null || { printf 'Missing APT test dependency: %s\n' "$tool" >&2; exit 1; }
done
apt_test_root=$(mktemp -d)
apt_test_cleanup() {
    local result=$?
    gpgconf --homedir "$apt_test_root/keyhome" --kill gpg-agent >/dev/null 2>&1 || :
    rm -rf -- "$apt_test_root"
    exit "$result"
}
trap apt_test_cleanup EXIT
version=$(bash scripts/version.sh)
name="octovault_${version}_ubuntu26.04_amd64.deb"
mkdir -p "$apt_test_root/package/DEBIAN" "$apt_test_root/input" "$apt_test_root/keyhome"
chmod 0755 "$apt_test_root/package/DEBIAN"
cat >"$apt_test_root/package/DEBIAN/control" <<CONTROL
Package: octovault
Version: $version
Architecture: amd64
Maintainer: OctoVault isolated CI fixture <fixture@example.invalid>
Description: Synthetic repository test package; never installed
CONTROL
dpkg-deb --root-owner-group --build "$apt_test_root/package" "$apt_test_root/input/$name" >/dev/null
(cd "$apt_test_root/input" && sha256sum "$name" >SHA256SUMS-ubuntu26.04)
bash scripts/apt-repository.sh --input "$apt_test_root/input" --output "$apt_test_root/unsigned" >"$apt_test_root/unsigned.log" 2>&1
test -f "$apt_test_root/unsigned/UNSIGNED-TEST-ONLY"
test ! -e "$apt_test_root/unsigned/dists/resolute/InRelease"
test ! -e "$apt_test_root/unsigned/octovault-resolute.sources"
test ! -e "$apt_test_root/unsigned/octovault-archive-keyring.gpg"
(cd "$apt_test_root/unsigned" && sha256sum --check SHA256SUMS >/dev/null)
cmp "$apt_test_root/input/$name" "$apt_test_root/unsigned/pool/resolute/main/o/octovault/$name"
grep -Fxq "Filename: pool/resolute/main/o/octovault/$name" "$apt_test_root/unsigned/dists/resolute/main/binary-amd64/Packages"
gzip -t "$apt_test_root/unsigned/dists/resolute/main/binary-amd64/Packages.gz"
gzip -t "$apt_test_root/unsigned/dists/resolute/main/dep11/Components-amd64.yml.gz"
appstreamcli convert "$apt_test_root/unsigned/dists/resolute/main/dep11/Components-amd64.yml" "$apt_test_root/roundtrip.xml" >/dev/null
[[ $(xmllint --xpath 'string(/components/component/pkgname)' "$apt_test_root/roundtrip.xml") == octovault ]]
appstreamcli validate --no-net "$apt_test_root/roundtrip.xml" >/dev/null

reject_build() {
    if bash scripts/apt-repository.sh --input "$apt_test_root/input" --output "$apt_test_root/rejected" >"$apt_test_root/reject.log" 2>&1; then
        printf 'FAIL: invalid APT repository configuration was accepted.\n' >&2; exit 1
    fi
    test ! -e "$apt_test_root/rejected"
}
# Package bytes, manifests, output paths, and distribution metadata are checked
# before any signing credentials can reach the repository.
printf 'corruption' >>"$apt_test_root/input/$name"
reject_build
cp "$apt_test_root/unsigned/pool/resolute/main/o/octovault/$name" "$apt_test_root/input/$name"
cp "$apt_test_root/input/$name" "$apt_test_root/input/unexpected.deb"
reject_build
rm "$apt_test_root/input/unexpected.deb"
cp "$apt_test_root/input/SHA256SUMS-ubuntu26.04" "$apt_test_root/checksum"
printf 'malformed manifest\n' >"$apt_test_root/input/SHA256SUMS-ubuntu26.04"
reject_build
cp "$apt_test_root/checksum" "$apt_test_root/input/SHA256SUMS-ubuntu26.04"
mv "$apt_test_root/input/$name" "$apt_test_root/held.deb"
ln -s "$apt_test_root/held.deb" "$apt_test_root/input/$name"
reject_build
rm "$apt_test_root/input/$name"
mv "$apt_test_root/held.deb" "$apt_test_root/input/$name"
if bash scripts/apt-repository.sh --input "$apt_test_root/input" --output "$apt_test_root/unsigned" >/dev/null 2>&1; then
    printf 'FAIL: existing APT output was overwritten.\n' >&2; exit 1
fi
export APT_REPOSITORY_URL=http://example.invalid/apt
reject_build
export APT_REPOSITORY_URL=https://example.invalid/../apt
reject_build
export APT_REPOSITORY_URL=https://example.invalid/apt
export APT_SIGNING_KEY_FINGERPRINT=0000000000000000000000000000000000000000
reject_build
unset APT_SIGNING_KEY_FINGERPRINT

# A protected disposable key exercises real signing. Nothing is read from or
# imported into the developer's ordinary GnuPG home.
synthetic_passphrase=OctoVault-APT-test-only-ef16a4bfb36941c2
if ! printf '%s\n' "$synthetic_passphrase" | gpg --no-options --batch --homedir "$apt_test_root/keyhome" \
    --pinentry-mode loopback --passphrase-fd 0 --quick-generate-key \
    'OctoVault isolated CI fixture <fixture@example.invalid>' ed25519 sign 1d >"$apt_test_root/keygen.log" 2>&1; then
    if [[ ${CI:-false} == true ]]; then
        printf 'FAIL: CI must support generation of the isolated APT test signing key.\n' >&2; exit 1
    fi
    printf 'APT: unsigned catalog, checksums and rejection tests passed; signing requires a local GnuPG agent (required in CI).\n'
    exit 0
fi
APT_SIGNING_KEY_FINGERPRINT=$(gpg --no-options --batch --homedir "$apt_test_root/keyhome" --with-colons --fingerprint --list-secret-keys 2>/dev/null |
    awk -F: '$1=="fpr" {print $10; exit}')
APT_SIGNING_KEY=$(printf '%s\n' "$synthetic_passphrase" | gpg --no-options --batch --homedir "$apt_test_root/keyhome" \
    --pinentry-mode loopback --passphrase-fd 0 --armor --export-secret-keys "$APT_SIGNING_KEY_FINGERPRINT" 2>/dev/null)
APT_SIGNING_PASSPHRASE=$synthetic_passphrase
export APT_SIGNING_KEY APT_SIGNING_PASSPHRASE APT_SIGNING_KEY_FINGERPRINT
test -n "$APT_SIGNING_KEY"
# Tracing must be shut off before any private key/passphrase is read.
bash -x scripts/apt-repository.sh --input "$apt_test_root/input" --output "$apt_test_root/signed" >"$apt_test_root/signed.log" 2>&1
test ! -e "$apt_test_root/signed/UNSIGNED-TEST-ONLY"
grep -Fxq 'Signed-By: /etc/apt/keyrings/octovault-archive-keyring.gpg' "$apt_test_root/signed/octovault-resolute.sources"
grep -Fxq 'URIs: https://example.invalid/apt' "$apt_test_root/signed/octovault-resolute.sources"
[[ $(cat "$apt_test_root/signed/octovault-archive-keyring.fingerprint") == "$APT_SIGNING_KEY_FINGERPRINT" ]]
gpgv --homedir "$apt_test_root/keyhome" --keyring "$apt_test_root/signed/octovault-archive-keyring.gpg" \
    "$apt_test_root/signed/dists/resolute/InRelease" >/dev/null 2>&1
gpgv --homedir "$apt_test_root/keyhome" --keyring "$apt_test_root/signed/octovault-archive-keyring.gpg" \
    "$apt_test_root/signed/dists/resolute/Release.gpg" "$apt_test_root/signed/dists/resolute/Release" >/dev/null 2>&1
(cd "$apt_test_root/signed" && sha256sum --check SHA256SUMS >/dev/null)
verify_release_hashes() (
    cd "$apt_test_root/signed/dists/resolute"
    awk '/^SHA256:/ {section=1; next} /^[^ ]/ {section=0} section {print $1 "  " $3}' Release | sha256sum --check >/dev/null 2>&1
)
verify_release_hashes
printf 'changed index\n' >>"$apt_test_root/signed/dists/resolute/main/binary-amd64/Packages"
if verify_release_hashes; then printf 'FAIL: changed package index was accepted.\n' >&2; exit 1; fi
printf 'changed metadata\n' >>"$apt_test_root/signed/dists/resolute/Release"
if gpgv --homedir "$apt_test_root/keyhome" --keyring "$apt_test_root/signed/octovault-archive-keyring.gpg" \
    "$apt_test_root/signed/dists/resolute/Release.gpg" "$apt_test_root/signed/dists/resolute/Release" >/dev/null 2>&1; then
    printf 'FAIL: changed release metadata was accepted.\n' >&2; exit 1
fi
export APT_SIGNING_KEY_FINGERPRINT=0000000000000000000000000000000000000000
reject_build
APT_SIGNING_KEY_FINGERPRINT=$(cat "$apt_test_root/signed/octovault-archive-keyring.fingerprint")
export APT_SIGNING_PASSPHRASE=incorrect-synthetic-passphrase
reject_build
if grep -rFq -- 'BEGIN PGP PRIVATE KEY' "$apt_test_root/signed" ||
    grep -rFq -- "$synthetic_passphrase" "$apt_test_root/signed" ||
    grep -Fq -- 'BEGIN PGP PRIVATE KEY' "$apt_test_root/signed.log" ||
    grep -Fq -- "$synthetic_passphrase" "$apt_test_root/signed.log"; then
    printf 'FAIL: signing material leaked into published output or logs.\n' >&2; exit 1
fi
[[ -z $(find "$apt_test_root" -maxdepth 1 -name '.octovault-apt.*' -print -quit) ]]
printf 'APT: unsigned catalog, package hashes, real protected-key signing, signature/index tampering, credential rejection and secret isolation passed\n'
