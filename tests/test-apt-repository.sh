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
ubuntu_versions=(24.04 26.04)
declare -A suites=([24.04]=noble [26.04]=resolute)
mkdir -p "$apt_test_root/package/DEBIAN" "$apt_test_root/package/usr/share/octovault" "$apt_test_root/input" "$apt_test_root/keyhome"
chmod 0755 "$apt_test_root/package/DEBIAN"
cat >"$apt_test_root/package/DEBIAN/control" <<CONTROL
Package: octovault
Version: $version
Architecture: amd64
Maintainer: OctoVault isolated CI fixture <fixture@example.invalid>
Description: Synthetic repository test package; never installed
CONTROL
for ubuntu in "${ubuntu_versions[@]}"; do
    name="octovault_${version}_ubuntu${ubuntu}_amd64.deb"
    printf 'Ubuntu %s repository fixture\n' "$ubuntu" >"$apt_test_root/package/usr/share/octovault/fixture"
    dpkg-deb --root-owner-group --build "$apt_test_root/package" "$apt_test_root/input/$name" >/dev/null
    (cd "$apt_test_root/input" && sha256sum "$name" >"SHA256SUMS-ubuntu$ubuntu")
done
bash scripts/apt-repository.sh --input "$apt_test_root/input" --output "$apt_test_root/unsigned" >"$apt_test_root/unsigned.log" 2>&1
test -f "$apt_test_root/unsigned/UNSIGNED-TEST-ONLY"
test ! -e "$apt_test_root/unsigned/octovault-archive-keyring.gpg"
(cd "$apt_test_root/unsigned" && sha256sum --check SHA256SUMS >/dev/null)
for ubuntu in "${ubuntu_versions[@]}"; do
    suite=${suites[$ubuntu]}
    name="octovault_${version}_ubuntu${ubuntu}_amd64.deb"
    test ! -e "$apt_test_root/unsigned/dists/$suite/InRelease"
    test ! -e "$apt_test_root/unsigned/octovault-$suite.sources"
    cmp "$apt_test_root/input/$name" "$apt_test_root/unsigned/pool/$suite/main/o/octovault/$name"
    grep -Fxq "Filename: pool/$suite/main/o/octovault/$name" "$apt_test_root/unsigned/dists/$suite/main/binary-amd64/Packages"
    [[ $(grep -c '^Package: ' "$apt_test_root/unsigned/dists/$suite/main/binary-amd64/Packages") == 1 ]]
    grep -Fxq "Codename: $suite" "$apt_test_root/unsigned/dists/$suite/Release"
    grep -Fxq "Suite: $suite" "$apt_test_root/unsigned/dists/$suite/Release"
    gzip -t "$apt_test_root/unsigned/dists/$suite/main/binary-amd64/Packages.gz"
    gzip -t "$apt_test_root/unsigned/dists/$suite/main/dep11/Components-amd64.yml.gz"
    appstreamcli convert "$apt_test_root/unsigned/dists/$suite/main/dep11/Components-amd64.yml" "$apt_test_root/roundtrip-$suite.xml" >/dev/null
    [[ $(xmllint --xpath 'string(/components/component/pkgname)' "$apt_test_root/roundtrip-$suite.xml") == octovault ]]
    [[ $(xmllint --xpath 'string(/components/@origin)' "$apt_test_root/roundtrip-$suite.xml") == "octovault-$suite-main" ]]
    appstreamcli validate --no-net "$apt_test_root/roundtrip-$suite.xml" >/dev/null
done

reject_build() {
    if bash scripts/apt-repository.sh --input "$apt_test_root/input" --output "$apt_test_root/rejected" >"$apt_test_root/reject.log" 2>&1; then
        printf 'FAIL: invalid APT repository configuration was accepted.\n' >&2; exit 1
    fi
    test ! -e "$apt_test_root/rejected"
}
# Package bytes, manifests, output paths, and distribution metadata are checked
# before any signing credentials can reach the repository.
for ubuntu in "${ubuntu_versions[@]}"; do
    suite=${suites[$ubuntu]}
    name="octovault_${version}_ubuntu${ubuntu}_amd64.deb"
    printf 'corruption' >>"$apt_test_root/input/$name"
    reject_build
    cp "$apt_test_root/unsigned/pool/$suite/main/o/octovault/$name" "$apt_test_root/input/$name"
    mv "$apt_test_root/input/$name" "$apt_test_root/held.deb"
    reject_build
    ln -s "$apt_test_root/held.deb" "$apt_test_root/input/$name"
    reject_build
    rm "$apt_test_root/input/$name"
    mv "$apt_test_root/held.deb" "$apt_test_root/input/$name"
    mv "$apt_test_root/input/SHA256SUMS-ubuntu$ubuntu" "$apt_test_root/checksum"
    reject_build
    printf 'malformed manifest\n' >"$apt_test_root/input/SHA256SUMS-ubuntu$ubuntu"
    reject_build
    rm "$apt_test_root/input/SHA256SUMS-ubuntu$ubuntu"
    ln -s "$apt_test_root/checksum" "$apt_test_root/input/SHA256SUMS-ubuntu$ubuntu"
    reject_build
    rm "$apt_test_root/input/SHA256SUMS-ubuntu$ubuntu"
    mv "$apt_test_root/checksum" "$apt_test_root/input/SHA256SUMS-ubuntu$ubuntu"
done
cp "$apt_test_root/input/$name" "$apt_test_root/input/unexpected.deb"
reject_build
rm "$apt_test_root/input/unexpected.deb"
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
[[ $(cat "$apt_test_root/signed/octovault-archive-keyring.fingerprint") == "$APT_SIGNING_KEY_FINGERPRINT" ]]
for suite in noble resolute; do
    grep -Fxq 'Signed-By: /etc/apt/keyrings/octovault-archive-keyring.gpg' "$apt_test_root/signed/octovault-$suite.sources"
    grep -Fxq 'URIs: https://example.invalid/apt' "$apt_test_root/signed/octovault-$suite.sources"
    grep -Fxq "Suites: $suite" "$apt_test_root/signed/octovault-$suite.sources"
    gpgv --homedir "$apt_test_root/keyhome" --keyring "$apt_test_root/signed/octovault-archive-keyring.gpg" \
        "$apt_test_root/signed/dists/$suite/InRelease" >/dev/null 2>&1
    gpgv --homedir "$apt_test_root/keyhome" --keyring "$apt_test_root/signed/octovault-archive-keyring.gpg" \
        "$apt_test_root/signed/dists/$suite/Release.gpg" "$apt_test_root/signed/dists/$suite/Release" >/dev/null 2>&1
done
(cd "$apt_test_root/signed" && sha256sum --check SHA256SUMS >/dev/null)
verify_release_hashes() (
    cd "$apt_test_root/signed/dists/$1"
    awk '/^SHA256:/ {section=1; next} /^[^ ]/ {section=0} section {print $1 "  " $3}' Release | sha256sum --check >/dev/null 2>&1
)
for suite in noble resolute; do
    verify_release_hashes "$suite"
    printf 'changed index\n' >>"$apt_test_root/signed/dists/$suite/main/binary-amd64/Packages"
    if verify_release_hashes "$suite"; then printf 'FAIL: changed %s package index was accepted.\n' "$suite" >&2; exit 1; fi
    printf 'changed metadata\n' >>"$apt_test_root/signed/dists/$suite/Release"
    if gpgv --homedir "$apt_test_root/keyhome" --keyring "$apt_test_root/signed/octovault-archive-keyring.gpg" \
        "$apt_test_root/signed/dists/$suite/Release.gpg" "$apt_test_root/signed/dists/$suite/Release" >/dev/null 2>&1; then
        printf 'FAIL: changed %s release metadata was accepted.\n' "$suite" >&2; exit 1
    fi
done
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
printf 'APT: both Ubuntu suites, isolated package catalogs, complete release inputs, protected-key signing, tampering rejection and secret isolation passed\n'
