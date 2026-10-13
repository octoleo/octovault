#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
# Real systemd-creds encryption, isolated from the installation's host secret.
set -Eeuo pipefail
umask 077
cd "$(dirname "$0")/.."
source lib/octovault/common.sh

credential_test_root=$(mktemp -d)
trap 'rm -rf -- "$credential_test_root"' EXIT
OV_ROOT="$credential_test_root/state"
mkdir -m 0700 "$OV_ROOT" "$credential_test_root/host"
# systemd's own test override keeps setup/encryption away from the real host
# credential.secret. This changes the key location, not the common adapter.
export SYSTEMD_CREDENTIAL_SECRET="$credential_test_root/host/credential.secret"

credential_test_unavailable() {
    if [[ ${CI:-false} == true ]]; then
        printf 'FAIL: CI must support the real systemd-creds host-key roundtrip: %s\n' "$1" >&2
        exit 1
    fi
    printf 'Restricted local runtime: systemd-creds roundtrip unavailable (%s). CI requires it.\n' "$1"
    exit 0
}

command -v systemd-creds >/dev/null || credential_test_unavailable 'systemd-creds is not installed'
((EUID == 0)) || credential_test_unavailable 'run this test as root'
credential_test_value=$'OctoVault-synthetic-only-9f5ba63c25df42e5bc11d620de9a6b08\nquotes: "literal" $variable ; never-executed'
credential_test_result=$(ov_credential_set roundtrip "$credential_test_value") || credential_test_unavailable 'auto encryption or isolated host-key setup is unsupported'
[[ -z $credential_test_result ]]
[[ -s $SYSTEMD_CREDENTIAL_SECRET && ! -L $SYSTEMD_CREDENTIAL_SECRET ]]
[[ -s $OV_ROOT/credentials/roundtrip.cred && ! -L $OV_ROOT/credentials/roundtrip.cred ]]
[[ $(stat -c %a "$OV_ROOT/credentials") == 700 ]]
[[ $(stat -c %a "$OV_ROOT/credentials/roundtrip.cred") == 600 ]]
[[ $(stat -c %u "$OV_ROOT/credentials/roundtrip.cred") == 0 ]]
[[ $(ov_credential_get roundtrip) == "$credential_test_value" ]]
if grep -rFq -- 'OctoVault-synthetic-only-9f5ba63c25df42e5bc11d620de9a6b08' "$OV_ROOT"; then
    printf 'FAIL: plaintext appeared in the persistent credential store.\n' >&2
    exit 1
fi
[[ $(find "$OV_ROOT/credentials" -maxdepth 1 -type f | wc -l) == 1 ]]

# The encrypted name is authenticated: renaming the file must not authorize
# decryption under a different credential reference.
cp "$OV_ROOT/credentials/roundtrip.cred" "$OV_ROOT/credentials/wrong-name.cred"
credential_test_status=0
credential_test_result=$(ov_credential_get wrong-name) || credential_test_status=$?
((credential_test_status != 0))
jq -e '.ok == false and .error.code == "credential_error"' <<<"$credential_test_result" >/dev/null

# Replacing the same reference is atomic and leaves only encrypted data.
ov_credential_set roundtrip 'OctoVault-synthetic-replacement-only'
[[ $(ov_credential_get roundtrip) == OctoVault-synthetic-replacement-only ]]
[[ $(stat -c %a "$OV_ROOT/credentials/roundtrip.cred") == 600 ]]
if grep -rFq -- 'OctoVault-synthetic-replacement-only' "$OV_ROOT"; then
    printf 'FAIL: plaintext appeared after credential replacement.\n' >&2
    exit 1
fi
ln -s roundtrip.cred "$OV_ROOT/credentials/unsafe.cred"
credential_test_status=0
credential_test_result=$(ov_credential_get unsafe) || credential_test_status=$?
((credential_test_status != 0))
jq -e '.ok == false and .error.code == "credential_missing"' <<<"$credential_test_result" >/dev/null
printf 'credentials: real auto-encrypted roundtrip, authenticated names, atomic replacement, permissions and no plaintext storage passed\n'
