#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Verify that registering FIDO metadata cannot replace the recovery secret.
# shellcheck disable=SC1091,SC2317,SC2034
set -Eeuo pipefail
PROJECT=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
source "$PROJECT/lib/octovault/common.sh"
source "$PROJECT/lib/octovault/vault.sh"
WORK=$(mktemp -d)
trap 'ov_secret_close; gpgconf --homedir "$WORK/gpg" --kill all >/dev/null 2>&1 || true; rm -rf -- "$WORK"' EXIT
OV_UID=$(id -u); OV_HOME=$WORK; OV_USER=$(id -un); OV_ROOT="$WORK/state"; OV_VAULT_TEMP_DIR="$WORK/temp"
install -d -m 0700 "$WORK/gpg" "$OV_VAULT_TEMP_DIR"
ov_vault_temporary() { :; }
ov_as_user() { "$@"; }
ov_secret_fd() { exec {OV_SECRET_FD}< <(printf '%s' "$1"); }
ov_vault_status() { printf '%s\n' "$1"; }
ov_load() { OV_RECORD=$SAVED; }
ov_save() { SAVED=$3; }
ov_ok() { printf '%s\n' "$1"; }
assert_fails() { if ( "$@" ) >/dev/null 2>&1; then printf 'Expected failure: %s\n' "$*" >&2; exit 1; fi; }
# Real symmetric encryption ensures the backend verifies the existing key even
# if a user submits the update while its vault is already open.
if ! printf 'recovery-passphrase' | gpg --no-options --homedir "$WORK/gpg" --batch --no-tty --pinentry-mode loopback --passphrase-fd 0 --symmetric --cipher-algo AES256 --output "$WORK/tomb.key" /etc/hostname 2>/dev/null; then
    if [[ ${CI:-} == true ]]; then printf 'Real GPG enrollment verification failed
' >&2; exit 1; fi
    # Restricted sandboxes may forbid gpg-agent sockets. Keep schema/update
    # tests runnable here; CI must exercise the actual encrypted key above.
    mkdir "$WORK/bin"
    cat > "$WORK/bin/gpg" <<'MOCK'
#!/bin/bash
while (($#)); do
    if [[ $1 == --passphrase-fd ]]; then fd=$2; break; fi
    shift
done
value=$(cat <&"$fd")
[[ $value == recovery-passphrase ]]
MOCK
    chmod +x "$WORK/bin/gpg"
    export PATH="$WORK/bin:$PATH"
    printf 'mock encrypted key' > "$WORK/tomb.key"
    printf 'note - sandbox blocks GPG agent; real key decryption is required in CI
'
fi
DESC=$(jq -nc '{version:1,vault_id:"vaulttest",credential:"YWJj",salt:"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",nonce:"AAAAAAAAAAAAAAAA",tag:"AAAAAAAAAAAAAAAAAAAAAA==",ciphertext:"YWJj"}')
SAVED=$(jq -nc --arg key "$WORK/tomb.key" '{id:"vaulttest",name:"Test",file:"/dummy",key_file:$key,mountpoint:"/dummy/mount",auth:"key",execution_scope:"system",open_on:"login",close_on:["shutdown"],force_close:false,hooks:{}}')
ov_vault_validate_record "$SAVED"
ov_vault_validate_record "$(jq --argjson fido "$DESC" '.fido2=$fido' <<< "$SAVED")"
assert_fails ov_vault_validate_record "$(jq --argjson fido "$DESC" '.id="other"|.fido2=$fido' <<< "$SAVED")"
assert_fails ov_vault_validate_record "$(jq --argjson fido "$DESC" '.auth="gpg"|.fido2=$fido' <<< "$SAVED")"
assert_fails ov_vault_validate_record "$(jq '.prompt_after_unlock="true"' <<< "$SAVED")"
assert_fails ov_vault_validate_record "$(jq '.prompt_after_resume=1' <<< "$SAVED")"
OV_PARAMS=$(jq -nc --argjson fido "$DESC" '{id:"vaulttest",fido2:$fido,password:"wrong"}')
assert_fails ov_vault_update
[[ $(jq -r '.fido2//empty' <<< "$SAVED") == '' ]]
OV_PARAMS=$(jq -nc --argjson fido "$DESC" '{id:"vaulttest",fido2:$fido,password:"recovery-passphrase",prompt_after_unlock:true,prompt_after_resume:true}')
ov_vault_update >/dev/null
jq -e '.fido2.version==1 and .prompt_after_unlock and .prompt_after_resume' <<< "$SAVED" >/dev/null
printf 'ok - FIDO descriptor requires vault identity, supported method and verified recovery passphrase\n'
# A new key file means a new recovery secret; a saved old descriptor is removed.
cp "$WORK/tomb.key" "$WORK/other.key"
OV_PARAMS=$(jq -nc --arg key "$WORK/other.key" '{id:"vaulttest",key_file:$key}')
ov_vault_update >/dev/null
jq -e 'has("fido2")|not' <<< "$SAVED" >/dev/null
printf 'ok - changing the Tomb key invalidates FIDO enrollment without changing the key bytes\n'
# These mutation fixtures stub only Tomb's key rewrite and verify the saved
# authorization descriptor cannot survive a changed recovery credential.
SAVED=$(jq --argjson fido "$DESC" '.fido2=$fido' <<< "$SAVED")
ov_vault_tomb() { :; }
OV_PARAMS='{"password":"new-recovery","old_password":"recovery-passphrase"}'
ov_vault_change_password "$SAVED" >/dev/null
jq -e 'has("fido2")|not' <<< "$SAVED" >/dev/null
SAVED=$(jq --argjson fido "$DESC" '.fido2=$fido' <<< "$SAVED")
ov_vault_require_closed() { :; }
ov_vault_pin() { OV_VAULT_CONTAINER_ALIAS=/dummy; }
ov_vault_unpin() { :; }
OV_PARAMS=$(jq -nc --arg key "$WORK/tomb.key" '{new_key_file:$key,password:"replacement-passphrase",old_password:"new-recovery"}')
ov_vault_replace_key "$SAVED" >/dev/null
jq -e 'has("fido2")|not' <<< "$SAVED" >/dev/null
printf 'ok - passphrase changes and replacement keys remove stale FIDO credentials\n'
