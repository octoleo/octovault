#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Mock process boundaries; real validation and request handling remain active.
# shellcheck disable=SC1091,SC2317,SC2034
set -Eeuo pipefail
PROJECT=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
source "$PROJECT/lib/octovault/common.sh"
source "$PROJECT/lib/octovault/vault.sh"
WORK=$(mktemp -d)
trap 'rm -rf -- "$WORK"' EXIT
OV_UID=$(id -u); OV_USER=$(id -un); OV_HOME="$WORK/home"; OV_ROOT="$WORK/state"
OV_VAULT_TEMP_DIR="$WORK/temporary"
mkdir -m 0700 "$OV_HOME" "$OV_ROOT" "$OV_VAULT_TEMP_DIR"
PRIMARY=1111111111111111111111111111111111111111
ENCRYPTION=2222222222222222222222222222222222222222
OTHER=3333333333333333333333333333333333333333
SERIAL=D2760001240102010006000000010000
SCENARIO=success
ov_vault_temporary() { :; }
ov_resource_lock() { :; }
ov_progress() { OV_STAGE=$1; }

ov_as_user() {
    if [[ $1 == timeout ]]; then
        shift
        while [[ $1 != gpg ]]; do shift; done
    fi
    if [[ $1 == tomb ]]; then
        touch "$WORK/allocation-called"
        printf 'Unexpected container allocation\n' >&2
        return 1
    fi
    if [[ $1 != gpg ]]; then "$@"; return; fi
    local argument mode='' trust=u fingerprint=$ENCRYPTION expires=0 binding=$SERIAL input_file=''
    for argument; do
        input_file=$argument
        case $argument in
            --card-status|--list-keys|--list-secret-keys|--encrypt|--decrypt) mode=$argument ;;
        esac
    done
    printf '%s\n' "$mode" >> "$WORK/gpg-calls"
    case $mode in
        --card-status)
            [[ $SCENARIO != missing_card ]] || return 2
            [[ $SCENARIO != wrong_card ]] || fingerprint=$OTHER
            [[ $SCENARIO != empty_card ]] || fingerprint=0000000000000000000000000000000000000000
            printf 'AID:%s:\n' "$SERIAL"
            printf 'fpr:%s:%s:%s:\n' "$PRIMARY" "$fingerprint" "$OTHER"
            ;;
        --list-secret-keys)
            [[ $SCENARIO != wrong_card ]] || fingerprint=$OTHER
            [[ $SCENARIO != software_copy ]] || binding=+
            [[ $SCENARIO != wrong_binding ]] || binding=D2760001240102010006000000020000
            printf 'ssb:u:2048:1:2222222222222222:1:0:::::e:::%s:\n' "$binding"
            printf 'fpr:::::::::%s:\n' "$fingerprint"
            ;;
        --list-keys)
            [[ $SCENARIO != missing_public ]] || return 2
            [[ $SCENARIO != untrusted ]] || trust=-
            [[ $SCENARIO != expired ]] || expires=1
            printf 'pub:%s:2048:1:1111111111111111:1:%s::u:::scESC:\n' "$trust" "$expires"
            printf 'fpr:::::::::%s:\n' "$PRIMARY"
            printf 'sub:%s:2048:1:2222222222222222:1:0:::::e:\n' "$trust"
            printf 'fpr:::::::::%s:\n' "$ENCRYPTION"
            ;;
        --encrypt) cat ;;
        --decrypt)
            printf 'private-subprocess-diagnostic-sentinel\n' >&2
            case $SCENARIO in
                cancel) printf '[GNUPG:] SC_OP_FAILURE 1\n' >&2; return 2 ;;
                agent_cancel) printf '[GNUPG:] ERROR pkdecrypt_failed 83886179\n' >&2; return 2 ;;
                bad_pin) printf '[GNUPG:] SC_OP_FAILURE 2\n' >&2; return 2 ;;
                no_pinentry) printf '[GNUPG:] ERROR get_passphrase 85\n' >&2; return 2 ;;
                missing_private) printf '[GNUPG:] NO_SECKEY 2222222222222222\n' >&2; return 2 ;;
                timed_out) return 124 ;;
                wrong_decryption_key) fingerprint=$OTHER ;;
                changed_challenge) cat >/dev/null; printf 'unexpected plaintext'; return 0 ;;
            esac
            if [[ -f $input_file ]]; then cat -- "$input_file"; else cat; fi
            printf '[GNUPG:] DECRYPTION_KEY %s %s u\n[GNUPG:] DECRYPTION_OKAY\n' "$fingerprint" "$PRIMARY" >&2
            ;;
        *) printf 'Unexpected GnuPG arguments\n' >&2; return 1 ;;
    esac
}

assert_failure() {
    local expected=$1
    shift
    if ( "$@" ) > "$WORK/response.json" 2> "$WORK/stderr"; then
        printf 'Expected failure %s\n' "$expected" >&2; exit 1
    fi
    jq -e --arg code "$expected" '.ok==false and .error.code==$code' "$WORK/response.json" >/dev/null || {
        cat "$WORK/response.json" >&2; exit 1;
    }
    ! grep -q private-subprocess-diagnostic-sentinel "$WORK/response.json"
}

for value in 0.05 0.050000000000000003 5e-2 5E-2; do
    [[ $(ov_vault_mib "$value") == 48 ]]
done
[[ $(ov_vault_mib 1.0000000000000002) == 954 ]]
for value in 0 -1 1e999 1e-999 3000000 '1;touch /tmp/never' NaN Infinity; do
    assert_failure invalid_size ov_vault_mib "$value"
done
printf 'ok - JSON floating-point and exponent sizes retain MiB safety bounds\n'

OV_OP=vault.auth-check
OV_PARAMS=$(jq -n --arg recipient "$PRIMARY" '{recipient:$recipient,require_token:false}')
ov_vault_dispatch > "$WORK/response.json"
jq -e --arg recipient "$PRIMARY" '.ok and .data.verified and .data.recipient==$recipient and .data.require_token==false' "$WORK/response.json" >/dev/null
OV_PARAMS=$(jq -n --arg recipient "$ENCRYPTION!" '{recipient:$recipient,require_token:true}')
ov_vault_dispatch > "$WORK/response.json"
jq -e --arg recipient "$ENCRYPTION!" '.ok and .data.verified and .data.recipient==$recipient and .data.require_token==true' "$WORK/response.json" >/dev/null
[[ ! -e $OV_HOME/.local/share/octovault && ! -e $WORK/allocation-called ]]
printf 'ok - software and exact security-key recipient challenge verification\n'

# Primary recipients are narrowed to the verified card encryption subkey.
ov_vault_auth_preflight "$PRIMARY" true
[[ $OV_VAULT_AUTH_RECIPIENT == "$ENCRYPTION!" ]]

# Reuse authenticates the ciphertext without requiring the recipient again.
printf 'existing-encrypted-key-fixture' > "$OV_HOME/existing.key"
OV_PARAMS=$(jq -n --arg key "$OV_HOME/existing.key" '{use_existing_key:true,key_file:$key,require_token:true}')
ov_vault_dispatch > "$WORK/response.json"
jq -e '.ok and .data.verified and .data.require_token' "$WORK/response.json" >/dev/null
[[ $(cat "$OV_HOME/existing.key") == existing-encrypted-key-fixture ]]
printf 'ok - existing encrypted key authentication preserves its file\n'

# Every authentication failure precedes managed folders, records and allocation.
OV_OP=vault.create
OV_PARAMS=$(jq -n --arg directory "$OV_HOME" --arg recipient "$ENCRYPTION!" \
    '{name:"New vault",directory:$directory,size_gb:0.050000000000000003,auth:"gpg",recipient:$recipient,require_token:true}')
while read -r SCENARIO expected; do
    assert_failure "$expected" ov_vault_dispatch
    [[ ! -e $OV_HOME/New\ vault.tomb && ! -e $OV_HOME/.local/share/octovault && ! -e $OV_ROOT/vaults && ! -e $WORK/allocation-called ]]
done <<'CASES'
missing_public public_key_missing
untrusted key_untrusted
expired key_unusable
missing_card token_missing
empty_card token_unconfigured
wrong_card token_mismatch
software_copy token_not_bound
wrong_binding token_not_bound
cancel authentication_cancelled
agent_cancel authentication_cancelled
bad_pin incorrect_pin
no_pinentry pinentry_unavailable
missing_private private_key_missing
timed_out authentication_timeout
wrong_decryption_key token_mismatch
changed_challenge authentication_failed
CASES
SCENARIO=success
assert_failure invalid_recipient ov_vault_auth_preflight short-id false
assert_failure invalid_auth ov_vault_auth_preflight "$PRIMARY" maybe
OV_PARAMS='{"recipient":"1111111111111111111111111111111111111111","require_token":"true"}'
assert_failure invalid_auth ov_vault_auth_check
printf 'ok - authentication failures and PIN cancellation cannot allocate a vault\n'

# Later unlock/resize/lock operations must require the actual card-backed key,
# not only an attached token or a local software copy with the same fingerprint.
record=$(jq -n --arg key "$OV_HOME/existing.key" --arg recipient "$ENCRYPTION!" \
    '{id:"token-vault",auth:"gpg",key_file:$key,recipient:$recipient,require_token:true}')
ov_vault_pin() { OV_VAULT_CONTAINER_ALIAS=/test/container; }
ov_vault_tomb() { cat > "$WORK/engine-key"; }
ov_vault_tomb_keyed "$record" open /test/container
[[ $(cat "$WORK/engine-key") == existing-encrypted-key-fixture && -z ${OV_VAULT_TOKEN_KEY+x} ]]
rm "$WORK/engine-key"
for SCENARIO in missing_card software_copy wrong_binding wrong_decryption_key cancel; do
    case $SCENARIO in
        missing_card) expected=token_missing ;;
        software_copy|wrong_binding) expected=token_not_bound ;;
        wrong_decryption_key) expected=token_mismatch ;;
        cancel) expected=authentication_cancelled ;;
    esac
    assert_failure "$expected" ov_vault_tomb_keyed "$record" open /test/container
    [[ ! -e $WORK/engine-key ]]
done
SCENARIO=success
head -c 4097 /dev/zero > "$OV_HOME/existing.key"
assert_failure invalid_key ov_vault_tomb_keyed "$record" open /test/container
[[ ! -e $WORK/engine-key ]]
printf 'ok - token policy applies to later operations; oversized or mismatched key material never reaches the engine\n'
