#!/bin/bash
# Real local repositories plus deterministic failure/security boundary tests.
# No remote accounts, personal files, or installed system configuration touched.
set -Eeuo pipefail
umask 077
TEST_ROOT=$(mktemp -d)
trap 'rm -rf -- "$TEST_ROOT"' EXIT
PROJECT_ROOT=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
source "$PROJECT_ROOT/lib/octovault/common.sh"
source "$PROJECT_ROOT/lib/octovault/backup.sh"
OV_ROOT="$TEST_ROOT/state"
OV_RUNTIME_ROOT="$TEST_ROOT/runtime"
OV_UID=$(id -u)
OV_USER=$(id -un)
export OV_UID OV_USER
OV_HOME="$TEST_ROOT/home"
mkdir -p "$OV_ROOT" "$OV_HOME" "$TEST_ROOT/storage" "$TEST_ROOT/source dir"
# The common encrypted-credential implementation is independently tested. This
# private disposable store isolates Restic tests from a machine TPM/host secret.
ov_credential_set() { ov_id "$1"; mkdir -p "$OV_ROOT/credentials"; printf '%s' "$2" >"$OV_ROOT/credentials/$1"; }
ov_credential_get() { ov_id "$1"; cat "$OV_ROOT/credentials/$1"; }
ov_vault_is_open() { [[ ${TEST_VAULT_STATE:-closed} == open ]]; }
ov_vault_is_exposed() { [[ ${TEST_VAULT_EXPOSED:-true} == true ]]; }
ov_vault_attached() { case ${TEST_VAULT_STATE:-closed} in open) return 0;; closed) return 1;; *) return 2;; esac; }
ov_schedule_sync() { :; }
ov_resource_lock() { :; }
ov_resource_unlock() { :; }

request() (
    OV_OP=$1
    OV_PARAMS=$2
    unset OV_BACKUP_TMP
    ov_backup_dispatch
)
assert_json() { jq -e "$2" >/dev/null <<<"$1" || { printf 'FAILED JSON assertion: %s\n%s\n' "$2" "$1" >&2; exit 1; }; }
expect_error() {
    local output rc=0
    output=$(request "$2" "$3" 2>/dev/null) || rc=$?
    [[ $rc != 0 ]] || { printf 'Expected failure: %s\n' "$2" >&2; exit 1; }
    assert_json "$output" ".ok == false and .error.code == \"$1\""
}

printf 'Testing destination validation and private records...\n'
destination=$(request destination.save "$(jq -n --arg path "$TEST_ROOT/storage" '{name:"Local test",type:"local",path:$path}')")
assert_json "$destination" '.ok and .data.schema_version == 1'
destination_id=$(jq -r .data.id <<<"$destination")
assert_json "$(request destination.list '{}')" '.ok and (.data | length == 1)'
assert_json "$(request destination.test "{\"id\":\"$destination_id\"}")" '.ok and .data.reachable'
[[ $(stat -c %a "$OV_ROOT/destinations/$destination_id.json") == 600 ]]
expect_error invalid_endpoint destination.save '{"name":"Bad URL","type":"s3","endpoint":"https://secret@example.com","bucket":"bucket","access_key":"fake","secret_key":"fake"}'
expect_error invalid_path destination.save '{"name":"Bad path","type":"local","path":"/tmp/../etc"}'
expect_error fingerprint_required destination.save '{"name":"SSH","type":"sftp","host":"example.com","user":"backup","path":"/backup"}'

if ! command -v restic >/dev/null; then
    printf 'FAIL: install Restic to run the required local backup/restore integration tests.\n' >&2
    exit 1
fi
printf 'Testing real Restic initialization, backup, browse, restore, retention and recovery...\n'
repository=$(request repository.create "$(jq -n --arg id "$destination_id" '{name:"Repository",destination_id:$id,path:"repository"}')")
assert_json "$repository" '.ok and .data.recovery_required and (.data.repository_id | length == 64)'
repository_id=$(jq -r .data.id <<<"$repository")
recovery=$(request repository.recovery "{\"id\":\"$repository_id\"}")
assert_json "$recovery" '.ok and (.data.RESTIC_PASSWORD | length >= 64) and .data.destination_type == "local"'
password=$(jq -r .data.RESTIC_PASSWORD <<<"$recovery")
if grep -rF -- "$password" "$OV_ROOT/repositories" "$OV_ROOT/destinations" >/dev/null; then printf 'Secret leaked into a public record.\n' >&2; exit 1; fi
printf 'Hello encrypted backup\n' >"$TEST_ROOT/source dir/document.txt"
printf 'not backed up\n' >"$TEST_ROOT/source dir/excluded.tmp"
chmod 0640 "$TEST_ROOT/source dir/document.txt"
if (( EUID == 0 )); then
    if ! chown 12345:12346 "$TEST_ROOT/source dir/document.txt" 2>/dev/null; then
        if [[ ${CI:-false} == true ]]; then
            printf 'FAIL: CI must support restoring files owned by another UID/GID.\n' >&2
            exit 1
        fi
        printf 'Restricted local namespace: alternate UID/GID setup unavailable; checking existing ownership instead. CI requires the alternate-owner case.\n'
    fi
fi
ln "$TEST_ROOT/source dir/document.txt" "$TEST_ROOT/source dir/hardlink.txt"
ln -s document.txt "$TEST_ROOT/source dir/symlink.txt"
plan=$(request backup.save "$(jq -n --arg rid "$repository_id" --arg source "$TEST_ROOT/source dir" '{name:"Documents",repository_id:$rid,sources:[$source],excludes:["*.tmp"],trigger:"manual"}')")
assert_json "$plan" '.ok and .data.vault_mode == "none" and .data.on_battery == false'
plan_id=$(jq -r .data.id <<<"$plan")
backup=$(request backup.run "{\"id\":\"$plan_id\"}")
assert_json "$backup" '.ok and .data.status == "success" and .data.exit_code == 0'
assert_json "$(request backup.history "{\"id\":\"$plan_id\"}")" '.ok and (.data | length == 1)'
snapshots=$(request repository.snapshots "{\"id\":\"$repository_id\"}")
assert_json "$snapshots" '.ok and (.data | length == 1)'
snapshot_id=$(jq -r '.data[0].id' <<<"$snapshots")
files=$(request repository.files "{\"id\":\"$repository_id\",\"snapshot\":\"$snapshot_id\"}")
assert_json "$files" '.ok and any(.data[]; .name == "document.txt") and (any(.data[]; .name == "excluded.tmp") | not)'
assert_json "$(request repository.find "{\"id\":\"$repository_id\",\"pattern\":\"document.txt\"}")" '.ok'
assert_json "$(request repository.diff "{\"id\":\"$repository_id\",\"snapshot_a\":\"$snapshot_id\",\"snapshot_b\":\"$snapshot_id\"}")" '.ok'
restore="$TEST_ROOT/restored"
assert_json "$(request repository.restore "$(jq -n --arg id "$repository_id" --arg target "$restore" '{id:$id,target:$target,snapshot:"latest",overwrite:"never"}')")" '.ok'
cmp "$TEST_ROOT/source dir/document.txt" "$restore$TEST_ROOT/source dir/document.txt"
[[ $(stat -c %a "$restore$TEST_ROOT/source dir/document.txt") == 640 ]]
[[ $(stat -c '%u:%g' "$restore$TEST_ROOT/source dir/document.txt") == "$(stat -c '%u:%g' "$TEST_ROOT/source dir/document.txt")" ]]
[[ $(readlink "$restore$TEST_ROOT/source dir/symlink.txt") == document.txt ]]
[[ $(stat -c %i "$restore$TEST_ROOT/source dir/document.txt") == "$(stat -c %i "$restore$TEST_ROOT/source dir/hardlink.txt")" ]]
[[ ! -e "$restore$TEST_ROOT/source dir/excluded.tmp" ]]
assert_json "$(request repository.check "{\"id\":\"$repository_id\",\"read_data\":true}")" '.ok and .data.successful and .data.read_data'
assert_json "$(request repository.stats "{\"id\":\"$repository_id\"}")" '.ok and .data.total_size > 0'
assert_json "$(request repository.forget "{\"id\":\"$repository_id\",\"keep_daily\":1}")" '.ok'
expect_error retention_required repository.forget "{\"id\":\"$repository_id\",\"keep_daily\":0}"
expect_error invalid_snapshot repository.restore "{\"id\":\"$repository_id\",\"snapshot\":\"--delete\",\"target\":\"$restore\"}"
expect_error in_use destination.remove "{\"id\":\"$destination_id\"}"
expect_error in_use repository.remove "{\"id\":\"$repository_id\"}"

printf 'Testing repository copy and password changes with portable recovery...\n'
copy_repository=$(request repository.create "$(jq -n --arg id "$destination_id" '{name:"Copy",destination_id:$id,path:"copy"}')")
copy_id=$(jq -r .data.id <<<"$copy_repository")
assert_json "$(request repository.copy "{\"id\":\"$repository_id\",\"target_id\":\"$copy_id\",\"snapshot\":\"$snapshot_id\"}")" '.ok'
assert_json "$(request repository.snapshots "{\"id\":\"$copy_id\"}")" '.ok and (.data | length == 1)'
assert_json "$(request repository.password "{\"id\":\"$repository_id\"}")" '.ok and .data.changed and .data.recovery_required'
recovery=$(request repository.recovery "{\"id\":\"$repository_id\"}")
new_password=$(jq -r .data.RESTIC_PASSWORD <<<"$recovery")
[[ $new_password != "$password" ]]
assert_json "$(request repository.snapshots "{\"id\":\"$repository_id\"}")" '.ok and (.data | length == 1)'
import_params=$(jq -n --arg did "$destination_id" '{name:"Imported independently",destination_id:$did,path:"repository"}')
import_params=$(jq --argjson params "$import_params" '$params + {password:.data.RESTIC_PASSWORD}' <<<"$recovery")
assert_json "$(request repository.import "$import_params")" '.ok'
assert_json "$(request backup.save "{\"id\":\"$plan_id\",\"retention\":{\"keep_daily\":1}}")" '.ok'
printf 'Second revision\n' >>"$TEST_ROOT/source dir/document.txt"
assert_json "$(request backup.run "{\"id\":\"$plan_id\"}")" '.ok and .data.retention.successful'
assert_json "$(request repository.snapshots "{\"id\":\"$repository_id\"}")" '.ok and (.data | length == 1)'

printf 'Testing partial failures, missing sources and fail-closed vault interlocks...\n'
vault_id=test-vault
printf 'encrypted-container-placeholder\n' >"$TEST_ROOT/container.tomb"
ov_save vaults "$vault_id" "$(jq -n --arg file "$TEST_ROOT/container.tomb" --arg mountpoint "$TEST_ROOT/mount" '{name:"Test vault",file:$file,mountpoint:$mountpoint}')"
assert_json "$(request backup.save "$(jq -n --arg rid "$repository_id" --arg source "$TEST_ROOT/source dir" '{name:"Independent files on vault event",repository_id:$rid,sources:[$source],vault_id:"test-vault",vault_mode:"none",trigger:"vault-open"}')")" '.ok and .data.vault_mode == "none" and .data.trigger == "vault-open"'
expect_error invalid_trigger backup.save "$(jq -n --arg rid "$repository_id" --arg source "$TEST_ROOT/source dir" '{name:"Conflicting trigger",repository_id:$rid,sources:[$source],vault_id:"test-vault",vault_mode:"closed-container",trigger:"vault-open"}')"
linked=$(request backup.save "$(jq -n --arg rid "$repository_id" --arg source "$TEST_ROOT/source dir" '{name:"Vault plan",repository_id:$rid,sources:[$source],vault_id:"test-vault",vault_mode:"open-files"}')")
linked_id=$(jq -r .data.id <<<"$linked")
expect_error vault_closed backup.run "{\"id\":\"$linked_id\"}"
TEST_VAULT_STATE=open
TEST_VAULT_EXPOSED=false
expect_error vault_not_exposed backup.run "{\"id\":\"$linked_id\"}"
TEST_VAULT_EXPOSED=true
findmnt() { if [[ " $* " == *' --mountpoint '* ]]; then printf '253:1\n'; else printf '8:1\n'; fi; }
expect_error source_not_in_vault backup.run "{\"id\":\"$linked_id\"}"
unset -f findmnt
assert_json "$(request backup.save "{\"id\":\"$linked_id\",\"vault_mode\":\"closed-container\"}")" '.ok'
TEST_VAULT_STATE=open
expect_error vault_open backup.run "{\"id\":\"$linked_id\"}"
TEST_VAULT_STATE=probe-failed
expect_error vault_verification_failed backup.run "{\"id\":\"$linked_id\"}"
TEST_VAULT_STATE=closed
missing=$(request backup.save "$(jq -n --arg rid "$repository_id" --arg source "$TEST_ROOT/missing" '{name:"Missing",repository_id:$rid,sources:[$source]}')")
missing_id=$(jq -r .data.id <<<"$missing")
expect_error source_missing backup.run "{\"id\":\"$missing_id\"}"
restic() { printf '{"message_type":"summary","files_new":1,"snapshot_id":"test"}\n'; return 3; }
expect_error partial backup.run "{\"id\":\"$plan_id\"}"
assert_json "$(request backup.history "{\"id\":\"$plan_id\"}")" '.ok and .data[-1].status == "partial" and .data[-1].exit_code == 3'
unset -f restic
assert_json "$(request backup.remove "{\"id\":\"$missing_id\"}")" '.ok and .data.data_preserved'
printf 'Testing S3 credential separation and verified SSH host keys without a network...\n'
s3=$(request destination.save '{"name":"S3 credentials","type":"s3","endpoint":"https://s3.example.test","bucket":"backup-test","region":"","access_key":"FAKE_TEST_ACCESS","secret_key":"FAKE_TEST_SECRET"}')
assert_json "$s3" '.ok and .data.region == "us-east-1" and (.data.credentials.access_key | type == "string")'
s3_id=$(jq -r .data.id <<<"$s3")
if grep -E 'FAKE_TEST_(ACCESS|SECRET)' "$OV_ROOT/destinations/$s3_id.json" >/dev/null; then printf 'S3 credentials leaked into a public record.\n' >&2; exit 1; fi
assert_json "$(request destination.save "{\"id\":\"$s3_id\",\"name\":\"Renamed\",\"access_key\":\"\",\"secret_key\":\"\"}")" '.ok and .data.name == "Renamed"'
curl() {
    [[ $1 == --config && -f $2 ]]
    [[ $(stat -c %a "$2") == 600 ]]
    grep -q 'FAKE_TEST_ACCESS:FAKE_TEST_SECRET' "$2"
    grep -q 'aws-sigv4' "$2"
}
assert_json "$(request destination.test "{\"id\":\"$s3_id\"}")" '.ok and .data.reachable'
unset -f curl
ssh-keygen -q -t ed25519 -N '' -f "$TEST_ROOT/hostkey"
ssh-keyscan() { printf 'example.test %s\n' "$(cut -d' ' -f1,2 "$TEST_ROOT/hostkey.pub")"; }
fingerprint=$(ssh-keygen -lf "$TEST_ROOT/hostkey.pub" -E sha256 | awk '{print $2}')
ssh_params=$(jq -n --arg fingerprint "$fingerprint" --rawfile key "$TEST_ROOT/hostkey" '{name:"SSH server",type:"sftp",host:"example.test",port:22,user:"backup",path:"/srv/backups",host_fingerprint:$fingerprint,ssh_private_key:$key}')
ssh_destination=$(request destination.save "$ssh_params")
ssh_id=$(jq -r .data.id <<<"$ssh_destination")
assert_json "$ssh_destination" '.ok and (.data.known_hosts | startswith("example.test ssh-ed25519"))'
expect_error host_key_mismatch destination.save "$(jq '.host_fingerprint="SHA256:AAAA"' <<<"$ssh_params")"
sftp() {
    local config=$3 keyfile
    [[ -f $config ]]
    grep -q 'StrictHostKeyChecking yes' "$config"
    keyfile=$(awk '$1 == "IdentityFile" {print $2}' "$config")
    [[ $(stat -c %a "$keyfile") == 600 ]]
    ssh-keygen -y -f "$keyfile" >/dev/null
}
assert_json "$(request destination.test "{\"id\":\"$ssh_id\"}")" '.ok and .data.reachable'
unset -f sftp ssh-keyscan

printf 'Testing shared vault-event and backup EXIT cleanup...\n'
(
    # Exercise the real vault cleanup and unpin logic without requiring mounts.
    # The fake attached loop must keep its alias available for a future close.
    source "$PROJECT_ROOT/lib/octovault/vault.sh"
    OV_VAULT_TEMP_DIR="$TEST_ROOT/vault-runtime"
    # shellcheck disable=SC2034 # Consumed by the dynamically sourced vault cleanup.
    OV_VAULT_PIN_RECORD='{"id":"event-vault"}'
    mkdir -m 0700 "$OV_VAULT_TEMP_DIR"
    printf 'disposable runtime key' >"$OV_VAULT_TEMP_DIR/key"
    printf 'pinned container' >"$TEST_ROOT/pinned-container"
    ov_vault_alias() { printf '%s\n' "$TEST_ROOT/pinned-container"; }
    losetup() { printf '/dev/loop-test\n'; }
    umount() { printf 'Attached vault alias was unexpectedly unmounted.\n' >&2; return 99; }
    unset OV_BACKUP_TMP
    ov_backup_workspace
    printf '%s' "$OV_BACKUP_TMP" >"$TEST_ROOT/backup-runtime-path"
    printf 'disposable backup password' >"$OV_BACKUP_TMP/password"
    # The workspace EXIT trap must clean both adapters without losing the alias.
)
[[ ! -e $TEST_ROOT/vault-runtime ]]
[[ ! -e $(cat "$TEST_ROOT/backup-runtime-path") ]]
[[ -f $TEST_ROOT/pinned-container ]]
printf 'All backup integration tests passed.\n'
