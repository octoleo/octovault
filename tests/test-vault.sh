#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# The sourced adapter invokes these mock functions and exported worker globals.
# Shell expressions in test fixtures must remain literal data.
# shellcheck disable=SC1091,SC2317,SC2034,SC2016
set -Eeuo pipefail
PROJECT=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
# shellcheck source=../lib/octovault/common.sh
source "$PROJECT/lib/octovault/common.sh"
# shellcheck source=../lib/octovault/vault.sh
source "$PROJECT/lib/octovault/vault.sh"
WORK=$(mktemp -d)
cleanup() {
    local status=$? mountpoint loop mapper device
    set +e
    if [[ ${INTEGRATION_RUNNING:-false} == true ]]; then
        # Only tear down mounts/devices backed by this test's temporary file.
        while IFS= read -r loop; do
            [[ -n $loop ]] || continue
            for mapper in /dev/mapper/tomb*; do
                [[ -e $mapper ]] || continue
                device=$(cryptsetup status "$mapper" 2>/dev/null | awk '$1=="device:"{print $2}')
                [[ $device == "$loop" ]] || continue
                while IFS= read -r mountpoint; do
                    [[ $mountpoint == "$WORK/"* ]] && umount -- "$mountpoint"
                done < <(findmnt --json --list --source "$mapper" --output TARGET 2>/dev/null |
                    jq -r '.filesystems|sort_by(.target|length)|reverse|.[].target')
                cryptsetup close "$mapper"
            done
            losetup --detach "$loop"
        done < <(losetup --noheadings --output NAME --associated "$OV_HOME/ci.tomb" 2>/dev/null)
    fi
    ov_secret_close; ov_resource_unlock; ov_vault_cleanup
    if ! findmnt -rn -o TARGET | awk -v root="$WORK/" 'index($0,root)==1 {found=1} END {exit !found}'; then
        rm -rf -- "$WORK"
    fi
    exit "$status"
}
trap cleanup EXIT
OV_UID=$(id -u); OV_USER=$(id -un); OV_HOME="$WORK/home"; OV_ROOT="$WORK/state"
mkdir -p "$OV_HOME" "$OV_ROOT"
export OV_UID OV_USER OV_HOME OV_ROOT
ov_as_user() { "$@"; }
ov_progress() { :; }
assert_equal() { [[ $1 == "$2" ]] || { printf 'Expected [%s], got [%s]\n' "$2" "$1" >&2; exit 1; }; }
assert_fails() { if ( "$@" ) >/dev/null 2>&1; then printf 'Expected failure: %s\n' "$*" >&2; exit 1; fi; }

test_validation() {
    assert_equal "$(ov_vault_mib 1)" 954
    assert_equal "$(ov_vault_mib 0.05)" 48
    assert_fails ov_vault_mib 0
    assert_fails ov_vault_mib '1;touch /tmp/never'
    assert_fails ov_vault_relative ../outside
    assert_fails ov_vault_relative folder/../outside
    assert_fails ov_vault_relative /absolute
    assert_fails ov_vault_relative bind-hooks
    assert_equal "$(ov_vault_relative "Documents/John's files")" "Documents/John's files"
    assert_fails ov_vault_clean_path $'/a\nb'
    touch "$OV_HOME/source"
    ln -s source "$OV_HOME/link"
    assert_fails ov_vault_user_path "$OV_HOME/link"
    printf 'ok - decimal sizes and safe paths\n'
}

test_native_binds() {
    local dir="$WORK/native"
    mkdir "$dir"
    ov_migration_write_bind "$dir" "Documents/John's files" 'My Documents'
    assert_equal "$(cat "$dir/bind-hooks")" "Documents/John's\\ files My\\ Documents"
    local -a values=()
    mapfile -d '' -t values < <(ov_vault_read_binds "$dir/bind-hooks")
    assert_equal "${values[0]}" "Documents/John's files"
    assert_equal "${values[1]}" 'My Documents'
    printf 'literal$(touch-nope) plain\n' >> "$dir/bind-hooks"
    mapfile -d '' -t values < <(ov_vault_read_binds "$dir/bind-hooks")
    assert_equal "${values[2]}" 'literal$(touch-nope)'
    printf 'one two three\n' > "$dir/bind-hooks"
    assert_fails ov_vault_read_binds "$dir/bind-hooks"
    printf 'ok - native escaped-space bind hooks, literal metacharacters\n'
}

test_compare() {
    mkdir -p "$WORK/left/nested" "$WORK/right"
    printf 'content\0binary\377\n' > "$WORK/left/nested/file"
    ln "$WORK/left/nested/file" "$WORK/left/hardlink"
    ln -s nested/file "$WORK/left/symlink"
    rsync -aHAX "$WORK/left/" "$WORK/right/"
    ov_migration_compare "$WORK/left" "$WORK/right"
    printf 'changed' >> "$WORK/right/nested/file"
    assert_fails ov_migration_compare "$WORK/left" "$WORK/right"
    printf 'ok - migration comparison checks contents and metadata\n'
}

test_migration() (
    local source="$OV_HOME/My Documents" mountpoint="$OV_HOME/mounted"
    local record migration staging="$OV_HOME/.octovault-staging-migrationtest"
    mkdir -p "$source/nested" "$mountpoint"
    printf 'precious data\n' > "$source/nested/original"
    record=$(jq -n --arg mount "$mountpoint" '{id:"vaulttest",file:"/dummy.tomb",mountpoint:$mount,hooks:{}}')
    migration=$(jq -n --arg source "$source" --arg staging "$staging" \
        '{migration_id:"migrationtest",source:$source,staging:$staging,relative:"Documents",stage:"prepared"}')
    MOCK_OPEN=true
    ov_vault_is_open() { [[ $MOCK_OPEN == true ]]; }
    ov_vault_open_record() {
        printf 'open\n' >> "$WORK/transitions"
        MOCK_OPEN=true
        # Stand in for a kernel bind mount; no privileged filesystem operations.
        rsync -aHAX "$mountpoint/Documents/" "$source/"
    }
    ov_vault_close_record() { printf 'close\n' >> "$WORK/transitions"; MOCK_OPEN=false; }
    findmnt() { return 0; }
    ov_vault_mapping_matches() { return 0; }
    ov_migration_finish "$record" "$migration"
    assert_equal "$(jq -r .stage <<< "$OV_MIGRATION")" complete
    [[ ! -e $staging ]]
    assert_equal "$(cat "$source/nested/original")" 'precious data'
    assert_equal "$(cat "$WORK/transitions")" $'close\nopen'
    assert_equal "$(cat "$mountpoint/bind-hooks")" 'Documents My\ Documents'
    printf 'ok - staged copy, native map, close, reopen, compare, cleanup\n'
)

test_interrupted_migration() (
    local source="$OV_HOME/Interrupted" mountpoint="$OV_HOME/recovery-vault" staging="$OV_HOME/.octovault-staging-recoverytest"
    local record migration
    mkdir -p "$source" "$mountpoint"
    printf 'keep me\n' > "$source/data"
    record=$(jq -n --arg mount "$mountpoint" '{id:"recoveryvault",mountpoint:$mount}')
    migration=$(jq -n --arg source "$source" --arg staging "$staging" \
        '{migration_id:"recoverytest",source:$source,staging:$staging,relative:"Data",stage:"prepared"}')
    ov_vault_is_open() { return 0; }
    ov_vault_close_record() { ov_fail busy "Simulated busy container"; }
    if (ov_migration_finish "$record" "$migration") >/dev/null 2>&1; then
        printf 'Expected interrupted migration\n' >&2; exit 1
    fi
    [[ -f $staging/data ]]
    assert_equal "$(cat "$staging/data")" 'keep me'
    assert_equal "$(jq -r .stage "$OV_ROOT/migrations/recoveryvault/recoverytest.json")" mapped
    printf 'ok - interrupted close retains staged original and recovery journal\n'
)

test_device_identity() (
    local record='{"file":"/correct.tomb","mountpoint":"/mount"}'
    findmnt() { printf '/dev/mapper/tomb.correct\n'; }
    cryptsetup() { printf '  device: /dev/loop4\n'; }
    losetup() { printf '/dev/loop4\n'; }
    readlink() { printf '%s\n' "${!#}"; }
    ov_vault_is_open "$record"
    losetup() { printf '/dev/loop5\n'; }
    assert_fails ov_vault_is_open "$record"
    printf 'ok - an unrelated mount is never reported as this vault\n'
)

test_unknown_state() (
    local record='{"file":"/correct.tomb","mountpoint":"/mount"}'
    ov_vault_is_open() { return 1; }
    losetup() { return 1; }
    assert_equal "$(ov_vault_status "$record" | jq -r .status)" unknown
    assert_fails ov_vault_require_closed "$record"
    assert_fails ov_vault_close_record "$record"
    losetup() { return 0; }
    ov_vault_require_closed "$record"
    printf 'ok - unknown kernel state fails closed\n'
)

test_secret_arguments() (
    local id=secrettest
    jq() {
        local arg
        for arg in "$@"; do
            [[ $arg != *'do-not-pass-this-secret-in-argv'* ]] || {
                printf 'Secret leaked into jq arguments\n' >&2; exit 99;
            }
        done
        command jq "$@"
    }
    OV_PARAMS=$(printf '{"name":"secret test","file":"%s/new.tomb","key_file":"%s/new.key","password":"do-not-pass-this-secret-in-argv","open_on":"manual"}' "$OV_HOME" "$OV_HOME")
    ov_vault_new_record "$id"
    [[ $OV_RECORD != *do-not-pass-this-secret-in-argv* ]]
    ov_save vaults "$id" "$OV_RECORD"
    OV_PARAMS='{"id":"secrettest","name":"updated","password":"do-not-pass-this-secret-in-argv"}'
    ov_vault_status() { printf '%s\n' "$1"; }
    ov_vault_update >/dev/null
    printf 'ok - request passphrases never appear in jq argv or saved vault records\n'
)

test_container_pin() (
    local record file="$OV_HOME/pin.tomb" alias="$WORK/pin-root/vault.tomb"
    mkdir -p "$(dirname "$alias")"; printf 'container' > "$file"
    record=$(jq -n --arg file "$file" '{id:"pintest",file:$file}')
    ov_vault_alias() { printf '%s/pin-root/vault.tomb\n' "$WORK"; }
    findmnt() { return 1; }
    mount() {
        assert_equal "$1" --no-canonicalize
        assert_equal "$2" --bind
        [[ $3 == /proc/*/fd/* ]]
        assert_equal "$(cat -- "$3")" container
        printf 'pinned\n' > "$WORK/pin-result"
    }
    ov_vault_pin "$record"
    assert_equal "$(cat "$WORK/pin-result")" pinned
    rm "$file"; ln -s /etc/passwd "$file"
    assert_fails ov_vault_pin "$record"
    rm "$file"; mkdir "$file"
    assert_fails ov_vault_pin "$record"
    # A path changed after validation cannot redirect the root bind mount.
    rmdir "$file"; printf 'container' > "$file"
    ov_vault_user_path() { printf '%s\n' "$1"; }
    readlink() { printf '/etc/passwd\n'; }
    assert_fails ov_vault_pin "$record"
    unset OV_VAULT_PIN_RECORD
    printf 'ok - container access pins validated regular inodes and rejects pathname swaps\n'
)

integration() {
    [[ $EUID == 0 ]] || { printf 'Integration requires root.\n' >&2; exit 1; }
    for program in tomb cryptsetup losetup pinentry-octovault rsync; do command -v "$program" >/dev/null; done
    [[ -e /dev/mapper/control ]] || { printf 'Device mapper unavailable.\n' >&2; exit 1; }
    INTEGRATION_RUNNING=true
    local response id file="$OV_HOME/ci.tomb" key="$OV_HOME/ci.key" source="$OV_HOME/Documents"
    OV_PARAMS=$(jq -n --arg file "$file" --arg key "$key" '{name:"CI vault",file:$file,key_file:$key,size_gb:"0.05",auth:"key",password:"OctoVault-CI-only-passphrase",open_on:"manual"}')
    OV_OP=vault.create; response=$(ov_vault_dispatch) || { printf '%s\n' "$response" >&2; return 1; }; id=$(jq -er .data.id <<< "$response")
    OV_PARAMS=$(jq -n --arg id "$id" '{id:$id,password:"OctoVault-CI-only-passphrase"}')
    OV_OP=vault.open; ov_vault_dispatch >/dev/null
    mkdir "$source"; printf 'important\n' > "$source/data"
    OV_PARAMS=$(jq -n --arg id "$id" --arg source "$source" '{id:$id,source:$source,relative:"Documents",password:"OctoVault-CI-only-passphrase"}')
    OV_OP=migration.add; ov_vault_dispatch >/dev/null
    [[ -f $source/data ]]
    OV_PARAMS=$(jq -n --arg id "$id" '{id:$id}'); OV_OP=vault.close; ov_vault_dispatch >/dev/null
    [[ ! -e $source/data ]]
    printf 'independent\n' > "$source/local"
    OV_PARAMS=$(jq -n --arg id "$id" '{id:$id,password:"OctoVault-CI-only-passphrase"}'); OV_OP=vault.open; ov_vault_dispatch >/dev/null
    [[ -f $source/data && ! -e $source/local ]]
    OV_OP=vault.close; ov_vault_dispatch >/dev/null
    assert_equal "$(cat "$source/local")" independent
    printf 'ok - real Tomb lifecycle, migration and independent closed locations\n'
}

if [[ ${1:-} == --integration ]]; then integration
else test_validation; test_native_binds; test_compare; test_migration; test_interrupted_migration; test_device_identity; test_unknown_state; test_secret_arguments; test_container_pin
fi
