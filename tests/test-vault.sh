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
    local status=$? mountpoint loop mapper device container
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
                    if [[ $mountpoint == "$WORK/"* || $mountpoint == "/run/octovault/mounts/$OV_UID/"* ]]; then
                        umount -- "$mountpoint"
                    fi
                done < <(findmnt --json --list --source "$mapper" --output TARGET 2>/dev/null |
                    jq -r '.filesystems|sort_by(.target|length)|reverse|.[].target')
                cryptsetup close "$mapper"
            done
            losetup --detach "$loop"
        done < <(for container in "$OV_HOME/"*.tomb; do
            [[ ! -f $container ]] || losetup --noheadings --output NAME --associated "$container" 2>/dev/null
        done)
    fi
    ov_secret_close; ov_resource_unlock; ov_vault_cleanup
    if [[ -n ${INTEGRATION_USER:-} ]]; then
        ov_as_user gpgconf --kill all 2>/dev/null || true
        userdel "$INTEGRATION_USER" 2>/dev/null || true
    fi
    if ! findmnt -rn -o TARGET | awk -v root="$WORK/" 'index($0,root)==1 {found=1} END {exit !found}'; then
        rm -rf -- "$WORK"
    fi
    exit "$status"
}
trap cleanup EXIT
OV_UID=$(id -u); OV_USER=$(id -un); OV_HOME="$WORK/home"; OV_ROOT="$WORK/state"
mkdir -p "$OV_HOME" "$OV_ROOT"
export OV_UID OV_USER OV_HOME OV_ROOT
if [[ ${1:-} != --integration ]]; then ov_as_user() { "$@"; }; fi
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
    touch "$OV_HOME/incomplete.tomb"
    record=$(jq -n --arg file "$OV_HOME/incomplete.tomb" '{file:$file,mountpoint:"/mount",creation_state:"initializing"}')
    assert_equal "$(ov_vault_status "$record" | jq -r .status)" incomplete
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

test_guided_creation() (
    OV_HOME="$WORK/guided-home"; OV_ROOT="$WORK/guided-state"; OV_OP=vault.create
    mkdir -p "$OV_HOME" "$OV_ROOT" "$WORK/guided-temp"
    OV_VAULT_TEMP_DIR="$WORK/guided-temp"
    ov_resource_lock() { printf '%s\n' "$1" > "$WORK/guided-locked-path"; }
    ov_vault_status() { printf '%s\n' "$1"; }
    ov_vault_temporary() { :; }
    ov_vault_unpin() { :; }
    tomb() {
        [[ $1 == --no-color && $2 == dig ]] || { printf 'Unexpected tomb call\n' >&2; return 1; }
        printf 'allocation\n' >> "$WORK/guided-allocations"
        local target
        for target; do :; done
        : > "$target"
    }
    ov_vault_tomb() {
        [[ $1 == forge && $2 == -k ]] || return 1
        [[ ! -e $3 ]] || return 1
        printf 'forge\n' >> "$WORK/guided-forges"
        printf 'encrypted-key-fixture\n' > "$3"
    }
    ov_vault_tomb_keyed() {
        [[ $2 == lock ]] || return 1
        printf '%s\n' "$1" > "$WORK/guided-lock-record"
    }
    ov_vault_image_embed() {
        [[ $1 == "$OV_VAULT_TEMP_DIR/created-"*.key ]] || return 1
        cat -- "$2" > "$3"
        printf 'encrypted-embedded-key\n' >> "$3"
    }
    OV_PARAMS=$(jq -n --arg directory "$OV_HOME" \
        '{name:"Personal files",directory:$directory,size_gb:"0.05",password:"guided-test-not-for-storage"}')
    ov_vault_dispatch > "$WORK/guided-response"
    local record key id original_key count cover="$OV_HOME/cover.bmp" image_hash
    record=$(jq .data "$WORK/guided-response"); key=$(jq -r .key_file <<< "$record"); id=$(jq -r .id <<< "$record")
    original_key=$key
    assert_equal "$(jq -r .file <<< "$record")" "$OV_HOME/Personal files.tomb"
    assert_equal "$(cat "$WORK/guided-locked-path")" "$OV_HOME/Personal files.tomb"
    assert_equal "$key" "$OV_HOME/.local/share/octovault/keys/$id/vault.key"
    assert_equal "$(jq -r '.key_managed,.key_reused,.creation_state' <<< "$record")" $'true\nfalse\nready'
    assert_equal "$(stat -c %a -- "$key")" 600
    assert_equal "$(stat -c %a -- "$(dirname "$key")")" 700
    assert_equal "$(stat -c %a -- "$OV_HOME/.local/share/octovault/keys")" 700
    [[ $(cat "$OV_ROOT/vaults/$id.json") != *guided-test-not-for-storage* ]]
    [[ $(cat "$key") != *guided-test-not-for-storage* ]]
    count=$(wc -l < "$WORK/guided-forges")
    OV_PARAMS=$(jq -n --arg directory "$OV_HOME" --arg key "$key" \
        '{name:"Second.tomb",directory:$directory,size_gb:"0.05",password:"guided-test-not-for-storage",use_existing_key:true,key_file:$key}')
    ov_vault_dispatch > "$WORK/guided-response"
    record=$(jq .data "$WORK/guided-response")
    assert_equal "$(jq -r .file <<< "$record")" "$OV_HOME/Second.tomb"
    assert_equal "$(jq -r '.key_managed,.key_reused,.key_file' <<< "$record")" "$(printf 'false\ntrue\n%s' "$key")"
    assert_equal "$(wc -l < "$WORK/guided-forges")" "$count"
    assert_equal "$(cat "$key")" encrypted-key-fixture

    printf 'BMcover-image-original\n' > "$cover"; image_hash=$(sha256sum "$cover")
    OV_PARAMS=$(jq -n --arg directory "$OV_HOME" --arg image "$cover" \
        '{name:"Picture",directory:$directory,size_gb:"0.05",auth:"image",image_source:$image,password:"guided-test-not-for-storage"}')
    ov_vault_dispatch > "$WORK/guided-response"
    record=$(jq .data "$WORK/guided-response"); key=$(jq -r .key_file <<< "$record")
    [[ $key == "$OV_HOME/.local/share/octovault/keys/"*/carrier.bmp && $key != "$cover" ]]
    assert_equal "$(sha256sum "$cover")" "$image_hash"
    assert_equal "$(stat -c %a "$key")" 600
    [[ ! -e $(dirname "$key")/recovery.key ]]

    # Older command lines used key_file for a cover. They now create a separate
    # managed carrier instead of overwriting the original photograph.
    OV_PARAMS=$(jq -n --arg directory "$OV_HOME" --arg image "$cover" \
        '{name:"Legacy picture",directory:$directory,size_gb:"0.05",auth:"image",key_file:$image,password:"guided-test-not-for-storage"}')
    ov_vault_dispatch > "$WORK/guided-response"
    assert_equal "$(sha256sum "$cover")" "$image_hash"
    [[ $(jq -r .data.key_file "$WORK/guided-response") != "$cover" ]]

    # A reused carrier reaches the engine as a carrier, never a newly forged key.
    count=$(wc -l < "$WORK/guided-forges")
    OV_PARAMS=$(jq -n --arg directory "$OV_HOME" --arg key "$key" \
        '{name:"Reused picture",directory:$directory,size_gb:"0.05",auth:"image",key_file:$key,use_existing_key:true,password:"guided-test-not-for-storage"}')
    ov_vault_dispatch > "$WORK/guided-response"
    assert_equal "$(jq -r .auth "$WORK/guided-lock-record")" image
    assert_equal "$(wc -l < "$WORK/guided-forges")" "$count"

    # GnuPG identifies the recipient from an existing protected key itself.
    OV_PARAMS=$(jq -n --arg directory "$OV_HOME" --arg key "$original_key" \
        '{name:"Existing OpenPGP",directory:$directory,size_gb:"0.05",auth:"gpg",key_file:$key,use_existing_key:true}')
    ov_vault_dispatch > "$WORK/guided-response"
    assert_equal "$(jq -r .auth "$WORK/guided-lock-record")" gpg
    assert_equal "$(wc -l < "$WORK/guided-forges")" "$count"

    # Carrier failure keeps a usable ordinary encrypted key and a manual record.
    ov_vault_image_embed() { return 1; }
    OV_PARAMS=$(jq -n --arg directory "$OV_HOME" --arg image "$cover" \
        '{name:"Carrier failure",directory:$directory,size_gb:"0.05",auth:"image",image_source:$image,password:"guided-test-not-for-storage"}')
    assert_fails ov_vault_dispatch
    record=$(ov_list vaults | jq -c '.[]|select(.name=="Carrier failure")')
    key=$(jq -r .key_file <<< "$record")
    assert_equal "$(jq -r '.auth,.open_on,.creation_state,.key_managed' <<< "$record")" $'key\nmanual\nready\ntrue'
    [[ -f $key && $key == */recovery.key ]]
    assert_equal "$(cat "$key")" encrypted-key-fixture
    assert_equal "$(sha256sum "$cover")" "$image_hash"

    # Invalid choices fail before allocating a container.
    count=$(wc -l < "$WORK/guided-allocations")
    local params
    for params in \
        '{"name":"../escape"}' '{"name":"."}' '{"name":".."}' \
        '{"name":"bad\nname"}' '{"name":"Conflicting paths","file":"/another.tomb"}' \
        '{"name":"Missing key","use_existing_key":true}' \
        '{"name":"Not a boolean","use_existing_key":"true"}' \
        '{"name":"Missing picture","auth":"image"}' \
        '{"name":"Missing recipient","auth":"gpg"}'; do
        OV_PARAMS=$(jq --arg directory "$OV_HOME" \
            '.+{directory:$directory,size_gb:"0.05",password:"guided-test-not-for-storage"}' <<< "$params")
        assert_fails ov_vault_dispatch
    done
    OV_PARAMS=$(jq -n --arg directory "$OV_HOME" --arg key "$original_key" \
        '{name:"Existing without checkbox",directory:$directory,size_gb:"0.05",key_file:$key,password:"guided-test-not-for-storage"}')
    assert_fails ov_vault_dispatch
    assert_equal "$(wc -l < "$WORK/guided-allocations")" "$count"
    printf 'ok - guided folder creation, managed permissions, existing keys, cover preservation, recoverable carrier failures and pre-allocation validation\n'
)

integration() {
    [[ $EUID == 0 ]] || { printf 'Integration requires root.\n' >&2; exit 1; }
    for program in tomb cryptsetup losetup pinentry-octovault rsync; do command -v "$program" >/dev/null; done
    [[ -e /dev/mapper/control ]] || { printf 'Device mapper unavailable.\n' >&2; exit 1; }
    INTEGRATION_RUNNING=true
    INTEGRATION_USER="octovault-ci-$(date +%s)"
    chmod 0755 "$WORK"
    useradd --no-create-home --home-dir "$OV_HOME" --shell /bin/bash "$INTEGRATION_USER"
    OV_USER=$INTEGRATION_USER; OV_UID=$(id -u "$OV_USER")
    chown "$OV_UID:$(id -g "$OV_USER")" "$OV_HOME"
    chmod 0700 "$OV_HOME"
    local response id file="$OV_HOME/ci.tomb" key source="$OV_HOME/Documents"
    OV_PARAMS=$(jq -n --arg directory "$OV_HOME" '{name:"ci",directory:$directory,size_gb:"0.05",auth:"key",password:"OctoVault-CI-only-passphrase",open_on:"manual"}')
    OV_OP=vault.create
    ov_vault_dispatch > "$WORK/response.json" || { cat "$WORK/response.json" >&2; return 1; }
    response=$(cat "$WORK/response.json"); id=$(jq -er .data.id <<< "$response")
    ov_load vaults "$id"
    key=$(ov_vault_field "$OV_RECORD" key_file)
    assert_equal "$key" "$OV_HOME/.local/share/octovault/keys/$id/vault.key"
    assert_equal "$(stat -c %u "$file")" "$OV_UID"
    assert_equal "$(stat -c %u "$key")" "$OV_UID"
    assert_equal "$(stat -c %a "$key")" 600
    assert_equal "$(stat -c %a "$(dirname "$key")")" 700
    OV_PARAMS=$(jq -n --arg id "$id" '{id:$id,password:"OctoVault-CI-only-passphrase"}')
    OV_OP=vault.open; ov_vault_dispatch >/dev/null
    ov_as_user mkdir "$source"
    printf 'important\n' | ov_as_user tee "$source/data" >/dev/null
    OV_PARAMS=$(jq -n --arg id "$id" --arg source "$source" '{id:$id,source:$source,relative:"Documents",password:"OctoVault-CI-only-passphrase"}')
    OV_OP=migration.add; ov_vault_dispatch >/dev/null
    [[ -f $source/data ]]
    OV_PARAMS=$(jq -n --arg id "$id" '{id:$id}'); OV_OP=vault.close; ov_vault_dispatch >/dev/null
    [[ ! -e $source/data ]]
    printf 'independent\n' | ov_as_user tee "$source/local" >/dev/null
    OV_PARAMS=$(jq -n --arg id "$id" '{id:$id,password:"OctoVault-CI-only-passphrase"}'); OV_OP=vault.open; ov_vault_dispatch >/dev/null
    [[ -f $source/data && ! -e $source/local ]]
    OV_OP=vault.close; ov_vault_dispatch >/dev/null
    assert_equal "$(cat "$source/local")" independent
    # Imported native metadata must never cause root writes through symlinks;
    # executable native hooks stay dormant until the user explicitly trusts them.
    local mountpoint guard="$WORK/root-owned-guard"
    printf 'must stay unchanged\n' > "$guard"; chmod 0600 "$guard"
    ov_load vaults "$id"; mountpoint=$(ov_vault_field "$OV_RECORD" mountpoint)
    OV_OP=vault.open; ov_vault_dispatch >/dev/null
    local metadata
    for metadata in .uid .tty .host .last .cleanexit; do
        ov_as_user ln -sf "$guard" "$mountpoint/$metadata"
    done
    printf '#!/bin/sh\ntouch "$HOME/untrusted-hook-ran"\n' | ov_as_user tee "$mountpoint/exec-hooks" >/dev/null
    ov_as_user chmod 0700 "$mountpoint/exec-hooks"
    OV_OP=vault.close; ov_vault_dispatch >/dev/null
    OV_OP=vault.open; ov_vault_dispatch >/dev/null
    assert_equal "$(cat "$guard")" 'must stay unchanged'
    assert_equal "$(stat -c %u "$guard")" 0
    [[ ! -e $OV_HOME/untrusted-hook-ran ]]
    OV_OP=vault.close; ov_vault_dispatch >/dev/null
    assert_equal "$(cat "$guard")" 'must stay unchanged'
    printf 'ok - real nonroot-owner lifecycle, migration, independent closed locations, metadata symlinks and untrusted hooks\n'
    # Exercise the released engine's passphrase descriptions and carrier/key
    # interfaces, not mocks: percent signs must survive unchanged.
    OV_PARAMS=$(jq -n --arg id "$id" '{id:$id,old_password:"OctoVault-CI-only-passphrase",password:"OctoVault-rotated-50%-pass"}')
    OV_OP=vault.passwd; ov_vault_dispatch >/dev/null
    OV_PARAMS=$(jq -n --arg id "$id" '{id:$id,password:"OctoVault-rotated-50%-pass"}')
    OV_OP=vault.open; ov_vault_dispatch >/dev/null
    OV_OP=vault.close; ov_vault_dispatch >/dev/null
    printf 'ok - real key passphrase rotation and percent-sign unlock\n'
    local text_key="$OV_HOME/ci-key.txt" image_key="$OV_HOME/ci-key.bmp" replacement="$OV_HOME/replacement.key"
    OV_PARAMS=$(jq -n --arg id "$id" --arg output "$text_key" '{id:$id,format:"text",output:$output}')
    OV_OP=vault.key-export; ov_vault_dispatch >/dev/null
    OV_PARAMS=$(jq -n --arg id "$id" --arg key "$text_key" '{id:$id,auth:"text",key_file:$key}')
    OV_OP=vault.update; ov_vault_dispatch >/dev/null
    OV_PARAMS=$(jq -n --arg id "$id" '{id:$id,password:"OctoVault-rotated-50%-pass"}')
    OV_OP=vault.open; ov_vault_dispatch >/dev/null
    OV_OP=vault.close; ov_vault_dispatch >/dev/null
    printf 'ok - real text-carrier export and unlock with included cipher\n'
    cc -std=c11 -O2 -Wall -Wextra -Werror "$PROJECT/tests/steghide-driver.c" -o "$WORK/cover-generator"
    ov_as_user "$WORK/cover-generator" --make-cover "$image_key"
    OV_PARAMS=$(jq -n --arg id "$id" --arg output "$image_key" '{id:$id,format:"image",output:$output,password:"OctoVault-rotated-50%-pass"}')
    OV_OP=vault.key-export; ov_vault_dispatch >/dev/null
    OV_PARAMS=$(jq -n --arg id "$id" --arg key "$image_key" '{id:$id,auth:"image",key_file:$key}')
    OV_OP=vault.update; ov_vault_dispatch >/dev/null
    OV_PARAMS=$(jq -n --arg id "$id" '{id:$id,password:"OctoVault-rotated-50%-pass"}')
    OV_OP=vault.open; ov_vault_dispatch >/dev/null
    OV_OP=vault.close; ov_vault_dispatch >/dev/null
    printf 'ok - real image-carrier export and unlock through descriptor-only helper\n'
    OV_VAULT_PASSWORD='OctoVault-replacement-75%-pass'
    ov_vault_temporary
    ov_vault_tomb forge -k "$OV_VAULT_TEMP_DIR/replacement-forged.key"
    ov_vault_publish "$OV_VAULT_TEMP_DIR/replacement-forged.key" "$replacement"
    OV_PARAMS=$(jq -n --arg id "$id" --arg key "$replacement" '{id:$id,new_key_file:$key,old_password:"OctoVault-rotated-50%-pass",password:"OctoVault-replacement-75%-pass"}')
    OV_OP=vault.setkey; ov_vault_dispatch >/dev/null
    OV_PARAMS=$(jq -n --arg id "$id" '{id:$id,password:"OctoVault-replacement-75%-pass"}')
    OV_OP=vault.open; ov_vault_dispatch >/dev/null
    OV_OP=vault.close; ov_vault_dispatch >/dev/null
    printf 'ok - real LUKS key replacement from image authentication and reopen\n' 

    # New containers can reuse a user's existing protected key without forging
    # or modifying it. The passphrase is only supplied for this operation.
    local reused_id existing_hash
    existing_hash=$(sha256sum "$replacement")
    ov_resource_unlock
    OV_PARAMS=$(jq -n --arg directory "$OV_HOME" --arg key "$replacement" \
        '{name:"reuse.tomb",directory:$directory,key_file:$key,use_existing_key:true,size_gb:"0.05",password:"OctoVault-replacement-75%-pass",open_on:"manual"}')
    OV_OP=vault.create; ov_vault_dispatch > "$WORK/response.json"
    reused_id=$(jq -er .data.id "$WORK/response.json")
    assert_equal "$(jq -r .data.file "$WORK/response.json")" "$OV_HOME/reuse.tomb"
    assert_equal "$(sha256sum "$replacement")" "$existing_hash"
    OV_PARAMS=$(jq -n --arg id "$reused_id" '{id:$id,password:"OctoVault-replacement-75%-pass"}')
    OV_OP=vault.open; ov_vault_dispatch >/dev/null
    OV_OP=vault.close; ov_vault_dispatch >/dev/null
    printf 'ok - real existing-key reuse creates another container without modifying the key\n'

    local auth carrier_id carrier_key cover="$OV_HOME/guided-cover.bmp" cover_hash
    ov_as_user "$WORK/cover-generator" --make-cover "$cover"; cover_hash=$(sha256sum "$cover")
    for auth in text image; do
        ov_resource_unlock
        OV_PARAMS=$(jq -n --arg directory "$OV_HOME" --arg auth "$auth" --arg cover "$cover" \
            '{name:("guided-"+$auth),directory:$directory,auth:$auth,size_gb:"0.05",password:"OctoVault-carrier-create-50%-pass",open_on:"manual"} |
             if $auth=="image" then .image_source=$cover else . end')
        OV_OP=vault.create; ov_vault_dispatch > "$WORK/response.json"
        carrier_id=$(jq -er .data.id "$WORK/response.json"); carrier_key=$(jq -er .data.key_file "$WORK/response.json")
        [[ $carrier_key == "$OV_HOME/.local/share/octovault/keys/$carrier_id/"* && $carrier_key != "$cover" ]]
        assert_equal "$(stat -c %u "$carrier_key")" "$OV_UID"
        assert_equal "$(stat -c %a "$carrier_key")" 600
        assert_equal "$(stat -c %a "$(dirname "$carrier_key")")" 700
        [[ ! -e $(dirname "$carrier_key")/recovery.key ]]
        OV_PARAMS=$(jq -n --arg id "$carrier_id" '{id:$id,password:"OctoVault-carrier-create-50%-pass"}')
        OV_OP=vault.open; ov_vault_dispatch >/dev/null
        OV_OP=vault.close; ov_vault_dispatch >/dev/null
        assert_equal "$(sha256sum "$cover")" "$cover_hash"
    done
    printf 'ok - real managed image/text creation and unlock, private carrier permissions and original cover preservation\n'

    # The disposable user's software OpenPGP key exercises the same public-key
    # mode as a compatible hardware token without requiring physical hardware.
    local recipient pgp_id pgp_key
    ov_as_user gpg --batch --pinentry-mode loopback --passphrase '' --quick-generate-key \
        'OctoVault disposable CI <octovault-ci@example.invalid>' default default 1d >&2
    recipient=$(ov_as_user gpg --batch --with-colons --list-keys 'octovault-ci@example.invalid' |
        awk -F: '$1=="fpr"{print $10;exit}')
    [[ -n $recipient ]]
    ov_resource_unlock
    OV_PARAMS=$(jq -n --arg directory "$OV_HOME" --arg recipient "$recipient" \
        '{name:"software-openpgp",directory:$directory,auth:"gpg",recipient:$recipient,size_gb:"0.05",open_on:"manual"}')
    OV_OP=vault.create; ov_vault_dispatch > "$WORK/response.json"
    pgp_id=$(jq -er .data.id "$WORK/response.json"); pgp_key=$(jq -er .data.key_file "$WORK/response.json")
    assert_equal "$(stat -c %a "$pgp_key")" 600
    OV_PARAMS=$(jq -n --arg id "$pgp_id" '{id:$id}')
    OV_OP=vault.open; ov_vault_dispatch >/dev/null
    OV_OP=vault.close; ov_vault_dispatch >/dev/null
    existing_hash=$(sha256sum "$pgp_key")
    ov_resource_unlock
    OV_PARAMS=$(jq -n --arg directory "$OV_HOME" --arg key "$pgp_key" \
        '{name:"reuse-openpgp",directory:$directory,auth:"gpg",key_file:$key,use_existing_key:true,size_gb:"0.05",open_on:"manual"}')
    OV_OP=vault.create; ov_vault_dispatch > "$WORK/response.json"
    pgp_id=$(jq -er .data.id "$WORK/response.json")
    OV_PARAMS=$(jq -n --arg id "$pgp_id" '{id:$id}')
    OV_OP=vault.open; ov_vault_dispatch >/dev/null
    OV_OP=vault.close; ov_vault_dispatch >/dev/null
    assert_equal "$(sha256sum "$pgp_key")" "$existing_hash"
    if grep -Rq -E 'OctoVault-(CI-only|rotated|replacement|carrier-create)' "$OV_ROOT"; then
        printf 'A fixture passphrase was persisted in vault state.\n' >&2; return 1
    fi
    printf 'ok - real software OpenPGP generation and existing-key reuse without a supplied recipient; no stored passphrases\n'
}

if [[ ${1:-} == --integration ]]; then integration
else test_validation; test_native_binds; test_compare; test_migration; test_interrupted_migration; test_device_identity; test_unknown_state; test_secret_arguments; test_container_pin; test_guided_creation
fi
