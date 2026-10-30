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
    local status=$? mountpoint loop mapper device container holder holder_file
    set +e
    if [[ ${INTEGRATION_RUNNING:-false} == true ]]; then
        # Only signal the recorded sleep fixtures owned by this test user.
        # Stop them before unmount cleanup if the force-close assertion fails.
        for holder_file in "$WORK/holder-reused.pid" "$WORK/holder-original.pid"; do
            [[ -f $holder_file ]] || continue
            read -r holder < "$holder_file"
            if [[ $holder =~ ^[0-9]+$ &&
                  $(stat -c %u "/proc/$holder" 2>/dev/null) == "$OV_UID" &&
                  $(cat "/proc/$holder/comm" 2>/dev/null) == sleep ]]; then
                kill "$holder" 2>/dev/null || true
            fi
        done
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
    # Native Tomb accepts a last record without a final line feed. Appending
    # another mapping must preserve both complete records.
    printf 'Earlier Earlier' > "$dir/bind-hooks"
    ov_migration_write_bind "$dir" Documents 'My Documents'
    mapfile -d '' -t values < <(ov_vault_read_binds "$dir/bind-hooks")
    assert_equal "${#values[@]}" 4
    assert_equal "${values[0]}" Earlier
    assert_equal "${values[1]}" Earlier
    assert_equal "${values[2]}" Documents
    assert_equal "${values[3]}" 'My Documents'
    printf 'invalid existing mapping' > "$dir/bind-hooks"
    assert_fails ov_migration_write_bind "$dir" Other Other
    assert_equal "$(cat "$dir/bind-hooks")" 'invalid existing mapping'
    printf 'ok - native escaped-space binds, literal metacharacters and atomic newline-safe updates\n'
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

test_failed_copy_preserves_original() (
    local source="$OV_HOME/Copy failure" mountpoint="$OV_HOME/copy-failure-vault"
    local staging="$OV_HOME/.octovault-staging-copyfailure" record migration
    mkdir -p "$source" "$mountpoint"
    printf 'original data\n' > "$source/data"
    record=$(jq -n --arg mount "$mountpoint" '{id:"copyfailurevault",mountpoint:$mount}')
    migration=$(jq -n --arg source "$source" --arg staging "$staging" \
        '{migration_id:"copyfailure",source:$source,staging:$staging,relative:"Data",stage:"prepared"}')
    ov_migration_save copyfailurevault copyfailure "$migration"
    ov_vault_is_open() { return 0; }
    rsync() { printf 'partial copy\n' > "${!#}/partial"; return 23; }
    if (ov_migration_finish "$record" "$migration") > "$WORK/copy-failure.json" 2>/dev/null; then
        printf 'Expected copying to fail\n' >&2; exit 1
    fi
    assert_equal "$(jq -r .error.code "$WORK/copy-failure.json")" migration_failed
    jq -e --arg source "$source" --arg target "$mountpoint/Data" \
        '(.error.retained_paths | index($source) != null) and (.error.retained_paths | index($target) != null)' "$WORK/copy-failure.json" >/dev/null
    assert_equal "$(cat "$source/data")" 'original data'
    [[ ! -e $staging && ! -L $staging && -f $mountpoint/Data/partial ]]
    assert_equal "$(jq -r .stage "$OV_ROOT/migrations/copyfailurevault/copyfailure.json")" prepared
    printf 'ok - failed initial copy leaves the original folder and prepared recovery record intact\n'
)

test_symlink_destination_preserves_original() (
    local source="$OV_HOME/Symlink destination Documents" mountpoint="$OV_HOME/symlink-destination-vault"
    local staging="$OV_HOME/.octovault-staging-symlinkdestination" external="$OV_HOME/external-destination" record migration
    mkdir -p "$source" "$mountpoint" "$external/Data"
    printf 'original stays here\n' > "$source/data"
    printf 'external stays unchanged\n' > "$external/Data/data"
    ln -s "$external" "$mountpoint/Linked"
    record=$(jq -n --arg mount "$mountpoint" '{id:"symlinkdestinationvault",mountpoint:$mount}')
    migration=$(jq -n --arg source "$source" --arg staging "$staging" \
        '{migration_id:"symlinkdestination",source:$source,staging:$staging,relative:"Linked/Data",stage:"prepared"}')
    ov_migration_save symlinkdestinationvault symlinkdestination "$migration"
    ov_vault_is_open() { return 0; }
    rsync() { touch "$WORK/unexpected-symlink-destination-copy"; return 1; }
    if (ov_migration_finish "$record" "$migration") > "$WORK/symlink-destination.json" 2>/dev/null; then
        printf 'Expected symlink destination rejection\n' >&2; exit 1
    fi
    assert_equal "$(jq -r .error.code "$WORK/symlink-destination.json")" unsafe_path
    assert_equal "$(cat "$source/data")" 'original stays here'
    assert_equal "$(cat "$external/Data/data")" 'external stays unchanged'
    [[ -L $mountpoint/Linked && ! -e $staging && ! -e $WORK/unexpected-symlink-destination-copy ]]
    assert_equal "$(jq -r .stage "$OV_ROOT/migrations/symlinkdestinationvault/symlinkdestination.json")" prepared
    printf 'ok - symlink destination parents are rejected before copying or moving original data\n'
)

test_closed_recovery_rechecks_destination() (
    local initial_stage source mountpoint staging external record migration mid
    local MOCK_RECOVERY_OPEN=false
    for initial_stage in prepared staged; do
        mid="closedrecovery$initial_stage"
        source="$OV_HOME/Closed recovery $initial_stage"
        mountpoint="$OV_HOME/closed-recovery-vault-$initial_stage"
        staging="$OV_HOME/.octovault-staging-$mid"
        external="$OV_HOME/closed-recovery-external-$initial_stage"
        mkdir -p "$mountpoint" "$external/Data"
        printf 'external remains unchanged\n' > "$external/Data/data"
        if [[ $initial_stage == prepared ]]; then
            mkdir -p "$source"
            printf 'original recovery data\n' > "$source/data"
        else
            mkdir -p "$staging"
            printf 'original recovery data\n' > "$staging/data"
        fi
        record=$(jq -n --arg mount "$mountpoint" '{id:"closedrecoveryvault",mountpoint:$mount}')
        migration=$(jq -n --arg mid "$mid" --arg source "$source" --arg staging "$staging" --arg stage "$initial_stage" \
            '{migration_id:$mid,source:$source,staging:$staging,relative:"Linked/Data",stage:$stage}')
        ov_migration_save closedrecoveryvault "$mid" "$migration"
        MOCK_RECOVERY_OPEN=false
        ov_vault_is_open() { [[ $MOCK_RECOVERY_OPEN == true ]]; }
        ov_vault_open_record() {
            # The locked user mountpoint was empty. Opening reveals an unsafe
            # destination parent stored inside the encrypted filesystem.
            ln -s "$external" "$mountpoint/Linked"
            MOCK_RECOVERY_OPEN=true
        }
        rsync() { touch "$WORK/unexpected-closed-recovery-copy"; return 1; }
        if (ov_migration_finish "$record" "$migration") > "$WORK/closed-recovery-$initial_stage.json" 2>/dev/null; then
            printf 'Expected revealed symlink destination rejection for %s\n' "$initial_stage" >&2; exit 1
        fi
        assert_equal "$(jq -r .error.code "$WORK/closed-recovery-$initial_stage.json")" unsafe_path
        assert_equal "$(cat "$external/Data/data")" 'external remains unchanged'
        [[ -L $mountpoint/Linked && ! -e $WORK/unexpected-closed-recovery-copy ]]
        if [[ $initial_stage == prepared ]]; then
            assert_equal "$(cat "$source/data")" 'original recovery data'
            [[ ! -e $staging && ! -L $staging ]]
        else
            assert_equal "$(cat "$staging/data")" 'original recovery data'
            [[ -d $source && ! -e $source/data ]]
        fi
        assert_equal "$(jq -r .stage "$OV_ROOT/migrations/closedrecoveryvault/$mid.json")" "$initial_stage"
    done
    printf 'ok - prepared and legacy recovery recheck destination symlinks revealed when unlocking\n'
)

test_full_vault_preserves_original() (
    local source="$OV_HOME/Too large" mountpoint="$OV_HOME/small-vault"
    local staging="$OV_HOME/.octovault-staging-capacity" record migration
    mkdir -p "$source" "$mountpoint"
    printf 'does not fit\n' > "$source/data"
    record=$(jq -n --arg mount "$mountpoint" '{id:"capacityvault",mountpoint:$mount}')
    migration=$(jq -n --arg source "$source" --arg staging "$staging" \
        '{migration_id:"capacity",source:$source,staging:$staging,relative:"Data",stage:"prepared"}')
    ov_migration_save capacityvault capacity "$migration"
    ov_vault_is_open() { return 0; }
    # rsync uses exit 11 for a file I/O error, including a full destination.
    rsync() { return 11; }
    if (ov_migration_finish "$record" "$migration") > "$WORK/capacity-failure.json" 2>/dev/null; then
        printf 'Expected full-vault copy failure\n' >&2; exit 1
    fi
    assert_equal "$(jq -r .error.code "$WORK/capacity-failure.json")" migration_failed
    assert_equal "$(cat "$source/data")" 'does not fit'
    [[ ! -e $staging && -d $mountpoint/Data ]]
    assert_equal "$(jq -r .stage "$OV_ROOT/migrations/capacityvault/capacity.json")" prepared
    printf 'ok - a full vault stops copying without moving or removing the original\n'
)

test_legacy_staging_recovery() (
    local source="$OV_HOME/Legacy Documents" mountpoint="$OV_HOME/legacy-vault"
    local staging="$OV_HOME/.octovault-staging-legacy" record migration
    mkdir -p "$staging" "$mountpoint"
    printf 'legacy original\n' > "$staging/data"
    record=$(jq -n --arg mount "$mountpoint" '{id:"legacyvault",mountpoint:$mount}')
    migration=$(jq -n --arg source "$source" --arg staging "$staging" \
        '{migration_id:"legacy",source:$source,staging:$staging,relative:"Data",stage:"staged"}')
    ov_migration_save legacyvault legacy "$migration"
    ov_vault_is_open() { return 0; }
    rsync() {
        [[ -d $source && ! -e $source/data ]] || exit 81
        touch "$WORK/legacy-placeholder-before-copy"
        return 23
    }
    if (ov_migration_finish "$record" "$migration") > "$WORK/legacy-failure.json" 2>/dev/null; then
        printf 'Expected interrupted legacy copy\n' >&2; exit 1
    fi
    assert_equal "$(jq -r .error.code "$WORK/legacy-failure.json")" migration_failed
    jq -e --arg staging "$staging" \
        '.error.retained_paths | index($staging) != null' "$WORK/legacy-failure.json" >/dev/null
    [[ -d $source && -f $WORK/legacy-placeholder-before-copy ]]
    assert_equal "$(cat "$staging/data")" 'legacy original'
    assert_equal "$(jq -r .stage "$OV_ROOT/migrations/legacyvault/legacy.json")" staged
    ov_save vaults legacyvault "$record"
    OV_PARAMS='{"id":"legacyvault","migration_id":"legacy","action":"rollback"}'
    printf 'new underlying file\n' > "$source/local"
    if (ov_migration_recover) > "$WORK/occupied-rollback.json" 2>/dev/null; then
        printf 'Expected occupied-folder rollback rejection\n' >&2; exit 1
    fi
    assert_equal "$(cat "$source/local")" 'new underlying file'
    assert_equal "$(cat "$staging/data")" 'legacy original'
    assert_equal "$(jq -r .error.code "$WORK/occupied-rollback.json")" conflict
    rm -- "$source/local"
    ov_migration_recover > "$WORK/empty-placeholder-rollback.json"
    assert_equal "$(jq -r .data.stage "$WORK/empty-placeholder-rollback.json")" rolled_back
    assert_equal "$(cat "$source/data")" 'legacy original'
    [[ ! -e $staging ]]
    printf 'ok - failed legacy resume preserves originals, protects new local files, and restores an empty placeholder\n'
)

test_prepared_rollback() (
    local source="$OV_HOME/Rollback Documents" mountpoint="$OV_HOME/rollback-vault"
    local staging="$OV_HOME/.octovault-staging-preparedrollback" migration
    mkdir -p "$source" "$mountpoint/Data"
    printf 'untouched original\n' > "$source/data"
    printf 'retained encrypted partial\n' > "$mountpoint/Data/partial"
    ov_save vaults preparedrollbackvault "$(jq -n --arg mount "$mountpoint" '{mountpoint:$mount}')"
    migration=$(jq -n --arg source "$source" --arg staging "$staging" \
        '{migration_id:"preparedrollback",source:$source,staging:$staging,relative:"Data",stage:"prepared"}')
    ov_migration_save preparedrollbackvault preparedrollback "$migration"
    OV_PARAMS='{"id":"preparedrollbackvault","migration_id":"preparedrollback","action":"rollback"}'
    ov_migration_recover > "$WORK/prepared-rollback.json"
    assert_equal "$(jq -r .data.stage "$WORK/prepared-rollback.json")" rolled_back
    assert_equal "$(cat "$source/data")" 'untouched original'
    assert_equal "$(cat "$mountpoint/Data/partial")" 'retained encrypted partial'
    [[ ! -e $staging ]]
    assert_equal "$(jq -r .stage "$OV_ROOT/migrations/preparedrollbackvault/preparedrollback.json")" rolled_back
    printf 'ok - rollback after an initial copy failure preserves the original and encrypted partial copy\n'
)

test_terminal_recovery_actions() (
    local source="$OV_HOME/Terminal recovery Documents" stage action expected migration output
    mkdir -p "$source"
    printf 'original stays visible\n' > "$source/data"
    ov_save vaults terminalrecoveryvault '{"mountpoint":"/unused-terminal-vault"}'
    ov_vault_password() { touch "$WORK/unexpected-terminal-authentication"; }
    ov_vault_open_record() { touch "$WORK/unexpected-terminal-open"; }
    ov_migration_finish() { touch "$WORK/unexpected-terminal-copy"; }
    for stage in rolled_back complete; do
        migration=$(jq -n --arg source "$source" --arg stage "$stage" \
            '{migration_id:"terminalmove",source:$source,relative:"Documents",stage:$stage}')
        ov_migration_save terminalrecoveryvault terminalmove "$migration"
        for action in resume rollback unknown; do
            OV_PARAMS=$(jq -n --arg action "$action" \
                '{id:"terminalrecoveryvault",migration_id:"terminalmove",action:$action}')
            expected=''
            case "$stage:$action" in
                *:unknown) expected=invalid_action ;;
                rolled_back:*) expected=migration_cancelled ;;
                complete:*) expected=already_protected ;;
            esac
            output="$WORK/terminal-$stage-$action.json"
            if [[ -n $expected ]]; then
                if (ov_migration_recover) > "$output" 2>/dev/null; then
                    printf 'Terminal recovery falsely accepted %s on %s\n' "$action" "$stage" >&2; exit 1
                fi
                assert_equal "$(jq -r .error.code "$output")" "$expected"
            else
                ov_migration_recover > "$output"
                jq -e --arg stage "$stage" '.ok and .data.stage == $stage' "$output" >/dev/null
            fi
            assert_equal "$(jq -r .stage "$OV_ROOT/migrations/terminalrecoveryvault/terminalmove.json")" "$stage"
            assert_equal "$(cat "$source/data")" 'original stays visible'
            [[ ! -e $WORK/unexpected-terminal-authentication && ! -e $WORK/unexpected-terminal-open &&
               ! -e $WORK/unexpected-terminal-copy ]]
        done
    done
    printf 'ok - stale recovery actions cannot claim resumed protection or restoration after a terminal outcome\n'
)

test_native_protection_status() (
    local status_mountpoint="$OV_HOME/status-vault" source="$OV_HOME/Original file" record status
    local MOCK_STATUS_OPEN=true MOCK_STATUS_EXPOSED=true
    mkdir -p "$status_mountpoint" "$OV_HOME/Unmapped folder"
    printf 'direct vault data\n' > "$status_mountpoint/direct-file"
    touch "$OV_HOME/status.tomb"
    record=$(jq -n --arg mount "$status_mountpoint" --arg file "$OV_HOME/status.tomb" \
        '{id:"statusvault",mountpoint:$mount,file:$file}')
    ov_vault_active_mount() { printf '%s\n' "$status_mountpoint"; }
    ov_vault_is_open() { [[ $MOCK_STATUS_OPEN == true ]]; }
    ov_vault_is_exposed() { [[ $MOCK_STATUS_OPEN == true && $MOCK_STATUS_EXPOSED == true ]]; }
    ov_vault_attached() { return 1; }
    findmnt() { [[ $* == *"--mountpoint $source"* ]]; }
    status=$(ov_vault_status "$record")
    jq -e '.status == "open" and .protected_locations == []' <<< "$status" >/dev/null
    [[ -f $status_mountpoint/direct-file ]]
    # Historical completion is not a current native mapping.
    ov_migration_save statusvault historicalstatus \
        '{"migration_id":"historicalstatus","relative":"OldDocuments","stage":"complete"}'
    status=$(ov_vault_status "$record")
    jq -e '.protected_locations == []' <<< "$status" >/dev/null
    printf 'protected bytes\n' > "$status_mountpoint/ProtectedFile"
    ln "$status_mountpoint/ProtectedFile" "$source"
    ov_migration_write_bind "$status_mountpoint" ProtectedFile 'Original file'
    ov_migration_write_bind "$status_mountpoint" MissingFolder 'Unmapped folder'
    status=$(ov_vault_status "$record")
    jq -e --arg source "$source" --arg inactive "$OV_HOME/Unmapped folder" \
        '.protected_locations == [{source:$source,relative:"ProtectedFile",active:true},
          {source:$inactive,relative:"MissingFolder",active:false}]' <<< "$status" >/dev/null
    MOCK_STATUS_EXPOSED=false
    status=$(ov_vault_status "$record"); jq -e '.protected_locations == null' <<< "$status" >/dev/null
    MOCK_STATUS_EXPOSED=true; MOCK_STATUS_OPEN=false
    status=$(ov_vault_status "$record"); jq -e '.status == "closed" and .protected_locations == null' <<< "$status" >/dev/null
    MOCK_STATUS_OPEN=true
    for status in 'invalid three fields' '../outside Documents' 'Documents ../outside'; do
        printf '%s\n' "$status" > "$status_mountpoint/bind-hooks"
        status=$(ov_vault_status "$record")
        jq -e '.protected_locations == null' <<< "$status" >/dev/null
    done
    rm -- "$status_mountpoint/bind-hooks"
    ln -s "$status_mountpoint/direct-file" "$status_mountpoint/bind-hooks"
    status=$(ov_vault_status "$record"); jq -e '.protected_locations == null' <<< "$status" >/dev/null
    printf 'ok - protection status comes from exposed native mappings, distinguishes direct files, and stays unknown when unavailable\n'
)

test_closed_vault_protection() (
    local source="$OV_HOME/Closed protect Documents" mountpoint="$OV_HOME/closed-protect-vault" record
    local MOCK_CLOSED_PROTECT_OPEN=false
    mkdir -p "$source" "$mountpoint"
    printf 'closed-vault original\n' > "$source/data"
    record=$(jq -n --arg mount "$mountpoint" --arg file "$OV_HOME/closed-protect.tomb" \
        '{mountpoint:$mount,file:$file,auth:"key"}')
    ov_save vaults closedprotectvault "$record"
    ov_vault_is_open() { [[ $MOCK_CLOSED_PROTECT_OPEN == true ]]; }
    ov_vault_is_exposed() { [[ $MOCK_CLOSED_PROTECT_OPEN == true ]]; }
    ov_vault_password() {
        OV_VAULT_PASSWORD=$(ov_param password '')
        printf 'credentials\n' >> "$WORK/closed-protect-credentials"
    }
    ov_vault_open_record() {
        [[ ${OV_EVENT_RUNNING:-0} == 1 && ${OV_VAULT_PASSWORD:-} == fixture-passphrase ]] || exit 83
        printf 'open\n' >> "$WORK/closed-protect-transitions"
        MOCK_CLOSED_PROTECT_OPEN=true
        # The first open exposes storage; the verification reopen stands in
        # for the kernel bind exposing the protected data at its original path.
        if [[ -d $mountpoint/Documents ]]; then rsync -aHAX "$mountpoint/Documents/" "$source/"; fi
    }
    ov_vault_close_record() {
        [[ ${OV_EVENT_RUNNING:-0} == 1 ]] || exit 84
        printf 'close\n' >> "$WORK/closed-protect-transitions"; MOCK_CLOSED_PROTECT_OPEN=false
    }
    findmnt() {
        if [[ $* == *'--json --list --output TARGET'* ]]; then printf '{"filesystems":[]}\n'; else return 1; fi
    }
    ov_vault_mapping_matches() { return 0; }
    OV_PARAMS=$(jq -n --arg source "$source" \
        '{id:"closedprotectvault",source:$source,relative:"Documents",password:"fixture-passphrase"}')
    ov_migration_add > "$WORK/closed-protect-result.json"
    jq -e '.ok and .data.stage == "complete"' "$WORK/closed-protect-result.json" >/dev/null
    assert_equal "$(cat "$source/data")" 'closed-vault original'
    assert_equal "$(cat "$WORK/closed-protect-credentials")" credentials
    assert_equal "$(cat "$WORK/closed-protect-transitions")" $'open\nclose\nopen'
    [[ -f $mountpoint/Documents/data ]]
    printf 'ok - protecting into a closed vault reuses supplied credentials and suppresses intermediate vault events\n'
)

test_closed_vault_partial_conflict() (
    local source="$OV_HOME/Retried protect Documents" mountpoint="$OV_HOME/retried-protect-vault" record
    local MOCK_RETRY_OPEN=false
    mkdir -p "$source" "$mountpoint/Documents"
    printf 'original retained\n' > "$source/data"
    printf 'encrypted partial retained\n' > "$mountpoint/Documents/partial"
    record=$(jq -n --arg mount "$mountpoint" --arg file "$OV_HOME/retried-protect.tomb" \
        '{mountpoint:$mount,file:$file,auth:"key"}')
    ov_save vaults retriedprotectvault "$record"
    ov_vault_is_open() { [[ $MOCK_RETRY_OPEN == true ]]; }
    ov_vault_is_exposed() { [[ $MOCK_RETRY_OPEN == true ]]; }
    ov_vault_open_record() { MOCK_RETRY_OPEN=true; }
    findmnt() {
        if [[ $* == *'--json --list --output TARGET'* ]]; then printf '{"filesystems":[]}\n'; else return 1; fi
    }
    OV_PARAMS=$(jq -n --arg source "$source" \
        '{id:"retriedprotectvault",source:$source,relative:"Documents",password:"fixture-passphrase"}')
    if (ov_migration_add) > "$WORK/retried-protect-result.json" 2>/dev/null; then
        printf 'Expected preserved partial-destination conflict\n' >&2; exit 1
    fi
    assert_equal "$(jq -r .error.code "$WORK/retried-protect-result.json")" exists
    assert_equal "$(cat "$source/data")" 'original retained'
    assert_equal "$(cat "$mountpoint/Documents/partial")" 'encrypted partial retained'
    [[ ! -d $OV_ROOT/migrations/retriedprotectvault ]]
    printf 'ok - fresh protection never replaces a retained partial encrypted destination\n'
)

test_published_mapping_blocks_rollback() (
    local source="$OV_HOME/Published Documents" mountpoint="$OV_HOME/published-vault"
    local staging="$OV_HOME/.octovault-staging-publishedrollback" migration
    mkdir -p "$staging" "$mountpoint/Data"
    printf 'staged original\n' > "$staging/data"
    printf 'encrypted data\n' > "$mountpoint/Data/data"
    ov_save vaults publishedrollbackvault "$(jq -n --arg mount "$mountpoint" '{mountpoint:$mount}')"
    migration=$(jq -n --arg source "$source" --arg staging "$staging" \
        '{migration_id:"publishedrollback",source:$source,staging:$staging,relative:"Data",stage:"copied"}')
    ov_migration_save publishedrollbackvault publishedrollback "$migration"
    # Simulate a crash after publishing bind-hooks but before saving mapped.
    ov_migration_write_bind "$mountpoint" Data 'Published Documents'
    ov_vault_is_exposed() { return 0; }
    OV_PARAMS='{"id":"publishedrollbackvault","migration_id":"publishedrollback","action":"rollback"}'
    if (ov_migration_recover) > "$WORK/published-rollback.json" 2>/dev/null; then
        printf 'Expected a published mapping to block rollback\n' >&2; exit 1
    fi
    jq -e '.ok == false and (.error.code | length > 0)' "$WORK/published-rollback.json" >/dev/null
    [[ ! -e $source && ! -L $source ]]
    assert_equal "$(cat "$staging/data")" 'staged original'
    assert_equal "$(cat "$mountpoint/Data/data")" 'encrypted data'
    assert_equal "$(jq -r .stage "$OV_ROOT/migrations/publishedrollbackvault/publishedrollback.json")" copied
    printf 'ok - rollback cannot restore plaintext beneath an already published folder mapping\n'
)

test_symlink_staging_blocks_rollback() (
    local source="$OV_HOME/Symlink Documents" mountpoint="$OV_HOME/symlink-recovery-vault"
    local staging="$OV_HOME/.octovault-staging-symlinkrollback" original="$OV_HOME/unrelated-original" migration
    mkdir -p "$original" "$mountpoint"
    printf 'untouched unrelated data\n' > "$original/data"
    ln -s "$original" "$staging"
    ov_save vaults symlinkrollbackvault "$(jq -n --arg mount "$mountpoint" '{mountpoint:$mount}')"
    migration=$(jq -n --arg source "$source" --arg staging "$staging" \
        '{migration_id:"symlinkrollback",source:$source,staging:$staging,relative:"Data",stage:"staged"}')
    ov_migration_save symlinkrollbackvault symlinkrollback "$migration"
    OV_PARAMS='{"id":"symlinkrollbackvault","migration_id":"symlinkrollback","action":"rollback"}'
    if (ov_migration_recover) > "$WORK/symlink-rollback.json" 2>/dev/null; then
        printf 'Expected symlink staging to block rollback\n' >&2; exit 1
    fi
    jq -e '.ok == false and (.error.code | length > 0)' "$WORK/symlink-rollback.json" >/dev/null
    [[ ! -e $source && ! -L $source && -L $staging ]]
    assert_equal "$(cat "$original/data")" 'untouched unrelated data'
    assert_equal "$(jq -r .stage "$OV_ROOT/migrations/symlinkrollbackvault/symlinkrollback.json")" staged
    printf 'ok - rollback rejects a replaced staging symlink and preserves unrelated data\n'
)

test_migration_source_safety() (
    local source="$OV_HOME/Safety Documents" mountpoint="$OV_HOME/safety-vault" record
    local MOCK_NESTED_MOUNT=false
    mkdir -p "$source/child" "$mountpoint"
    printf 'must not move\n' > "$source/data"
    record=$(jq -n --arg mount "$mountpoint" --arg file "$OV_HOME/safety.tomb" \
        --arg key "$OV_HOME/safety.key" '{mountpoint:$mount,file:$file,key_file:$key}')
    ov_vault_is_open() { return 0; }
    ov_vault_password() { touch "$WORK/unexpected-safety-authentication"; ov_fail test_failure 'Validation unexpectedly passed.'; }
    findmnt() {
        [[ $* == *'--json --list --output TARGET'* ]] || return 1
        if [[ $MOCK_NESTED_MOUNT == true ]]; then
            jq -n --arg target "$source/child" '{filesystems:[{target:$target}]}'
        else printf '{"filesystems":[]}\n'; fi
    }
    assert_source_rejected() {
        local expected=$1
        if (ov_migration_add) > "$WORK/source-safety-failure.json" 2>/dev/null; then
            printf 'Expected unsafe migration source rejection\n' >&2; exit 1
        fi
        assert_equal "$(jq -r .error.code "$WORK/source-safety-failure.json")" "$expected"
        assert_equal "$(cat "$source/data")" 'must not move'
        [[ ! -e $WORK/unexpected-safety-authentication ]]
        [[ ! -d $OV_ROOT/migrations/safetyvault ]]
    }
    OV_PARAMS=$(jq -n --arg source "$source" '{id:"safetyvault",source:$source,relative:"NewData"}')
    ov_save vaults safetyvault "$record"
    MOCK_NESTED_MOUNT=true; assert_source_rejected mounted; MOCK_NESTED_MOUNT=false
    ov_save vaults safetyvault "$(jq --arg file "$source/live.tomb" '.file=$file' <<< "$record")"
    assert_source_rejected invalid_source
    ov_save vaults safetyvault "$(jq --arg key "$source/live.key" '.key_file=$key' <<< "$record")"
    assert_source_rejected invalid_source
    ov_save vaults safetyvault "$(jq --arg cipher "$source/live.cipher" '.cipher_file=$cipher' <<< "$record")"
    assert_source_rejected invalid_source
    ov_save vaults safetyvault "$record"
    ov_migration_write_bind "$mountpoint" Existing 'Safety Documents/child'
    assert_source_rejected exists
    printf 'Existing Elsewhere\n' > "$mountpoint/bind-hooks"
    OV_PARAMS=$(jq -n --arg source "$source" '{id:"safetyvault",source:$source,relative:"Existing/child"}')
    assert_source_rejected exists
    printf 'ok - nested mounts, live container, key or cipher self-inclusion, and overlapping mappings are rejected before moving originals\n'
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

test_mount_protections() (
    local MOCK_MOUNT_OPTIONS='rw,nosuid,nodev,noatime' record
    local mountpoint="$WORK/protected-mount" engine="$WORK/protected-engine"
    mkdir -p "$mountpoint" "$engine"
    record=$(jq -n --arg mount "$mountpoint" '{id:"protections",file:"/fixture.tomb",mountpoint:$mount}')
    findmnt() {
        [[ $* == *'--output VFS-OPTIONS'* ]] || return 1
        printf '%s\n' "$MOCK_MOUNT_OPTIONS"
    }
    ov_vault_mount_safe "$engine"
    for MOCK_MOUNT_OPTIONS in 'rw,nodev' 'rw,nosuid' 'rw,suid,dev' '' $'rw,nosuid,nodev\nrw,nodev'; do
        assert_fails ov_vault_mount_safe "$engine"
    done
    MOCK_MOUNT_OPTIONS='rw,nodev'
    MOCK_OPEN=false
    ov_vault_is_open() { [[ $MOCK_OPEN == true ]]; }
    ov_vault_engine_mount() { printf '%s\n' "$engine"; }
    ov_vault_require_closed() { :; }
    ov_vault_tomb_keyed() {
        printf '%s\n' "$@" > "$WORK/protection-engine-args"
        MOCK_OPEN=true
    }
    ov_vault_tomb() { [[ $1 == close ]] && touch "$WORK/protection-closed"; }
    ov_vault_selector() { printf 'protections\n'; }
    ov_vault_expose() { touch "$WORK/protection-exposed"; }
    assert_fails ov_vault_open_record "$record"
    [[ -f $WORK/protection-closed && ! -e $WORK/protection-exposed ]]
    [[ $(tail -n 2 "$WORK/protection-engine-args") == $'-o\nrw,noatime,nodev,nosuid' ]]
    # A legacy mount must not bypass checking through the already-open shortcut.
    MOCK_OPEN=true
    assert_fails ov_vault_open_record "$record"
    printf 'ok - unsafe or ambiguous mount flags prevent vault exposure, including already-open mounts\n'
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
    # These creation tests isolate file lifecycle and permissions with synthetic
    # key bytes. The authentication contract is exercised in test-vault-auth.sh
    # and with a real protected OpenPGP key in the integration test below.
    ov_vault_auth_preflight() { :; }
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
    local protected_mount protected_engine
    ov_load vaults "$id"
    protected_mount=$(ov_vault_field "$OV_RECORD" mountpoint)
    protected_engine=$(ov_vault_engine_mount "$OV_RECORD")
    ov_vault_mount_safe "$protected_engine"
    ov_vault_mount_safe "$protected_mount"
    # Prepared/imported images can contain root-owned setuid files and device
    # nodes. Neither may confer privileges to the ordinary vault owner.
    # A dedicated probe also works on systems whose id command is a multicall
    # binary that chooses its behavior from its executable name.
    cc -std=c11 -O2 -Wall -Wextra -Werror -x c -o "$protected_engine/setuid-probe" - <<'PROBE'
#include <stdio.h>
#include <unistd.h>
int main(void)
{
    return printf("%lu:%lu\n", (unsigned long)getuid(), (unsigned long)geteuid()) < 0;
}
PROBE
    chown 0:0 "$protected_engine/setuid-probe"
    chmod 4755 "$protected_engine/setuid-probe"
    assert_equal "$(stat -c '%u:%a' "$protected_engine/setuid-probe")" 0:4755
    assert_equal "$(ov_as_user "$protected_mount/setuid-probe")" "$OV_UID:$OV_UID"
    mknod "$protected_engine/device-probe" c 1 3
    chmod 0666 "$protected_engine/device-probe"
    assert_fails ov_as_user head -c 1 "$protected_mount/device-probe"
    rm -- "$protected_engine/setuid-probe" "$protected_engine/device-probe"
    ov_as_user mkdir "$source"
    printf 'important\n' | ov_as_user tee "$source/data" >/dev/null
    OV_PARAMS=$(jq -n --arg id "$id" --arg source "$source" '{id:$id,source:$source,relative:"Documents",password:"OctoVault-CI-only-passphrase"}')
    OV_OP=migration.add; ov_vault_dispatch >/dev/null
    [[ -f $source/data ]]
    ov_vault_mount_safe "$source"
    OV_PARAMS=$(jq -n --arg id "$id" '{id:$id}'); OV_OP=vault.close; ov_vault_dispatch >/dev/null
    [[ ! -e $source/data ]]
    printf 'independent\n' | ov_as_user tee "$source/local" >/dev/null
    OV_PARAMS=$(jq -n --arg id "$id" '{id:$id,password:"OctoVault-CI-only-passphrase"}'); OV_OP=vault.open; ov_vault_dispatch >/dev/null
    [[ -f $source/data && ! -e $source/local ]]
    OV_OP=vault.close; ov_vault_dispatch >/dev/null
    assert_equal "$(cat "$source/local")" independent
    # Reproduce an older interrupted move: originals in adjacent staging,
    # partial encrypted data, no original Documents path, and a closed vault.
    local recovered="$OV_HOME/Recovered Documents" staged="$OV_HOME/.octovault-staging-legacy-resume" migration
    ov_as_user mkdir -m 0700 "$staged"
    printf 'retained original\n' | ov_as_user tee "$staged/data" >/dev/null
    OV_OP=vault.open; ov_vault_dispatch >/dev/null
    ov_as_user mkdir "$protected_mount/RecoveredDocuments"
    printf 'partial\n' | ov_as_user tee "$protected_mount/RecoveredDocuments/data" >/dev/null
    OV_OP=vault.close; ov_vault_dispatch >/dev/null
    migration=$(jq -n --arg id "$id" --arg source "$recovered" --arg staging "$staged" \
        '{schema_version:1,vault_id:$id,migration_id:"legacy-resume",source:$source,staging:$staging,relative:"RecoveredDocuments",stage:"staged"}')
    ov_migration_save "$id" legacy-resume "$migration"
    OV_PARAMS=$(jq -n --arg id "$id" '{id:$id,migration_id:"legacy-resume",action:"resume",password:"OctoVault-CI-only-passphrase"}')
    OV_OP=migration.recover; ov_vault_dispatch > "$WORK/recovered.json"
    assert_equal "$(jq -r .data.stage "$WORK/recovered.json")" complete
    assert_equal "$(cat "$recovered/data")" 'retained original'
    [[ ! -e $staged ]]
    ov_vault_mount_safe "$recovered"
    OV_PARAMS=$(jq -n --arg id "$id" '{id:$id,password:"OctoVault-CI-only-passphrase"}')
    OV_OP=vault.close; ov_vault_dispatch >/dev/null
    [[ -d $recovered && ! -e $recovered/data ]]
    OV_OP=vault.open; ov_vault_dispatch >/dev/null
    assert_equal "$(cat "$recovered/data")" 'retained original'
    OV_OP=vault.close; ov_vault_dispatch >/dev/null
    # Restoring the original instead needs no passphrase and does not open the
    # vault or overwrite another location.
    local restored="$OV_HOME/Restored Documents" restore_staging="$OV_HOME/.octovault-staging-legacy-restore"
    ov_as_user mkdir -m 0700 "$restore_staging"
    printf 'restored original\n' > "$WORK/restored-original.expected"
    ov_as_user tee "$restore_staging/data" < "$WORK/restored-original.expected" >/dev/null
    migration=$(jq -n --arg id "$id" --arg source "$restored" --arg staging "$restore_staging" \
        '{schema_version:1,vault_id:$id,migration_id:"legacy-restore",source:$source,staging:$staging,relative:"RestoredDocuments",stage:"staged"}')
    ov_migration_save "$id" legacy-restore "$migration"
    ov_as_user mkdir "$restored"
    OV_PARAMS=$(jq -n --arg id "$id" '{id:$id,migration_id:"legacy-restore",action:"rollback"}')
    OV_OP=migration.recover; ov_vault_dispatch > "$WORK/restored.json"
    assert_equal "$(jq -r .data.stage "$WORK/restored.json")" rolled_back
    assert_equal "$(cat "$restored/data")" 'restored original'
    [[ ! -e $restore_staging ]]
    ov_load vaults "$id"; assert_fails ov_vault_is_open "$OV_RECORD"
    cmp -s -- "$WORK/restored-original.expected" "$restored/data"
    jq -e '.protected_locations == null' <<< "$(ov_vault_status "$OV_RECORD")" >/dev/null
    OV_PARAMS=$(jq -n --arg id "$id" '{id:$id,password:"OctoVault-CI-only-passphrase"}')
    OV_OP=vault.open; ov_vault_dispatch >/dev/null
    cmp -s -- "$WORK/restored-original.expected" "$restored/data"
    [[ ! -e $protected_mount/RestoredDocuments ]]
    ov_load vaults "$id"
    jq -e --arg source "$restored" 'all(.protected_locations[]; .source != $source)' \
        <<< "$(ov_vault_status "$OV_RECORD")" >/dev/null
    OV_OP=vault.close; ov_vault_dispatch >/dev/null
    cmp -s -- "$WORK/restored-original.expected" "$restored/data"
    # Restore cancels the old attempt. A fresh explicit Protect request can
    # unlock the same closed vault and create a new verified native mapping.
    OV_PARAMS=$(jq -n --arg id "$id" --arg source "$restored" \
        '{id:$id,source:$source,relative:"RestoredDocuments",password:"OctoVault-CI-only-passphrase"}')
    OV_OP=migration.add; ov_vault_dispatch > "$WORK/reprotected.json"
    jq -e '.ok and .data.stage == "complete" and .data.migration_id != "legacy-restore"' "$WORK/reprotected.json" >/dev/null
    cmp -s -- "$WORK/restored-original.expected" "$restored/data"
    cmp -s -- "$WORK/restored-original.expected" "$protected_mount/RestoredDocuments/data"
    ov_load vaults "$id"
    jq -e --arg source "$restored" \
        'any(.protected_locations[]; .source == $source and .relative == "RestoredDocuments" and .active)' \
        <<< "$(ov_vault_status "$OV_RECORD")" >/dev/null
    OV_PARAMS=$(jq -n --arg id "$id" '{id:$id,password:"OctoVault-CI-only-passphrase"}')
    OV_OP=vault.close; ov_vault_dispatch >/dev/null
    [[ -d $restored && -z $(find "$restored" -mindepth 1 -maxdepth 1 -print -quit) ]]
    OV_OP=vault.open; ov_vault_dispatch >/dev/null
    cmp -s -- "$WORK/restored-original.expected" "$restored/data"
    ov_vault_mount_safe "$restored"
    OV_OP=vault.close; ov_vault_dispatch >/dev/null
    printf 'ok - real restore keeps plaintext visible until a fresh closed-vault Protect request verifies lock and unlock\n'
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
    printf 'ok - real nonroot-owner lifecycle, protected mounts and binds, setuid/device rejection, migration, metadata symlinks and untrusted hooks\n'
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
    # Every pinned container is named vault.tomb internally. Keep two open
    # together and close by verified mapper identity, never that shared label.
    ov_resource_unlock
    OV_PARAMS=$(jq -n --arg id "$id" '{id:$id,password:"OctoVault-replacement-75%-pass"}')
    OV_OP=vault.open; ov_vault_dispatch >/dev/null
    local reused_holder_job original_holder_job reused_holder original_holder
    touch "$WORK/holder-reused.pid" "$WORK/holder-original.pid"
    chown "$OV_UID:$(id -g "$OV_USER")" "$WORK/holder-reused.pid" "$WORK/holder-original.pid"
    chmod 0600 "$WORK/holder-reused.pid" "$WORK/holder-original.pid"
    ov_load vaults "$reused_id"
    ov_as_user bash -c 'set -e; cd -- "$1"; printf "%s\n" "$$" > "$2"; exec sleep 120' fixture \
        "$(ov_vault_field "$OV_RECORD" mountpoint)" "$WORK/holder-reused.pid" \
        >"$WORK/holder-reused.log" 2>&1 &
    reused_holder_job=$!
    ov_load vaults "$id"
    ov_as_user bash -c 'set -e; cd -- "$1"; printf "%s\n" "$$" > "$2"; exec sleep 120' fixture \
        "$(ov_vault_field "$OV_RECORD" mountpoint)" "$WORK/holder-original.pid" \
        >"$WORK/holder-original.log" 2>&1 &
    original_holder_job=$!
    for _ in {1..100}; do
        [[ -s $WORK/holder-reused.pid && -s $WORK/holder-original.pid ]] && break
        sleep 0.05
    done
    read -r reused_holder < "$WORK/holder-reused.pid"
    read -r original_holder < "$WORK/holder-original.pid"
    [[ $reused_holder =~ ^[0-9]+$ && $original_holder =~ ^[0-9]+$ ]]
    kill -0 "$reused_holder" "$original_holder"
    ov_resource_unlock
    OV_PARAMS=$(jq -n --arg id "$reused_id" '{id:$id,force:true}')
    OV_OP=vault.close; ov_vault_dispatch >/dev/null
    ov_load vaults "$reused_id"; ov_vault_require_closed "$OV_RECORD"
    ov_load vaults "$id"; ov_vault_is_open "$OV_RECORD"
    if kill -0 "$reused_holder" 2>/dev/null; then
        printf 'Force close did not terminate its vault holder.\n' >&2; exit 1
    fi
    kill -0 "$original_holder"
    kill "$original_holder"
    wait "$reused_holder_job" 2>/dev/null || true
    wait "$original_holder_job" 2>/dev/null || true
    rm -- "$WORK/holder-reused.pid" "$WORK/holder-original.pid"
    ov_resource_unlock
    OV_PARAMS=$(jq -n --arg id "$id" '{id:$id}')
    OV_OP=vault.close; ov_vault_dispatch >/dev/null
    ov_load vaults "$id"; ov_vault_require_closed "$OV_RECORD"
    printf 'ok - real existing-key reuse creates another container without modifying the key\n'
    printf 'ok - force and normal close target one mapper while an identically named vault and its holder remain open\n'

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

    # Exercise a protected software key through a real GPG agent and pinentry.
    # The scripted prompt is only for this disposable user's fixture; it proves
    # authentication is requested, but does not stand in for physical-card tests.
    local recipient pgp_id pgp_key
    ov_as_user mkdir -p -m 0700 "$OV_HOME/.gnupg"
    cat <<'PINENTRY' | ov_as_user tee "$OV_HOME/pinentry-fixture" >/dev/null
#!/bin/bash
set -euo pipefail
printf 'OK OctoVault disposable integration pinentry\n'
while IFS= read -r request; do
    case $request in
        GETPIN)
            printf 'prompt\n' >> "$HOME/pinentry-requests"
            printf 'D OctoVault-openpgp-test-passphrase\nOK\n'
            ;;
        BYE) printf 'OK\n'; exit 0 ;;
        *) printf 'OK\n' ;;
    esac
done
PINENTRY
    ov_as_user chmod 0700 "$OV_HOME/pinentry-fixture"
    printf 'pinentry-program %s/pinentry-fixture\ndefault-cache-ttl 0\nmax-cache-ttl 0\nno-allow-external-cache\n' "$OV_HOME" |
        ov_as_user tee "$OV_HOME/.gnupg/gpg-agent.conf" >/dev/null
    printf 'OctoVault-openpgp-test-passphrase\n' |
        ov_as_user gpg --batch --pinentry-mode loopback --passphrase-fd 0 --quick-generate-key \
        'OctoVault disposable CI <octovault-ci@example.invalid>' default default 1d >&2
    recipient=$(ov_as_user gpg --batch --with-colons --list-keys 'octovault-ci@example.invalid' |
        awk -F: '$1=="fpr"{print $10;exit}')
    [[ -n $recipient ]]
    ov_as_user gpgconf --kill gpg-agent
    ov_resource_unlock
    OV_PARAMS=$(jq -n --arg directory "$OV_HOME" --arg recipient "$recipient" \
        '{name:"software-openpgp",directory:$directory,auth:"gpg",recipient:$recipient,size_gb:"0.05",open_on:"manual"}')
    OV_OP=vault.create; ov_vault_dispatch > "$WORK/response.json"
    pgp_id=$(jq -er .data.id "$WORK/response.json"); pgp_key=$(jq -er .data.key_file "$WORK/response.json")
    [[ -s $OV_HOME/pinentry-requests ]]
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
    if grep -Rq -E 'OctoVault-(CI-only|rotated|replacement|carrier-create|openpgp-test)' "$OV_ROOT"; then
        printf 'A fixture passphrase was persisted in vault state.\n' >&2; return 1
    fi
    printf 'ok - real protected OpenPGP key, agent authentication and existing-key reuse without a supplied recipient; no stored passphrases\n'
}

if [[ ${1:-} == --integration ]]; then integration
else test_validation; test_native_binds; test_compare; test_migration; test_terminal_recovery_actions; test_native_protection_status; test_closed_vault_protection; test_closed_vault_partial_conflict; test_interrupted_migration; test_failed_copy_preserves_original; test_symlink_destination_preserves_original; test_closed_recovery_rechecks_destination; test_full_vault_preserves_original; test_legacy_staging_recovery; test_prepared_rollback; test_published_mapping_blocks_rollback; test_symlink_staging_blocks_rollback; test_migration_source_safety; test_device_identity; test_mount_protections; test_unknown_state; test_secret_arguments; test_container_pin; test_guided_creation
fi
