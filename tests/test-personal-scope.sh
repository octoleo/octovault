#!/usr/bin/env bash
# Saved privilege boundaries and real personal backup/restore isolation.
set -Eeuo pipefail
umask 077
cd "$(dirname "$0")/.."
work=$(mktemp -d)
trap 'rm -rf -- "$work"' EXIT
source lib/octovault/common.sh
source lib/octovault/backup.sh
source lib/octovault/events.sh
source lib/octovault/vault.sh
OV_ROOT="$work/state"
OV_RUNTIME_ROOT="$work/runtime"
OV_HOME="$work/home"
OV_USER=$(id -un)
OV_UID=$(id -u)
OV_USER_ENV=()
OV_EXECUTION_SCOPE=personal
OV_ACCESS_FILE="$work/access.json"
mkdir -p "$OV_ROOT" "$OV_HOME"

assert_json() { jq -e "$2" >/dev/null <<< "$1" || { printf 'Personal scope assertion failed: %s\n' "$2" >&2; exit 1; }; }
expect_failure() {
    local code=$1 result status=0
    shift
    result=$("$@") || status=$?
    [[ $status != 0 ]] || { printf 'Expected personal scope failure: %s\n' "$code" >&2; exit 1; }
    assert_json "$result" ".ok == false and .error.code == \"$code\""
}
request() (
    OV_OP=$1 OV_PARAMS=$2
    unset OV_BACKUP_TMP OV_BACKUP_IO OV_RESTIC_PASSWORD_FILE
    ov_backup_dispatch
)
vault_request() ( OV_OP=$1 OV_PARAMS=$2; ov_vault_dispatch; )
# Host credential encryption is covered independently. This disposable store
# isolates filesystem privilege tests from a machine TPM or host secret.
ov_credential_set() { ov_id "$1"; mkdir -p "$OV_ROOT/credentials"; printf '%s' "$2" > "$OV_ROOT/credentials/$1"; }
ov_credential_get() { ov_id "$1"; cat "$OV_ROOT/credentials/$1"; }

expect_failure admin_required ov_scope_require_record '{}'
expect_failure admin_required ov_scope_require_record '{"execution_scope":"system"}'
expect_failure invalid_state ov_record_scope '{"execution_scope":"untrusted"}'
ov_scope_require_record '{"execution_scope":"personal"}'
expect_failure invalid_scope ov_execution_scope ''
expect_failure admin_required ov_vault_close_record '{"execution_scope":"personal"}' true
expect_failure invalid_request vault_request vault.close '{"id":"unused","force":"true"}'
OV_BACKUP_TMP="$work/must-not-be-reused" OV_BACKUP_WORKSPACE_SCOPE=system OV_BACKUP_SCOPE=personal
expect_failure scope_mismatch ov_backup_workspace
unset OV_BACKUP_TMP OV_BACKUP_WORKSPACE_SCOPE OV_BACKUP_SCOPE
ov_save destinations system-destination '{"type":"local","path":"/root","name":"System destination"}'
ov_save repositories system-repository '{"destination_id":"system-destination","repository":"/root/backup","credential_id":"never-read"}'
ov_save plans system-plan '{"repository_id":"system-repository","name":"System plan","sources":["/root"],"trigger":"manual"}'
expect_failure admin_required request destination.save '{"id":"system-destination","name":"Changed","rest_password":"must-not-be-written"}'
[[ ! -e $OV_ROOT/credentials ]]
expect_failure admin_required request repository.recovery '{"id":"system-repository"}'
expect_failure admin_required request backup.run '{"id":"system-plan"}'
expect_failure admin_required request backup.save '{"id":"system-plan","name":"Changed"}'
assert_json "$(request destination.get '{"id":"system-destination"}')" '.ok and .data.name == "System destination"'
ov_save repositories mixed-repository '{"execution_scope":"personal","destination_id":"system-destination","repository":"/root/backup","credential_id":"never-read"}'
expect_failure admin_required request repository.recovery '{"id":"mixed-repository"}'
expect_failure admin_required request backup.save '{"name":"Mixed plan","repository_id":"system-repository","sources":["/root"]}'
ov_save plans revoked-plan '{"execution_scope":"personal","repository_id":"mixed-repository","name":"Revoked","sources":["/root"]}'
expect_failure access_revoked request backup.run '{"id":"revoked-plan"}'

# Personal schedule refresh must preserve all existing system units.
OV_SYSTEMD_DIR="$work/units"
mkdir -p "$OV_SYSTEMD_DIR"
printf 'system timer must stay unchanged\n' > "$OV_SYSTEMD_DIR/octovault-backup-$OV_UID-system-plan.timer"
printf 'system service must stay unchanged\n' > "$OV_SYSTEMD_DIR/octovault-backup-$OV_UID-system-plan.service"
ov_save plans personal-plan '{"execution_scope":"personal","name":"Personal plan","trigger":"calendar","calendar":"daily"}'
rm "$OV_ROOT/plans/revoked-plan.json"
systemctl() { printf '%s\n' "$*" >> "$work/systemctl-calls"; }
ov_schedule_sync
grep -qx 'system timer must stay unchanged' "$OV_SYSTEMD_DIR/octovault-backup-$OV_UID-system-plan.timer"
grep -qx 'system service must stay unchanged' "$OV_SYSTEMD_DIR/octovault-backup-$OV_UID-system-plan.service"
grep -qx '# OctoVault-Execution-Scope=personal' "$OV_SYSTEMD_DIR/octovault-backup-$OV_UID-personal-plan.service"
if grep -q system-plan "$work/systemctl-calls"; then printf 'Personal sync changed a system schedule.\n' >&2; exit 1; fi
unset -f systemctl
printf 'Personal scope: resource references, credentials, revocation and schedule separation passed.\n'

# CI must exercise real POSIX permissions using a separate non-sudo account.
if [[ $EUID != 0 ]] || ! runuser -u nobody -- /usr/bin/true 2>/dev/null; then
    if [[ ${CI:-false} == true ]]; then printf 'CI must support a distinct ordinary UID for personal backup tests.\n' >&2; exit 1; fi
    printf 'Personal filesystem integration requires root with runuser support; CI requires this test.\n'
    exit 0
fi
command -v restic >/dev/null
OV_USER=nobody
OV_UID=$(id -u "$OV_USER")
OV_HOME="$work/ordinary-home"
OV_ROOT="$work/ordinary-state"
mkdir -p "$OV_HOME" "$OV_ROOT" "$work/root-private"
chmod 0711 "$work"
chown "$OV_UID:$(id -g "$OV_USER")" "$OV_HOME"
printf 'administrator-only-data\n' > "$work/root-private/private.txt"
mkdir -p "$OV_HOME/source" "$OV_HOME/storage"
printf 'ordinary-user-data\n' > "$OV_HOME/source/document.txt"
chown -R "$OV_UID:$(id -g "$OV_USER")" "$OV_HOME"
jq -nc --argjson uid "$OV_UID" --arg user "$OV_USER" '{schema_version:1,grants:[{uid:$uid,user:$user}]}' > "$OV_ACCESS_FILE"
chmod 0600 "$OV_ACCESS_FILE"
systemctl() { :; }
ov_resource_lock() { :; }
ov_resource_unlock() { :; }

destination=$(request destination.save "$(jq -nc --arg path "$OV_HOME/storage" '{name:"Personal destination",type:"local",path:$path}')")
assert_json "$destination" '.ok and .data.execution_scope == "personal"'
destination_id=$(jq -r .data.id <<< "$destination")
assert_json "$(request destination.test "{\"id\":\"$destination_id\"}")" '.ok and .data.reachable'
repository=$(request repository.create "$(jq -nc --arg id "$destination_id" '{name:"Personal repository",destination_id:$id,path:"repository"}')")
assert_json "$repository" '.ok and .data.execution_scope == "personal"'
repository_id=$(jq -r .data.id <<< "$repository")
[[ $(stat -c %u "$OV_HOME/storage/repository/config") == "$OV_UID" ]]
plan=$(request backup.save "$(jq -nc --arg id "$repository_id" --arg source "$OV_HOME/source" '{name:"Personal files",repository_id:$id,sources:[$source],trigger:"manual"}')")
assert_json "$plan" '.ok and .data.execution_scope == "personal"'
plan_id=$(jq -r .data.id <<< "$plan")
assert_json "$(request backup.run "{\"id\":\"$plan_id\"}")" '.ok and .data.status == "success"'
expect_failure permission_denied request backup.save "$(jq -nc --arg id "$repository_id" --arg source "$work/root-private" '{name:"Forbidden files",repository_id:$id,sources:[$source]}')"

# Replacing an approved source with a link cannot make the root service read
# its protected target. Runtime checks and the owner process both enforce it.
mv "$OV_HOME/source" "$OV_HOME/original-source"
ln -s "$work/root-private" "$OV_HOME/source"
expect_failure permission_denied request backup.run "{\"id\":\"$plan_id\"}"
rm "$OV_HOME/source"
mv "$OV_HOME/original-source" "$OV_HOME/source"

restore="$OV_HOME/restored"
assert_json "$(request repository.restore "$(jq -nc --arg id "$repository_id" --arg target "$restore" '{id:$id,target:$target,snapshot:"latest",overwrite:"never"}')")" '.ok'
cmp "$OV_HOME/source/document.txt" "$restore$OV_HOME/source/document.txt"
[[ $(stat -c %u "$restore$OV_HOME/source/document.txt") == "$OV_UID" ]]

# Direct protected targets and user symlinks to them are inaccessible to the
# actual restore process; nothing is written into the protected directory.
for target in "$work/root-private" "$OV_HOME/restore-link"; do
    [[ $target != "$OV_HOME/restore-link" ]] || ln -s "$work/root-private" "$target"
    result=''; status=0
    result=$(request repository.restore "$(jq -nc --arg id "$repository_id" --arg target "$target" '{id:$id,target:$target,snapshot:"latest",overwrite:"always"}')") || status=$?
    [[ $status != 0 ]]
    assert_json "$result" '.ok == false'
done
[[ $(cat "$work/root-private/private.txt") == administrator-only-data ]]
[[ $(find "$work/root-private" -mindepth 1 -maxdepth 1 | wc -l) == 1 ]]

# A root internal worker still executes personal I/O as the recorded owner.
OV_EXECUTION_SCOPE=system
assert_json "$(request backup.run "{\"id\":\"$plan_id\"}")" '.ok and .data.status == "success"'
[[ $(stat -c %u "$OV_HOME/storage/repository/config") == "$OV_UID" ]]
# Revoking enrollment blocks the next run, including a system timer invocation.
printf '{"schema_version":1,"grants":[]}\n' > "$OV_ACCESS_FILE"
expect_failure access_revoked request backup.run "{\"id\":\"$plan_id\"}"
printf 'Personal filesystem integration: real owner-UID Restic, protected sources, symlink restore targets, ownership and scheduled scope passed.\n'
