#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Isolated automation contracts. Never modifies real system units or mounts.
# Sourced adapters consume the shared OV_* variables and mocked commands.
# shellcheck disable=SC1091,SC2034,SC2317
set -euo pipefail
cd "$(dirname "$0")/.."
source lib/octovault/common.sh
source lib/octovault/events.sh
work=$(mktemp -d)
trap 'rm -rf -- "$work"' EXIT
OV_UID=1001
OV_ROOT="$work/state"
OV_SYSTEMD_DIR="$work/units"
OV_USER=tester
OV_HOME="$work/home"
OV_PARAMS='{}'
OV_OP=schedule.sync
mkdir -p "$OV_ROOT" "$OV_SYSTEMD_DIR" "$OV_HOME"
log="$work/calls"
: > "$log"
systemctl() { printf '%s\n' "$*" >> "$log"; }
systemd-analyze() { [[ $1 == calendar && $2 == daily ]]; }
busctl() { printf 'u 0\n'; }
findmnt() { [[ $* == *UUID=SAFE-1234* ]]; }
ov_vault_is_open() { [[ $(jq -r '.test_open // false' <<<"$1") == true ]]; }
ov_as_user() { return 0; }
ov_vault_dispatch() {
    local id
    id=$(ov_require id)
    printf '%s %s\n' "$OV_OP" "$id" >> "$log"
    [[ "$id" != fail ]] || ov_fail busy 'Test lock blocker'
    ov_ok '{"locked":true}'
}
ov_backup_dispatch() { printf 'backup %s\n' "$(ov_require id)" >> "$log"; ov_ok '{"complete":true}'; }
assert_contains() { grep -q -F -- "$2" "$1" || { printf 'Missing %s in %s\n' "$2" "$1" >&2; exit 1; }; }
assert_json() { jq -e "$2" <<<"$1" >/dev/null; }
ov_save plans daily '{"name":"Daily","trigger":"calendar","calendar":"daily"}'
ov_save plans boot '{"name":"Boot","trigger":"boot","boot_delay_sec":3600}'
ov_save plans manual '{"name":"Manual","trigger":"manual"}'
out=$(ov_event_dispatch)
assert_json "$out" '.ok and .data.synchronized'
assert_contains "$OV_SYSTEMD_DIR/octovault-backup-1001-daily.timer" 'OnCalendar=daily'
assert_contains "$OV_SYSTEMD_DIR/octovault-backup-1001-boot.timer" 'OnBootSec=3600s'
assert_contains "$OV_SYSTEMD_DIR/octovault-backup-1001-manual.service" 'ExecStart=/usr/libexec/octovault/run-plan 1001 manual'
[[ ! -f "$OV_SYSTEMD_DIR/octovault-backup-1001-manual.timer" ]]
assert_contains "$log" 'enable --now'
# Invalid calendar data cannot inject unit directives or destroy previous timers.
ov_save plans unsafe '{"name":"Unsafe","trigger":"calendar","calendar":"daily\nExecStart=/bin/false"}'
if (ov_schedule_sync > "$work/rejected"); then printf 'Unsafe calendar accepted\n' >&2; exit 1; fi
assert_json "$(cat "$work/rejected")" '.error.code == "invalid_schedule"'
[[ -f "$OV_SYSTEMD_DIR/octovault-backup-1001-daily.timer" ]]
rm "$OV_ROOT/plans/unsafe.json"
# Removed plans lose only this owner's generated units.
printf 'untouched\n' > "$OV_SYSTEMD_DIR/octovault-backup-999-other.timer"
rm "$OV_ROOT/plans/boot.json"
ov_schedule_sync
[[ ! -f "$OV_SYSTEMD_DIR/octovault-backup-1001-boot.timer" ]]
[[ -f "$OV_SYSTEMD_DIR/octovault-backup-999-other.timer" ]]
ov_save vaults login '{"name":"Login","open_on":"login","close_on":["sleep","screen-lock"]}'
ov_save vaults manual '{"name":"Manual","open_on":"manual","close_on":["shutdown"]}'
ov_save vaults open '{"name":"Already open","open_on":"login","test_open":true,"close_on":[]}'
OV_OP=event.session OV_PARAMS='{"event":"login"}'
out=$(ov_event_dispatch)
assert_json "$out" '.ok and .data.unlock_requests == ["login"]'
OV_PARAMS='{"event":"login","force":true}'
if (ov_event_dispatch > "$work/rejected"); then exit 1; fi
assert_json "$(cat "$work/rejected")" '.error.code == "invalid_event"'
OV_PARAMS='{"event":"screen-lock"}'
out=$(ov_event_dispatch)
assert_json "$out" '.ok and .data.completed == 1'
assert_contains "$log" 'vault.close login'
# Backend never turns arbitrary session requests into privileged timer execution.
OV_PARAMS='{"event":"timer","id":"daily"}'
if (ov_event_dispatch > "$work/rejected"); then exit 1; fi
assert_json "$(cat "$work/rejected")" '.error.code == "forbidden"'
OV_OP=event.handle OV_INTERNAL=0
if (ov_event_dispatch > "$work/rejected"); then exit 1; fi
assert_json "$(cat "$work/rejected")" '.error.code == "forbidden"'
OV_INTERNAL=1
if ((EUID == 0)); then
    out=$(ov_event_dispatch)
    assert_json "$out" '.ok and .data.complete'
fi
OV_OP=event.session
# Sleep guard must return failure, never a successful-lock assumption.
ov_save vaults fail '{"name":"Busy","close_on":["sleep"]}'
OV_PARAMS='{"event":"sleep"}'
if (ov_event_dispatch > "$work/rejected"); then exit 1; fi
assert_json "$(cat "$work/rejected")" '.error.code == "event_incomplete"'
rm "$OV_ROOT/vaults/fail.json"
# Drive notification must correspond to an actual mounted identifier.
OV_OP=event.session OV_PARAMS='{"event":"drive","drive_uuid":"MISSING"}'
if (ov_event_dispatch > "$work/rejected"); then exit 1; fi
assert_json "$(cat "$work/rejected")" '.error.code == "missing_drive"'
ov_save vaults drive '{"name":"Drive","open_on":"drive","drive_uuid":"SAFE-1234","close_on":[]}'
OV_PARAMS='{"event":"drive","drive_uuid":"SAFE-1234"}'
out=$(ov_event_dispatch)
assert_json "$out" '.ok and .data.unlock_requests == ["drive"]'
# Vault events queue without waiting for another worker under the same user lock.
ov_save plans attached '{"name":"After open","trigger":"vault-open","vault_id":"login"}'
: > "$log"
ov_event_vault_transition vault-open login
assert_contains "$log" 'start --no-block octovault-backup-1001-attached.service'
# Idle emits once per idle episode, then resets once activity resumes.
ov_save plans idle '{"name":"Idle","trigger":"idle","idle_sec":60}'
OV_PARAMS='{"event":"idle","idle_seconds":120}'
out=$(ov_event_dispatch); assert_json "$out" '.data.completed == 1'
out=$(ov_event_dispatch); assert_json "$out" '.data.completed == 0'
OV_PARAMS='{"event":"idle","idle_seconds":0}'
ov_event_dispatch >/dev/null
OV_PARAMS='{"event":"idle","idle_seconds":"08"}'
out=$(ov_event_dispatch); assert_json "$out" '.ok and .data.completed == 0'
OV_PARAMS='{"event":"idle","idle_seconds":120}'
out=$(ov_event_dispatch); assert_json "$out" '.data.completed == 1'
# Metered restrictions postpone; they do not consume the next idle opportunity.
rm "$OV_ROOT/events/idle-idle"
busctl() { printf 'u 1\n'; }
out=$(ov_event_dispatch); assert_json "$out" '.ok and .data.completed == 0'
[[ ! -f "$OV_ROOT/events/idle-idle" ]]
busctl() { printf 'u 0\n'; }
out=$(ov_event_dispatch); assert_json "$out" '.data.completed == 1'
# Interrupted scheduled jobs are retried after resume without unlocking a vault.
printf '{"plan_id":"daily","reason":"sleep"}\n' > "$OV_ROOT/events/interrupted-daily.json"
OV_PARAMS='{"event":"resume"}'
out=$(ov_event_dispatch); assert_json "$out" '.ok and .data.unlock_requests == []'
[[ ! -e "$OV_ROOT/events/interrupted-daily.json" ]]
assert_contains "$log" 'start --no-block octovault-backup-1001-daily.service'
# Damaged root-owned state cannot silently report a successful lock.
printf '{broken' > "$OV_ROOT/vaults/broken.json"
OV_PARAMS='{"event":"sleep"}'
if (ov_event_dispatch > "$work/rejected" 2>/dev/null); then exit 1; fi
assert_json "$(cat "$work/rejected")" '.error.code == "invalid_state"'
rm "$OV_ROOT/vaults/broken.json"
printf 'Automation tests passed.\n'
