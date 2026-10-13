#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
# shellcheck disable=SC1091,SC2034,SC2317
set -euo pipefail
cd "$(dirname "$0")/.."
source lib/octovault/priority.sh
work=$(mktemp -d)
trap 'rm -rf -- "$work"' EXIT
OV_PRIORITY_UID=1001
OV_PRIORITY_STATE="$work/state"
OV_PRIORITY_DIRECTORY="$work/priority"
mkdir -p "$OV_PRIORITY_STATE/plans" "$OV_PRIORITY_DIRECTORY"
log="$work/calls"
: > "$log"
systemctl() {
    if [[ $1 == show ]]; then
        case "$*" in *-active.service) echo active ;; *-starting.service) echo activating ;; *) echo inactive ;; esac
    else printf '%s\n' "$*" >> "$log"; fi
}
timeout() { [[ $1 == --signal=TERM && $2 == --kill-after=2s && $3 == 25s ]]; shift 3; "$@"; }
for id in active starting idle; do jq -nc --arg id "$id" '{id:$id}' > "$OV_PRIORITY_STATE/plans/$id.json"; done
if ov_priority_blocked; then echo 'unexpected blocker' >&2; exit 1; fi
ov_priority_enter
[[ $(stat -c %a "$OV_PRIORITY_MARKER") == 600 ]]
ov_priority_blocked
ov_priority_cancel_plans
grep -q -F 'stop octovault-backup-1001-active.service octovault-backup-1001-starting.service' "$log"
[[ ! -e "$OV_PRIORITY_STATE/events/interrupted-idle.json" ]]
jq -e '.plan_id=="active" and .reason=="priority-close"' "$OV_PRIORITY_STATE/events/interrupted-active.json" >/dev/null
jq -e '.plan_id=="starting"' "$OV_PRIORITY_STATE/events/interrupted-starting.json" >/dev/null
[[ $(stat -c %a "$OV_PRIORITY_STATE/events/interrupted-active.json") == 600 ]]
ov_priority_leave
if ov_priority_blocked; then echo 'priority marker retained after completion' >&2; exit 1; fi
# An abandoned marker cannot block this owner indefinitely or another owner.
printf '%s 1\n' "$BASHPID" > "$OV_PRIORITY_DIRECTORY/1001-expired"
printf '%s %s\n' "$BASHPID" "$(date +%s)" > "$OV_PRIORITY_DIRECTORY/1002-other"
if ov_priority_blocked; then echo 'stale/other-owner marker blocks owner' >&2; exit 1; fi
[[ ! -e "$OV_PRIORITY_DIRECTORY/1001-expired" && -f "$OV_PRIORITY_DIRECTORY/1002-other" ]]
# Deferrals accept record IDs only, never an arbitrary pathname.
if ov_priority_defer '../escape' reason; then echo 'unsafe plan ID accepted' >&2; exit 1; fi
# A failed stop is propagated to prevent assuming the owner lock is available.
systemctl() { [[ $1 != show ]] || { echo active; return; }; return 1; }
if ov_priority_cancel_plans 2>/dev/null; then echo 'failed cancellation was ignored' >&2; exit 1; fi
printf 'Priority launch tests passed.\n'
