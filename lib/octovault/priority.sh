#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
# Shared only by fixed root launchers. These functions do not accept requests.
ov_priority_setup() {
    [[ $EUID -eq 0 && ${1-} =~ ^[0-9]{1,10}$ ]] || return 64
    OV_PRIORITY_UID=$1
    OV_PRIORITY_STATE="/var/lib/octovault/users/$1"
    OV_PRIORITY_DIRECTORY=/run/octovault/priorities
    [[ ! -L /run/octovault && ! -L "$OV_PRIORITY_DIRECTORY" && ! -L "$OV_PRIORITY_STATE" ]] || return 64
    install -d -m 0700 /run/octovault "$OV_PRIORITY_DIRECTORY"
}

ov_priority_defer() {
    local id=$1 reason=$2 temporary
    [[ $id =~ ^[a-zA-Z0-9_-]{1,64}$ ]] || return 64
    [[ ! -L "$OV_PRIORITY_STATE/events" ]] || return 64
    install -d -m 0700 "$OV_PRIORITY_STATE/events"
    temporary=$(mktemp "$OV_PRIORITY_STATE/events/.pending.XXXXXXXX") || return 1
    if ! jq -nc --arg id "$id" --arg reason "$reason" \
        '{plan_id:$id,reason:$reason,state:"retry-after-priority-operation"}' > "$temporary"; then
        rm -f -- "$temporary"; return 1
    fi
    chmod 0600 "$temporary"
    mv -fT -- "$temporary" "$OV_PRIORITY_STATE/events/interrupted-$id.json"
}

ov_priority_blocked() {
    local marker pid since now
    now=$(date +%s)
    for marker in "$OV_PRIORITY_DIRECTORY/$OV_PRIORITY_UID-"*; do
        [[ -f "$marker" && ! -L "$marker" ]] || continue
        if read -r pid since < "$marker" && [[ $pid =~ ^[0-9]+$ && $since =~ ^[0-9]+$ && ${#since} -le 12 ]] &&
           ((now >= since && now - since < 600)) && kill -0 "$pid" 2>/dev/null; then
            return 0
        fi
        # A killed launcher must not leave all future backups blocked forever.
        rm -f -- "$marker"
    done
    return 1
}

ov_priority_enter() {
    OV_PRIORITY_MARKER=$(mktemp "$OV_PRIORITY_DIRECTORY/$OV_PRIORITY_UID-XXXXXXXX") || return 1
    chmod 0600 "$OV_PRIORITY_MARKER"
    printf '%s %s\n' "$BASHPID" "$(date +%s)" > "$OV_PRIORITY_MARKER"
}

ov_priority_leave() {
    [[ -z ${OV_PRIORITY_MARKER:-} ]] || rm -f -- "$OV_PRIORITY_MARKER"
}

ov_priority_cancel_plans() {
    local plan id unit active
    local -a services=()
    for plan in "$OV_PRIORITY_STATE/plans/"*.json; do
        [[ -f "$plan" && ! -L "$plan" ]] || continue
        id=$(jq -er '.id' "$plan") || continue
        [[ $id =~ ^[a-zA-Z0-9_-]{1,64}$ ]] || continue
        unit="octovault-backup-$OV_PRIORITY_UID-$id.service"
        active=$(systemctl show --property=ActiveState --value "$unit" 2>/dev/null) || continue
        case "$active" in active|activating|reloading) ;; *) continue ;; esac
        ov_priority_defer "$id" priority-close || return 1
        services+=("$unit")
    done
    if ((${#services[@]})); then
        timeout --signal=TERM --kill-after=2s 25s systemctl stop "${services[@]}" >/dev/null || {
            printf 'OctoVault: scheduled backup cancellation did not finish in time.\n' >&2
            return 1
        }
    fi
}
