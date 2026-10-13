#!/usr/bin/env bash
# OctoVault automation. Only root-owned stored policies are interpreted here.
# SPDX-License-Identifier: Apache-2.0

ov_event_unit_name() {
    ov_id "$1"
    printf 'octovault-backup-%s-%s' "$OV_UID" "$1"
}

ov_event_records() {
    local collection=$1 record
    [[ -d "$OV_ROOT/$collection" ]] || return 0
    for record in "$OV_ROOT/$collection"/*.json; do
        [[ -f "$record" ]] || continue
        [[ ! -L "$record" ]] || return 1
        jq -ce 'select(type == "object" and .schema_version == 1)' "$record" || return 1
    done
}

ov_schedule_validate_record() {
    local record=$1 trigger calendar delay
    ov_id "$(jq -er '.id' <<<"$record")"
    trigger=$(jq -r '.trigger // "manual"' <<<"$record")
    case "$trigger" in
        calendar)
            calendar=$(jq -er '.calendar' <<<"$record") || ov_fail invalid_schedule 'A calendar schedule needs an expression.'
            [[ "$calendar" != *$'\n'* && "$calendar" != *$'\r'* && "$calendar" != *'%'* && ${#calendar} -le 200 ]] || ov_fail invalid_schedule 'Invalid calendar expression.'
            systemd-analyze calendar "$calendar" >/dev/null 2>&1 || ov_fail invalid_schedule 'The calendar expression is not valid for systemd.'
            ;;
        boot)
            delay=$(jq -r '.boot_delay_sec // 3600' <<<"$record")
            [[ "$delay" =~ ^[0-9]+$ && ${#delay} -le 8 && $delay -ge 1 ]] || ov_fail invalid_schedule 'Boot delay must be a positive number of seconds.'
            ;;
        manual|idle|vault-open|vault-close|drive) ;;
        *) ov_fail invalid_schedule 'Unknown backup schedule trigger.' ;;
    esac
}

ov_schedule_sync() {
    local unit_dir=${OV_SYSTEMD_DIR:-/etc/systemd/system}
    local record id base trigger timer calendar delay file records
    [[ $OV_UID =~ ^[0-9]+$ ]] || ov_fail invalid_user 'Invalid schedule owner.'
    records=$(ov_event_records plans) || ov_fail invalid_state 'A saved backup plan is damaged; existing schedules were retained.'
    # Validate every expression before changing any existing working timer.
    while IFS= read -r record; do
        [[ -n "$record" ]] || continue
        ov_schedule_validate_record "$record"
    done <<<"$records"
    mkdir -p -- "$unit_dir"
    # Names contain only the validated numeric owner and safe record identifier.
    # Stop old timers before replacing; active backups are deliberately not stopped.
    for file in "$unit_dir/octovault-backup-$OV_UID-"*.timer; do
        [[ -f "$file" ]] || continue
        systemctl disable --now "${file##*/}" >/dev/null 2>&1 || true
        rm -f -- "$file"
    done
    for file in "$unit_dir/octovault-backup-$OV_UID-"*.service; do
        [[ -f "$file" ]] || continue
        rm -f -- "$file"
    done
    local -a timers=()
    while IFS= read -r record; do
        [[ -n "$record" ]] || continue
        id=$(jq -er '.id' <<<"$record") || ov_fail invalid_plan 'A backup plan has no identifier.'
        base=$(ov_event_unit_name "$id")
        trigger=$(jq -r '.trigger // "manual"' <<<"$record")
        # Every plan has a fixed worker service so desktop/vault events can queue it.
        file="$unit_dir/$base.service"
        (umask 022; cat > "$file" <<UNIT
[Unit]
Description=OctoVault backup for user $OV_UID ($id)
Wants=network-online.target
After=network-online.target

[Service]
Type=oneshot
ExecStart=/usr/libexec/octovault/run-plan $OV_UID $id
TimeoutStartSec=infinity
TimeoutStopSec=20s
KillMode=control-group
UMask=0077
LimitCORE=0
Nice=10
IOSchedulingClass=best-effort
IOSchedulingPriority=7
NoNewPrivileges=yes
UNIT
        )
        timer=''
        case "$trigger" in
            calendar)
                calendar=$(jq -er '.calendar' <<<"$record") || ov_fail invalid_schedule 'A calendar schedule needs an expression.'
                [[ "$calendar" != *$'\n'* && "$calendar" != *$'\r'* && "$calendar" != *'%'* && ${#calendar} -le 200 ]] || ov_fail invalid_schedule 'Invalid calendar expression.'
                systemd-analyze calendar "$calendar" >/dev/null 2>&1 || ov_fail invalid_schedule 'The calendar expression is not valid for systemd.'
                timer=$(printf 'OnCalendar=%s\nPersistent=true' "$calendar")
                ;;
            boot)
                delay=$(jq -r '.boot_delay_sec // 3600' <<<"$record")
                [[ "$delay" =~ ^[0-9]+$ && ${#delay} -le 8 && $delay -ge 1 ]] || ov_fail invalid_schedule 'Boot delay must be a positive number of seconds.'
                timer="OnBootSec=${delay}s"
                ;;
            manual|idle|vault-open|vault-close|drive) ;;
            *) ov_fail invalid_schedule 'Unknown backup schedule trigger.' ;;
        esac
        if [[ -n "$timer" ]]; then
            file="$unit_dir/$base.timer"
            (umask 022; cat > "$file" <<UNIT
[Unit]
Description=OctoVault backup schedule for user $OV_UID ($id)

[Timer]
$timer
AccuracySec=30s
RandomizedDelaySec=30s
Unit=$base.service

[Install]
WantedBy=timers.target
UNIT
            )
            timers+=("$base.timer")
        fi
    done <<<"$records"
    systemctl daemon-reload >/dev/null || ov_fail schedule_reload 'Could not reload backup schedules.'
    if ((${#timers[@]})); then
        systemctl enable --now "${timers[@]}" >/dev/null || ov_fail schedule_enable 'Could not enable backup schedules.'
    fi
}

ov_event_plan_allowed() {
    local record=$1 online supply battery=0 meter
    if [[ $(jq -r '.on_battery // false' <<<"$record") != true ]]; then
        for supply in /sys/class/power_supply/*; do
            [[ -f "$supply/type" ]] || continue
            if [[ $(<"$supply/type") == Battery ]]; then battery=1; fi
        done
        if ((battery)); then
            online=0
            for supply in /sys/class/power_supply/*/online; do
                [[ -r "$supply" ]] || continue
                [[ $(<"$supply") == 1 ]] && online=1
            done
            ((online)) || return 1
        fi
    fi
    if [[ $(jq -r '.metered // false' <<<"$record") != true ]]; then
        # NM_METERED_YES=1 and NM_METERED_GUESS_YES=3. Unknown is not guessed metered.
        meter=$(busctl --system get-property org.freedesktop.NetworkManager /org/freedesktop/NetworkManager org.freedesktop.NetworkManager Metered 2>/dev/null) || meter='u 0'
        [[ "$meter" != 'u 1' && "$meter" != 'u 3' ]] || return 1
    fi
    return 0
}

ov_event_queue_plan() {
    local id=$1 record=$2 base
    ov_event_plan_allowed "$record" || return 2
    base=$(ov_event_unit_name "$id")
    # No blocking start: the worker currently owns the per-user backend lock.
    # systemd coalesces an already active service rather than overlapping it.
    systemctl start --no-block "$base.service" >/dev/null 2>&1 || {
        ov_progress scheduling 'A matching backup could not be queued.'
        return 1
    }
}

ov_event_vault_transition() {
    local event=$1 vault=$2 record trigger id records
    [[ "$event" == vault-open || "$event" == vault-close ]] || return 1
    records=$(ov_event_records plans) || return 1
    while IFS= read -r record; do
        [[ -n "$record" ]] || continue
        trigger=$(jq -r '.trigger // "manual"' <<<"$record")
        [[ "$trigger" == "$event" && $(jq -r '.vault_id // ""' <<<"$record") == "$vault" ]] || continue
        id=$(jq -er '.id' <<<"$record") || continue
        ov_event_queue_plan "$id" "$record" || true
    done <<<"$records"
}

ov_event_resume_plans() {
    local marker id record queue_status
    [[ -d "$OV_ROOT/events" ]] || return 0
    for marker in "$OV_ROOT/events/"interrupted-*.json; do
        [[ -f "$marker" && ! -L "$marker" ]] || continue
        id=$(jq -er '.plan_id' "$marker") || continue
        ov_id "$id"
        if [[ ! -f "$OV_ROOT/plans/$id.json" ]]; then rm -f -- "$marker"; continue; fi
        ov_load plans "$id"; record=$OV_RECORD
        if ov_event_queue_plan "$id" "$record"; then
            rm -f -- "$marker"
        else
            queue_status=$?
            [[ $queue_status == 2 ]] || ov_progress scheduling 'An interrupted backup remains queued for a later session event.'
        fi
    done
}

ov_event_vault_operation() {
    local operation=$1 id=$2 force=${3:-false} result status
    # Run adapter in a subshell: ov_ok/ov_fail may terminate the worker function.
    if result=$(OV_OP="vault.$operation" OV_PARAMS=$(jq -nc --arg id "$id" --argjson force "$force" '{id:$id,force:$force}') ov_vault_dispatch); then
        status=$(jq -r '.ok // false' <<<"$result" 2>/dev/null) || status=false
        [[ "$status" == true ]] && return 0
    fi
    ov_progress vault-event "A vault could not complete the requested $operation operation. Open OctoVault for its current status."
    return 1
}

ov_event_dispatch() {
    local event id record mode force failures=0 count=0 drive idle threshold trigger now marker queue_status records unlock_requests='[]'
    case "$OV_OP" in
        schedule.sync)
            ov_schedule_sync
            ov_ok '{"synchronized":true}'
            return ;;
        event.handle)
            [[ ${OV_INTERNAL:-0} == 1 && $EUID -eq 0 ]] || ov_fail forbidden 'This event is reserved for the system service.' ;;
        event.session) ;;
        *) ov_fail invalid_operation 'Unknown automation operation.' ;;
    esac
    event=$(ov_require event)
    case "$event" in login|resume|screen-lock|logout|sleep|shutdown|idle|drive|token|vault-open|vault-close|timer) ;;
        *) ov_fail invalid_event 'Unsupported event.' ;; esac
    if [[ "$OV_OP" == event.session ]]; then
        case "$event" in vault-open|vault-close|timer) ov_fail forbidden 'This event cannot originate in a desktop session.' ;; esac
        jq -e 'keys | all(.[]; IN("event","drive_uuid","idle_seconds"))' <<<"$OV_PARAMS" >/dev/null ||
            ov_fail invalid_event 'Desktop events cannot include operation or configuration overrides.'
    fi
    if [[ "$event" == idle ]]; then
        idle=$(ov_param idle_seconds 0)
        [[ "$idle" =~ ^[0-9]+$ && ${#idle} -le 12 ]] || ov_fail invalid_idle 'Invalid idle duration.'
        idle=$((10#$idle))
    fi
    if [[ "$event" == timer ]]; then
        id=$(ov_require id); ov_load plans "$id"; record=$OV_RECORD
        if ! ov_event_plan_allowed "$record"; then
            ov_ok '{"skipped":true,"reason":"power-or-network-policy"}'; return
        fi
        OV_OP=backup.run OV_PARAMS=$(jq -nc --arg id "$id" '{id:$id}') ov_backup_dispatch
        return
    fi
    if [[ "$event" == vault-open || "$event" == vault-close ]]; then
        id=$(ov_require id); ov_load vaults "$id"
        ov_event_vault_transition "$event" "$id"
        ov_ok '{"queued":true}'; return
    fi
    drive=$(ov_param drive_uuid '')
    if [[ "$event" == drive ]]; then
        [[ "$drive" =~ ^[a-zA-Z0-9-]{1,128}$ ]] || ov_fail invalid_drive 'Invalid drive identifier.'
        findmnt --noheadings --output TARGET --source "UUID=$drive" >/dev/null 2>&1 || ov_fail missing_drive 'The configured drive is not mounted.'
    fi
    if [[ "$event" == token ]]; then
        # Device notification is a trigger, never an authentication substitute.
        ov_as_user timeout --signal=TERM --kill-after=1s 6s /usr/bin/gpg --batch --with-colons --card-status </dev/null >/dev/null 2>&1 || {
            ov_ok '{"skipped":true,"reason":"no-openpgp-card"}'; return
        }
    fi
    case "$event" in login|resume|idle|drive) ov_event_resume_plans ;; esac
    records=$(ov_event_records vaults) || ov_fail invalid_state 'A saved vault record is damaged; lock state cannot be established.'
    while IFS= read -r record; do
        [[ -n "$record" ]] || continue
        id=$(jq -er '.id' <<<"$record") || continue
        case "$event" in
            screen-lock|logout|sleep|shutdown)
                jq -e --arg event "$event" '(.close_on // ["shutdown"]) | index($event) != null' <<<"$record" >/dev/null || continue
                force=$(jq -r '.force_close // false' <<<"$record")
                if ov_event_vault_operation close "$id" "$force"; then ((count+=1)); else ((failures+=1)); fi
                ;;
            login|drive|token)
                mode=$(jq -r '.open_on // "manual"' <<<"$record")
                [[ "$mode" == "$event" ]] || continue
                if [[ "$event" == drive && $(jq -r '.drive_uuid // ""' <<<"$record") != "$drive" ]]; then continue; fi
                # Authentication belongs in the owning desktop. Never launch root pinentry.
                # Existing mounts need no prompt; the session agent receives only safe IDs.
                if ! ov_vault_is_open "$record"; then
                    unlock_requests=$(jq -c --arg id "$id" '. + [$id]' <<<"$unlock_requests")
                fi
                ;;
        esac
    done <<<"$records"
    if [[ "$event" == idle || "$event" == drive ]]; then
        now=$(date +%s)
        mkdir -p -- "$OV_ROOT/events"; chmod 0700 "$OV_ROOT/events"
        records=$(ov_event_records plans) || ov_fail invalid_state 'A saved backup plan is damaged.'
        while IFS= read -r record; do
            [[ -n "$record" ]] || continue
            trigger=$(jq -r '.trigger // "manual"' <<<"$record")
            [[ "$trigger" == "$event" ]] || continue
            id=$(jq -er '.id' <<<"$record") || continue; ov_id "$id"
            if [[ "$event" == drive ]]; then
                [[ $(jq -r '.drive_uuid // ""' <<<"$record") == "$drive" ]] || continue
            else
                threshold=$(jq -r '.idle_sec // 900' <<<"$record")
                [[ "$threshold" =~ ^[0-9]+$ && ${#threshold} -le 8 && $threshold -ge 60 ]] || continue
                marker="$OV_ROOT/events/idle-$id"
                # One run per idle episode. Activity clears the marker.
                if ((idle < threshold)); then rm -f -- "$marker"; continue; fi
                [[ ! -f "$marker" ]] || continue
            fi
            if ov_event_queue_plan "$id" "$record"; then
                [[ "$event" != idle ]] || (umask 077; printf '%s\n' "$now" > "$marker")
                ((count+=1))
            else
                queue_status=$?
                [[ $queue_status == 2 ]] || ((failures+=1))
            fi
        done <<<"$records"
    fi
    ((failures == 0)) || ov_fail event_incomplete 'One or more event operations failed; vaults must not be assumed locked.'
    ov_ok "$(jq -nc --arg event "$event" --argjson count "$count" --argjson unlock_requests "$unlock_requests" '{event:$event,completed:$count,unlock_requests:$unlock_requests}')"
}
