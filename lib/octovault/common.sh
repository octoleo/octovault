#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
# Shared worker utilities. Configuration is JSON data, never sourced as code.

ov_now() { date -u +'%Y-%m-%dT%H:%M:%SZ'; }
ov_new_id() { cat /proc/sys/kernel/random/uuid; }
ov_fail() {
    jq -cn --arg code "$1" --arg message "$2" '{ok:false,error:{code:$code,message:$message}}'
    exit 1
}
ov_ok() { jq -c '{ok:true,data:.}' <<<"${1:-null}"; }
ov_progress() {
    local percent=${3:-0}
    [[ $percent =~ ^[0-9]+([.][0-9]+)?$ ]] || percent=0
    jq -cn --arg stage "$1" --arg message "$2" --argjson percent "$percent" \
        '{stage:$stage,message:$message,percent:$percent}' >&2
}
ov_param() { jq -r --arg key "$1" --arg fallback "${2-}" 'if has($key) and .[$key] != null then .[$key] else $fallback end' <<<"$OV_PARAMS"; }
ov_require() {
    local value
    value=$(ov_param "$1")
    [[ -n $value && $value != null ]] || ov_fail invalid_request "Missing required field: $1"
    printf '%s' "$value"
}
ov_id() { [[ $1 =~ ^[a-zA-Z0-9_-]{1,64}$ ]] || ov_fail invalid_id 'Invalid record identifier.'; }
ov_collection() {
    case "$1" in vaults|destinations|repositories|plans|migrations|history|settings) ;; *) ov_fail invalid_collection 'Invalid record collection.';; esac
}
ov_load() {
    ov_collection "$1"; ov_id "$2"
    local file="$OV_ROOT/$1/$2.json"
    [[ -f $file && ! -L $file ]] || ov_fail not_found 'The requested record does not exist.'
    # shellcheck disable=SC2034 # Shared result consumed by sourced adapters.
    OV_RECORD=$(jq -ce 'select(type == "object" and .schema_version == 1)' "$file") || ov_fail invalid_state 'The saved record is damaged or has an unsupported version.'
}
ov_save() {
    ov_collection "$1"; ov_id "$2"
    local dir="$OV_ROOT/$1" tmp now
    [[ ! -L $dir ]] || ov_fail unsafe_state 'Unsafe state directory.'
    install -d -m 0700 "$dir"
    now=$(ov_now)
    tmp=$(mktemp "$dir/.record.XXXXXX") || ov_fail storage_error 'Cannot prepare saved state.'
    if ! jq -ce --arg id "$2" --arg now "$now" \
        'select(type == "object") | .id=$id | .schema_version=1 | .created_at=(.created_at // $now) | .updated_at=$now' <<<"$3" >"$tmp"; then
        rm -f -- "$tmp"; ov_fail invalid_state 'Cannot save invalid state.'
    fi
    chmod 0600 "$tmp"
    sync -f "$tmp"
    mv -fT -- "$tmp" "$dir/$2.json"
}
ov_list() {
    ov_collection "$1"
    local files=() file
    if [[ -d $OV_ROOT/$1 ]]; then
        while IFS= read -r -d '' file; do
            [[ ! -L $file ]] || ov_fail unsafe_state 'Unsafe record file.'
            files+=("$file")
        done < <(find "$OV_ROOT/$1" -maxdepth 1 -type f -name '*.json' -print0)
    fi
    if ((${#files[@]})); then jq -sce 'map(select(type == "object" and .schema_version == 1)) | sort_by(.name // .id)' "${files[@]}";
    else printf '[]\n'; fi
}
ov_as_user() (
    # Close inherited worker descriptors in this child only. In particular, a
    # user hook must not be able to unlock the parent's flock open description
    # or read an inherited credential FD. Stdin/stdout/stderr remain available
    # for deliberate streaming (including GPG key input/output).
    local descriptor path
    [[ -r /proc/self/fd ]] || return 125
    for path in /proc/self/fd/*; do
        descriptor=${path##*/}
        [[ $descriptor =~ ^[0-9]+$ && $descriptor -gt 2 ]] || continue
        exec {descriptor}>&-
    done
    if [[ $OV_UID == 0 ]]; then
        exec env -i PATH=/usr/sbin:/usr/bin:/sbin:/bin HOME="$OV_HOME" USER="$OV_USER" LOGNAME="$OV_USER" LANG=C.UTF-8 "$@"
    else
        exec runuser -u "$OV_USER" -- env -i PATH=/usr/sbin:/usr/bin:/sbin:/bin HOME="$OV_HOME" USER="$OV_USER" LOGNAME="$OV_USER" \
            LANG=C.UTF-8 XDG_RUNTIME_DIR="/run/user/$OV_UID" DBUS_SESSION_BUS_ADDRESS="unix:path=/run/user/$OV_UID/bus" "$@"
    fi
)
ov_run() { "$@" >&2; }
ov_credential_set() {
    ov_id "$1"
    local dir="$OV_ROOT/credentials" tmp
    [[ ! -L $dir ]] || ov_fail unsafe_state 'Unsafe credential directory.'
    install -d -m 0700 "$dir"
    tmp=$(mktemp "$dir/.credential.XXXXXX") || ov_fail credential_error 'Cannot prepare encrypted credential.'
    if ! printf '%s' "$2" | systemd-creds encrypt --name="$1" --with-key=auto - "$tmp" >/dev/null 2>&1; then
        rm -f -- "$tmp"; ov_fail credential_error 'The operating system could not encrypt this credential. Check systemd credential support.'
    fi
    chmod 0600 "$tmp"; sync -f "$tmp"; mv -fT -- "$tmp" "$dir/$1.cred"
}
ov_credential_get() {
    ov_id "$1"
    [[ -f $OV_ROOT/credentials/$1.cred && ! -L $OV_ROOT/credentials/$1.cred ]] || ov_fail credential_missing 'The encrypted credential is unavailable.'
    systemd-creds decrypt --name="$1" "$OV_ROOT/credentials/$1.cred" - 2>/dev/null || ov_fail credential_error 'Cannot unlock the stored credential on this installation. Restore it using your recovery information.'
}
ov_secret_fd() {
    local file
    install -d -m 0700 /run/octovault
    file=$(mktemp /run/octovault/.secret.XXXXXX) || ov_fail credential_error 'Cannot allocate secret input.'
    chmod 0600 "$file"
    printf '%s' "$1" >"$file"
    exec {OV_SECRET_FD}<"$file"
    rm -f -- "$file"
    export OV_SECRET_FD
}
ov_secret_close() {
    if [[ ${OV_SECRET_FD-} =~ ^[0-9]+$ ]]; then exec {OV_SECRET_FD}<&-; fi
    if [[ ${OV_OLD_SECRET_FD-} =~ ^[0-9]+$ ]]; then exec {OV_OLD_SECRET_FD}<&-; fi
    unset OV_SECRET_FD OV_OLD_SECRET_FD OV_OLD_KEY_PATH
}
ov_old_secret_fd() {
    local file
    install -d -m 0700 /run/octovault
    file=$(mktemp /run/octovault/.secret.XXXXXX) || ov_fail credential_error 'Cannot allocate old secret input.'
    chmod 0600 "$file"
    printf '%s' "$1" >"$file"
    exec {OV_OLD_SECRET_FD}<"$file"
    rm -f -- "$file"
    export OV_OLD_SECRET_FD
}
ov_validate_path() {
    [[ $1 == /* && $1 != *$'\n'* && $1 != *$'\r'* ]] || ov_fail invalid_path 'Use an absolute path without line breaks.'
}
ov_resource_lock() {
    local identity
    [[ -z ${OV_RESOURCE_FD-} ]] || return 0
    install -d -m 0700 /run/octovault/locks
    if [[ -e $1 ]]; then
        identity=$(stat -Lc '%d_%i' -- "$1") || ov_fail unavailable 'Cannot identify the vault container.'
    else
        identity=$(realpath -m -- "$1" | sha256sum | cut -d' ' -f1)
    fi
    exec {OV_RESOURCE_FD}>"/run/octovault/locks/$identity.lock"
    flock -n "$OV_RESOURCE_FD" || ov_fail busy 'Another OctoVault operation is using this container. Retry after it completes.'
}
ov_resource_unlock() {
    if [[ ${OV_RESOURCE_FD-} =~ ^[0-9]+$ ]]; then exec {OV_RESOURCE_FD}>&-; fi
    unset OV_RESOURCE_FD
}
ov_init() {
    [[ $EUID == 0 ]] || ov_fail permission_denied 'The OctoVault worker must run through the system service.'
    [[ ${1-} =~ ^[0-9]+$ ]] || ov_fail invalid_owner 'Invalid account identifier.'
    OV_UID=$1
    local entry
    entry=$(getent passwd "$OV_UID") || ov_fail invalid_owner 'The account no longer exists.'
    OV_USER=$(cut -d: -f1 <<<"$entry"); OV_HOME=$(cut -d: -f6 <<<"$entry")
    [[ $OV_HOME == /* ]] || ov_fail invalid_owner 'The account home is invalid.'
    OV_ROOT="/var/lib/octovault/users/$OV_UID"
    [[ ! -L /var/lib/octovault && ! -L /var/lib/octovault/users && ! -L $OV_ROOT ]] || ov_fail unsafe_state 'Unsafe application state path.'
    install -d -m 0700 /var/lib/octovault /var/lib/octovault/users "$OV_ROOT"
    install -d -m 0700 /run/octovault
    exec {OV_LOCK_FD}>"$OV_ROOT/operation.lock"
    flock -w 300 "$OV_LOCK_FD" || ov_fail busy 'Another operation is still running. Try again when it completes.'
    export OV_UID OV_USER OV_HOME OV_ROOT
}
