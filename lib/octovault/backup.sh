#!/bin/bash
# OctoVault's Restic adapter. Sourced only by the privileged, authorized worker.
# Credentials never enter command arguments, persistent logs or configuration.

ov_backup_cleanup() {
    [[ -z ${OV_BACKUP_TMP:-} ]] || rm -rf -- "$OV_BACKUP_TMP"
    [[ -z ${OV_BACKUP_IO:-} || ${OV_BACKUP_IO:-} == "${OV_BACKUP_TMP:-}" ]] || rm -rf -- "$OV_BACKUP_IO"
    unset OV_BACKUP_TMP OV_BACKUP_IO OV_BACKUP_WORKSPACE_SCOPE
    if declare -F ov_secret_close >/dev/null; then ov_secret_close; fi
    if declare -F ov_resource_unlock >/dev/null; then ov_resource_unlock; fi
    if declare -F ov_error_cleanup >/dev/null; then ov_error_cleanup; fi
    # A vault event can enter the backup adapter in the same worker. Preserve
    # the backend's vault cleanup when this adapter installs its EXIT trap.
    # ov_vault_unpin deliberately retains aliases that still have a loop device.
    if declare -F ov_vault_cleanup >/dev/null; then ov_vault_cleanup; fi
}

ov_backup_workspace() {
    local scope=${OV_BACKUP_SCOPE:-${OV_EXECUTION_SCOPE:-system}}
    if [[ -n ${OV_BACKUP_TMP:-} ]]; then
        [[ ${OV_BACKUP_WORKSPACE_SCOPE:-system} == "$scope" ]] || ov_fail scope_mismatch 'Backup execution scope changed while preparing private inputs.'
        return 0
    fi
    OV_BACKUP_WORKSPACE_SCOPE=$scope
    install -d -m 0700 "${OV_RUNTIME_ROOT:-/run/octovault}"
    OV_BACKUP_TMP=$(mktemp -d "${OV_RUNTIME_ROOT:-/run/octovault}/backup.XXXXXXXX")
    chmod 0700 "$OV_BACKUP_TMP"
    OV_BACKUP_IO=$OV_BACKUP_TMP
    if [[ $scope == personal ]]; then
        # Root owns every directory entry. The owner process can read only the
        # individual inputs prepared for this operation, not replace entries.
        local base=/run/octovault-personal
        [[ ! -L $base ]] || ov_fail unsafe_state 'Unsafe personal backup runtime directory.'
        install -d -o root -g root -m 0711 "$base"
        [[ $(stat -c '%u:%a' "$base") == 0:711 ]] || ov_fail unsafe_state 'Unsafe personal backup runtime permissions.'
        OV_BACKUP_IO=$(mktemp -d "$base/job.XXXXXXXX")
        chmod 0711 "$OV_BACKUP_IO"
    fi
    trap ov_backup_cleanup EXIT
}

ov_backup_use_record() {
    ov_scope_require_record "$1"
    OV_BACKUP_SCOPE=$(ov_record_scope "$1")
}

ov_backup_require_record() {
    ov_scope_require_record "$1"
    [[ $(ov_record_scope "$1") == "${OV_BACKUP_SCOPE:-${OV_EXECUTION_SCOPE:-system}}" ]] ||
        ov_fail scope_mismatch 'Personal and system backup resources cannot be combined. Select resources with the same access scope.'
}

ov_backup_process() (
    local item path descriptor name owner_user=$OV_USER owner_home=$OV_HOME
    if [[ ${OV_BACKUP_SCOPE:-system} == personal ]]; then
        # These directory entries remain root-owned. Root never executes their
        # contents: an SSH askpass helper runs with the owner's identity.
        for path in "$OV_BACKUP_IO/"*; do
            [[ -e $path ]] || continue
            [[ -f $path && ! -L $path ]] || ov_fail unsafe_state 'Unsafe personal backup input.'
            chown "$OV_UID:$(id -g "$OV_USER")" -- "$path"
            if [[ ${path##*/} == askpass ]]; then chmod 0500 "$path"; else chmod 0400 "$path"; fi
        done
        # Credentials belong in the child environment, never env(1) arguments.
        for path in /proc/self/fd/*; do
            descriptor=${path##*/}
            [[ $descriptor =~ ^[0-9]+$ && $descriptor -gt 2 ]] || continue
            exec {descriptor}>&-
        done
        while IFS= read -r name; do unset "$name" 2>/dev/null || true; done < <(compgen -e)
        export PATH=/usr/sbin:/usr/bin:/sbin:/bin LANG=C.UTF-8 LC_ALL=C.UTF-8
        export HOME="$owner_home" USER="$owner_user" LOGNAME="$owner_user"
        for item in "${OV_RESTIC_ENV[@]}"; do export "${item?}"; done
        [[ -z ${OV_RESTIC_PASSWORD_FILE:-} ]] || export RESTIC_PASSWORD_FILE="$OV_RESTIC_PASSWORD_FILE"
        exec runuser --preserve-environment -u "$owner_user" -- "$@"
    fi
    unset RESTIC_PASSWORD RESTIC_PASSWORD_COMMAND RESTIC_REPOSITORY RESTIC_REPOSITORY_FILE
    unset AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY AWS_SESSION_TOKEN AWS_PROFILE
    unset RESTIC_REST_USERNAME RESTIC_REST_PASSWORD SSH_AUTH_SOCK
    for item in "${OV_RESTIC_ENV[@]}"; do export "${item?}"; done
    [[ -z ${OV_RESTIC_PASSWORD_FILE:-} ]] || export RESTIC_PASSWORD_FILE="$OV_RESTIC_PASSWORD_FILE"
    "$@"
)

ov_backup_string() {
    local value=$1 label=$2
    [[ $value != *$'\n'* && $value != *$'\r'* && $value != *$'\t'* ]] || ov_fail invalid_parameter "$label must not contain control characters."
}

ov_backup_absolute() {
    ov_backup_string "$1" path
    [[ $1 == /* && $1 != / && $1 != *'/../'* && $1 != */.. ]] || ov_fail invalid_path 'Provide an absolute path other than the filesystem root, without parent traversal.'
}

ov_backup_relative() {
    ov_backup_string "$1" path
    [[ $1 != /* && $1 != .. && $1 != ../* && $1 != *'/../'* && $1 != */.. ]] || ov_fail invalid_path 'Repository paths must be relative to their destination without parent traversal.'
}

ov_backup_number() {
    [[ $1 =~ ^[0-9]+$ && ${#1} -le 9 ]] || ov_fail invalid_parameter "$2 must be a nonnegative integer."
}

ov_backup_snapshot() {
    [[ $1 == latest || $1 =~ ^[a-fA-F0-9]{8,64}$ ]] || ov_fail invalid_snapshot 'Choose a snapshot ID or latest.'
}

ov_backup_require_tools() {
    command -v restic >/dev/null || ov_fail dependency_missing 'The backup engine is not installed.'
}

ov_backup_save_record() {
    local collection=$1 id=$2 record=$3 now
    now=$(ov_now)
    record=$(jq --arg now "$now" --arg scope "${OV_BACKUP_SCOPE:-${OV_EXECUTION_SCOPE:-system}}" '.execution_scope=$scope | .schema_version=1 | .created_at=(.created_at // $now) | .updated_at=$now' <<<"$record")
    ov_save "$collection" "$id" "$record"
}

ov_backup_get_destination() {
    ov_load destinations "$1"
    OV_DESTINATION=$OV_RECORD
    ov_backup_require_record "$OV_DESTINATION"
}

ov_backup_url() {
    local destination=$1 relative=$2 kind base host user port endpoint bucket
    ov_backup_relative "$relative"
    kind=$(jq -r .type <<<"$destination")
    base=$(jq -r '.path // ""' <<<"$destination")
    [[ -z $relative ]] || base="${base%/}/$relative"
    case "$kind" in
        local) printf '%s' "$base" ;;
        s3)
            endpoint=$(jq -r .endpoint <<<"$destination")
            bucket=$(jq -r .bucket <<<"$destination")
            printf 's3:%s/%s/%s' "${endpoint%/}" "$bucket" "${base#/}"
            ;;
        sftp)
            host=$(jq -r .host <<<"$destination")
            user=$(jq -r .user <<<"$destination")
            port=$(jq -r '.port // 22' <<<"$destination")
            [[ $host != *:* ]] || host="[$host]"
            printf 'sftp://%s@%s:%s/%s' "$user" "$host" "$port" "$base"
            ;;
        rest)
            endpoint=$(jq -r .endpoint <<<"$destination")
            printf 'rest:%s/%s' "${endpoint%/}" "${base#/}"
            ;;
        *) ov_fail invalid_destination 'Unsupported destination type.' ;;
    esac
}

# Write the secret directly to a private runtime file. Never place it in argv.
ov_backup_secret_file() {
    local reference=$1 output=$2
    ov_id "$reference"
    (umask 077; ov_credential_get "$reference" >"$output") || ov_fail credential_unavailable 'Unable to decrypt the backup credentials.'
}

ov_backup_prepare_destination() {
    local destination=$1 prefix=${2:-primary} kind reference value key_file known_file pass_file config_file host
    ov_backup_require_record "$destination"
    ov_backup_workspace
    kind=$(jq -r .type <<<"$destination")
    OV_RESTIC_OPTIONS=()
    OV_RESTIC_ENV=()
    case "$kind" in
        s3)
            for reference in access_key secret_key; do
                value=$(ov_credential_get "$(jq -r ".credentials.$reference" <<<"$destination")") || ov_fail credential_unavailable 'Unable to decrypt the S3 credentials.'
                case $reference in
                    access_key) OV_RESTIC_ENV+=("AWS_ACCESS_KEY_ID=$value") ;;
                    secret_key) OV_RESTIC_ENV+=("AWS_SECRET_ACCESS_KEY=$value") ;;
                esac
            done
            OV_RESTIC_ENV+=("AWS_DEFAULT_REGION=$(jq -r '.region // "us-east-1"' <<<"$destination")")
            ;;
        rest)
            for reference in rest_username rest_password; do
                if [[ $(jq -r ".credentials.$reference // empty" <<<"$destination") ]]; then
                    value=$(ov_credential_get "$(jq -r ".credentials.$reference" <<<"$destination")") || ov_fail credential_unavailable 'Unable to decrypt the server credentials.'
                    case $reference in
                        rest_username) OV_RESTIC_ENV+=("RESTIC_REST_USERNAME=$value") ;;
                        rest_password) OV_RESTIC_ENV+=("RESTIC_REST_PASSWORD=$value") ;;
                    esac
                fi
            done
            ;;
        sftp)
            key_file="$OV_BACKUP_IO/$prefix.identity"
            known_file="$OV_BACKUP_IO/$prefix.known_hosts"
            config_file="$OV_BACKUP_IO/$prefix.ssh_config"
            pass_file="$OV_BACKUP_IO/$prefix.passphrase"
            ov_backup_secret_file "$(jq -r .credentials.ssh_private_key <<<"$destination")" "$key_file"
            printf '\n' >>"$key_file"
            jq -r .known_hosts <<<"$destination" >"$known_file"
            host=$(jq -r .host <<<"$destination")
            {
                printf 'Host %s\n  HostName %s\n' "$host" "$host"
                printf '  User %s\n  Port %s\n' "$(jq -r .user <<<"$destination")" "$(jq -r .port <<<"$destination")"
                printf '  IdentityFile %s\n  UserKnownHostsFile %s\n' "$key_file" "$known_file"
                printf '  IdentitiesOnly yes\n  StrictHostKeyChecking yes\n  PasswordAuthentication no\n  KbdInteractiveAuthentication no\n  ConnectTimeout 20\n  ServerAliveInterval 30\n  ServerAliveCountMax 3\n'
            } >"$config_file"
            reference=$(jq -r '.credentials.ssh_passphrase // empty' <<<"$destination")
            if [[ -n $reference ]]; then
                ov_backup_secret_file "$reference" "$pass_file"
                printf '#!/bin/sh\nexec /bin/cat "$OCTOVAULT_SSH_PASSPHRASE_FILE"\n' >"$OV_BACKUP_IO/askpass"
                chmod 0700 "$OV_BACKUP_IO/askpass"
                OV_RESTIC_ENV+=("SSH_ASKPASS=$OV_BACKUP_IO/askpass" 'SSH_ASKPASS_REQUIRE=force' 'DISPLAY=:0' "OCTOVAULT_SSH_PASSPHRASE_FILE=$pass_file")
            else
                printf '  BatchMode yes\n' >>"$config_file"
            fi
            OV_RESTIC_OPTIONS+=(-o "sftp.args=-F $config_file")
            ;;
        local) ;;
        *) ov_fail invalid_destination 'Unsupported destination type.' ;;
    esac
}

ov_backup_prepare_repository() {
    local record=$1 prefix=${2:-primary}
    ov_backup_require_record "$record"
    ov_backup_require_tools
    ov_backup_get_destination "$(jq -r .destination_id <<<"$record")"
    ov_backup_prepare_destination "$OV_DESTINATION" "$prefix"
    OV_RESTIC_REPOSITORY=$(jq -r .repository <<<"$record")
    OV_RESTIC_PASSWORD_FILE="$OV_BACKUP_IO/$prefix.password"
    ov_backup_secret_file "$(jq -r .credential_id <<<"$record")" "$OV_RESTIC_PASSWORD_FILE"
}

# env arguments are populated by the shell, and would otherwise expose secrets
# in /proc/.../cmdline. Export only inside this short-lived subshell instead.
ov_backup_restic_process() (
    ov_backup_process restic --json --no-cache --repo "$OV_RESTIC_REPOSITORY" "${OV_RESTIC_OPTIONS[@]}" "$@"
)

ov_backup_execute() {
    local stage=$1 line percent parser result=0
    shift
    : >"$OV_BACKUP_TMP/output"
    : >"$OV_BACKUP_TMP/errors"
    rm -f "$OV_BACKUP_TMP/progress"
    mkfifo -m 0600 "$OV_BACKUP_TMP/progress"
    (
        while IFS= read -r line; do
            printf '%s\n' "$line" >>"$OV_BACKUP_TMP/output"
            if jq -e '.message_type == "status" and (.percent_done | type == "number")' >/dev/null 2>&1 <<<"$line"; then
                percent=$(jq -r '(.percent_done * 100 | floor) | if . < 0 then 0 elif . > 100 then 100 else . end' <<<"$line")
                ov_progress "$stage" 'The backup engine is processing the operation.' "$percent"
            fi
        done <"$OV_BACKUP_TMP/progress"
    ) &
    parser=$!
    ov_progress "$stage" 'Starting the backup engine.' 0
    ov_backup_restic_process "$@" >"$OV_BACKUP_TMP/progress" 2>"$OV_BACKUP_TMP/errors" || result=$?
    wait "$parser" || :
    rm -f "$OV_BACKUP_TMP/progress"
    OV_RESTIC_STATUS=$result
    OV_RESTIC_OUTPUT=$(cat "$OV_BACKUP_TMP/output")
    # Diagnostics can contain backend credentials. Keep them runtime-only and
    # return an actionable classified error instead of echoing raw stderr.
    return "$result"
}

ov_backup_check_result() {
    case ${OV_RESTIC_STATUS:-1} in
        0) return 0 ;;
        3) ov_fail partial 'The backup engine completed with unreadable source files or incomplete removals. Review source permissions and retry.' ;;
        10) ov_fail repository_missing 'The backup repository does not exist at the configured location.' ;;
        11) ov_fail repository_locked 'The repository is in use. Wait for the other operation to finish.' ;;
        12) ov_fail incorrect_password 'The repository password is incorrect.' ;;
        130|143) ov_fail cancelled 'The backup operation was cancelled.' ;;
        *) ov_fail restic_failed 'The backup engine could not complete the operation. Check destination access, available storage, and the selected paths.' ;;
    esac
}

ov_backup_json_result() {
    local mode=${1:-array} result
    if [[ $mode == text ]]; then
        # Never return raw backend errors or unsanitized text.
        ov_ok '{"completed":true}'
    elif [[ -z ${OV_RESTIC_OUTPUT:-} ]]; then
        ov_ok '{}'
    else
        result=$(jq -sc 'if length == 1 then .[0] else . end' <<<"$OV_RESTIC_OUTPUT") || ov_fail invalid_output 'The backup engine returned an unexpected response.'
        ov_ok "$result"
    fi
}

ov_destination_save() {
    local id record kind name key value reference old known fingerprint host port endpoint bucket path existing
    id=$(ov_param id)
    if [[ -n $id ]]; then ov_load destinations "$id"; record=$OV_RECORD; else id=$(ov_new_id); record='{}'; fi
    if [[ $record != '{}' ]]; then ov_backup_use_record "$record"; fi
    old=$record
    record=$(jq --arg id "$id" --argjson old "$record" '$old + ({name,type,endpoint,region,bucket,host,port,user,path,host_fingerprint} | with_entries(select(.value != null))) | .id=$id | .credentials=(.credentials // {})' <<<"$OV_PARAMS")
    kind=$(jq -r '.type // ""' <<<"$record")
    name=$(jq -r '.name // ""' <<<"$record")
    [[ -n $name ]] || ov_fail invalid_parameter 'A destination name is required.'
    ov_backup_string "$name" name
    if [[ $old != '{}' ]] && [[ $(jq -c '{type,endpoint,bucket,host,port,user,path}' <<<"$old") != "$(jq -c '{type,endpoint,bucket,host,port,user,path}' <<<"$record")" ]]; then
        for existing in "$OV_ROOT/repositories/"*.json; do
            [[ -f $existing ]] || continue
            if jq -e --arg id "$id" '.destination_id == $id' "$existing" >/dev/null; then
                ov_fail destination_in_use 'A destination used by repositories cannot change its storage location or account. Add another destination and import or copy the repository instead.'
            fi
        done
    fi
    case $kind in
        local)
            path=$(jq -r '.path // ""' <<<"$record")
            ov_backup_absolute "$path"
            ;;
        s3|rest)
            endpoint=$(jq -r '.endpoint // ""' <<<"$record")
            ov_backup_string "$endpoint" endpoint
            [[ $endpoint =~ ^https://[^/@?#[:space:]]+(:[0-9]+)?(/[^?#[:space:]]*)?$ || $endpoint =~ ^http://(127\.0\.0\.1|localhost)(:[0-9]+)?(/[^?#[:space:]]*)?$ ]] || ov_fail invalid_endpoint 'Use an HTTPS endpoint without embedded credentials, query parameters or fragments. HTTP is allowed only for local testing.'
            path=$(jq -r '.path // ""' <<<"$record")
            ov_backup_relative "$path"
            if [[ $kind == s3 ]]; then
                bucket=$(jq -r '.bucket // ""' <<<"$record")
                [[ $bucket =~ ^[a-zA-Z0-9][a-zA-Z0-9._-]{1,62}$ ]] || ov_fail invalid_bucket 'Provide a valid S3 bucket name.'
                value=$(jq -r '.region // "us-east-1"' <<<"$record")
                [[ -n $value ]] || value=us-east-1
                [[ $value =~ ^[a-zA-Z0-9_-]+$ ]] || ov_fail invalid_region 'Provide a valid S3 region identifier.'
                record=$(jq --arg region "$value" '.region=$region' <<<"$record")
            fi
            ;;
        sftp)
            host=$(jq -r '.host // ""' <<<"$record")
            [[ $host =~ ^[a-zA-Z0-9][a-zA-Z0-9.:-]*$ ]] || ov_fail invalid_host 'Provide a hostname or IP address.'
            value=$(jq -r '.user // ""' <<<"$record")
            [[ $value =~ ^[a-zA-Z_][a-zA-Z0-9_.-]*$ ]] || ov_fail invalid_user 'Provide a valid remote account name.'
            port=$(jq -r '.port // 22' <<<"$record")
            ov_backup_number "$port" port
            (( 10#$port >= 1 && 10#$port <= 65535 )) || ov_fail invalid_port 'SSH port must be between 1 and 65535.'
            path=$(jq -r '.path // ""' <<<"$record")
            ov_backup_string "$path" path
            [[ -n $path && $path != *'"'* && $path != *'\\'* ]] || ov_fail invalid_path 'Provide a remote path without quotes or backslashes.'
            fingerprint=$(jq -r '.host_fingerprint // ""' <<<"$record")
            [[ $fingerprint =~ ^SHA256:[A-Za-z0-9+/]+={0,2}$ ]] || ov_fail fingerprint_required 'Provide the server SSH SHA256 host-key fingerprint verified through a trusted channel.'
            ov_backup_workspace
            ssh-keyscan -T 10 -p "$port" "$host" >"$OV_BACKUP_TMP/keyscan" 2>/dev/null || ov_fail host_unreachable 'Unable to retrieve the SSH server host key.'
            known=''
            while IFS= read -r value; do
                [[ -n $value && $value != \#* ]] || continue
                printf '%s\n' "$value" >"$OV_BACKUP_TMP/keycandidate"
                if [[ $(ssh-keygen -lf "$OV_BACKUP_TMP/keycandidate" -E sha256 2>/dev/null | awk '{print $2}') == "$fingerprint" ]]; then known=$value; break; fi
            done <"$OV_BACKUP_TMP/keyscan"
            [[ -n $known ]] || ov_fail host_key_mismatch 'The SSH server key does not match the trusted fingerprint.'
            record=$(jq --arg known "$known" --argjson port "$port" '.known_hosts=$known | .port=$port' <<<"$record")
            ;;
        *) ov_fail invalid_type 'Destination type must be local, s3, sftp or rest.' ;;
    esac
    for key in access_key secret_key ssh_private_key ssh_passphrase rest_username rest_password; do
        value=$(jq -r --arg key "$key" '.[$key] // empty' <<<"$OV_PARAMS")
        [[ -n $value ]] || continue
        [[ $key == ssh_private_key ]] || ov_backup_string "$value" "$key"
        reference="destination-${id}-${key}"
        ov_credential_set "$reference" "$value"
        record=$(jq --arg key "$key" --arg reference "$reference" '.credentials[$key]=$reference' <<<"$record")
    done
    case $kind in
        s3) jq -e '.credentials.access_key and .credentials.secret_key' >/dev/null <<<"$record" || ov_fail credentials_required 'S3 access key and secret access key are required.' ;;
        sftp) jq -e .credentials.ssh_private_key >/dev/null <<<"$record" || ov_fail credentials_required 'An SSH private key is required.' ;;
    esac
    if systemd-creds has-tpm2 >/dev/null 2>&1; then value='tpm2-and-host'; else value='host-key'; fi
    record=$(jq --arg protection "$value" '.credential_protection=$protection' <<<"$record")
    ov_backup_save_record destinations "$id" "$record"
    ov_load destinations "$id"
    ov_ok "$OV_RECORD"
}

ov_backup_curl_quote() {
    local value=$1
    value=${value//\\/\\\\}; value=${value//\"/\\\"}
    printf '%s' "$value"
}

ov_destination_test() {
    local destination=$1 kind endpoint bucket access secret region username password path result=0
    ov_backup_prepare_destination "$destination"
    kind=$(jq -r .type <<<"$destination")
    path=$(jq -r '.path // ""' <<<"$destination")
    case $kind in
        local)
            if ! ov_backup_process test -d "$path" || ! ov_backup_process test -r "$path" || ! ov_backup_process test -w "$path"; then
                ov_fail destination_unavailable 'The local destination must exist and be readable and writable by the configured backup account.'
            fi
            ;;
        sftp)
            printf 'ls "%s"\n' "$path" >"$OV_BACKUP_IO/sftp_batch"
            ov_backup_process sftp -oBatchMode=no -F "$OV_BACKUP_IO/primary.ssh_config" -b "$OV_BACKUP_IO/sftp_batch" "$(jq -r .host <<<"$destination")" \
                >"$OV_BACKUP_TMP/test.out" 2>"$OV_BACKUP_TMP/test.err" || result=$?
            ;;
        s3|rest)
            endpoint=$(jq -r .endpoint <<<"$destination")
            {
                printf 'silent\nshow-error\nfail\nconnect-timeout = 15\nmax-time = 30\n'
                if [[ $kind == s3 ]]; then
                    bucket=$(jq -r .bucket <<<"$destination")
                    region=$(jq -r '.region // "us-east-1"' <<<"$destination")
                    access=$(ov_credential_get "$(jq -r .credentials.access_key <<<"$destination")")
                    secret=$(ov_credential_get "$(jq -r .credentials.secret_key <<<"$destination")")
                    printf 'aws-sigv4 = "aws:amz:%s:s3"\n' "$(ov_backup_curl_quote "$region")"
                    printf 'user = "%s:%s"\n' "$(ov_backup_curl_quote "$access")" "$(ov_backup_curl_quote "$secret")"
                    printf 'url = "%s/%s?list-type=2&max-keys=1"\n' "$(ov_backup_curl_quote "${endpoint%/}")" "$bucket"
                else
                    username=''; password=''
                    [[ $(jq -r '.credentials.rest_username // empty' <<<"$destination") == '' ]] || username=$(ov_credential_get "$(jq -r .credentials.rest_username <<<"$destination")")
                    [[ $(jq -r '.credentials.rest_password // empty' <<<"$destination") == '' ]] || password=$(ov_credential_get "$(jq -r .credentials.rest_password <<<"$destination")")
                    printf 'user = "%s:%s"\n' "$(ov_backup_curl_quote "$username")" "$(ov_backup_curl_quote "$password")"
                    printf 'url = "%s/%s/"\n' "$(ov_backup_curl_quote "${endpoint%/}")" "$(ov_backup_curl_quote "${path#/}")"
                fi
            } >"$OV_BACKUP_IO/curl.config"
            ov_backup_process curl --config "$OV_BACKUP_IO/curl.config" >"$OV_BACKUP_TMP/test.out" 2>"$OV_BACKUP_TMP/test.err" || result=$?
            ;;
    esac
    (( result == 0 )) || ov_fail destination_unavailable 'Destination access failed. Check network connectivity, credentials, remote path and access permissions.'
    ov_ok '{"reachable":true,"message":"Destination access succeeded. Repository operations also verify write permissions."}'
}

ov_repository_create() {
    local action=$1 id name destination_id relative destination repository password credential record rid
    id=$(ov_new_id)
    name=$(ov_require name)
    destination_id=$(ov_require destination_id)
    relative=$(ov_param path)
    ov_load destinations "$destination_id"
    ov_backup_use_record "$OV_RECORD"
    ov_backup_get_destination "$destination_id"; destination=$OV_DESTINATION
    repository=$(ov_backup_url "$destination" "$relative")
    if [[ $action == import ]]; then password=$(ov_require password); else password=$(head -c 48 /dev/urandom | base64 -w 0); fi
    credential="repository-$id"
    ov_credential_set "$credential" "$password"
    record=$(jq -n --arg id "$id" --arg name "$name" --arg did "$destination_id" --arg path "$relative" --arg repository "$repository" --arg cid "$credential" --arg scope "$OV_BACKUP_SCOPE" '{id:$id,name:$name,destination_id:$did,path:$path,repository:$repository,credential_id:$cid,execution_scope:$scope}')
    ov_backup_prepare_repository "$record"
    if [[ $action == create ]]; then ov_backup_execute initialize init || :; else ov_backup_execute import cat config || :; fi
    ov_backup_check_result
    # cat config returns the repository ID without exposing cryptographic keys.
    if [[ $action == create ]]; then ov_backup_execute inspect cat config || :; ov_backup_check_result; fi
    rid=$(jq -r .id <<<"$OV_RESTIC_OUTPUT")
    [[ $rid =~ ^[a-fA-F0-9]{64}$ ]] || ov_fail invalid_repository 'The repository did not provide a valid identity.'
    record=$(jq --arg rid "$rid" '.repository_id=$rid' <<<"$record")
    ov_backup_save_record repositories "$id" "$record"
    ov_load repositories "$id"
    ov_ok "$(jq '. + {recovery_required:true}' <<<"$OV_RECORD")"
}

ov_repository_recovery() {
    local record=$1 destination result key reference value
    ov_backup_require_record "$record"
    ov_backup_get_destination "$(jq -r .destination_id <<<"$record")"; destination=$OV_DESTINATION
    # Secret values enter jq through stdin, never its argv. jq --rawfile reads
    # only transient files whose names contain no secret information.
    ov_backup_workspace
    ov_backup_secret_file "$(jq -r .credential_id <<<"$record")" "$OV_BACKUP_TMP/recovery-password"
    result=$(jq --rawfile password "$OV_BACKUP_TMP/recovery-password" --argjson d "$destination" '{name,repository,repository_id,RESTIC_REPOSITORY:.repository,RESTIC_PASSWORD:$password,destination_type:$d.type,endpoint:$d.endpoint,region:$d.region,AWS_DEFAULT_REGION:(if $d.type == "s3" then ($d.region // "us-east-1") else null end),bucket:$d.bucket,ssh_host:$d.host,ssh_port:$d.port,ssh_user:$d.user,ssh_host_fingerprint:$d.host_fingerprint,ssh_known_hosts:$d.known_hosts} | with_entries(select(.value != null))' <<<"$record")
    for key in access_key secret_key ssh_private_key ssh_passphrase rest_username rest_password; do
        reference=$(jq -r --arg key "$key" '.credentials[$key] // empty' <<<"$destination")
        [[ -n $reference ]] || continue
        ov_backup_secret_file "$reference" "$OV_BACKUP_TMP/recovery-secret"
        case $key in access_key) key=AWS_ACCESS_KEY_ID ;; secret_key) key=AWS_SECRET_ACCESS_KEY ;; rest_username) key=RESTIC_REST_USERNAME ;; rest_password) key=RESTIC_REST_PASSWORD ;; esac
        result=$(jq --arg key "$key" --rawfile secret "$OV_BACKUP_TMP/recovery-secret" '.[$key]=(if $key == "ssh_private_key" then $secret + "\n" else $secret end)' <<<"$result")
    done
    ov_ok "$result"
}

ov_repository_action() {
    local action=$1 record=$2 snapshot path target overwrite value key new_password new_credential id result dry_run restore_help
    local -a args=()
    ov_backup_prepare_repository "$record"
    case $action in
        snapshots) args=(snapshots) ;;
        stats) args=(stats --mode raw-data) ;;
        check)
            args=(check)
            [[ $(ov_param read_data false) != true ]] || args+=(--read-data)
            ;;
        files)
            snapshot=$(ov_param snapshot latest); ov_backup_snapshot "$snapshot"
            args=(ls "$snapshot")
            path=$(ov_param path)
            [[ -z $path ]] || args+=(-- "$path")
            ;;
        find)
            value=$(ov_require pattern)
            args=(find -- "$value")
            ;;
        diff)
            snapshot=$(ov_require snapshot_a); ov_backup_snapshot "$snapshot"
            value=$(ov_require snapshot_b); ov_backup_snapshot "$value"
            args=(diff --metadata "$snapshot" "$value")
            ;;
        restore)
            snapshot=$(ov_param snapshot latest); ov_backup_snapshot "$snapshot"
            target=$(ov_require target); ov_backup_absolute "$target"
            overwrite=$(ov_param overwrite never)
            case $overwrite in never|if-newer|if-changed|always) ;; *) ov_fail invalid_overwrite 'Choose never, if-newer, if-changed or always.' ;; esac
            args=(restore "$snapshot" --target "$target" --verify)
            restore_help=$(restic restore --help 2>/dev/null)
            if [[ $restore_help == *--overwrite* ]]; then
                args+=(--overwrite "$overwrite")
            else
                case $overwrite in
                    never)
                        if ov_backup_process test -e "$target" && { ! ov_backup_process test -d "$target" || [[ -n $(ov_backup_process find "$target" -mindepth 1 -maxdepth 1 -print -quit) ]]; }; then
                            ov_fail restic_upgrade_required 'This backup engine version can safely restore without overwriting only into a new or empty folder. Choose another destination or update the backup engine.'
                        fi
                        ;;
                    always) ;;
                    *) ov_fail restic_upgrade_required 'Conditional overwrite requires a newer backup engine version. Choose a new destination or update the backup engine.' ;;
                esac
            fi
            jq -e '(.include // []) | type == "array" and all(.[]; type == "string")' >/dev/null <<<"$OV_PARAMS" || ov_fail invalid_include 'Include must be an array of file patterns.'
            while IFS= read -r -d '' value; do args+=(--include "$value"); done < <(jq -j '(.include // [])[] | ., "\u0000"' <<<"$OV_PARAMS")
            ;;
        forget)
            args=(forget)
            result=0
            for key in keep_daily keep_weekly keep_monthly; do
                value=$(ov_param "$key" 0); ov_backup_number "$value" "$key"
                if (( 10#$value > 0 )); then args+=("--${key//_/-}" "$value"); result=1; fi
            done
            (( result )) || ov_fail retention_required 'Keep at least one daily, weekly or monthly snapshot.'
            dry_run=$(ov_param dry_run true)
            [[ $dry_run == false ]] || args+=(--dry-run)
            ;;
        prune) args=(prune) ;;
        password)
            new_password=$(ov_param password)
            [[ -n $new_password ]] || new_password=$(head -c 48 /dev/urandom | base64 -w 0)
            id=$(jq -r .id <<<"$record")
            new_credential="repository-$id-$(ov_new_id | cut -c1-8)"
            ov_credential_set "$new_credential" "$new_password"
            ov_backup_secret_file "$new_credential" "$OV_BACKUP_IO/new-password"
            args=(key passwd --new-password-file "$OV_BACKUP_IO/new-password")
            ;;
        *) ov_fail unknown_operation 'Unknown repository operation.' ;;
    esac
    ov_backup_execute "$action" "${args[@]}" || :
    if [[ $action == check ]]; then
        record=$(jq --arg checked "$(ov_now)" --argjson read_data "$(ov_param read_data false)" --argjson status "$OV_RESTIC_STATUS" '.last_check={at:$checked,read_data:$read_data,successful:($status == 0)}' <<<"$record")
        ov_backup_save_record repositories "$(jq -r .id <<<"$record")" "$record"
    fi
    ov_backup_check_result
    if [[ $action == password ]]; then
        record=$(jq --arg cid "$new_credential" '.credential_id=$cid' <<<"$record")
        ov_backup_save_record repositories "$id" "$record"
        ov_ok '{"changed":true,"recovery_required":true}'
    elif [[ $action == check ]]; then
        ov_ok "$(jq .last_check <<<"$record")"
    elif [[ $action == prune ]]; then ov_backup_json_result text
    elif [[ $action == restore ]] && ! jq -e . >/dev/null 2>&1 <<<"$OV_RESTIC_OUTPUT"; then ov_backup_json_result text
    elif [[ $action == files || $action == find || $action == diff ]]; then
        result=$(jq -sc 'if length == 1 and (.[0] | type == "array") then .[0] else . end' <<<"$OV_RESTIC_OUTPUT") || ov_fail invalid_output 'The backup engine returned an unexpected response.'
        ov_ok "$result"
    else ov_backup_json_result; fi
}

ov_backup_plan_save() {
    local id record value key source vault mode trigger repository_id existing=false
    id=$(ov_param id)
    if [[ -n $id ]]; then ov_load plans "$id"; record=$OV_RECORD; existing=true; else id=$(ov_new_id); record='{}'; fi
    if [[ $record != '{}' ]]; then ov_backup_use_record "$record"; fi
    record=$(jq --arg id "$id" --argjson old "$record" '$old + ({name,repository_id,sources,excludes,one_file_system,vault_id,vault_mode,trigger,calendar,boot_delay_sec,idle_sec,drive_uuid,on_battery,metered,retention} | with_entries(select(.value != null))) | .id=$id | .excludes=(.excludes // []) | .one_file_system=(.one_file_system // false) | .vault_mode=(.vault_mode // "none") | .trigger=(.trigger // "manual") | .on_battery=(.on_battery // false) | .metered=(.metered // false)' <<<"$OV_PARAMS")
    [[ $(jq -r '.name // empty' <<<"$record") ]] || ov_fail invalid_parameter 'A backup plan name is required.'
    repository_id=$(jq -r '.repository_id // empty' <<<"$record")
    ov_load repositories "$repository_id"
    if [[ $existing == false ]]; then ov_backup_use_record "$OV_RECORD"; fi
    ov_backup_require_record "$OV_RECORD"
    ov_backup_get_destination "$(jq -r .destination_id <<< "$OV_RECORD")"
    jq -e '(.sources | type == "array" and length > 0 and all(.[]; type == "string" and length > 0)) and (.excludes | type == "array" and all(.[]; type == "string")) and (.one_file_system | type == "boolean") and (.on_battery | type == "boolean") and (.metered | type == "boolean")' >/dev/null <<<"$record" || ov_fail invalid_plan 'Select at least one source path and valid backup options.'
    while IFS= read -r -d '' source; do
        ov_backup_absolute "$source"
        if [[ $OV_BACKUP_SCOPE == personal ]]; then
            ov_as_user test -r "$source" || ov_fail permission_denied 'A selected backup source is not readable by your account. Choose your own files or ask an administrator to configure a system backup.'
        fi
    done < <(jq -j '.sources[] | ., "\u0000"' <<<"$record")
    mode=$(jq -r .vault_mode <<<"$record")
    case $mode in
        none) ;;
        open-files|closed-container)
            vault=$(jq -r '.vault_id // empty' <<<"$record")
            ov_load vaults "$vault"
            ov_backup_require_record "$OV_RECORD"
            ;;
        *) ov_fail invalid_mode 'Vault mode must be none, open-files or closed-container.' ;;
    esac
    trigger=$(jq -r .trigger <<<"$record")
    case $trigger in
        manual|calendar|boot|idle|drive|vault-open|vault-close) ;;
        *) ov_fail invalid_trigger 'Unsupported backup trigger.' ;;
    esac
    case $trigger in
        vault-open|vault-close)
            vault=$(jq -r '.vault_id // empty' <<<"$record")
            [[ -n $vault ]] || ov_fail invalid_trigger 'Select the vault whose event should start this backup.'
            ov_load vaults "$vault"
            ov_backup_require_record "$OV_RECORD"
            if [[ $trigger == vault-open && $mode == closed-container ]] || [[ $trigger == vault-close && $mode == open-files ]]; then
                ov_fail invalid_trigger 'The selected trigger conflicts with the required vault state. Use vault-open for unlocked files or vault-close for the closed container.'
            fi
            ;;
        calendar)
            value=$(jq -r '.calendar // empty' <<<"$record")
            [[ -n $value ]] || ov_fail invalid_calendar 'A calendar schedule is required.'
            systemd-analyze calendar "$value" >/dev/null 2>&1 || ov_fail invalid_calendar 'The calendar schedule is invalid.'
            ;;
        drive) [[ $(jq -r '.drive_uuid // empty' <<<"$record") =~ ^[a-zA-Z0-9-]+$ ]] || ov_fail invalid_drive 'A filesystem UUID is required.' ;;
    esac
    for key in boot_delay_sec idle_sec; do value=$(jq -r --arg key "$key" '.[$key] // 3600' <<<"$record"); ov_backup_number "$value" "$key"; done
    if [[ $trigger == idle ]]; then
        value=$(jq -r '.idle_sec // 3600' <<<"$record")
        (( 10#$value >= 60 )) || ov_fail invalid_schedule 'The idle delay must be at least 60 seconds.'
    fi
    jq -e '(.retention // {}) | type == "object" and all(to_entries[]; (.key == "keep_daily" or .key == "keep_weekly" or .key == "keep_monthly") and (.value | type == "number" and . >= 0 and . <= 100000 and floor == .))' >/dev/null <<<"$record" || ov_fail invalid_retention 'Retention must contain nonnegative integer keep_daily, keep_weekly or keep_monthly values.'
    if declare -F ov_schedule_validate_record >/dev/null; then ov_schedule_validate_record "$record"; fi
    ov_backup_save_record plans "$id" "$record"
    if declare -F ov_schedule_sync >/dev/null; then ov_schedule_sync >/dev/null; fi
    ov_load plans "$id"
    ov_ok "$OV_RECORD"
}

ov_backup_vault_guard() {
    local plan=$1 mode vault source container attached_status=0 expected_device source_device
    mode=$(jq -r '.vault_mode // "none"' <<<"$plan")
    [[ $mode != none ]] || return 0
    ov_load vaults "$(jq -r .vault_id <<<"$plan")"; vault=$OV_RECORD
    ov_resource_lock "$(jq -r .file <<<"$vault")"
    if [[ $mode == open-files ]]; then
        declare -F ov_vault_is_open >/dev/null || ov_fail vault_verification_unavailable 'Vault mount verification is unavailable.'
        declare -F ov_vault_is_exposed >/dev/null || ov_fail vault_verification_unavailable 'Vault exposure verification is unavailable.'
        ov_vault_is_open "$vault" || ov_fail vault_closed 'The linked vault is not open at its verified mountpoint; no backup was started.'
        ov_vault_is_exposed "$vault" || ov_fail vault_not_exposed 'The linked vault is open, but its user mountpoint no longer exposes the verified filesystem; no backup was started.'
        expected_device=$(findmnt -rn --mountpoint "$(jq -r .mountpoint <<<"$vault")" --output MAJ:MIN) || ov_fail vault_verification_failed 'Unable to identify the mounted vault filesystem.'
        [[ $expected_device =~ ^[0-9]+:[0-9]+$ ]] || ov_fail vault_verification_failed 'The mounted vault filesystem identity is invalid.'
        for source in "${OV_BACKUP_SOURCES[@]}"; do
            source_device=$(findmnt -rn --target "$source" --output MAJ:MIN) || ov_fail source_not_in_vault 'A selected source is not available on the linked vault.'
            [[ $source_device == "$expected_device" ]] || ov_fail source_not_in_vault 'A selected source is not mounted from the linked vault. Open-files backups require protected sources; use independent mode for mixed or unrelated sources.'
        done
    else
        declare -F ov_vault_attached >/dev/null || ov_fail vault_verification_unavailable 'Vault mount verification is unavailable.'
        ov_vault_attached "$vault" || attached_status=$?
        case $attached_status in
            0) ov_fail vault_open 'Close the linked vault before backing up its encrypted container.' ;;
            1) ;;
            *) ov_fail vault_verification_failed 'Unable to verify that the vault container is detached.' ;;
        esac
        container=$(realpath -e -- "$(jq -r .file <<<"$vault")") || ov_fail vault_missing 'The encrypted vault container is unavailable.'
        # Container mode has exactly one source. Never accidentally include a
        # key file or an unrelated plaintext path in this backup mode.
        OV_BACKUP_SOURCES=("$container")
    fi
}

ov_backup_history_add() {
    local id=$1 entry=$2 directory="$OV_ROOT/history" tmp
    install -d -m 0700 "$directory"
    tmp=$(mktemp "$directory/.history.XXXXXXXX")
    if [[ -f $directory/$id.json ]]; then
        jq --argjson entry "$entry" '. + [$entry] | .[-200:]' "$directory/$id.json" >"$tmp"
    else jq -n --argjson entry "$entry" '[$entry]' >"$tmp"; fi
    chmod 0600 "$tmp"
    mv -f -- "$tmp" "$directory/$id.json"
}

ov_backup_run_plan() {
    local plan=$1 id record source value started finished status snapshot summary history key maintenance=0
    local -a args=() retention_args=()
    ov_backup_use_record "$plan"
    if [[ $OV_BACKUP_SCOPE == personal ]] && ! ov_personal_enrolled; then
        ov_fail access_revoked 'Personal backup access is no longer enabled for this account. Ask an administrator to enable it again; saved data and safety-lock policies are retained.'
    fi
    id=$(jq -r .id <<<"$plan")
    ov_load repositories "$(jq -r .repository_id <<<"$plan")"; record=$OV_RECORD
    ov_backup_prepare_repository "$record"
    OV_BACKUP_SOURCES=()
    while IFS= read -r -d '' source; do OV_BACKUP_SOURCES+=("$source"); done < <(jq -j '.sources[] | ., "\u0000"' <<<"$plan")
    ov_backup_vault_guard "$plan"
    for source in "${OV_BACKUP_SOURCES[@]}"; do
        [[ -e $source || -L $source ]] || ov_fail source_missing 'A configured backup source is unavailable; no incomplete replacement backup was started.'
        if [[ $OV_BACKUP_SCOPE == personal ]]; then
            ov_as_user test -r "$source" || ov_fail permission_denied 'A configured source is no longer readable by your account; personal backups cannot read administrator-only files.'
        fi
    done
    args=(backup --tag "octovault-plan:$id")
    [[ $(jq -r '.one_file_system // false' <<<"$plan") != true ]] || args+=(--one-file-system)
    while IFS= read -r -d '' value; do args+=(--exclude "$value"); done < <(jq -j '(.excludes // [])[] | ., "\u0000"' <<<"$plan")
    args+=(-- "${OV_BACKUP_SOURCES[@]}")
    started=$(ov_now)
    ov_backup_execute backup "${args[@]}" || :
    ov_resource_unlock
    finished=$(ov_now)
    case $OV_RESTIC_STATUS in 0) status=success ;; 3) status=partial ;; 130|143) status=cancelled ;; *) status=failed ;; esac
    summary=$(jq -sc '[.[] | select(.message_type == "summary")][-1] // {}' <<<"$OV_RESTIC_OUTPUT" 2>/dev/null || printf '{}')
    history=$(jq -n --arg started "$started" --arg finished "$finished" --arg status "$status" --argjson code "$OV_RESTIC_STATUS" --argjson summary "$summary" '{started_at:$started,finished_at:$finished,status:$status,exit_code:$code,summary:$summary}')
    record=$(jq --argjson history "$history" '.last_run=$history' <<<"$plan")
    if (( OV_RESTIC_STATUS != 0 )); then
        ov_backup_history_add "$id" "$history"
        ov_backup_save_record plans "$id" "$record"
        ov_backup_check_result
    fi
    # Retention is opt-in and scoped to this plan's stable tag. Space reclaiming
    # is a separate explicit prune operation, never hidden inside backup.
    retention_args=(forget --tag "octovault-plan:$id" --group-by 'host,paths,tags')
    for key in keep_daily keep_weekly keep_monthly; do
        value=$(jq -r --arg key "$key" '.retention[$key] // 0' <<<"$plan")
        if (( value > 0 )); then retention_args+=("--${key//_/-}" "$value"); maintenance=1; fi
    done
    if (( maintenance )); then
        ov_backup_execute retention "${retention_args[@]}" || :
        if (( OV_RESTIC_STATUS != 0 )); then
            history=$(jq '.retention={successful:false,message:"Backup succeeded, but retention failed. Retry maintenance."}' <<<"$history")
        else history=$(jq '.retention={successful:true}' <<<"$history"); fi
        record=$(jq --argjson history "$history" '.last_run=$history' <<<"$record")
    fi
    ov_backup_history_add "$id" "$history"
    ov_backup_save_record plans "$id" "$record"
    ov_ok "$history"
}

ov_repository_copy() {
    local source=$1 target_id target source_destination target_destination snapshot saved_repo saved_password source_type target_type
    local -a source_options=() source_env=() target_options=() target_env=()
    target_id=$(ov_require target_id)
    [[ $target_id != "$(jq -r .id <<<"$source")" ]] || ov_fail invalid_target 'Source and target repositories must differ.'
    ov_load repositories "$target_id"; target=$OV_RECORD
    snapshot=$(ov_param snapshot latest); ov_backup_snapshot "$snapshot"
    ov_backup_prepare_repository "$source" source
    source_destination=$OV_DESTINATION
    saved_repo=$OV_RESTIC_REPOSITORY; saved_password=$OV_RESTIC_PASSWORD_FILE
    source_options=("${OV_RESTIC_OPTIONS[@]}"); source_env=("${OV_RESTIC_ENV[@]}")
    ov_backup_prepare_repository "$target" target
    target_destination=$OV_DESTINATION
    target_options=("${OV_RESTIC_OPTIONS[@]}"); target_env=("${OV_RESTIC_ENV[@]}")
    source_type=$(jq -r .type <<<"$source_destination"); target_type=$(jq -r .type <<<"$target_destination")
    if [[ $source_type == "$target_type" && $source_type != local && $(jq -r .id <<<"$source_destination") != "$(jq -r .id <<<"$target_destination")" ]]; then
        ov_fail incompatible_copy_credentials 'Direct copy between different accounts of the same remote backend is not supported by this backup engine credential interface. Copy through a local repository or use a shared destination account.'
    fi
    if [[ $source_type == sftp && $target_type == sftp ]]; then
        # A shared destination uses the same host/account/key. Either private
        # config is valid for both repository paths.
        OV_RESTIC_OPTIONS=("${target_options[@]}")
    else OV_RESTIC_OPTIONS=("${source_options[@]}" "${target_options[@]}"); fi
    OV_RESTIC_ENV=("${source_env[@]}" "${target_env[@]}")
    ov_backup_execute copy copy --from-repo "$saved_repo" --from-password-file "$saved_password" "$snapshot" || :
    ov_backup_check_result
    ov_backup_json_result text
}

ov_backup_remove() {
    local collection=$1 id=$2 files
    case $collection in
        destinations)
            for files in "$OV_ROOT/repositories/"*.json; do
                [[ -f $files ]] || continue
                jq -e --arg id "$id" '.destination_id == $id' "$files" >/dev/null && ov_fail in_use 'Remove or reassign repositories using this destination first.'
            done
            ;;
        repositories)
            for files in "$OV_ROOT/plans/"*.json; do
                [[ -f $files ]] || continue
                jq -e --arg id "$id" '.repository_id == $id' "$files" >/dev/null && ov_fail in_use 'Remove or reassign backup plans using this repository first.'
            done
            ;;
    esac
    rm -f -- "$OV_ROOT/$collection/$id.json"
    if [[ $collection == plans ]] && declare -F ov_schedule_sync >/dev/null; then ov_schedule_sync >/dev/null; fi
    ov_ok '{"removed":true,"data_preserved":true}'
}

ov_backup_dispatch() {
    local id action collection record
    OV_BACKUP_SCOPE=${OV_EXECUTION_SCOPE:-system}
    jq -e '[.. | strings | contains("\u0000")] | any | not' >/dev/null <<<"$OV_PARAMS" || ov_fail invalid_parameter 'NUL characters are not supported in application parameters.'
    case "$OV_OP" in
        destination.*) collection=destinations ;;
        repository.*) collection=repositories ;;
        backup.*) collection=plans ;;
        *) ov_fail unknown_operation 'Unknown backup operation.' ;;
    esac
    action=${OV_OP#*.}
    case "$OV_OP" in
        destination.list|repository.list|backup.list) ov_ok "$(ov_list "$collection")"; return ;;
        destination.save) ov_destination_save; return ;;
        repository.create|repository.import) ov_repository_create "$action"; return ;;
        backup.save) ov_backup_plan_save; return ;;
    esac
    id=$(ov_require id); ov_id "$id"; ov_load "$collection" "$id"; record=$OV_RECORD
    case "$OV_OP" in
        destination.get|repository.get|backup.get|backup.history) ;;
        *) ov_backup_use_record "$record" ;;
    esac
    case "$OV_OP" in
        destination.get|repository.get|backup.get) ov_ok "$record" ;;
        destination.remove|repository.remove|backup.remove) ov_backup_remove "$collection" "$id" ;;
        destination.test) ov_destination_test "$record" ;;
        repository.recovery) ov_repository_recovery "$record" ;;
        repository.copy) ov_repository_copy "$record" ;;
        repository.*) ov_repository_action "$action" "$record" ;;
        backup.run) ov_backup_run_plan "$record" ;;
        backup.history)
            if [[ -f $OV_ROOT/history/$id.json ]]; then ov_ok "$(cat "$OV_ROOT/history/$id.json")"; else ov_ok '[]'; fi
            ;;
        *) ov_fail unknown_operation 'Unknown backup operation.' ;;
    esac
}
