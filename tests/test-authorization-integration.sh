#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Installs the real service and creates real accounts in an explicitly disposable
# systemd machine. Polkit's normal setuid PAM helper verifies every credential.
set -Eeuo pipefail
cd "$(dirname "$0")/.."
if [[ ${1-} != --disposable-system ]]; then
    printf 'Real authorization integration requires --disposable-system and OCTOVAULT_DISPOSABLE_TEST=1; CI runs it in a dedicated machine.\n'
    exit 0
fi
[[ ${OCTOVAULT_DISPOSABLE_TEST:-} == 1 && $EUID == 0 ]] || {
    printf 'Refusing account and system-service changes outside an explicitly disposable root test.\n' >&2
    exit 2
}
[[ $(cat /proc/1/comm) == systemd ]] || { printf 'A real systemd/logind machine is required.\n' >&2; exit 2; }
for dependency in cc pkg-config jq systemctl systemd-run loginctl useradd chpasswd gdbus; do
    command -v "$dependency" >/dev/null || { printf 'Missing integration dependency: %s\n' "$dependency" >&2; exit 2; }
done
stage='preparing the disposable machine'
work=$(mktemp -d /var/tmp/octovault-authorization.XXXXXXXX)
chmod 0755 "$work"
administrator=ov-auth-admin-$BASHPID
ordinary=ov-auth-user-$BASHPID
other=ov-auth-other-$BASHPID
declare -A inputs outputs units sessions drivers
created_users=()
last='{}'
identity_trace_pid=
cleanup() {
    local user unit
    if [[ -n $identity_trace_pid ]]; then kill -INT "$identity_trace_pid" 2>/dev/null || true; wait "$identity_trace_pid" || true; fi
    for unit in "${units[@]}"; do systemctl stop "$unit" >/dev/null 2>&1 || true; done
    for user in "${created_users[@]}"; do userdel -r "$user" >/dev/null 2>&1 || true; done
    rm -f /etc/polkit-1/rules.d/00-octovault-authorization-ci.rules
    rm -f /etc/pam.d/octovault-authorization-ci
    rm -rf -- "$work"
}
failed() {
    local status=$? user unit
    printf 'Real authorization integration failed during: %s\n' "$stage" >&2
    jq -c '.response.error // empty | {code,message}' <<< "$last" >&2 || true
    jq -c '{challenges,authentications}' <<< "$last" >&2 || true
    if [[ -f $work/identity.trace ]]; then cat "$work/identity.trace" >&2; fi
    if [[ -f $work/identity-trace.err ]]; then cat "$work/identity-trace.err" >&2; fi
    if [[ -f $work/daemon-identity.txt ]]; then cat "$work/daemon-identity.txt" >&2; fi
    journalctl --no-pager -n 80 -u octovault.service -u polkit.service -u systemd-logind.service >&2 || true
    loginctl show-seat seat0 --property=CanTTY --property=ActiveSession --property=Sessions >&2 || true
    systemctl list-jobs --no-pager >&2 || true
    for unit in "${units[@]}"; do
        systemctl show "$unit" --property=ActiveState --property=SubState --property=Result \
            --property=MainPID --property=ExecMainCode --property=ExecMainStatus >&2 || true
        journalctl --no-pager -n 80 -u "$unit" >&2 || true
    done
    for user in "${created_users[@]}"; do
        if [[ -f $work/$user/client.err ]]; then cat "$work/$user/client.err" >&2; fi
        if [[ -n ${sessions[$user]:-} ]]; then
            loginctl show-session "${sessions[$user]}" --property=Name --property=Class --property=Type \
                --property=Seat --property=Active --property=Remote --property=LockedHint >&2 || true
        fi
    done
    exit "$status"
}
trap cleanup EXIT
trap failed ERR
step() { stage=$1; printf 'Authorization integration: %s\n' "$stage"; }
check() { jq -e "$1" <<< "$last" >/dev/null; }
query() {
    local user=$1 command=$2
    printf '%s\n' "$command" >&"${inputs[$user]}"
    IFS= read -r -t 150 last <&"${outputs[$user]}"
    jq -e 'type=="object" and has("response") and has("challenges")' <<< "$last" >/dev/null
}
activate_client() {
    local user=$1
    loginctl activate "${sessions[$user]}"
    [[ $(loginctl show-session "${sessions[$user]}" --property=Active --value) == yes ]]
}
start_client() {
    local user=$1 mode=${2:-desktop} input output session active
    local -a session_options=(--property=PAMName=octovault-authorization-ci
        --setenv=XDG_SESSION_CLASS=user --setenv=XDG_SESSION_TYPE=tty --setenv=XDG_SEAT=seat0)
    if [[ $mode == headless ]]; then session_options=(--setenv=OCTOVAULT_AUTH_TEST_HEADLESS=1); fi
    mkfifo -m 0600 "$work/$user/input" "$work/$user/output"
    exec {input}<>"$work/$user/input"
    exec {output}<>"$work/$user/output"
    inputs[$user]=$input; outputs[$user]=$output
    units[$user]=octovault-authorization-$user.service
    systemd-run --quiet --wait --collect --pipe --unit="${units[$user]}" \
        --uid="$user" "${session_options[@]}" --property=Type=exec --property=TimeoutStartSec=30s \
        --setenv=OCTOVAULT_DISPOSABLE_TEST=1 --setenv=G_DEBUG=fatal-criticals \
        "$work/agent" "$administrator" "$work/$user/credentials.json" \
        <"$work/$user/input" >"$work/$user/output" 2>"$work/$user/client.err" &
    drivers[$user]=$!
    IFS= read -r -t 40 last <&"$output"
    check '.response.ready == true'
    session=$(jq -r .response.session <<< "$last")
    sessions[$user]=$session
    if [[ $mode == headless ]]; then [[ -z $session ]]; return; fi
    activate_client "$user"
    [[ $(loginctl show-session "$session" --property=Name --value) == "$user" ]]
    [[ $(loginctl show-session "$session" --property=Class --value) == user ]]
    [[ $(loginctl show-session "$session" --property=Type --value) == tty ]]
    [[ $(loginctl show-session "$session" --property=Seat --value) == seat0 ]]
    active=$(loginctl show-session "$session" --property=Active --value)
    [[ $active == yes ]]
    [[ $(loginctl show-session "$session" --property=Remote --value) == no ]]
}
stop_client() {
    local user=$1 descriptor
    systemctl stop "${units[$user]}" 2>/dev/null || true
    wait "${drivers[$user]}" || true
    descriptor=${inputs[$user]}; exec {descriptor}>&-
    descriptor=${outputs[$user]}; exec {descriptor}>&-
    rm -f "$work/$user/input" "$work/$user/output"
}

step 'building the production daemon, client and real PAM authentication agent'
# No OCTOVAULT_TEST define is used anywhere in this integration build.
make build/octovaultd build/octovault
read -r -a cflags <<< "$(pkg-config --cflags polkit-agent-1 gio-2.0 json-glib-1.0)"
read -r -a libs <<< "$(pkg-config --libs polkit-agent-1 gio-2.0 json-glib-1.0)"
cc -std=c11 -Wall -Wextra -Werror -Isrc/service "${cflags[@]}" \
    tests/service/authorization_agent.c src/service/client.c -o "$work/agent" "${libs[@]}"
chmod 0755 "$work/agent"
install -Dm 0755 build/octovaultd /usr/libexec/octovault/daemon
install -Dm 0755 build/octovault /usr/bin/octovault
install -Dm 0755 lib/octovault/backend /usr/libexec/octovault/backend
install -Dm 0755 lib/octovault/priority-backend /usr/libexec/octovault/priority-backend
install -d /usr/lib/octovault
install -m 0644 lib/octovault/*.sh /usr/lib/octovault/
install -Dm 0644 data/io.vdm.octovault.policy /usr/share/polkit-1/actions/io.vdm.octovault.policy
install -Dm 0644 data/io.vdm.OctoVault1.conf /usr/share/dbus-1/system.d/io.vdm.OctoVault1.conf
install -Dm 0644 data/io.vdm.OctoVault1.service /usr/share/dbus-1/system-services/io.vdm.OctoVault1.service
install -Dm 0644 systemd/octovault.service /etc/systemd/system/octovault.service

step 'creating an administrator and two accounts without sudo privileges'
[[ $(passwd -S root | awk '{print $2}') == L ]]
admin_password=$(cat /proc/sys/kernel/random/uuid)
for user in "$administrator" "$ordinary" "$other"; do
    useradd --create-home --shell /bin/bash "$user"
    created_users+=("$user")
    user_password=$(cat /proc/sys/kernel/random/uuid)
    [[ $user != "$administrator" ]] || user_password=$admin_password
    printf '%s:%s\n' "$user" "$user_password" | chpasswd
    install -d -o "$user" -g "$user" -m 0700 "$work/$user"
    jq -cn --arg administrator "$admin_password" --arg self "$user_password" \
        '{administrator:$administrator,self:$self}' >"$work/$user/credentials.json"
    chown "$user:$user" "$work/$user/credentials.json"
    chmod 0600 "$work/$user/credentials.json"
    install -d -o "$user" -g "$user" -m 0700 "/home/$user/backups"
done
unset admin_password user_password
[[ " $(id -nG "$ordinary") " != *' sudo '* ]]
[[ " $(id -nG "$other") " != *' sudo '* ]]
# This administrator-owned site rule selects the fixture administrator. It does
# not authorize anything, disable a challenge, or replace polkit/PAM.
cat > /etc/polkit-1/rules.d/00-octovault-authorization-ci.rules <<RULE
polkit.addAdminRule(function(action, subject) {
    if (action.id.indexOf("io.vdm.octovault.") === 0) {
        return ["unix-user:$administrator"];
    }
});
RULE
chmod 0644 /etc/polkit-1/rules.d/00-octovault-authorization-ci.rules
# Root acts as the disposable login manager when starting the fixture. Register
# actual user-class sessions on logind's container seat; seatless service
# sessions are deliberately not considered local desktop sessions by polkit.
# Authentication itself still uses the distribution's unchanged polkit PAM
# stack and its real helper, not this session-registration stack.
cat > /etc/pam.d/octovault-authorization-ci <<'PAM'
account include common-account
session required pam_systemd.so class=user type=tty debug
PAM
chmod 0644 /etc/pam.d/octovault-authorization-ci
systemctl daemon-reload
systemctl restart polkit.service
systemctl reload dbus.service
systemctl start octovault.service
gdbus introspect --system --dest io.vdm.OctoVault1 --object-path /io/vdm/OctoVault1 >/dev/null
step 'starting a real local user login session'
[[ $(loginctl show-seat seat0 --property=CanTTY --value) == no ]] || {
    printf 'This fixture requires the disposable runner\047s non-VT container seat.\n' >&2
    exit 2
}
start_client "$ordinary"
start_client "$other"
activate_client "$ordinary"

step 'showing permissions without prompting and refusing an unapproved operation'
query "$ordinary" '{"op":"access.status","params":{}}'
check '.response.ok and .response.data.available and .response.data.can_request_system and (.response.data.authorized|not) and .challenges == 0'
query "$ordinary" "$(jq -cn --arg path "/home/$ordinary/backups" '{op:"destination.save",params:{name:"Unapproved",type:"local",path:$path}}')"
check '(.response.ok|not) and .challenges == 0'

step 'rejecting a wrong password through real PAM'
query "$ordinary" '{"test":"mode","value":"wrong"}'
query "$ordinary" '{"op":"access.unlock","params":{"scope":"system"}}'
check '(.response.ok|not) and .challenges >= 1 and .authentications == 0'

step 'handling authentication cancellation without granting access'
query "$ordinary" '{"test":"mode","value":"cancel"}'
query "$ordinary" '{"op":"access.unlock","params":{"scope":"system"}}'
check '(.response.ok|not) and .authentications == 0'
query "$ordinary" '{"op":"access.status","params":{}}'
check '(.response.data.authorized|not)'

step 'authenticating an administrator from the ordinary user session'
query "$ordinary" '{"test":"mode","value":"approve"}'
query "$ordinary" '{"op":"access.unlock","params":{"scope":"system"}}'
check '.response.ok and .response.data.authorized and .response.data.scope == "system" and .authentications == 1'
prompts=$(jq -r .challenges <<< "$last")
query "$ordinary" "$(jq -cn --arg path "/home/$ordinary/backups" '{op:"destination.save",params:{name:"System authorized destination",type:"local",path:$path}}')"
check ".response.ok and .challenges == $prompts"
system_destination=$(jq -r .response.data.id <<< "$last")
query "$ordinary" "$(jq -cn --arg id "$system_destination" '{op:"destination.test",params:{id:$id}}')"
check ".response.ok and .challenges == $prompts"
[[ -f /var/lib/octovault/users/$(id -u "$ordinary")/destinations/$system_destination.json ]]
[[ ! -e /var/lib/octovault/users/$(id -u "$administrator")/destinations/$system_destination.json ]]

step 'authorizing an application launched by the real systemd user manager'
query "$ordinary" "$(jq -cn --arg path "/home/$ordinary/backups" '{test:"manager-cli",arguments:["--json","destination","save","--name","User manager application","--type","local","--path",$path]}')"
check ".response.ok and .challenges == ($prompts + 1)"
prompts=$(jq -r .challenges <<< "$last")

step 'requiring a fresh challenge for recovery disclosure'
query "$ordinary" '{"test":"mode","value":"cancel"}'
query "$ordinary" '{"op":"repository.recovery","params":{"id":"missing-integration-record"}}'
check "(.response.ok|not) and .challenges > $prompts"
query "$ordinary" '{"test":"mode","value":"approve"}'

step 'retaining caller isolation when another account knows a record identifier'
activate_client "$other"
query "$other" '{"op":"access.status","params":{}}'
check '(.response.data.authorized|not) and .challenges == 0'
query "$other" "$(jq -cn --arg id "$system_destination" '{op:"destination.test",params:{id:$id}}')"
check '(.response.ok|not) and .challenges == 0'

step 'granting personal access only after fresh administrator authentication'
activate_client "$ordinary"
query "$ordinary" '{"op":"access.unlock","params":{"scope":"system"}}'
check '.response.ok and .response.data.scope == "system"'
query "$ordinary" '{"op":"access.status","params":{}}'
prompts=$(jq -r .challenges <<< "$last")
query "$ordinary" "$(jq -cn --arg user "$other" '{op:"access.grant",params:{user:$user}}')"
check ".response.ok and .challenges > $prompts"
activate_client "$other"
query "$other" '{"test":"mode","value":"cancel"}'
query "$other" '{"op":"access.status","params":{}}'
check '.response.ok and .response.data.delegated_personal and (.response.data.authorized|not) and .challenges == 0'
query "$other" '{"op":"access.unlock","params":{"scope":"personal"}}'
check '.response.ok and .response.data.scope == "personal" and .response.data.authorized and .challenges == 0'
query "$other" "$(jq -cn --arg path "/home/$other/backups" '{op:"destination.save",params:{name:"Personal destination",type:"local",path:$path}}')"
check '.response.ok and .challenges == 0'
personal_destination=$(jq -r .response.data.id <<< "$last")
jq -e '.execution_scope == "personal"' "/var/lib/octovault/users/$(id -u "$other")/destinations/$personal_destination.json" >/dev/null
query "$other" "$(jq -cn --arg id "$system_destination" '{op:"destination.test",params:{id:$id}}')"
check '(.response.ok|not) and .challenges == 0'
query "$other" '{"op":"access.grant","params":{"user":"root"}}'
check '(.response.ok|not)'

step 'keeping same-user system resources outside a personal authorization grant'
activate_client "$ordinary"
# Changing the administrator access policy revokes every existing grant,
# including the management client's own grant.
query "$ordinary" '{"op":"access.status","params":{}}'
check '(.response.data.authorized|not)'
query "$ordinary" '{"op":"access.unlock","params":{"scope":"system"}}'
check '.response.ok and .response.data.scope == "system"'
query "$ordinary" "$(jq -cn --arg user "$ordinary" '{op:"access.grant",params:{user:$user}}')"
check '.response.ok'
query "$ordinary" '{"op":"access.lock","params":{}}'
query "$ordinary" '{"op":"access.unlock","params":{"scope":"personal"}}'
check '.response.ok and .response.data.scope == "personal"'
query "$ordinary" "$(jq -cn --arg id "$system_destination" '{op:"destination.test",params:{id:$id}}')"
check '(.response.ok|not) and .response.error.code == "admin_required"'
query "$ordinary" "$(jq -cn --arg id "$system_destination" '{op:"destination.save",params:{id:$id,name:"Must not downgrade a system destination"}}')"
check '(.response.ok|not) and .response.error.code == "admin_required"'
jq -e '.execution_scope == "system" and .name == "System authorized destination"' "/var/lib/octovault/users/$(id -u "$ordinary")/destinations/$system_destination.json" >/dev/null
query "$ordinary" '{"op":"access.unlock","params":{"scope":"system"}}'
check '.response.ok and .response.data.scope == "system"'

step 'requiring the owner password to reveal a real personal repository recovery record'
activate_client "$other"
query "$other" '{"op":"access.status","params":{}}'
check '(.response.data.authorized|not) and .response.data.delegated_personal'
query "$other" '{"op":"access.unlock","params":{"scope":"personal"}}'
check '.response.ok and .response.data.scope == "personal"'
# Trace only numeric credential changes in the actual daemon context. This
# cannot record requests, arguments, file contents or passwords, and makes a
# host-specific privilege-drop failure actionable without weakening its unit.
install -m 0600 /dev/null "$work/identity.trace"
daemon_pid=$(systemctl show octovault.service --property=MainPID --value)
install -m 0600 /dev/null "$work/daemon-identity.txt"
awk '/^(Name|Uid|Gid|Groups|CapInh|CapPrm|CapEff|CapBnd|CapAmb|NoNewPrivs|Seccomp|Seccomp_filters):/' \
    "/proc/$daemon_pid/status" >"$work/daemon-identity.txt"
strace -f -qq -e trace=setuid,setreuid,setresuid,setgid,setregid,setresgid,setgroups,capget,capset \
    -o "$work/identity.trace" -p "$daemon_pid" 2>"$work/identity-trace.err" &
identity_trace_pid=$!
for _ in {1..20}; do
    [[ $(awk '/^TracerPid:/ {print $2}' "/proc/$daemon_pid/status") == "$identity_trace_pid" ]] && break
    sleep 0.1
done
[[ $(awk '/^TracerPid:/ {print $2}' "/proc/$daemon_pid/status") == "$identity_trace_pid" ]]
query "$other" "$(jq -cn --arg destination "$personal_destination" '{op:"repository.create",params:{name:"Personal integration repository",destination_id:$destination,path:"personal-repository"}}')"
kill -INT "$identity_trace_pid"
wait "$identity_trace_pid" || true
identity_trace_pid=
check '.response.ok'
personal_repository=$(jq -r .response.data.id <<< "$last")
prompts=$(jq -r .challenges <<< "$last")
query "$other" "$(jq -cn --arg id "$personal_repository" '{op:"repository.recovery",params:{id:$id}}')"
check "(.response.ok|not) and .challenges > $prompts"
query "$other" '{"test":"mode","value":"approve"}'
query "$other" "$(jq -cn --arg id "$personal_repository" '{op:"repository.recovery",params:{id:$id}}')"
check '.response.ok and (.response.data.RESTIC_PASSWORD | length > 20) and .authentications == 1'
# The synthetic repository secret stays in the private FIFO and shell variable;
# neither raw recovery output nor a password is printed in the CI log.
last='{}'
query "$other" '{"test":"mode","value":"cancel"}'

step 'using the public CLI with automatic personal authorization'
prompts=$(jq -r .challenges <<< "$last")
query "$other" "$(jq -cn --arg path "/home/$other/backups" '{test:"cli",arguments:["--json","destination","save","--name","CLI personal destination","--type","local","--path",$path]}')"
check ".response.ok and .challenges == $prompts"

step 'revoking an already open personal session immediately'
activate_client "$ordinary"
query "$ordinary" '{"op":"access.unlock","params":{"scope":"system"}}'
check '.response.ok and .response.data.scope == "system"'
query "$ordinary" "$(jq -cn --arg user "$other" '{op:"access.revoke",params:{user:$user}}')"
check '.response.ok'
activate_client "$other"
query "$other" '{"op":"access.status","params":{}}'
check '(.response.data.authorized|not) and (.response.data.delegated_personal|not)'
query "$other" "$(jq -cn --arg id "$personal_destination" '{op:"destination.test",params:{id:$id}}')"
check '(.response.ok|not)'

step 'dropping authorization when the client connection closes'
activate_client "$ordinary"
query "$ordinary" '{"op":"access.status","params":{}}'
check '(.response.data.authorized|not)'
query "$ordinary" '{"op":"access.unlock","params":{"scope":"system"}}'
check '.response.ok and .response.data.authorized'
query "$ordinary" "$(jq -cn --arg user "$ordinary" '{op:"access.revoke",params:{user:$user}}')"
check '.response.ok'
query "$ordinary" '{"op":"access.unlock","params":{"scope":"system"}}'
check '.response.ok and .response.data.authorized'
query "$ordinary" '{"test":"reconnect"}'
query "$ordinary" '{"op":"access.status","params":{}}'
check '(.response.data.authorized|not)'
query "$ordinary" '{"op":"access.unlock","params":{"scope":"system"}}'
check '.response.ok and .response.data.authorized'

step 'revoking access on the real desktop-session lock signal'
loginctl lock-session "${sessions[$ordinary]}"
query "$ordinary" '{"test":"set-locked","value":true}'
check '.response.ok'
query "$ordinary" '{"op":"access.status","params":{}}'
check '(.response.data.authorized|not)'
query "$ordinary" '{"test":"set-locked","value":false}'
query "$ordinary" '{"op":"access.status","params":{}}'
check '(.response.data.authorized|not)'

step 'expiring a real sixty-second grant without extending it through status polling'
query "$ordinary" '{"op":"access.unlock","params":{"scope":"system","duration_seconds":60}}'
check '.response.ok and .response.data.authorized'
deadline=$((SECONDS + 70))
while ((SECONDS < deadline)); do
    sleep 5
    query "$ordinary" '{"op":"access.status","params":{}}'
    if jq -e '.response.data.authorized == false' <<< "$last" >/dev/null; then break; fi
done
check '(.response.data.authorized|not)'

step 'keeping manual lock and service restart effective'
query "$ordinary" '{"op":"access.unlock","params":{"scope":"system"}}'
check '.response.ok'
query "$ordinary" '{"op":"access.lock","params":{}}'
check '.response.ok'
query "$ordinary" '{"op":"access.status","params":{}}'
check '(.response.data.authorized|not)'
query "$ordinary" '{"op":"access.unlock","params":{"scope":"system"}}'
check '.response.ok'
systemctl restart octovault.service
query "$ordinary" '{"op":"access.status","params":{}}'
check '(.response.data.authorized|not)'

step 'ending a real login session and checking a new login has no old authorization'
query "$ordinary" '{"op":"access.unlock","params":{"scope":"system"}}'
check '.response.ok'
loginctl terminate-session "${sessions[$ordinary]}"
stop_client "$ordinary"
start_client "$ordinary"
query "$ordinary" '{"op":"access.status","params":{}}'
check '(.response.data.authorized|not) and .challenges == 0'

step 'authenticating every headless operation without creating a reusable lease'
stop_client "$other"
start_client "$other" headless
query "$other" '{"op":"access.status","params":{}}'
check '.response.ok and (.response.data.available|not) and (.response.data.authorized|not) and .challenges == 0'
query "$other" '{"op":"access.unlock","params":{"scope":"system"}}'
check '(.response.ok|not) and .response.error.code == "AUTH_SESSION_UNAVAILABLE" and .challenges == 0'
query "$other" "$(jq -cn --arg path "/home/$other/backups" '{op:"destination.save",params:{name:"Headless first operation",type:"local",path:$path}}')"
check '.response.ok and .challenges == 1 and .authentications == 1'
query "$other" "$(jq -cn --arg path "/home/$other/backups" '{op:"destination.save",params:{name:"Headless second operation",type:"local",path:$path}}')"
check '.response.ok and .challenges == 2 and .authentications == 2'
query "$other" '{"op":"access.status","params":{}}'
check '.response.ok and (.response.data.authorized|not) and .challenges == 2'
printf 'Real Polkit/PAM authorization integration passed: locked root account, wrong password, cancellation, non-sudo administrator approval, repeated operations, caller and resource-scope isolation, delegated personal access, real personal repository and owner recovery authentication, CLI, revocation, reconnect, lock, expiry, service restart, logout and fresh headless authorization.\n'
