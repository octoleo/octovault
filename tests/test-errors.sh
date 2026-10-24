#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
set -Eeuo pipefail
PROJECT=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
WORK=$(mktemp -d)
trap 'rm -rf -- "$WORK"' EXIT
cat > "$WORK/worker" <<'WORKER'
set -Eeuo pipefail
source "$1/lib/octovault/common.sh"
source "$1/lib/octovault/vault.sh"
OV_ROOT=$2 OV_OP=vault.create
mkdir -p "$OV_ROOT"
ov_error_init
trap 'ov_error_cleanup' EXIT
trap 'ov_abort' ERR
OV_PARAMS='{"password":"never-log-this-passphrase","recipient":"never-log-request"}'
case $3 in
    nested) value=$(ov_require directory) ;;
    unexpected) false ;;
    retained)
        touch "$OV_ROOT/container.tomb"
        ov_failure_retain "$OV_ROOT/container.tomb"
        ov_failure_retain "$OV_ROOT/missing.key"
        ov_progress initialize 'Initializing filesystem' 65
        ov_fail initialize_failed 'Initialization could not finish.'
        ;;
esac
WORKER
for kind in nested unexpected retained; do
    status=0
    output=$(bash "$WORK/worker" "$PROJECT" "$WORK/$kind" "$kind" 2>/dev/null) || status=$?
    [[ $status == 1 ]]
    jq -e '.ok==false and (.error.diagnostic_id|length>0) and (.error.diagnostic_file|length>0)' <<< "$output" >/dev/null
    report=$(jq -r '.error.diagnostic_file' <<< "$output")
    [[ -f $report && $(stat -c %a -- "$report") == 600 ]]
    [[ $(stat -c %a -- "$(dirname -- "$report")") == 700 ]]
    [[ -z $(find "$WORK/$kind" -maxdepth 1 -name '.failure.*' -print -quit) ]]
    jq -e '.operation=="vault.create" and .schema_version==1' "$report" >/dev/null
    if grep -q 'never-log' "$report"; then printf 'Request secrets entered diagnostics\n' >&2; exit 1; fi
    case $kind in
        nested) jq -e '.error.code=="invalid_request" and .error.message=="Missing required field: directory" and (.error.retained_paths|length)==0' <<< "$output" >/dev/null ;;
        unexpected) jq -e '.error.code=="operation_failed" and (.error.message|contains("retained")|not)' <<< "$output" >/dev/null ;;
        retained) jq -e '.error.stage=="initialize" and (.error.retained_paths|length)==1 and (.error.retained_paths[0]|endswith("container.tomb"))' <<< "$output" >/dev/null ;;
    esac
done
printf 'ok - typed nested failures, truthful retained paths and private secret-free diagnostics\n'

source "$PROJECT/lib/octovault/common.sh"
OV_UID=$(id -u) OV_USER=$(id -un) OV_HOME=$WORK
mkdir "$WORK/keyring"
touch "$WORK/Xauthority"
session=$(jq -cn --arg keyring "$WORK/keyring" --arg xauthority "$WORK/Xauthority" '{display:":23",xauthority:$xauthority,wayland_display:"wayland-3",gnupg_home:$keyring}')
ov_session_init "$session"
# Exercise the clean-env branch without requiring user-switch privileges.
OV_UID=0
export UNRELATED_SECRET=must-not-leak
environment=$(ov_as_user /usr/bin/env)
[[ $environment == *'DISPLAY=:23'* && $environment == *'WAYLAND_DISPLAY=wayland-3'* && $environment == *"GNUPGHOME=$WORK/keyring"* ]]
[[ $environment == *"XAUTHORITY=$WORK/Xauthority"* ]]
[[ $environment != *UNRELATED_SECRET* && $environment != *OV_ERROR_FILE* ]]
for session in '{"PATH":"/tmp"}' '{"display":"bad\nvalue"}' '{"gpg_tty":"/etc/passwd"}' '{"gnupg_home":"relative"}' '{"wayland_display":"../other"}'; do
    if (ov_session_init "$session") >/dev/null; then printf 'Invalid session accepted: %s\n' "$session" >&2; exit 1; fi
done
printf 'ok - only validated authentication session fields reach user programs\n'

# Exercise the actual backend dispatcher with an isolated account-state setup.
# Invalid unused GPG session hints must not block the diagnostic/recovery UI.
mkdir "$WORK/lib" "$WORK/dispatcher"
cp "$PROJECT/lib/octovault/"{common,vault,backup,events}.sh "$WORK/lib/"
cat >> "$WORK/lib/common.sh" <<'INIT'
ov_init() {
    OV_ROOT=$OV_TEST_ROOT
    OV_UID=$(id -u) OV_USER=$(id -un) OV_HOME=$OV_TEST_ROOT
}
INIT
sed "s|readonly OV_LIB=/usr/lib/octovault|readonly OV_LIB=$WORK/lib|" "$PROJECT/lib/octovault/backend" > "$WORK/backend"
for operation in diagnostic.list vault.list; do
    request=$(jq -cn --arg operation "$operation" '{op:$operation,params:{},session:{gpg_tty:"/dev/pts/999999",gnupg_home:"/missing-keyring"}}')
    output=$(OV_TEST_ROOT="$WORK/dispatcher" bash "$WORK/backend" 0 <<< "$request")
    jq -e '.ok and .data==[]' <<< "$output" >/dev/null
done
printf 'ok - stale authentication sessions do not block vault lists or saved diagnostics\n'
