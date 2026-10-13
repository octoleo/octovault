#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
set -Eeuo pipefail
cd "$(dirname "$0")/.."
source lib/octovault/common.sh
task_tmp=$(mktemp -d)
trap 'rm -rf -- "$task_tmp"' EXIT
OV_ROOT=$task_tmp
OV_PARAMS='{"enabled":false,"count":0,"text":"with spaces"}'
[[ $(ov_param enabled true) == false ]]
[[ $(ov_param count 99) == 0 ]]
[[ $(ov_param text) == 'with spaces' ]]
[[ $(ov_param absent fallback) == fallback ]]
ov_save vaults example '{"name":"Vault with spaces","file":"/tmp/a b"}'
ov_load vaults example
jq -e '.schema_version==1 and .name=="Vault with spaces" and .id=="example"' <<<"$OV_RECORD" >/dev/null
[[ $(stat -c %a "$OV_ROOT/vaults/example.json") == 600 ]]
[[ $(ov_list vaults | jq length) == 1 ]]
ov_ok '{"password":"sample%secret"}' | jq -e '.ok and .data.password=="sample%secret"' >/dev/null
if (ov_id '../escape') >/dev/null; then echo 'unsafe ID accepted' >&2; exit 1; fi
if (ov_collection '../../etc') >/dev/null; then echo 'unsafe collection accepted' >&2; exit 1; fi
if (ov_validate_path relative/path) >/dev/null; then echo 'relative path accepted' >&2; exit 1; fi
ln -s /etc/passwd "$OV_ROOT/vaults/unsafe.json"
if (ov_load vaults unsafe) >/dev/null; then echo 'symlink record accepted' >&2; exit 1; fi

# User programs cannot inherit the worker's locks, credential inputs, or other
# privileged descriptors. Parent locks must stay held until explicitly closed.
OV_UID=0 OV_USER=tester OV_HOME="$task_tmp"
exec {OV_LOCK_FD}>"$task_tmp/owner.lock"
exec {OV_RESOURCE_FD}>"$task_tmp/resource.lock"
flock -n "$OV_LOCK_FD"
flock -n "$OV_RESOURCE_FD"
printf 'test-secret' > "$task_tmp/secret"
exec {OV_SECRET_FD}<"$task_tmp/secret"
exec {OV_OLD_SECRET_FD}<"$task_tmp/secret"
exec {extra_fd}<"$task_tmp/secret"
export OV_SECRET_FD OV_OLD_SECRET_FD
# The helper's clean environment is intentional; the expected home is an argv.
# shellcheck disable=SC2016 # This program is expanded by the child shell.
check_closed='expected_home=$1; shift
for descriptor in "$@"; do [[ ! -e /proc/self/fd/$descriptor ]] || exit 20; done
[[ -z ${OV_SECRET_FD-} && -z ${OV_OLD_SECRET_FD-} && $HOME == "$expected_home" ]]'
ov_as_user /bin/bash -c "$check_closed" -- "$task_tmp" "$OV_LOCK_FD" "$OV_RESOURCE_FD" "$OV_SECRET_FD" "$OV_OLD_SECRET_FD" "$extra_fd"
[[ $(printf 'pipe input' | ov_as_user /bin/cat) == 'pipe input' ]]
if flock -n "$task_tmp/owner.lock" /bin/true; then echo 'parent owner lock released by child' >&2; exit 1; fi
if flock -n "$task_tmp/resource.lock" /bin/true; then echo 'parent resource lock released by child' >&2; exit 1; fi
[[ -e /proc/self/fd/$OV_SECRET_FD && -e /proc/self/fd/$extra_fd ]]

# Exercise the runuser branch without needing CAP_SETUID/CAP_SETGID in CI.
mkdir "$task_tmp/bin"
cat > "$task_tmp/bin/runuser" <<'HELPER'
#!/bin/bash
set -euo pipefail
[[ $1 == -u && $2 == tester && $3 == -- ]]
shift 3
exec "$@"
HELPER
chmod 0755 "$task_tmp/bin/runuser"
OV_UID=1001
PATH="$task_tmp/bin:$PATH" ov_as_user /bin/bash -c "$check_closed" -- "$task_tmp" "$OV_LOCK_FD" "$OV_RESOURCE_FD" "$OV_SECRET_FD" "$OV_OLD_SECRET_FD" "$extra_fd"
if flock -n "$task_tmp/owner.lock" /bin/true; then echo 'parent lock released through runuser' >&2; exit 1; fi
exec {OV_LOCK_FD}>&-
ov_resource_unlock
ov_secret_close
exec {extra_fd}<&-
flock -n "$task_tmp/owner.lock" /bin/true
flock -n "$task_tmp/resource.lock" /bin/true
echo 'common: JSON state, validation, permissions and descriptor isolation passed'
