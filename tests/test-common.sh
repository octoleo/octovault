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
echo 'common: JSON state, defaults, permissions and path validation passed'
