#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
set -Eeuo pipefail
cd "$(dirname "$0")/.."
task_tmp=$(mktemp -d)
trap 'rm -rf -- "$task_tmp"' EXIT
cc -Wall -Wextra -Werror -O2 src/service/pinentry.c -o "$task_tmp/pinentry"
if env -u OV_SECRET_FD "$task_tmp/pinentry" </dev/null >/dev/null; then echo 'Missing secret accepted' >&2; exit 1; fi
umask 077
printf 'new%%password\nsecond' >"$task_tmp/new"
printf 'old-password' >"$task_tmp/old"
exec {OV_SECRET_FD}<"$task_tmp/new"
exec {OV_OLD_SECRET_FD}<"$task_tmp/old"
export OV_SECRET_FD OV_OLD_SECRET_FD OV_OLD_KEY_PATH=/keys/original.key
if "$task_tmp/pinentry" </dev/null >/dev/null; then echo 'Linked secret accepted' >&2; exit 1; fi
rm "$task_tmp/new" "$task_tmp/old"
result=$(printf 'SETDESC Insert password to: original.key\nGETPIN\nSETDESC Type the new password to secure your key\nGETPIN\nBYE\n' | "$task_tmp/pinentry")
[[ $result == *'D old-password'* ]]
[[ $result == *'D new%25password%0Asecond'* ]]
result2=$(printf 'GETPIN\nBYE\n' | "$task_tmp/pinentry")
[[ $result2 == *'D new%25password%0Asecond'* ]]
exec {OV_SECRET_FD}<&-
exec {OV_OLD_SECRET_FD}<&-
echo 'pinentry: private anonymous descriptors, reusable reads, escaping and old/new passwords passed'
