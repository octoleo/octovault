#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
set -Eeuo pipefail
cd "$(dirname "$0")/.."
task_tmp=$(mktemp -d)
trap 'rm -rf -- "$task_tmp"' EXIT
# Execute the actual configuration step, not a second implementation of it.
awk '
    /^  apt-configuration:/ { job=1; next }
    job && /^  [a-z][a-z-]*:/ { exit }
    job && /^        run: \|$/ { script=1; next }
    script && /^          / { print substr($0,11) }
' .github/workflows/ci.yml >"$task_tmp/configure.sh"
test -s "$task_tmp/configure.sh"

check_configuration() {
    local expected=$1 key=$2 fingerprint=$3 url=$4
    : >"$task_tmp/output"
    : >"$task_tmp/summary"
    APT_SIGNING_KEY="$key" APT_SIGNING_KEY_FINGERPRINT="$fingerprint" APT_REPOSITORY_URL="$url" \
        GITHUB_OUTPUT="$task_tmp/output" GITHUB_STEP_SUMMARY="$task_tmp/summary" \
        bash "$task_tmp/configure.sh" >"$task_tmp/log" 2>&1
    grep -qx "configured=$expected" "$task_tmp/output"
    if grep -Fq 'private-test-fixture' "$task_tmp/output" "$task_tmp/summary" "$task_tmp/log"; then
        printf 'Signing material appeared in configuration output.\n' >&2
        exit 1
    fi
    if [[ $expected == false ]]; then
        grep -Fq 'GitHub packages are already published' "$task_tmp/summary"
    fi
}
check_configuration false '' '' ''
check_configuration false '' AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA https://example.invalid/octovault
check_configuration false private-test-fixture '' https://example.invalid/octovault
check_configuration false private-test-fixture AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA ''
check_configuration true private-test-fixture AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA https://example.invalid/octovault
printf 'publication configuration: missing credentials skip; complete configuration enables rollout without disclosure\n'
