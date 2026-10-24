#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Exercise native client/daemon framing, identity handling, jobs and cancellation.
set -euo pipefail
cd "$(dirname "$0")/.."
for command in pkg-config cc dbus-run-session jq gdbus; do
    command -v "$command" >/dev/null || { printf 'Required test dependency missing: %s\n' "$command" >&2; exit 1; }
done
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
cat > "$work/backend" <<'BACKEND'
#!/usr/bin/env bash
set -euo pipefail
request=$(cat)
case $(jq -r .op <<<"$request") in
    backup.run) printf '{"stage":"backup","message":"Backing up","percent":10}\n' >&2; sleep 20 ;;
    vault.search) printf 'non JSON private diagnostic\n' >&2; printf 'not JSON'; exit 1 ;;
esac
jq -cn --argjson request "$request" --arg uid "$1" '{ok:true,data:{uid:$uid,request:$request}}'
BACKEND
chmod 755 "$work/backend"
cat > "$work/priority-backend" <<'PRIORITY'
#!/usr/bin/env bash
set -euo pipefail
work=$(dirname -- "$0")
printf '%s\n' "$1" > "$work/priority-called"
exec "$work/backend" "$@"
PRIORITY
chmod 755 "$work/priority-backend"
# Test-only binary: private bus and compile-time authorization bypass. Never installed.
read -r -a cflags <<<"$(pkg-config --cflags gio-2.0 gio-unix-2.0 json-glib-1.0)"
read -r -a libs <<<"$(pkg-config --libs gio-2.0 gio-unix-2.0 json-glib-1.0)"
cc -std=c11 -Wall -Wextra -Werror -DOCTOVAULT_TEST "-DOV_BACKEND_PATH=\"$work/backend\"" \
    "-DOV_PRIORITY_BACKEND_PATH=\"$work/priority-backend\"" \
    -Isrc/service "${cflags[@]}" src/service/daemon.c src/service/client.c -o "$work/daemon" "${libs[@]}"
cc -std=c11 -Wall -Wextra -Werror -DOCTOVAULT_TEST -Isrc/service "${cflags[@]}" \
    src/service/cli.c src/service/client.c -o "$work/cli" "${libs[@]}"
cat > "$work/exercise" <<'EXERCISE'
#!/usr/bin/env bash
set -Eeuo pipefail
work=$1
stage='starting the private test service'
# Report the failed check without printing a request or its secret fields.
trap 'status=$?; printf "Service test failed during %s (line %s, exit %s).\n" "$stage" "$LINENO" "$status" >&2; exit "$status"' ERR
"$work/daemon" & daemon=$!
trap 'kill "$daemon" 2>/dev/null || true; wait "$daemon" || true' EXIT
ready=false
for _ in {1..50}; do
    if gdbus introspect --session --dest io.vdm.OctoVault1 --object-path /io/vdm/OctoVault1 >/dev/null 2>&1; then ready=true; break; fi
    sleep .05
done
[[ $ready == true ]]
stage='CLI version and typed request framing'
"$work/cli" --version | grep -q OctoVault
output=$("$work/cli" --json vault create --size-gb 1.5 --name 'My documents' --close-on sleep --close-on shutdown --force-close false)
jq -e --arg uid "$(id -u)" '.ok and .data.uid == $uid and .data.request.params.size_gb == "1.5" and .data.request.params.close_on == ["sleep","shutdown"] and .data.request.params.force_close == false' <<<"$output" >/dev/null
stage='preserving decimal capacity through client and service'
output=$("$work/cli" --json vault create --size-gb 0.05 --name 'Small vault')
jq -e '.ok and .data.request.params.size_gb == "0.05"' <<<"$output" >/dev/null
stage='rejecting command-line secrets and identity overrides'
if "$work/cli" --json vault open --id x --password do-not-leak >"$work/rejected"; then exit 1; fi
if grep -q 'do-not-leak' "$work/rejected"; then printf 'Rejected credential appeared in client output.\n' >&2; exit 1; fi
if printf '{"op":"vault.list","params":{"uid":999}}' | "$work/cli" --json request - >"$work/identity"; then exit 1; fi
jq -e '.ok == false' "$work/identity" >/dev/null
if printf '{"op":"event.handle","params":{"event":"sleep"}}' | "$work/cli" --json request - >"$work/internal"; then exit 1; fi
jq -e '.ok == false' "$work/internal" >/dev/null
if "$work/cli" --json vault create --size-gb NaN >"$work/nan"; then exit 1; fi
stage='handling invalid backend output without disclosing raw diagnostics'
if "$work/cli" --json vault search --id x --query x >"$work/invalid"; then exit 1; fi
jq -e '.error.code == "BACKEND_FAILURE"' "$work/invalid" >/dev/null
if grep -q 'private diagnostic' "$work/invalid"; then printf 'Raw backend diagnostics appeared in client output.\n' >&2; exit 1; fi
stage='cancelling an asynchronous job'
reply=$(gdbus call --session --dest io.vdm.OctoVault1 --object-path /io/vdm/OctoVault1 --method io.vdm.OctoVault1.Submit '{"op":"backup.run","params":{}}')
id=$(sed -n "s/^('\([^']*\)',)$/\1/p" <<<"$reply")
[[ -n $id ]]
"$work/cli" --json job cancel "$id" | jq -e '.cancelled' >/dev/null
for _ in {1..40}; do
    result=$("$work/cli" --json job get "$id")
    [[ $(jq -r .state <<<"$result") == cancelled ]] && break
    sleep .1
done
jq -e '.state == "cancelled" and .result.error.code == "CANCELLED"' <<<"$result" >/dev/null
[[ ! -e $work/priority-called ]]
# A security close takes priority and stops a running upload before it waits for the owner lock.
stage='prioritizing vault locking over a running backup'
reply=$(gdbus call --session --dest io.vdm.OctoVault1 --object-path /io/vdm/OctoVault1 --method io.vdm.OctoVault1.Submit '{"op":"backup.run","params":{}}')
id=$(sed -n "s/^('\([^']*\)',)$/\1/p" <<<"$reply")
timeout 10 "$work/cli" --json vault close --id x | jq -e '.ok and .data.request.op == "vault.close"' >/dev/null
[[ $(cat "$work/priority-called") == "$(id -u)" ]]
"$work/cli" --json job get "$id" | jq -e '.state == "cancelled"' >/dev/null
# Complete results do not consume the active-job allowance; repeated dashboard refresh works.
stage='repeated dashboard refresh after completed jobs'
for _ in {1..20}; do "$work/cli" --json vault list | jq -e .ok >/dev/null; done
printf 'Native service and CLI tests passed.\n'
EXERCISE
chmod 755 "$work/exercise"
dbus-run-session -- "$work/exercise" "$work"
