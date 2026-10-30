#!/usr/bin/env bash
# OctoVault's Tomb adapter. Encryption and container lifecycle remain in Tomb.
# This file is sourced by the privileged worker; it never accepts an executable
# path, identity, environment, or shell command from a request.

ov_vault_field() { jq -r --arg key "$2" '.[$key] // empty' <<< "$1"; }

ov_vault_temporary() {
    if [[ -z ${OV_VAULT_TEMP_DIR:-} ]]; then
        install -d -m 0700 /run/octovault
        OV_VAULT_TEMP_DIR=$(mktemp -d /run/octovault/vault.XXXXXXXX)
    fi
}

ov_vault_cleanup() {
    if [[ -n ${OV_VAULT_PIN_RECORD:-} ]]; then ov_vault_unpin "$OV_VAULT_PIN_RECORD" || true; fi
    [[ -z ${OV_VAULT_TEMP_DIR:-} ]] || rm -rf -- "$OV_VAULT_TEMP_DIR"
    unset OV_VAULT_TEMP_DIR OV_VAULT_PASSWORD OV_VAULT_OLD_PASSWORD OV_VAULT_TOKEN_KEY
}

ov_vault_alias() {
    local id
    id=$(ov_vault_field "$1" id); ov_id "$id"
    printf '/run/octovault/containers/%s/%s/vault.tomb\n' "$OV_UID" "$id"
}

# The kernel filesystem is mounted only beneath a root-owned directory. User
# paths receive a bind exposure after their directory inode has been pinned.
ov_vault_engine_mount() {
    local id
    id=$(ov_vault_field "$1" id); ov_id "$id"
    printf '/run/octovault/mounts/%s/%s\n' "$OV_UID" "$id"
}

ov_vault_active_mount() {
    local engine
    if [[ -n $(ov_vault_field "$1" id) ]]; then
        engine=$(ov_vault_engine_mount "$1")
        if findmnt -rn --mountpoint "$engine" >/dev/null 2>&1; then printf '%s\n' "$engine"; return; fi
    fi
    ov_vault_field "$1" mountpoint
}

# Container filesystems can be prepared on another machine with root-owned
# setuid programs, file capabilities or device nodes. Their ownership is not
# evidence of trust. Verify the effective kernel flags before exposing them.
ov_vault_mount_safe() {
    local options
    options=$(findmnt -rn --mountpoint "$1" --output VFS-OPTIONS) || return 1
    [[ -n $options && $options != *$'\n'* && ,$options, == *,nosuid,* && ,$options, == *,nodev,* ]]
}

ov_vault_expose() {
    local record=$1 mountpoint engine descriptor resolved rc=0
    mountpoint=$(ov_vault_field "$record" mountpoint); engine=$(ov_vault_engine_mount "$record")
    ov_vault_mount_safe "$engine" || return 1
    exec {descriptor}< "$mountpoint" || return 1
    resolved=$(readlink -f -- "/proc/self/fd/$descriptor") || { exec {descriptor}<&-; return 1; }
    if [[ ! -d /proc/self/fd/$descriptor || $resolved != "$mountpoint" ||
          $(stat -Lc %u -- "/proc/self/fd/$descriptor") != "$OV_UID" ]]; then
        exec {descriptor}<&-; return 1
    fi
    # The directory must still be empty immediately before the bind. Content
    # written underneath later remains independent and is never reconciled.
    if [[ -n $(find "/proc/self/fd/$descriptor/" -mindepth 1 -maxdepth 1 -print -quit) ]]; then
        exec {descriptor}<&-; return 1
    fi
    mount --no-canonicalize --bind "$engine" "/proc/self/fd/$descriptor" >&2 || rc=$?
    exec {descriptor}<&-
    ((rc==0)) || return "$rc"
    [[ $(stat -Lc '%d:%i' -- "$mountpoint") == $(stat -Lc '%d:%i' -- "$engine") ]] &&
        ov_vault_mount_safe "$mountpoint"
}

ov_vault_backing() {
    local alias
    # Tests and legacy imported objects without an id use their original file.
    if [[ -n $(ov_vault_field "$1" id) ]]; then
        alias=$(ov_vault_alias "$1")
        if [[ -f $alias ]] && findmnt -rn --mountpoint "$alias" >/dev/null 2>&1; then
            printf '%s\n' "$alias"; return
        fi
    fi
    ov_vault_field "$1" file
}

ov_vault_pin() {
    local record=$1 file alias descriptor resolved identity alias_identity
    file=$(ov_vault_field "$record" file)
    ov_vault_user_path "$file" >/dev/null
    ov_as_user test -w "$file" || ov_fail permission_denied "The container must be writable by your account."
    # Opening read-only cannot create or truncate an attacker-swapped target.
    exec {descriptor}< "$file" || ov_fail unavailable "The container could not be opened."
    resolved=$(readlink -f -- "/proc/self/fd/$descriptor")
    if [[ ! -f /proc/self/fd/$descriptor || $resolved != "$file" ||
          $(stat -Lc %u -- "/proc/self/fd/$descriptor") != "$OV_UID" ]]; then
        exec {descriptor}<&-
        ov_fail unsafe_container "The container must be a regular file owned by your account at its registered path."
    fi
    identity=$(stat -Lc '%d:%i' -- "/proc/self/fd/$descriptor")
    alias=$(ov_vault_alias "$record")
    install -d -m 0700 /run/octovault/containers "/run/octovault/containers/$OV_UID" "$(dirname -- "$alias")"
    if findmnt -rn --mountpoint "$alias" >/dev/null 2>&1; then
        alias_identity=$(stat -Lc '%d:%i' -- "$alias")
        exec {descriptor}<&-
        [[ $identity == "$alias_identity" ]] || ov_fail busy "Another inode is still pinned for this vault. Close it before replacing its container file."
    else
        : > "$alias"; chmod 0600 "$alias"
        if ! mount --no-canonicalize --bind "/proc/self/fd/$descriptor" "$alias" >&2; then
            exec {descriptor}<&-; rm -f -- "$alias"
            ov_fail mount_failed "Could not pin the container securely for the privileged operation."
        fi
        exec {descriptor}<&-
    fi
    OV_VAULT_CONTAINER_ALIAS=$alias
    OV_VAULT_PIN_RECORD=$record
}

ov_vault_unpin() {
    local alias loops
    alias=$(ov_vault_alias "$1")
    [[ -f $alias ]] || return 0
    loops=$(losetup --noheadings --output NAME --associated "$alias" 2>/dev/null) || return 1
    [[ -z $loops ]] || return 0
    if findmnt -rn --mountpoint "$alias" >/dev/null 2>&1; then
        umount -- "$alias" >&2 || return 1
    fi
    rm -f -- "$alias"
    rmdir -- "$(dirname -- "$alias")" 2>/dev/null || true
}

# Write keys/images through the user's identity. Privileged operations never
# follow a user-controlled output symlink when publishing an encrypted key.
ov_vault_publish() {
    local input=$1 output=$2 replace=${3:-false} temporary
    temporary=$(ov_as_user mktemp "$(dirname -- "$output")/.octovault-key.XXXXXXXX") || return 1
    if ! cat -- "$input" | ov_as_user tee -- "$temporary" >/dev/null; then
        ov_as_user rm -f -- "$temporary"; return 1
    fi
    if [[ $replace == true ]]; then
        ov_as_user mv -fT -- "$temporary" "$output" || return 1
    else
        ov_as_user mv -nT -- "$temporary" "$output" || return 1
        if [[ -e $temporary ]]; then ov_as_user rm -f -- "$temporary"; return 1; fi
    fi
}

ov_vault_image_extract() {
    local image=$1 output=$2 rc=0
    ov_vault_temporary
    ov_as_user cat -- "$image" > "$OV_VAULT_TEMP_DIR/carrier.jpg" || return 1
    ov_secret_fd "$OV_VAULT_PASSWORD"
    /usr/libexec/octovault/steghide extract "$OV_VAULT_TEMP_DIR/carrier.jpg" "$output" >&2 || rc=$?
    ov_secret_close
    return "$rc"
}

ov_vault_image_embed() {
    local key=$1 image=$2 output=$3 rc=0
    ov_vault_temporary
    # Tomb's carrier format omits public armor headers; the encrypted payload
    # remains protected. The trusted PTY helper keeps steghide passwords out
    # of argv (Tomb's own bury/exhume currently pass them with -p).
    awk '/^-----/ {next} /^Version/ {next} {print}' "$key" > "$OV_VAULT_TEMP_DIR/steg-payload"
    ov_as_user cat -- "$image" > "$OV_VAULT_TEMP_DIR/carrier.jpg" || return 1
    ov_secret_fd "$OV_VAULT_PASSWORD"
    /usr/libexec/octovault/steghide embed "$OV_VAULT_TEMP_DIR/carrier.jpg" "$OV_VAULT_TEMP_DIR/steg-payload" "$output" >&2 || rc=$?
    ov_secret_close
    return "$rc"
}

ov_vault_text_embed() {
    local key=$1 cipher=$2 output=$3
    ov_vault_temporary
    ov_as_user cat -- "$cipher" > "$OV_VAULT_TEMP_DIR/cloak-cipher" || return 1
    /usr/libexec/octovault/text-carrier encode "$key" "$OV_VAULT_TEMP_DIR/cloak-cipher" "$output"
}

ov_vault_plain_key() {
    local record=$1 auth key
    auth=$(ov_vault_field "$record" auth); key=$(ov_vault_field "$record" key_file)
    ov_vault_temporary
    OV_VAULT_MATERIALIZED_KEY="$OV_VAULT_TEMP_DIR/$(ov_new_id).key"
    case $auth in
        image) ov_vault_image_extract "$key" "$OV_VAULT_MATERIALIZED_KEY" || ov_fail key_failed "The image could not be unlocked." ;;
        text)
            ov_as_user cat -- "$key" > "$OV_VAULT_TEMP_DIR/cloaked.txt" || ov_fail key_failed "The text carrier cannot be read."
            ov_as_user cat -- "$(ov_vault_field "$record" cipher_file)" > "$OV_VAULT_TEMP_DIR/cloak-cipher" || ov_fail key_failed "The cipher file cannot be read."
            /usr/libexec/octovault/text-carrier decode "$OV_VAULT_TEMP_DIR/cloaked.txt" "$OV_VAULT_TEMP_DIR/cloak-cipher" "$OV_VAULT_MATERIALIZED_KEY" >&2 ||
                ov_fail key_failed "The text key could not be decoded; verify the cipher file and installed encryption extras."
            ;;
        *) ov_as_user cat -- "$key" > "$OV_VAULT_MATERIALIZED_KEY" || ov_fail key_failed "The encrypted key cannot be read by your account." ;;
    esac
}

ov_vault_clean_path() {
    local path=$1
    [[ $path == /* && $path != *$'\n'* && $path != *$'\r'* && $path != *$'\t'* ]] ||
        ov_fail invalid_path "Use an absolute path without control characters."
    [[ $path != / && $path != */../* && $path != */.. && $path != */./* ]] ||
        ov_fail invalid_path "The filesystem root and relative path components are not allowed."
    printf '%s\n' "$path"
}

ov_vault_user_path() {
    local path canonical parent
    path=$(ov_vault_clean_path "$1") || return
    if [[ -e $path || -L $path ]]; then
        [[ ! -L $path ]] || ov_fail unsafe_path "Symbolic links cannot be used here."
        canonical=$(realpath -e -- "$path") || ov_fail invalid_path "The path cannot be resolved."
        ov_as_user test -r "$canonical" || ov_fail permission_denied "The path is not accessible to your account."
    else
        parent=$(realpath -e -- "$(dirname -- "$path")") || ov_fail invalid_path "The parent directory does not exist."
        ov_as_user test -w "$parent" || ov_fail permission_denied "The parent directory is not writable by your account."
        canonical="$parent/$(basename -- "$path")"
    fi
    printf '%s\n' "$canonical"
}

ov_vault_relative() {
    local value=$1 part
    [[ -n $value && $value != /* && $value != *$'\n'* && $value != *$'\r'* && $value != *$'\t'* ]] ||
        ov_fail invalid_path "A nonempty relative path is required."
    local -a parts
    IFS=/ read -r -a parts <<< "$value"
    for part in "${parts[@]}"; do
        [[ -n $part && $part != . && $part != .. ]] || ov_fail invalid_path "Relative paths cannot contain empty, dot or parent components."
    done
    [[ ${parts[0]} != bind-hooks && ${parts[0]} != exec-hooks && ${parts[0]} != .octovault ]] ||
        ov_fail reserved_path "This name is reserved for vault metadata."
    [[ $value != *'__ESC_SPACE__'* && $value != *'\ '* ]] ||
        ov_fail invalid_path "This path cannot be represented faithfully by the native folder-mapping format."
    printf '%s\n' "$value"
}

ov_vault_mib() {
    local size=$1
    # JSON serializers may render 0.05 as 0.050000000000000003, or use
    # scientific notation. Validate the entire token before applying bounds.
    [[ ${#size} -le 128 && $size =~ ^[0-9]+([.][0-9]+)?([eE][+-]?[0-9]+)?$ ]] ||
        ov_fail invalid_size "Size must be a positive decimal number of GB."
    awk -v gb="$size" 'BEGIN {m=gb*1000000000/1048576; n=int(m); if(n<m)n++; if(n<10||n>2147483647)exit 1; printf "%.0f\n",n}' ||
        ov_fail invalid_size "The requested size is outside the supported range."
}

# Interpret only documented GnuPG status records. Raw stderr and credentials
# never become GUI messages or activity history. Numeric errors use libgpg-error
# codes (the low 16 bits), independent of the source component.
ov_vault_auth_failure() {
    local status=$1 rc=$2 reason code message
    reason=$(awk '
      $1=="[GNUPG:]" {
        if ($2=="SC_OP_FAILURE" && $3==1) cancelled=1
        if ($2=="SC_OP_FAILURE" && $3==2) bad_pin=1
        if ($2=="NO_SECKEY") missing=1
        if ($2=="BAD_PASSPHRASE" || $2=="MISSING_PASSPHRASE") passphrase=1
        if ($2=="INV_RECP" && $3==10) untrusted=1
        if ($2=="ERROR" || $2=="FAILURE") {
          split($4, parts, "_"); value=parts[1]
          if (value ~ /^[0-9]+$/) {
            value=value % 65536
            if (value==99 || value==198) cancelled=1
            if (value==85) pinentry=1
            if (value==87) bad_pin=1
            if (value==112) card=1
          }
        }
      }
      END {
        if (cancelled) print "cancelled"
        else if (bad_pin) print "bad_pin"
        else if (pinentry) print "pinentry"
        else if (card) print "card"
        else if (missing) print "missing"
        else if (untrusted) print "untrusted"
        else if (passphrase) print "passphrase"
      }' "$status")
    rm -f -- "$status"
    if [[ $rc == 124 || $rc == 137 ]]; then
        code=authentication_timeout; message="Authentication timed out. Check the PIN or passphrase window, connect your security key if needed, and try again."
    else
        case $reason in
            cancelled) code=authentication_cancelled; message="Authentication was cancelled. Try again when you are ready to enter your PIN or passphrase." ;;
            bad_pin) code=incorrect_pin; message="The security key rejected the PIN. Check it before trying again; repeated incorrect PINs can block the key." ;;
            pinentry) code=pinentry_unavailable; message="GnuPG could not open its PIN or passphrase window. Check your desktop GnuPG pinentry setup and try again." ;;
            card) code=token_missing; message="The required security key is not available. Connect it and try again." ;;
            missing) code=private_key_missing; message="The matching private OpenPGP key is unavailable. Connect its security key or restore the private key using your OpenPGP key manager." ;;
            untrusted) code=key_untrusted; message="GnuPG does not trust this public key for encryption. Verify its fingerprint and certify it in your OpenPGP key manager, then try again." ;;
            passphrase) code=incorrect_passphrase; message="GnuPG could not unlock the private key with that passphrase. Check the passphrase and try again." ;;
            *) code=authentication_failed; message="GnuPG could not verify this key. Check that its private key or security key is available and that the PIN or passphrase prompt can open." ;;
        esac
    fi
    ov_fail "$code" "$message"
}

ov_vault_require_token() {
    local expected=${1:-} card fingerprint serial secrets binding status
    ov_vault_temporary
    status="$OV_VAULT_TEMP_DIR/card-status"
    ov_progress authentication "Checking the connected OpenPGP security key" 1
    if ! card=$(ov_as_user timeout --foreground --signal=TERM --kill-after=5 15 \
        gpg --no-options --batch --no-tty --status-fd 2 --with-colons --card-status 2> "$status"); then
        rm -f -- "$status"
        ov_fail token_missing "No usable OpenPGP security key was found. Connect a key with its OpenPGP application enabled, then try again."
    fi
    fingerprint=$(awk -F: '$1=="fpr" {print toupper($3);exit}' <<< "$card")
    serial=$(awk -F: '$1=="AID" {print toupper($2);exit}' <<< "$card")
    [[ $fingerprint =~ ^([[:xdigit:]]{40}|[[:xdigit:]]{64})$ && -n ${fingerprint//0/} ]] ||
        ov_fail token_unconfigured "The connected security key has no OpenPGP encryption key. Set up or restore that key with your OpenPGP key manager first."
    [[ $serial =~ ^[[:xdigit:]]{16,64}$ ]] || ov_fail token_unconfigured "The connected OpenPGP security key could not be identified. Check its setup in your OpenPGP key manager."
    expected=${expected%!}
    [[ -z $expected || ${expected^^} == "$fingerprint" ]] ||
        ov_fail token_mismatch "The connected security key does not match this vault. Connect the matching key and try again."
    if ! secrets=$(ov_as_user timeout --foreground --signal=TERM --kill-after=5 15 \
        gpg --no-options --batch --no-tty --with-colons --with-fingerprint --with-subkey-fingerprint \
        --list-secret-keys -- "$fingerprint" 2> "$status"); then
        rm -f -- "$status"
        ov_fail private_key_missing "GnuPG cannot use the security key's private encryption key. Check the card association in your OpenPGP key manager."
    fi
    # GnuPG doc/DETAILS field 15 contains the token serial for sec/ssb.
    # An empty field or '+' represents a local secret, not proof of a token.
    binding=$(awk -F: -v wanted="$fingerprint" '
      $1=="sec" || $1=="ssb" {serial=toupper($15)}
      $1=="fpr" && toupper($10)==wanted {print serial;exit}' <<< "$secrets")
    rm -f -- "$status"
    [[ $binding == "$serial" ]] ||
        ov_fail token_not_bound "The selected private key is not bound to the connected security key in GnuPG. Use its card-backed encryption key; a software private-key copy cannot satisfy security-key authentication."
    OV_VAULT_TOKEN_FINGERPRINT=$fingerprint
}

ov_vault_auth_preflight() {
    local recipient=$1 require_token=$2 existing_key=${3:-} fingerprint='' card_fingerprint=''
    local keys state trust selected card_usable primary_usable status encrypted challenge decrypted actual rc=0 exact=no
    [[ $require_token == true || $require_token == false ]] || ov_fail invalid_auth "The security-key requirement must be true or false."
    if [[ -z $existing_key || -n $recipient ]]; then
        [[ $recipient =~ ^([[:xdigit:]]{40}|[[:xdigit:]]{64})!?$ ]] ||
            ov_fail invalid_recipient "Choose a complete OpenPGP encryption-key fingerprint."
        fingerprint=${recipient%!}; fingerprint=${fingerprint^^}
        [[ -n ${fingerprint//0/} ]] || ov_fail invalid_recipient "Choose a valid OpenPGP encryption-key fingerprint."
        recipient=${recipient^^}
        [[ $recipient != *! ]] || exact=yes
    fi
    ov_vault_temporary
    status="$OV_VAULT_TEMP_DIR/auth-status"
    if [[ $require_token == true ]]; then
        ov_vault_require_token
        card_fingerprint=$OV_VAULT_TOKEN_FINGERPRINT
    fi
    if [[ -z $existing_key ]]; then
        if ! keys=$(ov_as_user timeout --foreground --signal=TERM --kill-after=5 15 \
            gpg --no-options --batch --no-tty --with-colons --with-fingerprint --with-subkey-fingerprint \
            --list-keys -- "$fingerprint" 2> "$status"); then
            rm -f -- "$status"
            ov_fail public_key_missing "The selected public OpenPGP key is missing from your keyring. Import its matching public key, then choose it again."
        fi
        # Tomb checks primary-key validity before forge. Check it here, plus
        # expiration, encryption usage and the exact requested fingerprint.
        state=$(awk -F: -v wanted="$fingerprint" -v card="$card_fingerprint" -v exact="$exact" -v now="$(date +%s)" '
          $1=="pub" || $1=="sub" {
            usable=($2 !~ /^[redi]/ && $12 !~ /D/ && ($7=="" || $7==0 || $7>now))
            if ($1=="pub") {trust=$2; primary=usable}
            encryption=($12 ~ /e/ || ($1=="pub" && exact=="no" && $12 ~ /E/))
          }
          $1=="fpr" {
            if (toupper($10)==wanted && usable && encryption) selected=1
            if (toupper($10)==card && usable && encryption) matched=1
          }
          END {printf "%s %d %d %d\n", (trust=="" ? "-" : trust),selected,matched,primary}' <<< "$keys")
        read -r trust selected card_usable primary_usable <<< "$state"
        [[ $primary_usable == 1 && $selected == 1 ]] || ov_fail key_unusable "The selected OpenPGP key cannot encrypt. Choose a current encryption key that is not expired, revoked or disabled."
        [[ $trust == [mfuws] ]] || ov_fail key_untrusted "The selected public key is not trusted for vault encryption. Verify its fingerprint and certify it in your OpenPGP key manager, then try again."
        if [[ $require_token == true ]]; then
            [[ $card_usable == 1 && ( $exact == no || $fingerprint == "$card_fingerprint" ) ]] ||
                ov_fail token_mismatch "The connected security key does not match the selected encryption key. Connect the matching key or detect the intended key again."
            recipient="$card_fingerprint!"
        fi
        challenge="OctoVault authentication check $(ov_new_id)"
        encrypted="$OV_VAULT_TEMP_DIR/auth-challenge.gpg"
        ov_progress authentication "Verifying access to your OpenPGP key; enter its PIN or passphrase and touch the key if requested" 2
        printf '%s' "$challenge" | ov_as_user timeout --foreground --signal=TERM --kill-after=5 30 \
            gpg --no-options --batch --no-tty --status-fd 2 --output - --encrypt --recipient "$recipient" \
            > "$encrypted" 2> "$status" || rc=$?
        ((rc==0)) || ov_vault_auth_failure "$status" "$rc"
        decrypted=$(ov_as_user timeout --foreground --signal=TERM --kill-after=5 120 \
            gpg --no-options --batch --no-tty --status-fd 2 --output - --decrypt < "$encrypted" 2> "$status") || rc=$?
        rm -f -- "$encrypted"
        ((rc==0)) || ov_vault_auth_failure "$status" "$rc"
        [[ $decrypted == "$challenge" ]] || ov_fail authentication_failed "The OpenPGP verification did not return the expected result. No new vault has been allocated."
        unset challenge decrypted
    else
        ov_progress authentication "Verifying your existing encrypted vault key; enter its PIN or passphrase if requested" 2
        ov_as_user cat -- "$existing_key" | ov_as_user timeout --foreground --signal=TERM --kill-after=5 120 \
            gpg --no-options --batch --no-tty --status-fd 2 --output - --decrypt > /dev/null 2> "$status" || rc=$?
        ((rc==0)) || ov_vault_auth_failure "$status" "$rc"
    fi
    actual=$(awk '$1=="[GNUPG:]" && $2=="DECRYPTION_KEY" {print toupper($3);exit}' "$status")
    rm -f -- "$status"
    [[ $actual =~ ^([[:xdigit:]]{40}|[[:xdigit:]]{64})$ ]] ||
        ov_fail invalid_key "The selected file or key did not authenticate with an OpenPGP private key. Choose an OpenPGP-encrypted vault key."
    [[ $require_token != true || $actual == "$card_fingerprint" ]] ||
        ov_fail token_mismatch "The encrypted vault key belongs to a different OpenPGP key than the connected security key."
    if [[ $require_token == true ]]; then OV_VAULT_AUTH_RECIPIENT="$card_fingerprint!"
    else OV_VAULT_AUTH_RECIPIENT=${recipient:-$actual!}; fi
}

ov_vault_auth_check() {
    local recipient require_token reuse key=''
    recipient=$(ov_param recipient); require_token=$(ov_param require_token false); reuse=$(ov_param use_existing_key false)
    jq -e '((.require_token//false)|type=="boolean") and ((.use_existing_key//false)|type=="boolean")' <<< "$OV_PARAMS" >/dev/null ||
        ov_fail invalid_auth "The security-key and existing-key options must be true or false."
    if [[ $reuse == true ]]; then
        key=$(ov_vault_user_path "$(ov_require key_file)")
        [[ -f $key ]] || ov_fail invalid_key "Choose an existing encrypted vault key file."
    fi
    ov_vault_auth_preflight "$recipient" "$require_token" "$key"
    ov_ok "$(jq -n --arg recipient "$OV_VAULT_AUTH_RECIPIENT" --argjson token "$require_token" '{verified:true,recipient:$recipient,require_token:$token}')"
}

# The desktop selects a directory, while scripts may still supply the complete
# container filename. Normalize once before acquiring the container lock.
ov_vault_create_path() {
    local name directory file
    name=$(ov_require name)
    [[ ${#name} -le 200 && $name != . && $name != .. && $name != */* && ! $name =~ [[:cntrl:]] ]] ||
        ov_fail invalid_name "Use a vault name without slashes or control characters."
    directory=$(ov_param directory); file=$(ov_param file)
    [[ -z $directory || -z $file ]] || ov_fail invalid_path "Choose a storage folder or a complete container filename, not both."
    if [[ -n $directory ]]; then
        directory=$(ov_vault_user_path "$directory")
        [[ -d $directory ]] || ov_fail invalid_path "Select an existing folder in which to store the vault."
        ov_as_user test -w "$directory" || ov_fail permission_denied "The storage folder is not writable by your account."
        if [[ $name == *.tomb ]]; then file="$directory/$name"; else file="$directory/$name.tomb"; fi
    else
        [[ -n $file ]] || ov_fail invalid_request "Choose the folder in which to store the vault."
    fi
    file=$(ov_vault_user_path "$file")
    OV_PARAMS=$(jq --arg file "$file" '.file=$file' <<< "$OV_PARAMS")
}

ov_vault_managed_key_directory() {
    local id=$1 directory="$OV_HOME/.local/share/octovault/keys" path
    ov_id "$id"
    # Everything is created and permissioned under the user's identity. No
    # privileged writer follows a user-controlled key-directory symlink.
    for path in "$directory" "$directory/$id"; do
        [[ ! -L $path ]] || ov_fail unsafe_path "The managed key folder cannot be a symbolic link."
        ov_as_user install -d -m 0700 -- "$path" || ov_fail permission_denied "Could not create the private key folder."
        [[ -d $path && $(stat -c %u -- "$path") == "$OV_UID" ]] || ov_fail unsafe_path "The private key folder must belong to your account."
        ov_as_user chmod 0700 -- "$path" || ov_fail permission_denied "Could not secure the private key folder."
    done
    printf '%s\n' "$directory/$id"
}

# A loop association is intentionally conservative: even a partially mounted
# container must not be backed up as a stable closed file.
ov_vault_attached() {
    local file loops
    file=$(ov_vault_backing "$1")
    loops=$(losetup --noheadings --output NAME --associated "$file" 2>/dev/null) || return 2
    [[ -n $loops ]]
}

# Unknown kernel state is never equivalent to a safely closed container.
ov_vault_require_closed() {
    local state=0
    ov_vault_attached "$1" || state=$?
    case $state in
        0) ov_fail busy "The container is still attached; close it before continuing." ;;
        1) return 0 ;;
        *) ov_fail state_unknown "The encrypted device state could not be verified." ;;
    esac
}

ov_vault_is_open() {
    local record=$1 file mountpoint source device loops loop
    file=$(ov_vault_backing "$record")
    mountpoint=$(ov_vault_active_mount "$record")
    [[ -n $mountpoint && -n $file ]] || return 1
    source=$(findmnt -rn --mountpoint "$mountpoint" --output SOURCE 2>/dev/null) || return 1
    source=${source%%\[*}
    [[ $source == /dev/mapper/* || $source == /dev/dm-* ]] || return 1
    device=$(cryptsetup status "$source" 2>/dev/null | awk '$1=="device:" {print $2}') || return 1
    [[ -n $device ]] || return 1
    device=$(readlink -f -- "$device") || return 1
    loops=$(losetup --noheadings --output NAME --associated "$file" 2>/dev/null) || return 1
    while IFS= read -r loop; do
        [[ -n $loop ]] || continue
        [[ $(readlink -f -- "$loop") == "$device" ]] && return 0
    done <<< "$loops"
    return 1
}

# Tomb accepts a mapper-hash selector. Selecting only a basename could close
# another vault with the same filename on a different device or account.
ov_vault_is_exposed() {
    local record=$1 user_mount engine
    ov_vault_is_open "$record" || return 1
    user_mount=$(ov_vault_field "$record" mountpoint); engine=$(ov_vault_active_mount "$record")
    findmnt -rn --mountpoint "$user_mount" >/dev/null 2>&1 || return 1
    [[ $(stat -Lc '%d:%i' -- "$user_mount") == $(stat -Lc '%d:%i' -- "$engine") ]]
}

ov_vault_selector() {
    local source selector
    source=$(findmnt -rn --mountpoint "$(ov_vault_active_mount "$1")" --output SOURCE) || return 1
    source=${source%%\[*}; selector=${source%.*}; selector=${selector##*.}
    [[ $selector =~ ^[a-fA-F0-9]{64}$ ]] || return 1
    printf '%s\n' "$selector"
}

ov_vault_unbind() {
    local record=$1 mountpoint mapper mounts target
    mountpoint=$(ov_vault_active_mount "$record")
    mapper=$(findmnt -rn --mountpoint "$mountpoint" --output SOURCE) || return 1
    mapper=${mapper%%\[*}
    mounts=$(findmnt --json --list --source "$mapper" --output TARGET) || return 1
    while IFS= read -r target; do
        [[ $target == "$mountpoint" ]] && continue
        umount -- "$target" >&2 || return 1
    done < <(jq -r '.filesystems | sort_by(.target|length) | reverse | .[].target' <<< "$mounts")
}

# Report native mappings only while their metadata is visible. A missing
# mapping file means no mapped locations, not that the container has no files.
ov_vault_protected_locations() (
    local record=$1 mountpoint hook source relative active result='[]' i
    local -a bindings=()
    ov_vault_is_exposed "$record" || { printf 'null\n'; return; }
    mountpoint=$(ov_vault_field "$record" mountpoint); hook="$mountpoint/bind-hooks"
    if [[ ! -e $hook && ! -L $hook ]]; then printf '[]\n'; return; fi
    if [[ ! -f $hook || -L $hook ]] || ! ov_vault_read_binds "$hook" >/dev/null 2>&1; then
        printf 'null\n'; return
    fi
    mapfile -d '' -t bindings < <(ov_vault_read_binds "$hook")
    ((${#bindings[@]} % 2 == 0)) || { printf 'null\n'; return; }
    # Invalid native paths make this read-only inspection unavailable. Do not
    # publish a failure report or modify the worker's first-error state.
    unset OV_ERROR_FILE
    for ((i=0; i<${#bindings[@]}; i+=2)); do
        relative=${bindings[i]}; source=${bindings[i+1]}
        if ! (ov_vault_relative "$relative" >/dev/null 2>&1) ||
           ! (ov_vault_relative "$source" >/dev/null 2>&1); then
            printf 'null\n'; return
        fi
        source="$OV_HOME/$source"; active=false
        ov_vault_mapping_matches "$record" "$source" "$relative" >/dev/null 2>&1 && active=true
        result=$(jq -c --arg source "$source" --arg relative "$relative" --argjson active "$active" \
            '. + [{source:$source,relative:$relative,active:$active}]' <<< "$result")
    done
    printf '%s\n' "$result"
)

ov_vault_status() {
    local record=$1 status=closed usage='null' mountpoint
    mountpoint=$(ov_vault_active_mount "$record")
    if ov_vault_is_open "$record"; then
        status=open
        usage=$(df -B1 --output=size,used,avail,pcent -- "$mountpoint" 2>/dev/null | tail -n 1 |
            awk '{gsub(/%/,"",$4);printf "{\"total\":%s,\"used\":%s,\"available\":%s,\"percent\":%s}",$1,$2,$3,$4}')
        [[ -n $usage ]] || usage=null
    else
        local state=0
        ov_vault_attached "$record" || state=$?
        case $state in
            0) status=attention ;;
            1)
                if [[ ! -f $(ov_vault_field "$record" file) ]]; then status=missing
                elif [[ $(ov_vault_field "$record" creation_state) == initializing ]]; then status=incomplete
                fi
                ;;
            *) status=unknown ;;
        esac
    fi
    local pending='[]' id locations
    id=$(ov_vault_field "$record" id)
    if [[ -n $id ]]; then
        pending=$(ov_migration_list "$id" | jq '[.[] | select(.stage != "complete" and .stage != "rolled_back")]')
    fi
    locations=$(ov_vault_protected_locations "$record")
    jq --arg status "$status" --argjson usage "$usage" --argjson pending "$pending" --argjson locations "$locations" \
        '. + {status:$status,usage:$usage,pending_migrations:$pending,protected_locations:$locations}' <<< "$record"
}

ov_vault_verify_recovery_passphrase() {
    local record=$1 rc=0
    [[ $(ov_vault_field "$record" auth) != gpg ]] || ov_fail invalid_auth 'FIDO2 enrollment needs a passphrase-protected Tomb key.'
    ov_vault_password
    [[ -n $OV_VAULT_PASSWORD ]] || ov_fail password_required 'Enter the existing recovery passphrase before adding a FIDO2 key.'
    ov_vault_plain_key "$record"
    ov_secret_fd "$OV_VAULT_PASSWORD"
    ov_vault_temporary
    install -d -m 0700 "$OV_VAULT_TEMP_DIR/verify-gpg"
    timeout --signal=TERM --kill-after=2 30 gpg --no-options --homedir "$OV_VAULT_TEMP_DIR/verify-gpg" \
        --batch --no-tty --pinentry-mode loopback --passphrase-fd "$OV_SECRET_FD" \
        --output /dev/null --decrypt "$OV_VAULT_MATERIALIZED_KEY" >/dev/null 2>&1 || rc=$?
    ov_secret_close
    gpgconf --homedir "$OV_VAULT_TEMP_DIR/verify-gpg" --kill all >/dev/null 2>&1 || true
    rm -f -- "$OV_VAULT_MATERIALIZED_KEY"
    ((rc==0)) || ov_fail invalid_password 'The recovery passphrase could not unlock this Tomb key. The FIDO2 enrollment was not saved.'
}

ov_vault_validate_fido2() {
    local record=$1
    jq -e '
      def b64($min;$max): type=="string" and length>=$min and length<=$max and test("^[A-Za-z0-9+/]+={0,2}$");
      . as $r | .fido2 |
      .==null or (type=="object" and
      (keys|sort)==(["version","vault_id","credential","salt","nonce","ciphertext","tag"]|sort) and
      .version==1 and .vault_id==$r.id and
      (.credential|b64(4;1368)) and (.salt|b64(44;44)) and (.nonce|b64(16;16)) and
      (.tag|b64(24;24)) and (.ciphertext|b64(4;5464)) and $r.auth!="gpg")
    ' <<< "$record" >/dev/null || ov_fail invalid_fido2 'The FIDO2 enrollment is invalid for this vault.'
}

ov_vault_validate_record() {
    local record=$1
    ov_record_scope "$record" >/dev/null
    ov_vault_validate_fido2 "$record"
    if [[ ${OV_EXECUTION_SCOPE:-system} == personal && $(ov_vault_field "$record" force_close) == true ]]; then
        ov_fail admin_required 'Force locking can terminate other processes. Unlock administrator access to enable this policy.'
    fi
    jq -e '(.name|type=="string" and length>0 and length<=200) and
      (.file|type=="string") and (.key_file|type=="string") and
      (.auth|IN("key","gpg","image","text")) and
      (.open_on|IN("manual","login","drive","token")) and
      ((.prompt_after_unlock//false)|type=="boolean") and ((.prompt_after_resume//false)|type=="boolean") and
      (.close_on|type=="array" and all(.[];IN("screen-lock","logout","sleep","shutdown"))) and
      (.force_close|type=="boolean") and ((.trust_native_hooks//false)|type=="boolean") and
      ((.require_token//false)|type=="boolean") and
      ((.recipient//"")|type=="string") and (.hooks|type=="object")' <<< "$record" >/dev/null ||
        ov_fail invalid_vault "The vault configuration is invalid."
    [[ $(ov_vault_field "$record" auth) != text || -n $(ov_vault_field "$record" cipher_file) ]] ||
        ov_fail invalid_auth "A text-cloaking cipher file is required."
    [[ $(ov_vault_field "$record" require_token) != true || $(ov_vault_field "$record" auth) == gpg ]] ||
        ov_fail invalid_auth "Security-key authentication requires OpenPGP protection."
    [[ $(ov_vault_field "$record" open_on) != drive || -n $(ov_vault_field "$record" drive_uuid) ]] ||
        ov_fail invalid_event "Select a drive UUID before enabling drive-triggered unlocking."
    local hook
    while IFS= read -r hook; do
        [[ -z $hook ]] || ov_vault_user_path "$hook" >/dev/null
    done < <(jq -r '.hooks | .open // empty, .close // empty, .after_close // empty' <<< "$record")
}

# Tomb's native hook runner inherits root when Tomb is invoked by a service.
# Always disable it; hooks are explicitly run as the requesting user below.
# The immutable pinentry adapter reads a seekable inherited FD, never argv.
ov_vault_tomb() {
    local password=${OV_VAULT_PASSWORD:-} rc=0 backend
    ov_vault_temporary
    install -d -m 0700 "$OV_VAULT_TEMP_DIR/gnupg"
    # Tomb remains the encryption and mount engine. Its sourced interface
    # lets us disable root metadata writes that otherwise follow symlinks
    # inside imported filesystems. OctoVault records lifecycle metadata itself.
    # shellcheck disable=SC2016 # This fixed script is parsed by zsh, not Bash.
    local -a command=(/usr/bin/zsh -f -c '
        source /usr/bin/tomb source || exit
        TMPDIR=$OV_TOMB_TMP
        _get_home() { print -r -- "$OV_TOMB_TMP"; }
        _track_stat() { return 0; }
        _restore_stat() { return 0; }
        _update_control_file() { return 0; }
        touch() {
            [[ -n "$OV_TOMB_ENGINE" && "${@[-1]}" == "$OV_TOMB_ENGINE/.cleanexit" ]] && return 0
            command touch "$@"
        }
        cat() {
            local control_path
            for control_path in "$@"; do
                case "$control_path" in
                    "$OV_TOMB_ENGINE/.last"|"$OV_TOMB_ENGINE/.uid"|"$OV_TOMB_ENGINE/.host"|"$OV_TOMB_ENGINE/.tty")
                        return 1 ;;
                esac
            done
            command cat "$@"
        }
        # Tomb 2.9 reads native metadata through its own mapfile helper.
        # Route only that legacy helper through the same guarded reader.
        if (( $+functions[_cat] )); then
            _cat() { cat "$@"; }
        fi
        if [[ $1 == close || $1 == slam ]]; then
            OPTS[--no-color]=1; OPTS[-n]=1
            if (( $+functions[slam_tomb] )); then
                # Noble ships Tomb 2.9, whose mount lookup accepts labels
                # rather than mapper hashes. Never fall back to a label:
                # two users can own vaults with identical filenames.
                OV_TOMB_LEGACY_SOURCE=$(command findmnt -rn --mountpoint "$OV_TOMB_ENGINE" --output SOURCE) || exit 1
                [[ "$OV_TOMB_LEGACY_SOURCE" == /dev/mapper/tomb.*."$2".* ]] || exit 1
                list_tomb_mounts() {
                    command findmnt -rn --mountpoint "$OV_TOMB_ENGINE" --output SOURCE,TARGET,FSTYPE,OPTIONS,LABEL |
                        awk -v expected="$OV_TOMB_LEGACY_SOURCE" "\$1 == expected { print \$1 \";\" \$2 \";\" \$3 \";(\" \$4 \");[\" \$5 \"]\" }"
                }
                # OctoVault unbinds its verified exposures itself; legacy
                # Tomb discovers binds by label and could touch another vault.
                list_tomb_binds() { return 0; }
                if [[ $1 == slam ]]; then
                    # Legacy slam normally unmounts immediately after killing
                    # holders. Keep the engine mounted until OctoVault removes
                    # its verified bind exposures, then its normal-close retry
                    # invokes the original umount_tomb in a fresh process.
                    umount_tomb() { return 0; }
                    slam_tomb "$2"
                else umount_tomb "$2"; fi
            else
                [[ $1 == slam ]] && SLAM=1
                umount_tomb "$2"
            fi
        else
            main --no-color "$@"
        fi
    ' octovault)
    if [[ -n $password ]]; then
        [[ -x /usr/bin/pinentry-octovault ]] || ov_fail missing_dependency "OctoVault's secure passphrase adapter is missing."
        ov_vault_temporary
        install -d -m 0700 "$OV_VAULT_TEMP_DIR/pinentry"
        # Tomb 2.9 finds pinentry-curses through PATH; newer Tomb also checks
        # its ELF dependencies. Both use our root-only scoped adapter.
        for backend in pinentry pinentry-curses pinentry-tty; do
            ln -sf /usr/bin/pinentry-octovault "$OV_VAULT_TEMP_DIR/pinentry/$backend"
        done
        ov_secret_fd "$password"
        if [[ -n ${OV_VAULT_OLD_PASSWORD:-} ]]; then ov_old_secret_fd "$OV_VAULT_OLD_PASSWORD"; fi
        OV_TOMB_TMP="$OV_VAULT_TEMP_DIR" GNUPGHOME="$OV_VAULT_TEMP_DIR/gnupg" OV_TOMB_ENGINE="${OV_VAULT_ENGINE_MOUNT:-}" PATH="$OV_VAULT_TEMP_DIR/pinentry:/usr/sbin:/usr/bin:/sbin:/bin" DISPLAY='' WAYLAND_DISPLAY='' OV_PINENTRY_RAW=1 SUDO_USER="$OV_USER" SUDO_UID="$OV_UID" SUDO_GID="$(id -g "$OV_USER")" \
            HOME="$OV_HOME" "${command[@]}" "$@" >&2 || rc=$?
        ov_secret_close
        return "$rc"
    fi
    OV_TOMB_TMP="$OV_VAULT_TEMP_DIR" GNUPGHOME="$OV_VAULT_TEMP_DIR/gnupg" OV_TOMB_ENGINE="${OV_VAULT_ENGINE_MOUNT:-}" SUDO_USER="$OV_USER" SUDO_UID="$OV_UID" SUDO_GID="$(id -g "$OV_USER")" HOME="$OV_HOME" \
        "${command[@]}" "$@" >&2
}

ov_vault_password() {
    OV_VAULT_PASSWORD=$(ov_param password '')
    OV_VAULT_OLD_PASSWORD=$(ov_param old_password '')
    [[ $OV_VAULT_PASSWORD != *$'\n'* && $OV_VAULT_PASSWORD != *$'\r'* ]] ||
        ov_fail invalid_password "Passphrases cannot contain newlines."
    [[ $OV_VAULT_OLD_PASSWORD != *$'\n'* && $OV_VAULT_OLD_PASSWORD != *$'\r'* ]] ||
        ov_fail invalid_password "Passphrases cannot contain newlines."
    [[ ! $OV_VAULT_PASSWORD =~ [[:cntrl:]] && ! $OV_VAULT_OLD_PASSWORD =~ [[:cntrl:]] ]] ||
        ov_fail invalid_password "Passphrases cannot contain control characters."
}

ov_vault_auth_args() {
    local record=$1
    OV_VAULT_AUTH_ARGS=(-k "$(ov_vault_field "$record" key_file)")
    [[ $(ov_vault_field "$record" auth) != gpg ]] ||
        OV_VAULT_AUTH_ARGS+=(-g -r "$(ov_vault_field "$record" recipient)")
}

ov_vault_read_token_key() {
    local record=$1 key status actual bytes rc=0
    ov_vault_require_token "$(ov_vault_field "$record" recipient)"
    key=$(ov_vault_field "$record" key_file)
    status="$OV_VAULT_TEMP_DIR/token-decrypt-status"
    # A bounded base64 value stays in shell memory until GnuPG proves which
    # private key decrypted it. No decrypted key is written to disk or argv.
    OV_VAULT_TOKEN_KEY=$(ov_as_user timeout --foreground --signal=TERM --kill-after=5 120 \
        gpg --no-options --batch --no-tty --status-fd 2 --output - --decrypt -- "$key" 2> "$status" |
        head -c 4097 | base64 -w0) || rc=$?
    if ((rc!=0)); then unset OV_VAULT_TOKEN_KEY; ov_vault_auth_failure "$status" "$rc"; fi
    actual=$(awk '$1=="[GNUPG:]" && $2=="DECRYPTION_KEY" {print toupper($3);exit}' "$status")
    rm -f -- "$status"
    if [[ $actual != "$OV_VAULT_TOKEN_FINGERPRINT" ]]; then
        unset OV_VAULT_TOKEN_KEY
        ov_fail token_mismatch "The encrypted vault key does not belong to the connected security key."
    fi
    bytes=$(printf '%s' "$OV_VAULT_TOKEN_KEY" | base64 --decode | wc -c)
    if ((bytes==0 || bytes>4096)); then
        unset OV_VAULT_TOKEN_KEY
        ov_fail invalid_key "The encrypted vault key does not contain a valid amount of key material."
    fi
}

ov_vault_tomb_keyed() {
    local record=$1 action=$2 file=$3
    shift 3
    local auth key rc=0
    auth=$(ov_vault_field "$record" auth)
    key=$(ov_vault_field "$record" key_file)
    [[ $auth == gpg || -n ${OV_VAULT_PASSWORD:-} ]] ||
        ov_fail password_required "Enter this vault's passphrase to continue."
    ov_vault_pin "$record"
    file=$OV_VAULT_CONTAINER_ALIAS
    ov_vault_auth_args "$record"
    if [[ $auth == gpg ]]; then
        # Keep the user's GPG configuration, agent and smartcard interaction
        # outside the privileged process. Tomb's documented stdin key interface
        # avoids ever writing the decrypted key to disk.
        if [[ $(ov_vault_field "$record" require_token) == true ]]; then
            ov_vault_read_token_key "$record"
            printf '%s' "$OV_VAULT_TOKEN_KEY" | base64 --decode |
                ov_vault_tomb --unsafe "$action" "$file" -k cleartext "$@" || rc=$?
            unset OV_VAULT_TOKEN_KEY
        else
            ov_as_user gpg --no-options --decrypt -- "$key" |
                ov_vault_tomb --unsafe "$action" "$file" -k cleartext "$@" || rc=$?
        fi
    else
        ov_vault_plain_key "$record"
        ov_vault_tomb "$action" "$file" -k "$OV_VAULT_MATERIALIZED_KEY" "$@" || rc=$?
        rm -f -- "$OV_VAULT_MATERIALIZED_KEY"
    fi
    return "$rc"
}

ov_vault_hooks() {
    local record=$1 event=$2 mountpoint hook mapper device
    mountpoint=$(ov_vault_field "$record" mountpoint)
    mapper=$(findmnt -rn --mountpoint "$mountpoint" --output SOURCE 2>/dev/null || true)
    mapper=${mapper%%\[*}
    device=$(cryptsetup status "$mapper" 2>/dev/null | awk '$1=="device:" {print $2}' || true)
    if [[ $event != after_close && $(ov_vault_field "$record" trust_native_hooks) == true && -x $mountpoint/exec-hooks ]]; then
        ov_as_user timeout --signal=TERM --kill-after=5 60 "$mountpoint/exec-hooks" "$event" "$mountpoint" \
            "$(basename -- "$(ov_vault_field "$record" file)" .tomb)" "$device" "$mapper" >&2 ||
            return 1
    fi
    hook=$(jq -r --arg event "$event" '.hooks[$event] // empty' <<< "$record")
    if [[ -n $hook ]]; then
        ov_as_user timeout --signal=TERM --kill-after=5 60 "$hook" "$event" "$mountpoint" >&2 || return 1
    fi
}

# Native Tomb supports escaped spaces, not shell expansion or evaluation.
ov_vault_read_binds() {
    local hook=$1 line token char i
    local -a fields
    [[ -f $hook && ! -L $hook ]] || return 0
    while IFS= read -r line || [[ -n $line ]]; do
        [[ -n $line && $line != \#* ]] || continue
        fields=(); token=''
        for ((i=0;i<${#line};i++)); do
            char=${line:i:1}
            if [[ $char == \\ && ${line:i+1:1} == ' ' ]]; then
                token+=' '; ((i+=1)); continue
            elif [[ $char == ' ' || $char == $'\t' ]]; then
                [[ -z $token ]] || { fields+=("$token"); token=''; }
            else token+=$char
            fi
        done
        [[ -z $token ]] || fields+=("$token")
        [[ ${#fields[@]} == 2 ]] || return 1
        printf '%s\0%s\0' "${fields[0]}" "${fields[1]}"
    done < "$hook"
}

# Unlinking the private parsed file on error is safe: its read FD is already open.
# shellcheck disable=SC2094
ov_vault_bind_hooks() {
    local record=$1 mountpoint hook src dst src_path dst_path src_fd dst_fd
    mountpoint=$(ov_vault_field "$record" mountpoint)
    ov_vault_mount_safe "$mountpoint" || return 1
    hook="$mountpoint/bind-hooks"
    [[ -f $hook ]] || return 0
    local parsed
    parsed=$(mktemp "$OV_ROOT/.binds.XXXXXXXX") || return 1
    if ! ov_vault_read_binds "$hook" > "$parsed"; then rm -f "$parsed"; return 1; fi
    while IFS= read -r -d '' src && IFS= read -r -d '' dst; do
        ov_vault_relative "$src" >/dev/null
        ov_vault_relative "$dst" >/dev/null
        src_path=$(realpath -e -- "$mountpoint/$src") || { rm -f "$parsed"; return 1; }
        dst_path=$(realpath -e -- "$OV_HOME/$dst") || { rm -f "$parsed"; return 1; }
        [[ $src_path == "$mountpoint/"* && $dst_path == "$OV_HOME/"* ]] || { rm -f "$parsed"; return 1; }
        [[ ! -L $mountpoint/$src && ! -L $OV_HOME/$dst ]] || { rm -f "$parsed"; return 1; }
        if ! ov_as_user test -r "$src_path" || ! ov_as_user test -w "$dst_path"; then rm -f "$parsed"; return 1; fi
        # Pin both inodes before the privileged mount, preventing a pathname
        # swap from redirecting a bind operation outside the validated trees.
        exec {src_fd}< "$src_path" || { rm -f "$parsed"; return 1; }
        exec {dst_fd}< "$dst_path" || { exec {src_fd}<&-; rm -f "$parsed"; return 1; }
        if [[ $(readlink -f "/proc/self/fd/$src_fd") != "$src_path" ||
              $(readlink -f "/proc/self/fd/$dst_fd") != "$dst_path" ]]; then
            exec {src_fd}<&-; exec {dst_fd}<&-; rm -f "$parsed"; return 1
        fi
        mount --no-canonicalize --bind "/proc/self/fd/$src_fd" "/proc/self/fd/$dst_fd" >&2 || {
            exec {src_fd}<&-; exec {dst_fd}<&-; rm -f "$parsed"; return 1;
        }
        exec {src_fd}<&-; exec {dst_fd}<&-
        ov_vault_mount_safe "$dst_path" || { rm -f "$parsed"; return 1; }
    done < "$parsed"
    rm -f -- "$parsed"
}

ov_vault_open_record() {
    local record=$1 id mountpoint engine
    id=$(ov_vault_field "$record" id)
    mountpoint=$(ov_vault_field "$record" mountpoint)
    if ov_vault_is_open "$record"; then
        if ! ov_vault_mount_safe "$(ov_vault_active_mount "$record")" || ! ov_vault_mount_safe "$mountpoint"; then
            ov_fail unsafe_mount "This vault was opened without required filesystem protections. Close it and reopen it before use."
        fi
        return 0
    fi
    ov_vault_require_closed "$record"
    [[ -d $mountpoint && ! -L $mountpoint ]] || ov_fail invalid_mount "The registered mountpoint is missing."
    findmnt -rn --mountpoint "$mountpoint" >/dev/null 2>&1 && ov_fail occupied "The vault mountpoint is already in use."
    [[ -z $(find "$mountpoint" -mindepth 1 -maxdepth 1 -print -quit) ]] ||
        ov_fail occupied "The vault mountpoint must be empty."
    engine=$(ov_vault_engine_mount "$record")
    OV_VAULT_ENGINE_MOUNT=$engine
    install -d -m 0700 /run/octovault/mounts "/run/octovault/mounts/$OV_UID" "$engine"
    ov_progress unlock "Unlocking the vault" 20
    ov_vault_tomb_keyed "$record" open "$(ov_vault_field "$record" file)" "$engine" -n -p -o rw,noatime,nodev,nosuid ||
        ov_fail unlock_failed "The vault could not be unlocked. Check the key and passphrase."
    ov_vault_is_open "$record" || ov_fail verification_failed "The unlocked device could not be verified."
    if ! ov_vault_mount_safe "$engine"; then
        ov_vault_tomb close "$(ov_vault_selector "$record")" || true
        ov_fail unsafe_mount "Required filesystem protections could not be verified. The vault has not been exposed."
    fi
    if [[ $(ov_vault_field "$record" created_by_octovault) == true && -z $(ov_vault_field "$record" last_opened_at) ]]; then
        # Newly formatted ext4 starts root-owned. Preserve all content ownership
        # and initialize only this new filesystem's top-level directory.
        chown --no-dereference "$OV_UID:$(id -g "$OV_USER")" -- "$engine" || ov_fail permission_denied "Could not initialize the vault directory owner."
    fi
    if ! ov_vault_expose "$record"; then
        ov_vault_unbind "$record" || true
        ov_vault_tomb close "$(ov_vault_selector "$record")" || true
        ov_fail mapping_failed "The user mountpoint changed or could not be safely exposed."
    fi
    if ! ov_vault_bind_hooks "$record"; then
        ov_vault_unbind "$record" || true
        ov_vault_tomb close "$(ov_vault_selector "$record")" -n || true
        ov_fail mapping_failed "A native folder mapping failed. The vault may need attention."
    fi
    ov_vault_hooks "$record" open || ov_fail hook_failed "The vault is open, but its user hook failed."
    record=$(jq --arg time "$(ov_now)" --arg user "$OV_USER" '.last_opened_at=$time | .last_opened_by=$user | .updated_at=$time' <<< "$record")
    ov_save vaults "$id" "$record"
    OV_RECORD=$record
    if [[ ${OV_EVENT_RUNNING:-0} != 1 ]] && declare -F ov_event_vault_transition >/dev/null; then
        ov_event_vault_transition vault-open "$id" >&2 || true
    fi
}

ov_vault_close_record() {
    local record=$1 force=${2:-false} id name
    if [[ ${OV_EXECUTION_SCOPE:-system} == personal && $force == true ]]; then
        ov_fail admin_required 'Force locking can terminate other processes. Unlock administrator access, or close applications and use normal locking.'
    fi
    id=$(ov_vault_field "$record" id)
    OV_VAULT_ENGINE_MOUNT=$(ov_vault_active_mount "$record")
    if ! ov_vault_is_open "$record"; then
        ov_vault_require_closed "$record"
        return 0
    fi
    ov_vault_hooks "$record" close || ov_fail hook_failed "The close hook failed; the vault remains open."
    name=$(ov_vault_selector "$record") || ov_fail verification_failed "The mounted vault's unique identity could not be established."
    ov_progress lock "Closing the vault" 30
    if [[ $force == true ]]; then
        # Let Tomb terminate holders; a second close below also handles Tomb
        # versions whose raw findmnt parser cannot unmount paths with spaces.
        ov_vault_tomb slam "$name" -n || true
    fi
    if ov_vault_is_open "$record"; then
        ov_vault_unbind "$record" || ov_fail busy "An application is still using a mapped location."
    fi
    if ov_vault_is_open "$record"; then
        ov_vault_tomb close "$name" -n || ov_fail busy "The vault could not close. Close applications using it, or explicitly request force close."
    fi
    ov_vault_require_closed "$record"
    ov_vault_unpin "$record" || ov_fail cleanup_failed "The vault is closed, but its temporary container reference could not be detached."
    rmdir -- "$(ov_vault_engine_mount "$record")" 2>/dev/null || true
    record=$(jq --arg time "$(ov_now)" '.last_closed_at=$time | .updated_at=$time' <<< "$record")
    ov_save vaults "$id" "$record"
    OV_RECORD=$record
    ov_vault_hooks "$record" after_close || ov_fail hook_failed "The vault is closed, but the after-lock script failed."
    if [[ ${OV_EVENT_RUNNING:-0} != 1 ]] && declare -F ov_event_vault_transition >/dev/null; then
        ov_event_vault_transition vault-close "$id" >&2 || true
    fi
}

ov_vault_new_record() {
    local id=$1 file key mountpoint auth name
    name=$(ov_require name)
    file=$(ov_vault_user_path "$(ov_require file)")
    key=$(ov_vault_user_path "${2:-$(ov_require key_file)}")
    auth=$(ov_param auth key)
    mountpoint=$(ov_param mountpoint "$OV_HOME/.local/share/octovault/mounts/$id")
    ov_vault_clean_path "$mountpoint" >/dev/null
    [[ $mountpoint != *' '* && $mountpoint != *';'* && $mountpoint != *'['* && $mountpoint != *']'* ]] ||
        ov_fail invalid_mount "Choose a mountpoint without spaces, semicolons or brackets; mapped user locations may contain spaces."
    [[ $file != "$key" && $file != "$mountpoint" && $key != "$mountpoint" ]] || ov_fail invalid_path "Container, key and mountpoint must be separate paths."
    OV_RECORD=$(jq --arg id "$id" --arg name "$name" --arg file "$file" --arg key "$key" --arg mount "$mountpoint" \
        --arg auth "$auth" --arg time "$(ov_now)" --arg scope "${OV_EXECUTION_SCOPE:-system}" \
        '. as $p | {schema_version:1,id:$id,name:$name,file:$file,key_file:$key,mountpoint:$mount,auth:$auth,execution_scope:$scope,
        recipient:($p.recipient//""),require_token:($p.require_token//false),cipher_file:(if ($p.cipher_file//"")=="" then "/usr/share/octovault/cloak-ciphers/words" else $p.cipher_file end),size_gb:($p.size_gb//null),
        open_on:($p.open_on//"login"),prompt_after_unlock:($p.prompt_after_unlock//false),prompt_after_resume:($p.prompt_after_resume//false),drive_uuid:($p.drive_uuid//""),close_on:($p.close_on//["shutdown"]),
        force_close:($p.force_close//false),trust_native_hooks:($p.trust_native_hooks//false),hooks:($p.hooks//{}),created_at:$time,updated_at:$time}' <<< "$OV_PARAMS")
    ov_vault_validate_record "$OV_RECORD"
    ov_as_user install -d -m 0700 -- "$mountpoint" || ov_fail permission_denied "Could not create the vault mountpoint."
    mountpoint=$(ov_vault_user_path "$mountpoint")
    [[ -d $mountpoint && $(stat -c %u -- "$mountpoint") == "$OV_UID" ]] || ov_fail invalid_mount "The mountpoint must be a directory owned by your account."
    [[ $file != "$mountpoint" && $key != "$mountpoint" ]] || ov_fail invalid_path "Container, key and mountpoint must be separate paths."
    OV_RECORD=$(jq --arg mount "$mountpoint" '.mountpoint=$mount' <<< "$OV_RECORD")
}

ov_vault_create() {
    local id record file key auth size tempkey rootkey reuse image_source managed=false key_directory='' image_kind=''
    local locking_record recovery_record cipher require_token
    id=$(ov_new_id)
    file=$(ov_require file); key=$(ov_param key_file); auth=$(ov_param auth key)
    reuse=$(ov_param use_existing_key false); image_source=$(ov_param image_source)
    jq -e '(.use_existing_key//false)|type=="boolean"' <<< "$OV_PARAMS" >/dev/null ||
        ov_fail invalid_auth "The existing-key option must be true or false."
    [[ $auth == key || $auth == gpg || $auth == image || $auth == text ]] || ov_fail invalid_auth "Choose a supported protection method."
    size=$(ov_vault_mib "$(ov_require size_gb)")
    [[ ! -e $file && ! -L $file ]] || ov_fail exists "A file already exists at the selected container path."
    ov_vault_password
    [[ $auth == gpg || -n $OV_VAULT_PASSWORD ]] || ov_fail password_required "Enter the passphrase that protects this vault's key."
    if [[ $reuse == true ]]; then
        [[ -n $key ]] || ov_fail invalid_auth "Choose your existing encrypted key or carrier."
        key=$(ov_vault_user_path "$key")
        [[ -f $key ]] || ov_fail invalid_auth "The existing key or carrier must be a readable regular file."
    else
        [[ $auth != gpg || -n $(ov_param recipient) ]] || ov_fail invalid_auth "Choose the OpenPGP public key that will protect this vault."
        if [[ $auth == image ]]; then
            # Compatibility with the initial CLI: its key_file named the cover
            # image. Keep accepting that input, but always preserve the cover.
            if [[ -z $image_source && -n $key && -f $key ]]; then image_source=$key; key=''; fi
            [[ -n $image_source ]] || ov_fail invalid_image "Choose a JPEG or BMP cover image for the new key carrier."
            image_source=$(ov_vault_user_path "$image_source")
            [[ -f $image_source ]] || ov_fail invalid_image "The cover image must be a readable regular file."
            image_kind=$(ov_as_user od -An -tx1 -N2 -- "$image_source" | tr -d ' \n')
            [[ $image_kind == ffd8 || $image_kind == 424d ]] || ov_fail invalid_image "Choose a JPEG or BMP image; other image formats are not supported."
        fi
        if [[ -n $key ]]; then
            key=$(ov_vault_user_path "$key")
            [[ ! -e $key && ! -L $key ]] || ov_fail exists "The key destination already exists. Select the existing-key option to reuse a key."
        fi
    fi
    if [[ $auth == text ]]; then
        if [[ ! -x /usr/libexec/octovault/text-carrier ]]; then
            ov_fail missing_dependency "OctoVault's text-carrier helper is missing. Reinstall OctoVault."
        fi
        cipher=$(ov_param cipher_file)
        ov_as_user test -r "${cipher:-/usr/share/octovault/cloak-ciphers/words}" || ov_fail not_found "The cloak cipher file is unavailable."
    fi
    require_token=$(ov_param require_token false)
    jq -e '(.require_token//false)|type=="boolean"' <<< "$OV_PARAMS" >/dev/null ||
        ov_fail invalid_auth "The security-key requirement must be true or false."
    [[ $require_token != true || $auth == gpg ]] || ov_fail invalid_auth "Security-key authentication requires OpenPGP protection."
    if [[ $auth == gpg ]]; then
        unset OV_VAULT_AUTH_RECIPIENT
        if [[ $reuse == true ]]; then
            ov_vault_auth_preflight "$(ov_param recipient)" "$require_token" "$key"
        else
            ov_vault_auth_preflight "$(ov_param recipient)" "$require_token"
        fi
        OV_PARAMS=$(jq --arg recipient "${OV_VAULT_AUTH_RECIPIENT:-$(ov_param recipient)}" --argjson token "$require_token" \
            '.recipient=$recipient | .require_token=$token' <<< "$OV_PARAMS")
    fi
    if [[ -z $key ]]; then
        key_directory=$(ov_vault_managed_key_directory "$id"); managed=true
        case $auth in
            image) if [[ $image_kind == 424d ]]; then key="$key_directory/carrier.bmp"; else key="$key_directory/carrier.jpg"; fi ;;
            text) key="$key_directory/vault.txt" ;;
            *) key="$key_directory/vault.key" ;;
        esac
    fi
    ov_vault_new_record "$id" "$key"
    record=$(jq --argjson managed "$managed" --argjson reused "$reuse" \
        '.created_by_octovault=true | .key_managed=$managed | .key_reused=$reused | .creation_state="ready"' <<< "$OV_RECORD")
    tempkey=$key
    if [[ $reuse != true && ( $auth == image || $auth == text ) ]]; then
        [[ -n $key_directory ]] || key_directory=$(ov_vault_managed_key_directory "$id")
        tempkey="$key_directory/recovery.key"
    fi

    ov_progress create "Allocating the encrypted container" 5
    ov_failure_retain "$file"
    ov_as_user tomb --no-color dig -s "$size" "$file" >&2 || ov_fail create_failed "The vault container could not be allocated."
    ov_progress key "Preparing the protected encryption key" 40
    if [[ $reuse == true ]]; then
        locking_record=$record
    elif [[ $auth == gpg ]]; then
        ov_failure_retain "$tempkey"
        ov_as_user tomb --no-color forge -g -r "$(ov_vault_field "$record" recipient)" -k "$tempkey" >&2 ||
            ov_fail key_failed "The OpenPGP-protected key could not be created. The uninitialized container was retained."
        ov_as_user chmod 0600 -- "$tempkey" || ov_fail permission_denied "Could not secure the encrypted key."
    else
        ov_vault_temporary; rootkey="$OV_VAULT_TEMP_DIR/created-$id.key"
        ov_vault_tomb forge -k "$rootkey" || ov_fail key_failed "Key generation failed. The uninitialized container was retained."
        ov_failure_retain "$tempkey"
        ov_vault_publish "$rootkey" "$tempkey" || ov_fail key_failed "The encrypted recovery key could not be saved."
    fi
    if [[ $reuse != true ]]; then
        locking_record=$(jq --arg key "$tempkey" '.key_file=$key | if .auth=="image" or .auth=="text" then .auth="key" else . end' <<< "$record")
    fi
    # Once a persistent encrypted key exists, remember it even if initialization
    # is interrupted. Incomplete records never trigger an automatic unlock.
    recovery_record=$(jq '.creation_state="initializing" | .open_on="manual"' <<< "$locking_record")
    if [[ $tempkey != "$key" ]]; then recovery_record=$(jq '.key_managed=true' <<< "$recovery_record"); fi
    ov_failure_retain "$tempkey"
    ov_failure_retain "$OV_ROOT/vaults/$id.json"
    ov_save vaults "$id" "$recovery_record"
    ov_progress initialize "Initializing the vault filesystem" 65
    ov_vault_tomb_keyed "$locking_record" lock "$file" || ov_fail initialize_failed "The vault could not be initialized; its container, encrypted key and recovery record were retained."
    ov_vault_unpin "$record" || ov_fail cleanup_failed "The new vault was initialized but its temporary container reference remains attached."
    recovery_record=$(jq '.creation_state="ready"' <<< "$recovery_record")
    ov_save vaults "$id" "$recovery_record"
    if [[ $reuse != true && $auth == image ]]; then
        ov_vault_image_embed "$rootkey" "$image_source" "$OV_VAULT_TEMP_DIR/export.jpg" ||
            ov_fail key_failed "Image key export failed. The vault was saved with its ordinary encrypted recovery key; it can still be opened with your passphrase."
        ov_vault_publish "$OV_VAULT_TEMP_DIR/export.jpg" "$key" ||
            ov_fail key_failed "The image carrier could not be saved. The vault still uses its retained encrypted recovery key."
    elif [[ $reuse != true && $auth == text ]]; then
        ov_vault_text_embed "$rootkey" "$(ov_vault_field "$record" cipher_file)" "$OV_VAULT_TEMP_DIR/export.txt" ||
            ov_fail key_failed "Text key export failed. The vault was saved with its ordinary encrypted recovery key; it can still be opened with your passphrase."
        ov_vault_publish "$OV_VAULT_TEMP_DIR/export.txt" "$key" ||
            ov_fail key_failed "The text carrier could not be saved. The vault still uses its retained encrypted recovery key."
    fi
    ov_save vaults "$id" "$record"
    if [[ $tempkey != "$key" ]]; then ov_as_user rm -f -- "$tempkey"; fi
    ov_progress complete "Vault created" 100
    ov_ok "$(ov_vault_status "$record")"
}

ov_vault_import() {
    local id record file key existing
    id=$(ov_new_id); ov_vault_new_record "$id"; record=$OV_RECORD
    file=$(ov_vault_field "$record" file); key=$(ov_vault_field "$record" key_file)
    [[ -f $file && -f $key ]] || ov_fail invalid_path "The existing container and key must both be regular files."
    if [[ $(ov_vault_field "$record" require_token) == true ]]; then
        ov_vault_auth_preflight "$(ov_vault_field "$record" recipient)" true "$key"
        record=$(jq --arg recipient "$OV_VAULT_AUTH_RECIPIENT" '.recipient=$recipient' <<< "$record")
    fi
    ov_as_user test -w "$file" || ov_fail permission_denied "Your account must own or be able to write the container."
    ov_vault_pin "$record"
    cryptsetup isLuks "$OV_VAULT_CONTAINER_ALIAS" || ov_fail invalid_container "This file does not contain a LUKS encrypted container."
    ov_vault_unpin "$record" || ov_fail cleanup_failed "The temporary container reference could not be detached."
    existing=$(ov_list vaults | jq -r --arg file "$file" '.[]|select(.file==$file)|.id')
    [[ -z $existing ]] || ov_fail exists "This container is already registered."
    ov_save vaults "$id" "$record"
    ov_ok "$(ov_vault_status "$record")"
}

ov_vault_update() {
    local id record
    id=$(ov_require id); ov_load vaults "$id"; record=$OV_RECORD
    jq -e 'has("file") or has("mountpoint")' <<< "$OV_PARAMS" >/dev/null &&
        ov_fail immutable "Container and mountpoint paths cannot be changed on a registered vault."
    record=$(jq --argjson record "$record" --arg time "$(ov_now)" '
        . as $p | $record + ($p | with_entries(select(.key|IN("name","key_file","auth","recipient","require_token","cipher_file","open_on","prompt_after_unlock","prompt_after_resume","fido2","drive_uuid","close_on","force_close","hooks","trust_native_hooks")))) | .updated_at=$time' <<< "$OV_PARAMS")
    if [[ $(ov_vault_field "$record" key_file) != "$(ov_vault_field "$OV_RECORD" key_file)" ||
          $(ov_vault_field "$record" auth) != "$(ov_vault_field "$OV_RECORD" auth)" ]]; then
        record=$(jq 'del(.fido2)' <<< "$record")
    fi
    ov_vault_validate_record "$record"
    ov_vault_user_path "$(ov_vault_field "$record" key_file)" >/dev/null
    if jq -e 'has("fido2") and .fido2 != null' <<< "$OV_PARAMS" >/dev/null; then
        ov_vault_verify_recovery_passphrase "$record"
    fi
    if [[ $(ov_vault_field "$record" require_token) == true ]] &&
        jq -e 'has("key_file") or has("auth") or has("recipient") or has("require_token")' <<< "$OV_PARAMS" >/dev/null; then
        ov_vault_auth_preflight "$(ov_vault_field "$record" recipient)" true "$(ov_vault_field "$record" key_file)"
        record=$(jq --arg recipient "$OV_VAULT_AUTH_RECIPIENT" '.recipient=$recipient' <<< "$record")
    fi
    ov_save vaults "$id" "$record"
    ov_ok "$(ov_vault_status "$record")"
}

ov_vault_change_password() {
    local record=$1 auth key new_password recipient token_key rc=0
    auth=$(ov_vault_field "$record" auth); key=$(ov_vault_field "$record" key_file)
    ov_vault_password; ov_vault_temporary
    if [[ $auth == gpg ]]; then
        recipient=$(ov_param recipient "$(ov_vault_field "$record" recipient)")
        [[ -n $recipient ]] || ov_fail invalid_auth "Choose the replacement OpenPGP recipient."
        if [[ $(ov_vault_field "$record" require_token) == true ]]; then
            ov_vault_read_token_key "$record"
            token_key=$OV_VAULT_TOKEN_KEY; unset OV_VAULT_TOKEN_KEY
            ov_vault_auth_preflight "$recipient" true
            recipient=$OV_VAULT_AUTH_RECIPIENT
            printf '%s' "$token_key" | base64 --decode |
                ov_as_user gpg --no-options --batch --armor --encrypt --recipient "$recipient" > "$OV_VAULT_TEMP_DIR/rewrapped.key" || rc=$?
            unset token_key
            ((rc==0)) || ov_fail key_failed "The key could not be re-encrypted for the selected security key."
        else
            ov_as_user gpg --no-options --decrypt -- "$key" |
                ov_as_user gpg --no-options --batch --armor --encrypt --recipient "$recipient" > "$OV_VAULT_TEMP_DIR/rewrapped.key" ||
                ov_fail key_failed "The key could not be re-encrypted for the selected recipient."
        fi
        ov_vault_publish "$OV_VAULT_TEMP_DIR/rewrapped.key" "$key" true || ov_fail key_failed "Could not save the replacement encrypted key."
        record=$(jq --arg recipient "$recipient" '.recipient=$recipient' <<< "$record")
        ov_save vaults "$(ov_vault_field "$record" id)" "$record"
        ov_ok '{"changed":true,"type":"gpg-recipient"}'; return
    fi
    [[ -n $OV_VAULT_PASSWORD && -n $OV_VAULT_OLD_PASSWORD ]] || ov_fail password_required "Provide the current and new passphrases."
    new_password=$OV_VAULT_PASSWORD; OV_VAULT_PASSWORD=$OV_VAULT_OLD_PASSWORD
    ov_vault_plain_key "$record"
    OV_VAULT_PASSWORD=$new_password
    OV_OLD_KEY_PATH=$OV_VAULT_MATERIALIZED_KEY; export OV_OLD_KEY_PATH
    ov_vault_tomb passwd -k "$OV_VAULT_MATERIALIZED_KEY" || ov_fail password_failed "The passphrase could not be updated; the original key is unchanged."
    case $auth in
        image)
            ov_vault_image_embed "$OV_VAULT_MATERIALIZED_KEY" "$key" "$OV_VAULT_TEMP_DIR/rewrapped.jpg" || ov_fail key_failed "Could not update the image; the original remains unchanged."
            ov_vault_publish "$OV_VAULT_TEMP_DIR/rewrapped.jpg" "$key" true || ov_fail key_failed "Could not save the replacement image."
            ;;
        text)
            ov_vault_text_embed "$OV_VAULT_MATERIALIZED_KEY" "$(ov_vault_field "$record" cipher_file)" "$OV_VAULT_TEMP_DIR/rewrapped.txt" ||
                ov_fail key_failed "Could not update the text carrier; the original remains unchanged."
            ov_vault_publish "$OV_VAULT_TEMP_DIR/rewrapped.txt" "$key" true || ov_fail key_failed "Could not save the replacement text."
            ;;
        *) ov_vault_publish "$OV_VAULT_MATERIALIZED_KEY" "$key" true || ov_fail key_failed "Could not save the replacement encrypted key." ;;
    esac
    record=$(jq 'del(.fido2)' <<< "$record")
    ov_save vaults "$(ov_vault_field "$record" id)" "$record"
    ov_ok '{"changed":true}'
}

ov_vault_replace_key() {
    local record=$1 new_key auth key new_password rc=0
    ov_vault_require_closed "$record"
    new_key=$(ov_vault_user_path "$(ov_require new_key_file)")
    [[ -f $new_key ]] || ov_fail not_found "The replacement key file was not found."
    ov_vault_password
    [[ -n $OV_VAULT_PASSWORD ]] || ov_fail password_required "Provide the replacement key passphrase."
    auth=$(ov_vault_field "$record" auth); key=$(ov_vault_field "$record" key_file)
    ov_vault_pin "$record"
    ov_vault_temporary
    local new_material="$OV_VAULT_TEMP_DIR/replacement.key"
    ov_as_user cat -- "$new_key" > "$new_material" || ov_fail key_failed "The replacement key cannot be read."
    if [[ $auth == gpg ]]; then
        if [[ $(ov_vault_field "$record" require_token) == true ]]; then
            ov_vault_read_token_key "$record"
            printf '%s' "$OV_VAULT_TOKEN_KEY" | base64 --decode |
                ov_vault_tomb --unsafe setkey cleartext "$OV_VAULT_CONTAINER_ALIAS" -k "$new_material" || rc=$?
            unset OV_VAULT_TOKEN_KEY
        else
            ov_as_user gpg --no-options --decrypt -- "$key" |
                ov_vault_tomb --unsafe setkey cleartext "$OV_VAULT_CONTAINER_ALIAS" -k "$new_material" || rc=$?
        fi
    else
        [[ -n $OV_VAULT_OLD_PASSWORD ]] || ov_fail password_required "Provide the current key passphrase."
        new_password=$OV_VAULT_PASSWORD; OV_VAULT_PASSWORD=$OV_VAULT_OLD_PASSWORD
        ov_vault_plain_key "$record"; OV_VAULT_PASSWORD=$new_password
        OV_OLD_KEY_PATH=$OV_VAULT_MATERIALIZED_KEY; export OV_OLD_KEY_PATH
        ov_vault_tomb setkey "$OV_VAULT_MATERIALIZED_KEY" "$OV_VAULT_CONTAINER_ALIAS" -k "$new_material" || rc=$?
    fi
    ((rc==0)) || ov_fail key_failed "The key could not be replaced. The saved configuration has not changed."
    ov_vault_unpin "$record" || ov_fail cleanup_failed "The key changed but its temporary container reference remains attached."
    record=$(jq --arg key "$new_key" --arg time "$(ov_now)" 'del(.fido2) | .key_file=$key | .auth="key" | .require_token=false | .recipient="" | .cipher_file="" | .updated_at=$time' <<< "$record")
    ov_save vaults "$(ov_vault_field "$record" id)" "$record"
    ov_ok "$record"
}

ov_vault_export_key() {
    local record=$1 output format cipher key generated
    output=$(ov_vault_user_path "$(ov_require output)"); format=$(ov_param format key)
    [[ ! -e $output || $format == image ]] || ov_fail exists "The export destination already exists."
    ov_vault_password
    ov_vault_plain_key "$record"; key=$OV_VAULT_MATERIALIZED_KEY
    case $format in
        key) ov_vault_publish "$key" "$output" || ov_fail export_failed "Could not export the encrypted key." ;;
        image)
            [[ -f $output && -n $OV_VAULT_PASSWORD ]] || ov_fail invalid_image "An existing JPEG carrier and its passphrase are required."
            ov_vault_image_embed "$key" "$output" "$OV_VAULT_TEMP_DIR/export.jpg" || ov_fail export_failed "Could not hide the key in the image."
            ov_vault_publish "$OV_VAULT_TEMP_DIR/export.jpg" "$output" true || ov_fail export_failed "Could not save the carrier image."
            ;;
        text)
            cipher=$(ov_param cipher_file '')
            [[ -n $cipher ]] || cipher=$(ov_vault_field "$record" cipher_file)
            [[ -n $cipher ]] || cipher=/usr/share/octovault/cloak-ciphers/words
            cipher=$(ov_vault_user_path "$cipher")
            ov_vault_text_embed "$key" "$cipher" "$OV_VAULT_TEMP_DIR/export.txt" || ov_fail export_failed "Could not cloak the key; check the installed encryption extras."
            ov_vault_publish "$OV_VAULT_TEMP_DIR/export.txt" "$output" || ov_fail export_failed "Could not save the cloaked key."
            ;;
        qr)
            (cd "$OV_VAULT_TEMP_DIR" && tomb --no-color engrave -k "$key") >&2 || ov_fail export_failed "Could not generate the QR code; check qrencode is installed."
            generated="$OV_VAULT_TEMP_DIR/$(basename -- "$key").qr.png"
            ov_vault_publish "$generated" "$output" || ov_fail export_failed "Could not save the QR image."
            ;;
        *) ov_fail invalid_format "Choose key, image, text or qr." ;;
    esac
    ov_ok "$(jq -n --arg output "$output" '{output:$output}')"
}

ov_vault_index_or_search() {
    local record=$1 action=$2 query=${3:-} mountpoint mapper inventory
    ov_vault_is_exposed "$record" || ov_fail locked "Open the vault before indexing or searching."
    mountpoint=$(ov_vault_field "$record" mountpoint)
    mapper=$(findmnt -rn --mountpoint "$mountpoint" --output SOURCE); mapper=${mapper%%\[*}
    inventory="$mapper;$mountpoint;ext4;(rw);[OctoVault]"
    # Tomb's native index/search functions consume a mount inventory. Scope
    # that inventory to this verified vault and its accessible user exposure.
    # All actual indexing and searching still use packaged Tomb's functions.
    # shellcheck disable=SC2016
    ov_as_user /usr/bin/zsh -f -c '
        source /usr/bin/tomb source || exit
        OCTOVAULT_INVENTORY=$1
        list_tomb_mounts() { print -r -- "$OCTOVAULT_INVENTORY"; }
        OPTS[--no-color]=1
        case "$2" in
            index) index_tombs ;;
            search) search_tombs "$3" ;;
            *) exit 2 ;;
        esac
    ' octovault "$inventory" "$action" "$query"
}

# Staging is adjacent to the original so renaming is atomic and works across
# devices. Original placeholders are ordinary independent writable locations.
# No closed-vault monitoring or reconciliation is performed.
ov_migration_dir() { printf '%s/migrations/%s\n' "$OV_ROOT" "$1"; }
ov_migration_save() {
    local id=$1 migration=$2 json=$3 dir tmp
    ov_id "$id"; ov_id "$migration"; dir=$(ov_migration_dir "$id")
    install -d -m 0700 "$dir"
    tmp=$(mktemp "$dir/.record.XXXXXXXX")
    printf '%s\n' "$json" > "$tmp"; chmod 0600 "$tmp"; sync -f "$tmp"
    mv -f -- "$tmp" "$dir/$migration.json"; sync -f "$dir"
}

ov_migration_list() {
    local dir
    dir=$(ov_migration_dir "$1")
    if [[ -d $dir ]]; then
        find "$dir" -maxdepth 1 -type f -name '*.json' -exec cat -- {} + | jq -s '.'
    else printf '[]\n'; fi
}

ov_migration_compare() {
    local original=$1 candidate=$2 diff
    [[ -e $original && -e $candidate && ! -L $original && ! -L $candidate ]] || return 1
    if [[ -d $original && -d $candidate ]]; then
        diff=$(ov_as_user rsync -aHAXnc --delete --itemize-changes -- "$original/" "$candidate/") || return 1
    elif [[ -f $original && -f $candidate ]]; then
        cmp -s -- "$original" "$candidate" || return 1
        diff=$(ov_as_user rsync -aHAXnc --itemize-changes -- "$original" "$candidate") || return 1
    else return 1; fi
    [[ -z $diff ]]
}

ov_vault_mapping_matches() {
    local record=$1 source=$2 relative=$3 mountpoint
    mountpoint=$(ov_vault_field "$record" mountpoint)
    findmnt -rn --mountpoint "$source" >/dev/null || return 1
    [[ $(stat -Lc '%d:%i' -- "$source") == $(stat -Lc '%d:%i' -- "$mountpoint/$relative") ]]
}

ov_migration_stage() {
    local record=$1 migration=$2 stage=$3 id migration_id
    id=$(ov_vault_field "$record" id); migration_id=$(jq -r .migration_id <<< "$migration")
    OV_MIGRATION=$(jq --arg stage "$stage" --arg time "$(ov_now)" '.stage=$stage | .updated_at=$time' <<< "$migration")
    ov_migration_save "$id" "$migration_id" "$OV_MIGRATION"
}

ov_migration_write_bind() {
    local mountpoint=$1 relative=$2 target=$3 line escaped_relative escaped_target temporary
    escaped_relative=${relative// /\\ }; escaped_target=${target// /\\ }
    line="$escaped_relative $escaped_target"
    # Publish a complete file, including a separator when an imported native
    # bind-hooks file has no final newline. Never append a partial record.
    [[ ! -L $mountpoint/bind-hooks ]] || return 1
    temporary=$(ov_as_user mktemp "$mountpoint/.octovault-binds.XXXXXXXX") || return 1
    if ! {
        if [[ -s $mountpoint/bind-hooks ]]; then
            ov_as_user cat -- "$mountpoint/bind-hooks" || return 1
            printf '\n'
        fi
        printf '%s\n' "$line"
    } |
        ov_as_user tee -- "$temporary" >/dev/null; then
        ov_as_user rm -f -- "$temporary"; return 1
    fi
    if ! ov_vault_read_binds "$temporary" >/dev/null || ! sync -f "$temporary" ||
        ! ov_as_user mv -fT -- "$temporary" "$mountpoint/bind-hooks"; then
        ov_as_user rm -f -- "$temporary"; return 1
    fi
}

ov_migration_copy() {
    local original=$1 target=$2
    # Recovery may have just opened the vault, revealing children that were
    # hidden beneath its closed mountpoint. Recheck before any destination write.
    [[ $(realpath -m -- "$target") == "$target" && ! -L $target ]] ||
        ov_fail unsafe_path "The encrypted destination or one of its parent folders is a symbolic link. The original data has been retained."
    ov_progress copy "Copying into the encrypted vault; the original data is retained" 25
    ov_as_user mkdir -p -- "$(dirname -- "$target")" || ov_fail migration_failed "Could not create the destination directory. The original data has been retained."
    if [[ -d $original ]]; then
        ov_as_user mkdir -p -- "$target" || ov_fail migration_failed "Could not create the destination directory. The original data has been retained."
        ov_as_user rsync -aHAX -- "$original/" "$target/" >&2 ||
            ov_fail migration_failed "Copy failed. The original data has been retained; use Folder protection & recovery to retry or restore it."
    else
        ov_as_user rsync -aHAX -- "$original" "$target" >&2 ||
            ov_fail migration_failed "Copy failed. The original data has been retained; use Folder protection & recovery to retry or restore it."
    fi
    ov_progress verify "Checking the encrypted copy against the original" 45
    ov_migration_compare "$original" "$target" ||
        ov_fail verification_failed "The copied data did not match. The original data has been retained; close applications changing these files before retrying."
}

ov_migration_placeholder() {
    local source=$1 staging=$2
    # Legacy interrupted moves may have no original location. New moves create
    # this placeholder immediately after rename, before close/reopen can fail.
    if [[ ! -e $source && ! -L $source ]]; then
        if [[ -d $staging ]]; then
            ov_as_user mkdir -- "$source" || ov_fail migration_failed "Could not create the empty original folder. The staged original is retained; use Folder protection & recovery."
        else
            ov_as_user touch -- "$source" || ov_fail migration_failed "Could not create the empty original file. The staged original is retained; use Folder protection & recovery."
        fi
    fi
    [[ ! -L $source && ( -d $staging && -d $source || -f $staging && -f $source ) ]] ||
        ov_fail recovery_needed "The original location has changed type. The staged original has been retained."
}

ov_migration_finish() {
    local record=$1 migration=$2 stage source staging relative mountpoint target
    stage=$(jq -r .stage <<< "$migration"); source=$(jq -r .source <<< "$migration")
    staging=$(jq -r .staging <<< "$migration"); relative=$(jq -r .relative <<< "$migration")
    mountpoint=$(ov_vault_field "$record" mountpoint); target="$mountpoint/$relative"
    ov_failure_retain "$source"; ov_failure_retain "$staging"; ov_failure_retain "$target"
    [[ $(realpath -m -- "$target") == "$target" && ! -L $target ]] ||
        ov_fail unsafe_path "The encrypted destination or one of its parent folders is a symbolic link. The original data has been retained."
    if [[ $stage == prepared ]]; then
        # Keep the familiar original location throughout the expensive copy.
        # A legacy journal or crash after rename is resumed from staging below.
        if [[ ! -e $staging && ! -L $staging ]]; then
            [[ -e $source && ! -L $source ]] || ov_fail recovery_needed "The original and staged data cannot be found."
            ov_vault_is_open "$record" || ov_vault_open_record "$record"
            ov_migration_copy "$source" "$target"
            ov_progress map "Preparing the original location to show the protected data" 60
            ov_as_user mv -nT -- "$source" "$staging" || ov_fail migration_failed "Could not stage the verified original. It remains at the original location."
            [[ ! -e $source && ! -L $source && -e $staging ]] || ov_fail recovery_needed "The staging location changed. No original data was removed."
            ov_migration_placeholder "$source" "$staging"
            ov_migration_compare "$staging" "$target" ||
                ov_fail verification_failed "The original data changed while it was being moved. The staged original has been retained; close applications using it and resume the interrupted move."
            ov_migration_stage "$record" "$migration" copied; migration=$OV_MIGRATION; stage=copied
        else
            [[ -e $staging && ! -L $staging ]] || ov_fail recovery_needed "The staged original cannot be found safely."
            ov_migration_stage "$record" "$migration" staged; migration=$OV_MIGRATION; stage=staged
        fi
    fi
    if [[ $stage == staged ]]; then
        ov_migration_placeholder "$source" "$staging"
        ov_vault_is_open "$record" || ov_vault_open_record "$record"
        ov_migration_copy "$staging" "$target"
        ov_migration_stage "$record" "$migration" copied; migration=$OV_MIGRATION; stage=copied
    fi
    if [[ $stage == copied ]]; then
        ov_vault_is_open "$record" || ov_vault_open_record "$record"
        # A preexisting or newly written underlying location is never replaced.
        ov_migration_placeholder "$source" "$staging"
        local found=false a b
        ov_vault_read_binds "$mountpoint/bind-hooks" >/dev/null || ov_fail invalid_mapping "The folder mapping file is invalid. The staged original has been retained."
        while IFS= read -r -d '' a && IFS= read -r -d '' b; do
            if [[ $a == "$relative" && $b == "${source#"$OV_HOME/"}" ]]; then found=true; break; fi
        done < <(ov_vault_read_binds "$mountpoint/bind-hooks")
        $found || ov_migration_write_bind "$mountpoint" "$relative" "${source#"$OV_HOME/"}" || ov_fail migration_failed "Could not save the native mapping."
        ov_migration_stage "$record" "$migration" mapped; migration=$OV_MIGRATION; stage=mapped
    fi
    if [[ $stage == mapped ]]; then
        ov_progress check_lock "Testing that the vault locks safely" 70
        ov_vault_close_record "$record" false
        ov_migration_stage "$record" "$migration" closed; migration=$OV_MIGRATION; stage=closed
    fi
    if [[ $stage == closed ]]; then
        ov_progress check_unlock "Unlocking again to test the original location" 80
        ov_vault_open_record "$record"
        ov_migration_stage "$record" "$migration" reopened; migration=$OV_MIGRATION; stage=reopened
    fi
    if [[ $stage == reopened ]]; then
        ov_progress verify_mapping "Verifying the protected data at its original location" 90
        ov_vault_is_open "$record" || ov_vault_open_record "$record"
        ov_vault_mapping_matches "$record" "$source" "$relative" || ov_fail verification_failed "The expected native mapping is not mounted. The staged original is retained."
        ov_migration_compare "$staging" "$source" || ov_fail verification_failed "Reopened content does not match. The staged original is retained."
        ov_migration_stage "$record" "$migration" verified; migration=$OV_MIGRATION; stage=verified
    fi
    if [[ $stage == verified ]]; then
        # Verify again before deletion, including when recovering a crash after
        # the previous verification but before staged-original removal.
        if [[ -e $staging ]]; then
            ov_vault_is_open "$record" || ov_fail recovery_needed "Open the vault before completing migration cleanup."
            ov_vault_mapping_matches "$record" "$source" "$relative" || ov_fail recovery_needed "The verified mapping is no longer mounted; staging is retained."
            ov_migration_compare "$staging" "$source" || ov_fail verification_failed "Content changed since verification; staging is retained."
            ov_as_user rm -rf --one-file-system -- "$staging" || ov_fail cleanup_failed "The verified original could not be removed; it remains recoverable."
        fi
        ov_migration_stage "$record" "$migration" complete
    fi
}

ov_migration_add() {
    local id record source relative staging migration migration_id mountpoint protected mounts
    local OV_EVENT_RUNNING=1 password_loaded=false
    id=$(ov_require id); ov_load vaults "$id"; record=$OV_RECORD
    source=$(ov_vault_user_path "$(ov_require source)"); relative=$(ov_vault_relative "$(ov_require relative)")
    [[ $source == "$OV_HOME/"* && $source != "$OV_HOME/.local/share/octovault"* ]] ||
        ov_fail invalid_source "Native folder mappings must be inside your home directory."
    [[ -f $source || -d $source ]] || ov_fail invalid_source "Choose an existing regular file or directory."
    findmnt -rn --mountpoint "$source" >/dev/null 2>&1 && ov_fail mounted "The selected path is already a mountpoint."
    # Renaming a parent containing an existing bind moves those mounts too.
    # Never stage a whole Documents tree after protecting one of its children.
    mounts=$(findmnt --json --list --output TARGET) || ov_fail state_unknown "Mounted folders could not be checked. Your original location has not been moved."
    if jq -e --arg source "$source/" 'any(.filesystems[]?; .target | startswith($source))' <<< "$mounts" >/dev/null; then
        ov_fail mounted "The selected folder contains a mounted or already protected location. Protect the whole folder before adding its individual files or subfolders. Your original location has not been moved."
    fi
    mountpoint=$(ov_vault_field "$record" mountpoint)
    [[ $source != "$mountpoint" && $source != "$mountpoint/"* && $mountpoint != "$source/"* ]] || ov_fail invalid_source "A vault cannot be migrated into itself."
    for protected in "$(ov_vault_field "$record" file)" "$(ov_vault_field "$record" key_file)" "$(ov_vault_field "$record" cipher_file)" "$OV_HOME/.local/share/octovault" "$OV_ROOT"; do
        [[ -z $protected || ( $protected != "$source" && $protected != "$source/"* ) ]] ||
            ov_fail invalid_source "The selected location contains this vault file, its unlocking key, or OctoVault's settings. Choose a folder that does not contain these files."
    done
    if ! ov_vault_is_open "$record"; then
        ov_vault_password; password_loaded=true
        ov_vault_open_record "$record"; record=$OV_RECORD
        # Opening can expose native mappings beneath the selected folder.
        # Inspect the now-visible mount tree before copying or renaming it.
        findmnt -rn --mountpoint "$source" >/dev/null 2>&1 && ov_fail mounted "The selected path is already a mountpoint."
        mounts=$(findmnt --json --list --output TARGET) || ov_fail state_unknown "Mounted folders could not be checked. Your original location has not been moved."
        if jq -e --arg source "$source/" 'any(.filesystems[]?; .target | startswith($source))' <<< "$mounts" >/dev/null; then
            ov_fail mounted "The selected folder contains a mounted or already protected location. Your original location has not been moved."
        fi
    fi
    [[ ! -e $mountpoint/$relative && ! -L $mountpoint/$relative ]] ||
        ov_fail exists "This destination already exists inside the vault, possibly from an earlier copy. It has been retained. Choose another name in Advanced options, or inspect the existing files before retrying."
    local a b
    ov_vault_relative "${source#"$OV_HOME/"}" >/dev/null
    ov_vault_read_binds "$mountpoint/bind-hooks" >/dev/null || ov_fail invalid_mapping "The existing folder mapping file is invalid. Your original location has not been moved."
    while IFS= read -r -d '' a && IFS= read -r -d '' b; do
        protected=${source#"$OV_HOME/"}
        [[ $b != "$protected" && $b != "$protected/"* && $protected != "$b/"* &&
           $a != "$relative" && $a != "$relative/"* && $relative != "$a/"* ]] ||
            ov_fail exists "This location overlaps an existing protected folder. Protect a whole folder or its individual items, rather than both."
    done < <(ov_vault_read_binds "$mountpoint/bind-hooks")
    ov_vault_is_exposed "$record" || ov_fail mapping_failed "The unlocked vault folder is unavailable. Lock and unlock the vault before protecting files. Your original location has not been moved."
    migration_id=$(ov_new_id); staging="$(dirname -- "$source")/.octovault-staging-$migration_id"
    [[ ! -e $staging && ! -L $staging ]] || ov_fail exists "The migration staging location already exists."
    migration=$(jq -n --arg id "$id" --arg mid "$migration_id" --arg source "$source" --arg relative "$relative" \
        --arg staging "$staging" --arg time "$(ov_now)" '{schema_version:1,vault_id:$id,migration_id:$mid,source:$source,relative:$relative,staging:$staging,stage:"prepared",created_at:$time,updated_at:$time}')
    ov_migration_save "$id" "$migration_id" "$migration"
    $password_loaded || ov_vault_password
    ov_progress migrate "Preparing to copy and verify your files" 10
    ov_migration_finish "$record" "$migration"
    ov_progress complete "Files verified after reopening; staging removed" 100
    ov_ok "$OV_MIGRATION"
}

ov_migration_recover() {
    local id mid action record migration path source staging stage mountpoint relative a b
    id=$(ov_require id); mid=$(ov_require migration_id); action=$(ov_param action resume)
    ov_id "$mid"; ov_load vaults "$id"; record=$OV_RECORD
    path="$(ov_migration_dir "$id")/$mid.json"
    [[ -f $path ]] || ov_fail not_found "The migration recovery record was not found."
    migration=$(cat -- "$path"); stage=$(jq -r .stage <<< "$migration")
    case $action in resume|rollback) ;; *) ov_fail invalid_action "Recovery action must be resume or rollback." ;; esac
    case $stage in
        rolled_back)
            ov_fail migration_cancelled "This protection attempt was cancelled when the original files were restored. Select the folder with Protect a folder or file to protect it again."
            ;;
        complete)
            ov_fail already_protected "This protection attempt has already completed. Refresh the vault to see its current protected folders."
            ;;
    esac
    case $action in
        resume) local OV_EVENT_RUNNING=1; ov_vault_password; ov_migration_finish "$record" "$migration"; ov_ok "$OV_MIGRATION" ;;
        rollback)
            source=$(jq -r .source <<< "$migration"); staging=$(jq -r .staging <<< "$migration")
            [[ $stage == prepared || $stage == staged || $stage == copied ]] ||
                ov_fail recovery_needed "A mapped migration must be resumed; automatic rollback would change underlying locations."
            if [[ $stage == copied ]]; then
                # A crash may have published bind-hooks before saving 'mapped'.
                # Inspect the actual metadata before restoring an original that
                # a later unlock could hide beneath the copied data.
                ov_vault_is_exposed "$record" || ov_fail recovery_needed "Unlock this vault before restoring a copied move, so its folder mappings can be checked. You can also resume the interrupted move."
                mountpoint=$(ov_vault_field "$record" mountpoint); relative=$(jq -r .relative <<< "$migration")
                ov_vault_read_binds "$mountpoint/bind-hooks" >/dev/null || ov_fail invalid_mapping "The folder mapping file is invalid. The staged original has been retained."
                while IFS= read -r -d '' a && IFS= read -r -d '' b; do
                    [[ $a != "$relative" && $b != "${source#"$OV_HOME/"}" ]] ||
                        ov_fail recovery_needed "This move already has a folder mapping. Resume it so the staged original is verified safely."
                done < <(ov_vault_read_binds "$mountpoint/bind-hooks")
            fi
            if [[ $stage == prepared && -e $source && ! -L $source && ! -e $staging && ! -L $staging ]]; then
                # New migrations copy before staging. An interrupted copy has
                # left the original untouched; the encrypted partial copy stays.
                ov_migration_stage "$record" "$migration" rolled_back; ov_ok "$OV_MIGRATION"; return
            fi
            [[ ! -L $staging && ( -d $staging || -f $staging ) ]] ||
                ov_fail conflict "The retained original has changed, so it cannot be restored automatically."
            # rmdir atomically refuses folders containing any new files. This
            # also handles the empty placeholder left by a failed resume.
            if [[ -d $source && ! -L $source && -d $staging ]]; then
                ov_as_user rmdir -- "$source" ||
                    ov_fail conflict "The original folder contains other files or is still mounted. Both locations have been retained."
            fi
            [[ ! -e $source && ! -L $source && ! -L $staging && ( -d $staging || -f $staging ) ]] ||
                ov_fail conflict "The original location is occupied or the staged original has changed, so rollback will not overwrite it."
            ov_as_user mv -nT -- "$staging" "$source" || ov_fail recovery_failed "The original could not be restored."
            [[ ! -e $staging && ! -L $staging ]] || ov_fail conflict "The original location became occupied. The staged original was retained."
            ov_migration_stage "$record" "$migration" rolled_back; ov_ok "$OV_MIGRATION"
            ;;
        *) ov_fail invalid_action "Recovery action must be resume or rollback." ;;
    esac
}

ov_vault_dispatch() {
    local id record items result size
    if [[ $OV_OP == vault.close ]]; then
        jq -e 'has("force") | not' <<< "$OV_PARAMS" >/dev/null ||
            jq -e '.force | type == "boolean"' <<< "$OV_PARAMS" >/dev/null ||
            ov_fail invalid_request 'Force locking must be a true or false choice.'
    fi
    case $OV_OP in
        vault.list|vault.get|vault.auth-check|vault.create|vault.import|migration.list) ;;
        *) ov_load vaults "$(ov_require id)"; ov_scope_require_record "$OV_RECORD" ;;
    esac
    case $OV_OP in
        vault.list|vault.get|vault.auth-check|migration.list|vault.search) ;;
        vault.create) ov_vault_create_path; ov_resource_lock "$(ov_require file)" ;;
        vault.import) ov_resource_lock "$(ov_require file)" ;;
        *)
            id=$(ov_require id); ov_load vaults "$id"
            ov_resource_lock "$(ov_vault_field "$OV_RECORD" file)"
            ;;
    esac
    case $OV_OP in
        vault.list)
            items=$(ov_list vaults); result='[]'
            while IFS= read -r record; do result=$(jq --argjson item "$(ov_vault_status "$record")" '.+[$item]' <<< "$result"); done < <(jq -c '.[]' <<< "$items")
            ov_ok "$result" ;;
        vault.create) ov_vault_create ;;
        vault.auth-check) ov_vault_auth_check ;;
        vault.import) ov_vault_import ;;
        vault.update) ov_vault_update ;;
        migration.add) ov_migration_add ;;
        migration.recover) ov_migration_recover ;;
        *)
            id=$(ov_require id); ov_load vaults "$id"; record=$OV_RECORD
            case $OV_OP in
                vault.get) ov_ok "$(ov_vault_status "$record")" ;;
                vault.open) ov_vault_password; ov_vault_open_record "$record"; ov_ok "$(ov_vault_status "$OV_RECORD")" ;;
                vault.close) ov_vault_close_record "$record" "$(ov_param force false)"; ov_ok "$(ov_vault_status "$OV_RECORD")" ;;
                vault.remove)
                    ov_vault_require_closed "$record"
                    [[ $(ov_migration_list "$id" | jq '[.[]|select(.stage!="complete" and .stage!="rolled_back")]|length') == 0 ]] || ov_fail recovery_needed "Complete or recover pending migrations first."
                    rm -f -- "$OV_ROOT/vaults/$id.json"; ov_ok '{"removed":true,"files_preserved":true}' ;;
                vault.resize)
                    ov_vault_require_closed "$record"
                    size=$(ov_vault_mib "$(ov_require size_gb)"); ov_vault_password
                    ov_vault_tomb_keyed "$record" resize "$(ov_vault_field "$record" file)" -s "$size" || ov_fail resize_failed "The vault could not be resized."
                    ov_vault_unpin "$record" || ov_fail cleanup_failed "The vault was resized but its temporary container reference remains attached."
                    record=$(jq --arg size "$(ov_param size_gb)" --arg time "$(ov_now)" '.size_gb=$size | .updated_at=$time' <<< "$record")
                    ov_save vaults "$id" "$record"; ov_ok "$(ov_vault_status "$record")" ;;
                vault.passwd) ov_vault_change_password "$record" ;;
                vault.setkey) ov_vault_replace_key "$record" ;;
                vault.key-export) ov_vault_export_key "$record" ;;
                vault.index)
                    ov_vault_is_open "$record" || ov_fail locked "Open the vault before indexing."
                    ov_vault_index_or_search "$record" index >&2 || ov_fail index_failed "Vault indexing failed."
                    ov_ok '{"indexed":true}' ;;
                vault.search)
                    ov_vault_is_open "$record" || ov_fail locked "Open the vault before searching."
                    result=$(ov_vault_index_or_search "$record" search "$(ov_require query)" 2>/dev/null) || ov_fail search_failed "The vault indexes could not be searched."
                    ov_ok "$(jq -n --arg results "$result" '{results:$results}')" ;;
                migration.list) ov_ok "$(ov_migration_list "$id")" ;;
                *) ov_fail unknown_operation "Unknown vault operation." ;;
            esac
            ;;
    esac
}
