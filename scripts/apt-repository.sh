#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Assemble public files only. Never install a source or key into the build host.
set +x +a
set -Eeuo pipefail
IFS=$' \t\n'
umask 077

aptrepo_error() { printf 'APT repository: %s\n' "$*" >&2; return 1; }

aptrepo_main() (
    local signing_key=${APT_SIGNING_KEY:-} passphrase=${APT_SIGNING_PASSPHRASE:-}
    export -n signing_key passphrase
    unset APT_SIGNING_KEY APT_SIGNING_PASSPHRASE
    local fingerprint=${APT_SIGNING_KEY_FINGERPRINT:-} url=${APT_REPOSITORY_URL:-}
    local input='' output='' work='' keyhome='' signed=false root version file name actual tool mode ubuntu suite
    local -a packages=() primary_keys=() public_keys=() ubuntu_versions=(24.04 26.04)
    local -A suites=([24.04]=noble [26.04]=resolute)
    while (($#)); do
        case $1 in
            --input) [[ $# -ge 2 && -z $input ]] || return 2; input=$2; shift 2 ;;
            --output) [[ $# -ge 2 && -z $output ]] || return 2; output=$2; shift 2 ;;
            --help)
                printf '%s\n' 'Usage: bash scripts/apt-repository.sh --input PACKAGES_DIR --output NEW_DIR' \
                    'Input: octovault_VERSION_ubuntu{24.04,26.04}_amd64.deb and each matching SHA256SUMS-ubuntuVERSION.' \
                    'Without credentials, output is explicitly UNSIGNED-TEST-ONLY.' \
                    'Signing: APT_SIGNING_KEY (armored secret), APT_SIGNING_PASSPHRASE (optional secret),' \
                    'APT_SIGNING_KEY_FINGERPRINT (full uppercase primary fingerprint), APT_REPOSITORY_URL (HTTPS).'
                return ;;
            *) aptrepo_error 'Unknown argument; use --help.'; return 2 ;;
        esac
    done
    [[ -n $input && -n $output ]] || { aptrepo_error 'Both --input and --output are required.'; return 2; }
    if [[ -n $signing_key || -n $passphrase || -n $fingerprint ]]; then
        [[ -n $signing_key && $fingerprint =~ ^[A-F0-9]{40}$ && -n $url ]] || {
            aptrepo_error 'Signing requires the private key, full primary fingerprint, and public HTTPS URL.'; return 1;
        }
        [[ $passphrase != *$'\n'* && $passphrase != *$'\r'* ]] || {
            aptrepo_error 'The signing passphrase must be a single line.'; return 1;
        }
        signed=true
    fi
    url=${url%/}
    if [[ -n $url ]]; then
        [[ $url =~ ^https://[A-Za-z0-9]([A-Za-z0-9.-]*[A-Za-z0-9])?(:[0-9]{1,5})?(/[A-Za-z0-9._~-]+)*$ &&
            $url != */../* && $url != */.. && $url != */./* && $url != */. ]] || {
            aptrepo_error 'The repository URL must be HTTPS without credentials, queries, fragments, or unsafe path segments.'; return 1;
        }
    else
        url=https://example.invalid/octovault
    fi
    for tool in apt-ftparchive dpkg-deb gzip install realpath sha256sum xmllint appstreamcli; do
        command -v "$tool" >/dev/null || { aptrepo_error "Missing build tool: $tool"; return 1; }
    done
    [[ -d $input && ! -L $input && ! -e $output && ! -L $output ]] || {
        aptrepo_error 'Input must be a regular directory; output must not exist.'; return 1;
    }
    input=$(realpath -e -- "$input")
    output=$(realpath -m -- "$output")
    [[ -d ${output%/*} && ! -e $output && ! -L $output ]] || {
        aptrepo_error 'Output parent must exist and output must be new.'; return 1;
    }
    root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)
    version=$(bash "$root/scripts/version.sh")
    bash "$root/scripts/version.sh" --check
    shopt -s nullglob
    packages=("$input"/*.deb)
    shopt -u nullglob
    ((${#packages[@]} == ${#ubuntu_versions[@]})) || {
        aptrepo_error 'Exactly one amd64 release package for each of Ubuntu 24.04 and 26.04 is required.'; return 1;
    }
    for ubuntu in "${ubuntu_versions[@]}"; do
        name="octovault_${version}_ubuntu${ubuntu}_amd64.deb"
        file="$input/$name"
        [[ -f $file && ! -L $file &&
            -f $input/SHA256SUMS-ubuntu$ubuntu && ! -L $input/SHA256SUMS-ubuntu$ubuntu ]] || {
            aptrepo_error "A matching regular package and checksum manifest are required for Ubuntu $ubuntu."; return 1;
        }
        [[ $(dpkg-deb -f "$file" Package) == octovault && $(dpkg-deb -f "$file" Version) == "$version" &&
            $(dpkg-deb -f "$file" Architecture) == amd64 ]] || {
            aptrepo_error "Package control fields do not match the Ubuntu $ubuntu release filename."; return 1;
        }
        actual=$(sha256sum "$file")
        # Compare the complete expected manifest; do not follow paths from a supplied manifest.
        printf '%s  %s\n' "${actual%% *}" "$name" | cmp -s - "$input/SHA256SUMS-ubuntu$ubuntu" || {
            aptrepo_error "The Ubuntu $ubuntu package checksum manifest does not match."; return 1;
        }
    done
    work=$(mktemp -d "${output%/*}/.octovault-apt.XXXXXXXX")
    # shellcheck disable=SC2317,SC2329
    aptrepo_cleanup() {
        local result=$?
        if [[ -n $keyhome ]]; then gpgconf --homedir "$keyhome" --kill gpg-agent >/dev/null 2>&1 || :; fi
        rm -rf -- "$work"
        exit "$result"
    }
    trap aptrepo_cleanup EXIT
    trap 'exit 130' INT
    trap 'exit 143' TERM
    mkdir "$work/repository"
    (
        cd "$work/repository"
        # Parse the checked-in XML using the distribution XML parser. The package
        # mapping and repository icon are catalog fields, not upstream metainfo.
        [[ $(xmllint --xpath 'string(/component/id)' "$root/data/io.vdm.OctoVault.metainfo.xml") == io.vdm.OctoVault ]]
        install -D -m 0644 "$root/data/icons/hicolor/512x512/apps/io.vdm.OctoVault.png" "media/v$version/io.vdm.OctoVault.png"
        for ubuntu in "${ubuntu_versions[@]}"; do
            suite=${suites[$ubuntu]}
            name="octovault_${version}_ubuntu${ubuntu}_amd64.deb"
            install -D -m 0644 "$input/$name" "pool/$suite/main/o/octovault/$name"
            mkdir -p "dists/$suite/main/binary-amd64" "dists/$suite/main/dep11"
            # Index only this suite's pool: equal app versions have different
            # distribution library dependencies and must never be interchanged.
            apt-ftparchive --md5=false --sha1=false packages "pool/$suite" >"dists/$suite/main/binary-amd64/Packages"
            gzip -n -9 -c "dists/$suite/main/binary-amd64/Packages" >"dists/$suite/main/binary-amd64/Packages.gz"
            {
                printf '<?xml version="1.0" encoding="UTF-8"?>\n<components version="1.0" origin="octovault-%s-main" architecture="amd64">\n<component type="desktop-application">\n' "$suite"
                xmllint --xpath '/component/node()[not(self::pkgname or self::source_pkgname or self::bundle or self::icon)]' "$root/data/io.vdm.OctoVault.metainfo.xml"
                printf '<pkgname>octovault</pkgname><icon type="remote" width="512" height="512">%s/media/v%s/io.vdm.OctoVault.png</icon>\n</component></components>\n' "$url" "$version"
            } >"dists/$suite/main/dep11/Components-amd64.xml"
            appstreamcli validate --no-net "dists/$suite/main/dep11/Components-amd64.xml" >&2
            appstreamcli convert "dists/$suite/main/dep11/Components-amd64.xml" "dists/$suite/main/dep11/Components-amd64.yml" >&2
            gzip -n -9 -c "dists/$suite/main/dep11/Components-amd64.yml" >"dists/$suite/main/dep11/Components-amd64.yml.gz"
            apt-ftparchive --md5=false --sha1=false \
                -o APT::FTPArchive::Release::Origin=OctoVault \
                -o 'APT::FTPArchive::Release::Label=Vast Development Method' \
                -o "APT::FTPArchive::Release::Suite=$suite" \
                -o "APT::FTPArchive::Release::Codename=$suite" \
                -o APT::FTPArchive::Release::Architectures=amd64 \
                -o APT::FTPArchive::Release::Components=main \
                -o 'APT::FTPArchive::Release::Description=OctoVault native packages and application metadata' \
                release "dists/$suite" >Release.tmp
            mv Release.tmp "dists/$suite/Release"
            grep -Fq main/dep11/Components-amd64.yml.gz "dists/$suite/Release"
        done
    )
    if [[ $signed == true ]]; then
        for tool in gpg gpgv gpgconf; do command -v "$tool" >/dev/null || { aptrepo_error "Missing signing tool: $tool"; return 1; }; done
        keyhome="$work/gnupg"
        mkdir -m 0700 "$keyhome"
        if ! printf '%s\n' "$signing_key" | gpg --no-options --batch --no-tty --homedir "$keyhome" --quiet --import > /dev/null 2>"$keyhome/import.log"; then
            aptrepo_error 'The private signing key could not be imported.'; return 1;
        fi
        signing_key=''
        mapfile -t primary_keys < <(gpg --no-options --batch --homedir "$keyhome" --with-colons --fingerprint --list-secret-keys 2>/dev/null |
            awk -F: '$1=="sec" {primary=1; next} primary && $1=="fpr" {print $10; primary=0}')
        mapfile -t public_keys < <(gpg --no-options --batch --homedir "$keyhome" --with-colons --fingerprint --list-keys 2>/dev/null |
            awk -F: '$1=="pub" {primary=1; next} primary && $1=="fpr" {print $10; primary=0}')
        [[ ${#primary_keys[@]} == 1 && ${#public_keys[@]} == 1 && ${primary_keys[0]} == "$fingerprint" && ${public_keys[0]} == "$fingerprint" ]] || {
            aptrepo_error 'Signing material must contain only the expected private primary key.'; return 1;
        }
        gpg --no-options --batch --homedir "$keyhome" --export "$fingerprint" >"$work/repository/octovault-archive-keyring.gpg"
        gpg --no-options --batch --homedir "$keyhome" --armor --export "$fingerprint" >"$work/repository/octovault-archive-keyring.asc"
        printf '%s\n' "$fingerprint" >"$work/repository/octovault-archive-keyring.fingerprint"
        for ubuntu in "${ubuntu_versions[@]}"; do
            suite=${suites[$ubuntu]}
            for mode in clearsign detach-sign; do
                actual="$work/repository/dists/$suite/InRelease"
                [[ $mode != detach-sign ]] || actual="$work/repository/dists/$suite/Release.gpg"
                if ! printf '%s\n' "$passphrase" | gpg --no-options --batch --no-tty --homedir "$keyhome" \
                    --pinentry-mode loopback --passphrase-fd 0 --local-user "$fingerprint" --armor --digest-algo SHA256 \
                    --output "$actual" "--$mode" "$work/repository/dists/$suite/Release" 2>"$keyhome/sign.log"; then
                    aptrepo_error "Signing $suite failed; check key validity, capability, and passphrase."; return 1;
                fi
            done
            gpgv --homedir "$keyhome" --keyring "$work/repository/octovault-archive-keyring.gpg" \
                "$work/repository/dists/$suite/InRelease" >/dev/null 2>"$keyhome/verify.log"
            gpgv --homedir "$keyhome" --keyring "$work/repository/octovault-archive-keyring.gpg" \
                "$work/repository/dists/$suite/Release.gpg" "$work/repository/dists/$suite/Release" >/dev/null 2>"$keyhome/verify.log"
            printf 'Types: deb\nURIs: %s\nSuites: %s\nComponents: main\nArchitectures: amd64\nSigned-By: /etc/apt/keyrings/octovault-archive-keyring.gpg\n' \
                "$url" "$suite" >"$work/repository/octovault-$suite.sources"
        done
        passphrase=''
    else
        printf 'UNSIGNED TEST ARTIFACT. Do not publish or configure APT to trust this repository.\n' >"$work/repository/UNSIGNED-TEST-ONLY"
    fi
    printf 'OctoVault %s native APT repository\nPublisher: Vast Development Method (https://www.vdm.io)\nSuites: noble (Ubuntu 24.04), resolute (Ubuntu 26.04); architecture: amd64\nSigned: %s\nRepository URL: %s\n\nUse only the suite matching your Ubuntu release.\nVerify the signing fingerprint independently before installing the public key and Signed-By source.\nSee https://github.com/octoleo/octovault/blob/main/docs/packaging.md for enrollment instructions.\nNever use trusted=yes or disable signature checks.\n' \
        "$version" "$signed" "$url" >"$work/repository/README.txt"
    cat >"$work/repository/index.html" <<HTML
<!doctype html>
<html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>OctoVault APT repository</title><style>body{font:18px/1.6 system-ui,sans-serif;max-width:48rem;margin:3rem auto;padding:0 1rem}code{overflow-wrap:anywhere}</style>
<main><h1>OctoVault $version</h1><p>Encrypted vaults and independent backups for GNOME, by <a href="https://www.vdm.io">Vast Development Method</a>.</p>
<p>Ubuntu 24.04 (noble) and 26.04 (resolute), amd64. Repository signed: $signed.</p>
<ul>
HTML
    for ubuntu in "${ubuntu_versions[@]}"; do
        suite=${suites[$ubuntu]}
        name="octovault_${version}_ubuntu${ubuntu}_amd64.deb"
        printf '<li><a href="pool/%s/main/o/octovault/%s">Ubuntu %s Debian package</a></li>\n' "$suite" "$name" "$ubuntu" >>"$work/repository/index.html"
    done
    printf '<li><a href="https://github.com/octoleo/octovault/blob/main/docs/packaging.md">Installation and updates</a></li><li><a href="README.txt">Repository details</a></li></ul>\n' >>"$work/repository/index.html"
    if [[ $signed == true ]]; then
        printf '<p>Independently verify the primary signing fingerprint: <code>%s</code></p>\n<p><a href="octovault-archive-keyring.asc">Public key</a></p>\n<p>Choose the APT source matching your Ubuntu release:</p><ul>\n' "$fingerprint" >>"$work/repository/index.html"
        for ubuntu in "${ubuntu_versions[@]}"; do
            suite=${suites[$ubuntu]}
            printf '<li><a href="octovault-%s.sources">Ubuntu %s APT source configuration</a></li>\n' "$suite" "$ubuntu" >>"$work/repository/index.html"
        done
        printf '</ul>\n' >>"$work/repository/index.html"
    else
        printf '<p><strong>Unsigned test artifact: inspection only. Do not enroll this repository.</strong></p>\n' >>"$work/repository/index.html"
    fi
    printf '</main></html>\n' >>"$work/repository/index.html"
    (
        cd "$work/repository"
        # shellcheck disable=SC2094
        find . -type f ! -name SHA256SUMS -print0 | LC_ALL=C sort -z | xargs -0 sha256sum >SHA256SUMS
    )
    find "$work/repository" -type d -exec chmod 0755 {} +
    find "$work/repository" -type f -exec chmod 0644 {} +
    mv -T --no-clobber -- "$work/repository" "$output"
    [[ ! -d $work/repository ]] || { aptrepo_error 'Output appeared during build; it was not overwritten.'; return 1; }
    printf 'Created OctoVault %s APT repository (signed=%s): %s\n' "$version" "$signed" "$output"
)

aptrepo_main "$@"
