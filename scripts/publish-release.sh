#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
set +x
set -Eeuo pipefail
umask 077
[[ $# == 2 && ${GH_REPO:-} == octoleo/octovault && -n ${GH_TOKEN:-} ]] || { printf 'Usage: publish-release.sh COMMIT ARTIFACT_DIR (GH_REPO and GH_TOKEN required)\n' >&2; exit 2; }
commit=$1
artifacts=$(realpath -- "$2")
[[ $commit =~ ^[a-f0-9]{40}$ ]] || exit 2
root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)
version=$(bash "$root/scripts/version.sh")
tag="v$version"
bash "$root/scripts/version.sh" --check "$tag"
[[ $(gh api "repos/$GH_REPO/git/ref/heads/main" --jq .object.sha) == "$commit" ]] || { printf 'A newer main commit exists; skipping publication.\n'; exit 0; }
temp=$(mktemp -d)
trap 'rm -rf -- "$temp"' EXIT
gh api --paginate --slurp "repos/$GH_REPO/releases?per_page=100" >"$temp/releases.json"
jq --arg tag "$tag" '[.[][] | select(.tag_name == $tag)]' "$temp/releases.json" >"$temp/matches.json"
count=$(jq length "$temp/matches.json")
[[ $count -le 1 ]] || { printf 'Duplicate release records require review.\n' >&2; exit 1; }
if [[ $count == 1 ]] && jq -e '.[0].draft == false' "$temp/matches.json" >/dev/null; then
    printf 'Version %s is already public; it will not be overwritten.\n' "$tag"
    exit 0
fi
files=()
ubuntu_versions=(26.04)
for ubuntu in "${ubuntu_versions[@]}"; do
    filename="octovault_${version}_ubuntu${ubuntu}_amd64.deb"
    test -f "$artifacts/$filename" && test ! -L "$artifacts/$filename"
    hash=$(sha256sum "$artifacts/$filename")
    printf '%s  %s\n' "${hash%% *}" "$filename" >"$temp/SHA256SUMS-ubuntu$ubuntu"
    cmp "$temp/SHA256SUMS-ubuntu$ubuntu" "$artifacts/SHA256SUMS-ubuntu$ubuntu"
    [[ $(dpkg-deb -f "$artifacts/$filename" Package) == octovault && $(dpkg-deb -f "$artifacts/$filename" Version) == "$version" && $(dpkg-deb -f "$artifacts/$filename" Architecture) == amd64 ]]
    files+=("$artifacts/$filename" "$artifacts/SHA256SUMS-ubuntu$ubuntu")
done
# An existing tag must identify this exact source, including annotated tags.
# --target only controls newly created tags; it cannot correct an old tag.
gh api "repos/$GH_REPO/git/matching-refs/tags/$tag" >"$temp/tags.json"
tag_sha=$(jq -r --arg ref "refs/tags/$tag" '.[] | select(.ref == $ref) | .object.sha' "$temp/tags.json")
tag_type=$(jq -r --arg ref "refs/tags/$tag" '.[] | select(.ref == $ref) | .object.type' "$temp/tags.json")
for ((depth=0; depth<8; depth++)); do
    [[ $tag_type == tag ]] || break
    gh api "repos/$GH_REPO/git/tags/$tag_sha" >"$temp/tag.json"
    tag_sha=$(jq -er .object.sha "$temp/tag.json")
    tag_type=$(jq -er .object.type "$temp/tag.json")
done
[[ -z $tag_sha || ( $tag_type == commit && $tag_sha == "$commit" ) ]] || { printf 'Existing tag refers to different code; refusing publication.\n' >&2; exit 1; }
if [[ $count == 1 ]]; then
    jq -e --arg commit "$commit" '.[0].target_commitish == $commit' "$temp/matches.json" >/dev/null || { printf 'Existing draft belongs to another commit.\n' >&2; exit 1; }
else
    cat >"$temp/notes.md" <<EOF
OctoVault $version by Vast Development Method, part of the OctoLeo Suite.

Download the Debian package matching your Ubuntu release and CPU architecture, verify its SHA-256 manifest, and install it using your desktop package installer or \
\`sudo apt install ./octovault_${version}_ubuntu26.04_amd64.deb\` on Ubuntu 26.04.

The package includes the GNOME application, CLI, desktop event observer, and privilege service. APT installs its dependencies. Vaults, repositories, and private configuration are retained during upgrades and removal. This download does not configure an automatic APT update repository.

Read the [usage and recovery instructions](https://github.com/octoleo/octovault/blob/$tag/README.md) before configuring your first vault or unattended backup. Keep recovery credentials outside this computer.

Built from $commit after the Ubuntu 26.04 package and real encryption integration checks passed.
EOF
    gh release create "$tag" --repo "$GH_REPO" --draft --target "$commit" --title "OctoVault $version" --notes-file "$temp/notes.md"
fi
# GitHub can acknowledge a draft before its read endpoint is consistent.
visible=false
for ((attempt=0; attempt<5; attempt++)); do
    if gh release view "$tag" --repo "$GH_REPO" --json isDraft,targetCommitish >"$temp/draft.json" 2>"$temp/read-error"; then
        visible=true
        break
    fi
    sleep 1
done
[[ $visible == true ]] || { printf 'Draft is not readable yet; retry this workflow to resume it.\n' >&2; exit 1; }
jq -e --arg commit "$commit" '.isDraft == true and .targetCommitish == $commit' "$temp/draft.json" >/dev/null || { printf 'Release state changed; refusing to overwrite it.\n' >&2; exit 1; }
gh release upload "$tag" "${files[@]}" --repo "$GH_REPO" --clobber
mkdir "$temp/download"
gh release download "$tag" --repo "$GH_REPO" --dir "$temp/download"
for file in "${files[@]}"; do cmp "$file" "$temp/download/${file##*/}"; done
[[ $(find "$temp/download" -maxdepth 1 -type f | wc -l) == "${#files[@]}" ]] || { printf 'Draft contains unexpected assets; refusing publication.\n' >&2; exit 1; }
[[ $(gh api "repos/$GH_REPO/git/ref/heads/main" --jq .object.sha) == "$commit" ]] || { printf 'main changed during publication; leaving a reviewable draft.\n' >&2; exit 1; }
gh release edit "$tag" --repo "$GH_REPO" --draft=false --latest
