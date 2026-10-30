#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Run the real publication script against a local GitHub CLI fixture and a
# genuine Debian archive. No GitHub requests, credentials, or releases are used.
set -Eeuo pipefail
root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)
task_tmp=$(mktemp -d)
trap 'rm -rf -- "$task_tmp"' EXIT
version=$(bash "$root/scripts/version.sh")
commit=1111111111111111111111111111111111111111
other_commit=2222222222222222222222222222222222222222
filename="octovault_${version}_ubuntu26.04_amd64.deb"
ubuntu_versions=(24.04 26.04)
mkdir -p "$task_tmp/bin" "$task_tmp/package/DEBIAN" "$task_tmp/package/usr/share/octovault" "$task_tmp/original"
cat >"$task_tmp/package/DEBIAN/control" <<EOF
Package: octovault
Version: $version
Architecture: amd64
Maintainer: OctoVault test fixture <fixture@example.invalid>
Description: Disposable release publication test fixture
EOF
for ubuntu in "${ubuntu_versions[@]}"; do
    package_name="octovault_${version}_ubuntu${ubuntu}_amd64.deb"
    printf 'Release verification fixture for Ubuntu %s\n' "$ubuntu" >"$task_tmp/package/usr/share/octovault/fixture"
    dpkg-deb --build --root-owner-group "$task_tmp/package" "$task_tmp/original/$package_name" >/dev/null
    (cd "$task_tmp/original" && sha256sum "$package_name" >"SHA256SUMS-ubuntu$ubuntu")
done

cat >"$task_tmp/bin/gh" <<'FIXTURE'
#!/usr/bin/env bash
set -Eeuo pipefail
[[ ${GH_REPO:-} == octoleo/octovault && ${GH_TOKEN:-} == octovault-test-fixture-not-a-real-token ]]
printf '%s\n' "$*" >>"$MOCK_STATE/calls"
save_release() {
    jq "$@" "$MOCK_STATE/release.json" >"$MOCK_STATE/release.next"
    mv "$MOCK_STATE/release.next" "$MOCK_STATE/release.json"
}
if [[ $1 == api ]]; then
    shift
    if [[ ${1:-} == --paginate && ${2:-} == --slurp ]]; then shift 2; fi
    case ${1:-} in
        "repos/$GH_REPO/git/ref/heads/main")
            calls=$(cat "$MOCK_STATE/main-calls")
            calls=$((calls + 1))
            printf '%s\n' "$calls" >"$MOCK_STATE/main-calls"
            if [[ $MOCK_MODE == stale-main || ( $MOCK_MODE == main-moved && $calls -gt 1 ) ]]; then
                printf '%s\n' "$MOCK_OTHER"
            else
                printf '%s\n' "$MOCK_COMMIT"
            fi
            ;;
        "repos/$GH_REPO/releases?per_page=100")
            if [[ -f $MOCK_STATE/release.json ]]; then jq '[[.]]' "$MOCK_STATE/release.json"; else printf '[[]]\n'; fi
            ;;
        "repos/$GH_REPO/git/matching-refs/tags/$MOCK_TAG") cat "$MOCK_STATE/tags.json" ;;
        "repos/$GH_REPO/git/tags/3333333333333333333333333333333333333333")
            jq -n --arg sha "$MOCK_COMMIT" '{object:{type:"commit",sha:$sha}}'
            ;;
        *) printf 'Unexpected fixture API call: %s\n' "$*" >&2; exit 90 ;;
    esac
    exit
fi
[[ $1 == release && $3 == "$MOCK_TAG" ]]
operation=$2
shift 3
case $operation in
    create)
        [[ ! -e $MOCK_STATE/release.json ]]
        target='' notes='' draft=false
        while (($#)); do
            case $1 in
                --repo|--title) shift 2 ;;
                --target) target=$2; shift 2 ;;
                --notes-file) notes=$2; shift 2 ;;
                --draft) draft=true; shift ;;
                *) exit 91 ;;
            esac
        done
        [[ $target == "$MOCK_COMMIT" && $draft == true && -s $notes ]]
        cp "$notes" "$MOCK_STATE/notes.md"
        jq -n --arg tag "$MOCK_TAG" --arg target "$target" '{tag_name:$tag,draft:true,target_commitish:$target}' >"$MOCK_STATE/release.json"
        ;;
    view)
        [[ -f $MOCK_STATE/release.json ]]
        jq '{isDraft:.draft,targetCommitish:.target_commitish}' "$MOCK_STATE/release.json"
        ;;
    upload)
        jq -e .draft "$MOCK_STATE/release.json" >/dev/null
        while (($#)); do
            case $1 in
                --repo) shift 2 ;;
                --clobber) shift ;;
                --*) exit 92 ;;
                *) cp -- "$1" "$MOCK_STATE/assets/${1##*/}"; shift ;;
            esac
        done
        ;;
    download)
        destination=''
        while (($#)); do
            case $1 in
                --repo) shift 2 ;;
                --dir) destination=$2; shift 2 ;;
                *) exit 93 ;;
            esac
        done
        [[ -d $destination ]]
        cp "$MOCK_STATE/assets/"* "$destination/"
        if [[ $MOCK_MODE == corrupt-download ]]; then printf 'bad transport\n' >>"$destination/$MOCK_FILENAME"; fi
        if [[ $MOCK_MODE == unexpected-asset ]]; then printf 'unreviewed\n' >"$destination/extra.txt"; fi
        ;;
    edit)
        [[ $* == "--repo octoleo/octovault --draft=false --latest" ]]
        if [[ $MOCK_MODE != remains-draft ]]; then save_release '.draft = false'; fi
        target=$MOCK_COMMIT
        if [[ $MOCK_MODE == wrong-final-tag ]]; then target=$MOCK_OTHER; fi
        jq -n --arg ref "refs/tags/$MOCK_TAG" --arg target "$target" '[{ref:$ref,object:{type:"commit",sha:$target}}]' >"$MOCK_STATE/tags.json"
        ;;
    *) printf 'Unexpected fixture release call: %s\n' "$operation" >&2; exit 94 ;;
esac
FIXTURE
chmod 0755 "$task_tmp/bin/gh"

export PATH="$task_tmp/bin:$PATH"
export GH_REPO=octoleo/octovault GH_TOKEN=octovault-test-fixture-not-a-real-token
export MOCK_COMMIT="$commit" MOCK_OTHER="$other_commit" MOCK_TAG="v$version" MOCK_FILENAME="$filename"
# GitHub package publication must work with no external distribution secrets.
unset APT_SIGNING_KEY APT_SIGNING_PASSPHRASE APT_SIGNING_KEY_FINGERPRINT APT_REPOSITORY_URL SNAPCRAFT_STORE_CREDENTIALS
case_count=0
start_case() {
    case_count=$((case_count + 1))
    MOCK_MODE=$1
    MOCK_STATE="$task_tmp/$case_count-$1"
    GITHUB_OUTPUT="$MOCK_STATE/outputs"
    export MOCK_MODE MOCK_STATE GITHUB_OUTPUT
    mkdir -p "$MOCK_STATE/artifacts" "$MOCK_STATE/assets"
    cp "$task_tmp/original/"* "$MOCK_STATE/artifacts/"
    printf '[]\n' >"$MOCK_STATE/tags.json"
    printf '0\n' >"$MOCK_STATE/main-calls"
    : >"$MOCK_STATE/calls"
    : >"$GITHUB_OUTPUT"
}
run_success() {
    if ! bash "$root/scripts/publish-release.sh" "$commit" "$MOCK_STATE/artifacts" >"$MOCK_STATE/log" 2>&1; then
        cat "$MOCK_STATE/log" >&2
        printf 'Publication fixture unexpectedly failed: %s\n' "$MOCK_MODE" >&2
        exit 1
    fi
}
run_failure() {
    if bash "$root/scripts/publish-release.sh" "$commit" "$MOCK_STATE/artifacts" >"$MOCK_STATE/log" 2>&1; then
        printf 'Publication fixture unexpectedly succeeded: %s\n' "$MOCK_MODE" >&2
        exit 1
    fi
    assert_available false
}
assert_available() {
    [[ $(sed -n 's/^available=//p' "$GITHUB_OUTPUT" | tail -n 1) == "$1" ]]
}
assert_no_mutations() {
    if grep -Eq '^release (create|upload|edit) ' "$MOCK_STATE/calls"; then
        printf 'Unexpected release mutation: %s\n' "$MOCK_MODE" >&2
        exit 1
    fi
}
assert_no_publication() {
    if grep -q '^release edit ' "$MOCK_STATE/calls"; then
        printf 'Unverified release was published: %s\n' "$MOCK_MODE" >&2
        exit 1
    fi
}
fixture_release() {
    jq -n --arg tag "v$version" --arg commit "$2" --argjson draft "$1" '{tag_name:$tag,draft:$draft,target_commitish:$commit}' >"$MOCK_STATE/release.json"
}
fixture_tag() {
    jq -n --arg ref "refs/tags/v$version" --arg sha "$1" --arg type "${2:-commit}" '[{ref:$ref,object:{type:$type,sha:$sha}}]' >"$MOCK_STATE/tags.json"
}

start_case fresh
run_success
assert_available true
grep -Fxq "tag=v$version" "$GITHUB_OUTPUT"
jq -e '.draft == false' "$MOCK_STATE/release.json" >/dev/null
for ubuntu in "${ubuntu_versions[@]}"; do
    package_name="octovault_${version}_ubuntu${ubuntu}_amd64.deb"
    cmp "$task_tmp/original/$package_name" "$MOCK_STATE/assets/$package_name"
    cmp "$task_tmp/original/SHA256SUMS-ubuntu$ubuntu" "$MOCK_STATE/assets/SHA256SUMS-ubuntu$ubuntu"
    grep -Fq "sudo apt install ./$package_name" "$MOCK_STATE/notes.md"
done
[[ $(find "$MOCK_STATE/assets" -maxdepth 1 -type f | wc -l) == 4 ]]
[[ $(grep -c '^release create ' "$MOCK_STATE/calls") == 1 ]]
grep -q '^release download ' "$MOCK_STATE/calls"

start_case resume
fixture_release true "$commit"
printf 'interrupted upload\n' >"$MOCK_STATE/assets/$filename"
run_success
assert_available true
! grep -q '^release create ' "$MOCK_STATE/calls"
cmp "$task_tmp/original/$filename" "$MOCK_STATE/assets/$filename"

for tag_style in lightweight annotated; do
    start_case "public-$tag_style"
    fixture_release false "$commit"
    if [[ $tag_style == annotated ]]; then fixture_tag 3333333333333333333333333333333333333333 tag; else fixture_tag "$commit"; fi
    run_success
    assert_available true
    assert_no_mutations
done

start_case public-other-source
fixture_release false "$other_commit"
fixture_tag "$other_commit"
run_success
assert_available false
assert_no_mutations

start_case mismatched-tag
fixture_tag "$other_commit"
run_failure
assert_no_mutations

start_case mismatched-draft
fixture_release true "$other_commit"
run_failure
assert_no_mutations

for ubuntu in "${ubuntu_versions[@]}"; do
    package_name="octovault_${version}_ubuntu${ubuntu}_amd64.deb"
    start_case "bad-checksum-$ubuntu"
    printf 'corruption\n' >>"$MOCK_STATE/artifacts/$package_name"
    run_failure
    assert_no_mutations

    start_case "missing-package-$ubuntu"
    rm "$MOCK_STATE/artifacts/$package_name"
    run_failure
    assert_no_mutations

    start_case "missing-checksum-$ubuntu"
    rm "$MOCK_STATE/artifacts/SHA256SUMS-ubuntu$ubuntu"
    run_failure
    assert_no_mutations
done

for failure in corrupt-download unexpected-asset main-moved; do
    start_case "$failure"
    run_failure
    assert_no_publication
    jq -e .draft "$MOCK_STATE/release.json" >/dev/null
done

start_case stale-main
run_success
assert_available false
assert_no_mutations

for failure in remains-draft wrong-final-tag; do
    start_case "$failure"
    run_failure
    grep -q '^release edit ' "$MOCK_STATE/calls"
done

printf 'release: %s publication, retry, integrity and distribution handoff cases passed\n' "$case_count"
