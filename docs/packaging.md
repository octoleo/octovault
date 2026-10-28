# Build, test, and distribute

The Debian package contains a C/GTK4/libadwaita GUI, a C command-line client, the privileged D-Bus service, a desktop event observer, Bash engine adapters, and a user-side FIDO2 helper linked with libfido2 and OpenSSL. Build on the Ubuntu release and architecture you intend to distribute. A binary compiled on a newer distribution is not automatically compatible with an older one.

Install the packages named in `debian/control` under `Build-Depends`, then run:

```bash
make check
dpkg-buildpackage -us -uc -b
```

`make check` builds the actual binaries, checks shell and desktop/XML metadata, verifies version consistency, and runs every `tests/test-*.sh` test. The suite includes isolated backend/service tests; tests must use temporary state and must never access a developer's real vaults, credentials, or repositories.

The CI workflow builds Ubuntu 26.04 amd64 packages, runs the native GTK smoke test as an ordinary user on a temporary display, and exercises install, upgrade, reinstall, remove, and purge in disposable containers. Its upgrade baseline is a locally constructed lower-version package, explicitly labeled `0.0.0~lifecycle`, so it tests Debian lifecycle behavior without claiming an earlier public release exists. User-state retention is checked across each transition.

Do not run `scripts/test-package-lifecycle.sh` on a normal workstation. It installs and removes packages and is guarded by both an explicit argument and the `OCTOVAULT_DISPOSABLE_TEST=1` environment marker. This marker designates a disposable CI system; it does not make an existing workstation disposable.

Desktop entry: `io.vdm.OctoVault.desktop`. Application ID: `io.vdm.OctoVault`. D-Bus name: `io.vdm.OctoVault1`. The package installs the GUI and CLI into `/usr/bin`, fixed workers into `/usr/libexec/octovault`, and root-owned Bash modules into `/usr/lib/octovault`. State is stored separately under `/var/lib/octovault/users/UID`.

The desktop observer is started through XDG desktop autostart on desktops using logind. GNOME on Ubuntu remains the baseline tested desktop; GNOME-specific logout and idle integrations are not claimed for other desktops. Its systemd user unit is also supplied for managed environments; do not deliberately start duplicate observers. The observer requests configured unlock offers through the GUI, including the authorization step when needed; it does not pass secrets on a command line or unlock vaults without their credentials. The system daemon is activated on demand by D-Bus. A required pre-sleep unit runs before systemd's sleep executors. The shutdown helper runs before the shutdown and unmount targets. These guards invoke only saved vault policies and do not create policies during package installation.

## Versioned release

The current version lives in `VERSION`. Before a release, update it, add a matching top Debian changelog entry, and update the first AppStream release entry with the same version and release date. Run `bash scripts/version.sh --check` to verify all three agree. Public versions use `MAJOR.MINOR.PATCH`.

Work on a review branch and open a pull request. The PR workflow creates downloadable test artifacts without publishing. After the reviewed new version is merged into `main`, the workflow rebuilds the package matrix, tests it, then publishes a `vX.Y.Z` GitHub release using GitHub's temporary workflow token. It checks that the commit is still current `main`, uploads the package assets to a draft, downloads and compares the bytes, and publishes only after validation. An existing public version is not overwritten. A newer commit with the same version is tested but needs a version increment for its own release.

For an interrupted publication, use **Actions → Test and package → Run workflow**, choose `main`, and enable `publish`. It defaults to false, so ordinary manual runs are test-only. A draft can be resumed only for its recorded source commit. No personal access token or application-store account is needed for GitHub release assets.

GitHub publication and optional APT publication are separate jobs. Missing APT credentials never prevent a versioned GitHub release. GitHub receives the `.deb` and its SHA-256 manifest using the workflow's temporary `GITHUB_TOKEN`; no publisher signing key, personal access token, or store account is required. Install a matching newer `.deb` through APT or the desktop package installer to upgrade. Tomb, Restic, and other declared dependencies are installed and updated through the normal Ubuntu package sources.

## Optional signed APT updates

The workflow also builds an inspectable unsigned APT repository from the tested Ubuntu 26.04 amd64 package. It contains package indexes, AppStream metadata and the application icon, and is explicitly marked `UNSIGNED-TEST-ONLY`. This artifact is for inspection and tests, never client enrollment. Unit tests additionally use a fresh, passphrase-protected disposable GnuPG key to verify actual signatures, altered index and metadata rejection, fingerprint checks, and separation of private signing material from public files.

After the GitHub release is available, the optional APT job checks the publishing configuration. If the private key, fingerprint or URL is absent, it logs a clean skip. With all three configured, it downloads the published packages and checksum manifests, verifies them, builds signed `InRelease` and `Release.gpg` metadata, verifies both signatures, and deploys the public repository through GitHub Pages. A broken configured key or wrong passphrase fails that optional job rather than publishing an unsigned repository; the already published GitHub release remains available.

Configure these values under **Settings → Secrets and variables → Actions**:

- Secret `APT_SIGNING_KEY`: the publisher's ASCII-armored OpenPGP private signing key. Export an existing dedicated release key; never commit it. The script requires exactly one primary key matching the expected fingerprint and uses an isolated temporary GnuPG home.
- Secret `APT_SIGNING_PASSPHRASE`: that key's passphrase, when protected. It is passed to GnuPG through standard input, never a command-line argument.
- Variable `APT_SIGNING_KEY_FINGERPRINT`: the full uppercase 40-character primary fingerprint, independently verified by the publisher.
- Variable `APT_REPOSITORY_URL`: the HTTPS base URL where the repository is deployed, without credentials, query strings or fragments. For the default project Pages address this is `https://octoleo.github.io/octovault`; use the actual Pages URL if a custom domain is configured.

In **Settings → Pages**, select **GitHub Actions** as the build and deployment source. The deployment uses the `github-pages` environment; align its branch and deployment policies with publishing from reviewed `main`. No extra enable flag is necessary: complete signing configuration enables this optional distribution job. The repository supports Ubuntu 26.04 (`resolute`) on `amd64` only. The workflow never generates a permanent publisher identity or adds a package source to users' computers.

This is the same native Debian/APT distribution model as OctoShield. It supplies normal `apt update` and `apt upgrade` support and AppStream metadata for compatible software centers. It is **not** a Snap Store submission; Snap Store credentials are a different publishing mechanism and are not used by this Debian package workflow.

### Client enrollment

The published repository provides `octovault-archive-keyring.gpg`, its armored equivalent and fingerprint, and an `octovault-resolute.sources` file with an explicit `Signed-By` keyring. Verify the fingerprint through an independently trusted publisher channel before installing either file. Installing a `.deb` does not silently enroll the repository or grant trust to its publisher.

These commands download and verify the public key before adding the Ubuntu 26.04 source. Enter the configured repository URL and the independently verified primary fingerprint at the prompts:

```bash
bash <<'ENROLL'
set -Eeuo pipefail
. /etc/os-release
[[ ${ID:-} == ubuntu && ${VERSION_ID:-} == 26.04 && $(dpkg --print-architecture) == amd64 ]] || {
    printf 'This repository supports Ubuntu 26.04 amd64.\n' >&2
    exit 1
}
read -r -p 'Repository HTTPS URL: ' repository_url </dev/tty
read -r -p 'Verified primary fingerprint: ' expected_fingerprint </dev/tty
repository_url=${repository_url%/}
[[ $repository_url =~ ^https://[A-Za-z0-9]([A-Za-z0-9.-]*[A-Za-z0-9])?(:[0-9]{1,5})?(/[A-Za-z0-9._~-]+)*$ ]]
[[ $expected_fingerprint =~ ^[A-F0-9]{40}$ ]]
enrollment_dir=$(mktemp -d)
trap 'rm -rf -- "$enrollment_dir"' EXIT
curl --fail --silent --show-error --location --proto '=https' --proto-redir '=https' \
    "$repository_url/octovault-archive-keyring.gpg" --output "$enrollment_dir/keyring.gpg"
actual_fingerprint=$(gpg --no-options --batch --homedir "$enrollment_dir" --show-keys --with-colons "$enrollment_dir/keyring.gpg" |
    awk -F: '$1=="pub" {primary=1; next} primary && $1=="fpr" {print $10; primary=0}')
[[ $actual_fingerprint == "$expected_fingerprint" ]] || { printf 'Signing fingerprint mismatch.\n' >&2; exit 1; }
printf 'Types: deb\nURIs: %s\nSuites: resolute\nComponents: main\nArchitectures: amd64\nSigned-By: /etc/apt/keyrings/octovault-archive-keyring.gpg\n' \
    "$repository_url" >"$enrollment_dir/octovault.sources"
sudo install -d -m 0755 /etc/apt/keyrings
sudo install -m 0644 "$enrollment_dir/keyring.gpg" /etc/apt/keyrings/octovault-archive-keyring.gpg
sudo install -m 0644 "$enrollment_dir/octovault.sources" /etc/apt/sources.list.d/octovault.sources
sudo apt update
sudo apt install octovault
ENROLL
```

Subsequent releases are available through normal system updates. Removing `/etc/apt/sources.list.d/octovault.sources` and `/etc/apt/keyrings/octovault-archive-keyring.gpg` unenrolls this source; it does not remove OctoVault or its data. Checksums detect changed bytes, while signed repository metadata authenticates the publisher. Never use `trusted=yes` or disable signature verification.

To reproduce the repository artifact locally, install `apt-utils`, `gnupg`, `appstream`, and `libxml2-utils`, place the release `.deb` and its matching `SHA256SUMS-ubuntu26.04` in `packages/`, and run:

```bash
bash scripts/apt-repository.sh --input packages --output apt-test
```

The output directory must be new. Without signing credentials, this produces only the clearly labeled unsigned test artifact. Supplying the signing environment above produces a signed repository without uploading it or changing local APT configuration.

## Test scope

Automated tests are the merge gate. Native smoke tests establish that the actual GUI starts and its operation wiring is loadable. Service tests establish request authorization boundaries and job behavior in isolation. Integration tests exercise the adapters using controlled fixtures and actual tools where available. A container does not reproduce every laptop's physical power state or token; optional tests on representative equipment are useful additional evidence, not a prerequisite imposed on the user before completing development.

FIDO2 USB access uses the distribution's udev security-token rules and active-session permissions. The package depends on modern udev; it does not install world-writable device rules or run the hardware helper as root.
