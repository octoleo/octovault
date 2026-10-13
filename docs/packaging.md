# Build, test, and distribute

The Debian package contains a C/GTK4/libadwaita GUI, a C command-line client, the privileged D-Bus service, a desktop event observer, and Bash engine adapters. Build on the Ubuntu release and architecture you intend to distribute. A binary compiled on a newer distribution is not automatically compatible with an older one.

Install the packages named in `debian/control` under `Build-Depends`, then run:

```bash
make check
dpkg-buildpackage -us -uc -b
```

`make check` builds the actual binaries, checks shell and desktop/XML metadata, verifies version consistency, and runs every `tests/test-*.sh` test. The suite includes isolated backend/service tests; tests must use temporary state and must never access a developer's real vaults, credentials, or repositories.

The CI workflow builds Ubuntu 26.04 amd64 packages, runs the native GTK smoke test as an ordinary user on a temporary display, and exercises install, upgrade, reinstall, remove, and purge in disposable containers. Its upgrade baseline is a locally constructed lower-version package, explicitly labeled `0.0.0~lifecycle`, so it tests Debian lifecycle behavior without claiming an earlier public release exists. User-state retention is checked across each transition.

Do not run `scripts/test-package-lifecycle.sh` on a normal workstation. It installs and removes packages and is guarded by both an explicit argument and the `OCTOVAULT_DISPOSABLE_TEST=1` environment marker. This marker designates a disposable CI system; it does not make an existing workstation disposable.

Desktop entry: `io.vdm.OctoVault.desktop`. Application ID: `io.vdm.OctoVault`. D-Bus name: `io.vdm.OctoVault1`. The package installs the GUI and CLI into `/usr/bin`, fixed workers into `/usr/libexec/octovault`, and root-owned Bash modules into `/usr/lib/octovault`. State is stored separately under `/var/lib/octovault/users/UID`.

The desktop observer is started through GNOME autostart. Its systemd user unit is also supplied for managed environments; do not deliberately start duplicate observers. The system daemon is activated on demand by D-Bus. A required pre-sleep unit runs before systemd's sleep executors. The shutdown helper runs before the shutdown and unmount targets. These guards invoke only saved vault policies and do not create policies during package installation.

## Versioned release

The current version lives in `VERSION`. Before a release, update it, add a matching top Debian changelog entry, and update the first AppStream release entry with the same version and release date. Run `bash scripts/version.sh --check` to verify all three agree. Public versions use `MAJOR.MINOR.PATCH`.

Work on a review branch and open a pull request. The PR workflow creates downloadable test artifacts without publishing. After the reviewed new version is merged into `main`, the workflow rebuilds the package matrix, tests it, then publishes a `vX.Y.Z` GitHub release using GitHub's temporary workflow token. It checks that the commit is still current `main`, uploads the package assets to a draft, downloads and compares the bytes, and publishes only after validation. An existing public version is not overwritten. A newer commit with the same version is tested but needs a version increment for its own release.

For an interrupted publication, use **Actions → Test and package → Run workflow**, choose `main`, and enable `publish`. It defaults to false, so ordinary manual runs are test-only. A draft can be resumed only for its recorded source commit. No personal access token or application-store account is needed for GitHub release assets.

Install a matching newer `.deb` through APT or the desktop package installer to upgrade. Automatic discovery through the system's normal APT updater requires a separately configured signed repository and client trust enrollment. OctoVault does not silently add a package source or trust a publisher key during installation. The release workflow publishes downloadable packages; signing and hosting an APT repository is a distinct administrator configuration.

Checksums detect changed bytes. For authenticated APT distribution, the publisher must generate signed repository metadata using its own private signing key, protect that key in its publishing environment, expose a stable HTTPS endpoint, and distribute the public fingerprint through a trusted channel. Never commit signing keys or mark an unsigned repository trusted.

## Test scope

Automated tests are the merge gate. Native smoke tests establish that the actual GUI starts and its operation wiring is loadable. Service tests establish request authorization boundaries and job behavior in isolation. Integration tests exercise the adapters using controlled fixtures and actual tools where available. A container does not reproduce every laptop's physical power state or token; optional tests on representative equipment are useful additional evidence, not a prerequisite imposed on the user before completing development.
