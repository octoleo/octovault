# OctoVault

**Encrypted local vaults and independent encrypted backups, managed from a native GNOME application or the command line.** Developed by [Vast Development Method](https://www.vdm.io), part of the [OctoLeo Suite](https://github.com/octoleo).

OctoVault provides two independent tracks. Vaults protect local working folders; backups preserve recoverable versions in local, SFTP, S3-compatible, or REST repositories. A backup can also follow a vault event, but neither track requires the other.

## Install

Download the `.deb` matching **your Ubuntu release and CPU architecture** from [Releases](https://github.com/octoleo/octovault/releases). CI builds Ubuntu 26.04 amd64 packages. The initial baseline is Ubuntu 26.04 LTS with GNOME. Open the matching package in the desktop package installer, or use APT:

```bash
sha256sum --check SHA256SUMS-ubuntu26.04
sudo apt install ./octovault_1.0.0_ubuntu26.04_amd64.deb
```

APT installs the required encryption, backup, desktop, and system-integration dependencies. The checksum detects damaged or changed downloads; it is not an independent publisher signature. A downloaded Debian package does not enroll the computer into an automatic update repository.

Launch **OctoVault** from GNOME, or run `octovault-gtk`. Run both interfaces as your regular user: privileged operations request administrator authentication. Running `sudo octovault` selects the root account's configuration, not your normal account. In a headless terminal the CLI starts a PolicyKit terminal authentication agent when needed.

## Vaults

Create a vault by choosing its name, location, capacity in decimal GB, authentication, and event policy. Capacity is converted to whole MiB for the underlying engine. An existing vault can be registered without converting its format. Authentication can use a passphrase-protected key file, a key concealed in a supported image or text carrier, or an OpenPGP recipient, including a compatible OpenPGP hardware token. A physical token still follows its configured PIN/touch policy; merely attaching a USB device is not authentication.

Vaults can open manually, at desktop login, when a selected drive is mounted, or when a configured OpenPGP token becomes available. Closing policies are independently selectable for screen lock, logout, sleep, and shutdown. Policies run through the background services even when the application window is closed. A busy vault is reported as busy; force closing is a separate explicit setting because it can terminate applications and lose unsaved work.

To protect an existing folder or file, open the vault and choose its migration action. OctoVault retains a staging original, copies the content, creates the native mapping and original-path placeholder, then closes and reopens the vault to verify the mapping. It removes staging only after successful verification. Interrupted migrations retain recovery material and remain visible for recovery. Do not manually delete that staging material until the operation has completed or you have recovered it.

The ordinary directory or file underneath a closed vault's mapping remains independent and writable. OctoVault does not monitor, erase, merge, or reconcile content written there while the vault is closed. Reopening the vault temporarily covers that underlying content with the encrypted contents; closing reveals it again.

## Backups and recovery

Start by adding a destination: a local directory, an S3-compatible endpoint and bucket, an SFTP server, or a REST server. Remote access is separate from the repository's encryption password. For SFTP, verify the server host-key fingerprint instead of accepting an unknown host blindly.

Create a repository within that destination, or register an existing repository with its password. A new repository receives a generated password. Save the recovery information into your own password manager when it is shown: it includes the repository address and the credentials needed to access and decrypt it. The explicit **Recovery** action reveals it again after administrator authentication. Keep that copy outside this computer; encrypted local credential files alone are not a portable recovery kit.

Create backup plans with selected source paths and exclusions. Plans can run manually, on a calendar, after boot, while idle, after a configured drive arrives, or following a vault opening or closing. Power and metered-network preferences apply to automatic runs. Timed plans become systemd units, so scheduling does not require leaving the GUI open.

For an open-vault plan, back up the accessible plaintext content: Restic encrypts it independently in the repository. For a closed-vault plan, back up the closed encrypted container. Do not copy a changing, mounted container and assume that copy is consistent. Application databases also need their own quiescing or application-consistent export when a consistent transaction boundary matters.

Browse snapshots and files, compare snapshots, search paths, restore into a chosen target, inspect repository statistics, check repository integrity, preview retention, and prune unreferenced data. Prefer restoring into an empty directory before replacing working files. Restores run with the privileges necessary to preserve ownership; carefully review the destination and overwrite choice. Unregistering a destination, repository, or vault removes its OctoVault record, not the underlying data.

## Command line

```bash
octovault --help
octovault vault list
octovault repository list
octovault backup list
octovault --json vault list
```

The command structure is `octovault GROUP ACTION`. Options use `--hyphenated-names`; arrays use repeated `--source`, `--exclude`, `--include`, or `--close-on`. Use the actual record IDs returned by list operations. Secret options such as `--password`, `--secret-key`, and `--ssh-private-key` **take no command-line value**: they prompt without terminal echo. Automated callers can supply a complete JSON request through standard input using `octovault --json request -`. Avoid persisting secret requests in shell history or world-readable files.

GUI and CLI share the same service, records, authorization checks, asynchronous jobs, and adapters. See `man octovault` for available groups. An error returns a nonzero status; cancellation requests stop the worker and its subprocesses while preserving recovery material.

## Security and maintenance

OctoVault uses encrypted systemd credentials rather than compiling secrets into a script. Host-bound protection is used where available; TPM-backed protection depends on the computer's support and systemd configuration. Secrets still have to be available to the authorized process during use. **A fully compromised running root account can access active secrets and decrypted data.** No local unattended-backup design can honestly guarantee otherwise. The [security guide](docs/security.md) describes the boundaries.

Upgrading with a newer matching `.deb` preserves configuration, encrypted credentials, vaults, repositories, and migration recovery state. Removal and purge remove the software without intentionally deleting your data. Generated backup schedules are disabled when the program is removed. Installing the software does not create vaults or backup repositories, migrate folders, or grant access to remote servers.

## Development and release

Read [packaging and release](docs/packaging.md), [security](docs/security.md), and [recovery](docs/recovery.md). CI builds the real GUI and CLI, tests the backend and service, runs native GTK smoke checks as an ordinary user, and verifies Debian install/upgrade/removal behavior. Tests run on pull requests; public release publication occurs only after a new version is merged into `main` and the required workflow jobs pass. Existing published versions are never overwritten.

GitHub releases use the built-in workflow token and require no store or signing credentials. An optional, separate job publishes a signed APT repository through GitHub Pages when its signing key, fingerprint, and public URL are configured. Without that configuration, APT deployment is skipped and versioned GitHub downloads remain available. This is native Debian/APT distribution, not a Snap Store upload; see the [publisher setup](docs/packaging.md).

## Credits and licenses

OctoVault is licensed under [Apache-2.0](LICENSE). Its independently installed engines are [Tomb](https://github.com/dyne/Tomb) (GPL-3.0-or-later) and [Restic](https://github.com/restic/restic) (BSD-2-Clause). Desktop integration uses GTK, libadwaita, GLib, D-Bus, PolicyKit, and systemd under their respective licenses. Installed dependency notices remain in `/usr/share/doc/PACKAGE/copyright`. OctoVault orchestrates these tools and preserves their native data formats.
