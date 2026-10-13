# OctoVault

**Encrypted local vaults and independent encrypted backups, managed from a native GNOME application or the command line.** Developed by [Vast Development Method](https://www.vdm.io), part of the [OctoLeo Suite](https://github.com/octoleo).

OctoVault provides two independent tracks. Vaults protect local working folders; backups preserve recoverable versions in local, SFTP, S3-compatible, or REST repositories. A backup can also follow a vault event, but neither track requires the other.

## Install

Download the `.deb` matching **your Ubuntu release and CPU architecture** from [Releases](https://github.com/octoleo/octovault/releases). CI builds Ubuntu 26.04 amd64 packages. The initial baseline is Ubuntu 26.04 LTS with GNOME. Open the matching package in the desktop package installer, or use APT:

```bash
sha256sum --check SHA256SUMS-ubuntu26.04
sudo apt install ./octovault_1.1.0_ubuntu26.04_amd64.deb
```

APT installs the required encryption, backup, desktop, and system-integration dependencies. The checksum detects damaged or changed downloads; it is not an independent publisher signature. A downloaded Debian package does not enroll the computer into an automatic update repository.

Launch **OctoVault** from GNOME, or run `octovault-gtk`. Run both interfaces as your regular user: privileged operations request administrator authentication. Running `sudo octovault` selects the root account's configuration, not your normal account. In a headless terminal the CLI starts a PolicyKit terminal authentication agent when needed.

## Vaults

Create a vault by choosing its name, a folder to save it in, and its capacity in decimal GB. OctoVault creates the encrypted container in that folder and generates a new encryption key automatically. Choose a passphrase and confirm it; OctoVault remembers the encrypted key's location, never the passphrase. The private managed key folder is accessible only to your account. Select **I already have a key** only when you want to reuse an existing compatible vault key or protected carrier. Capacity is converted to whole MiB for the underlying engine.

Choose how the generated key is protected. **Passphrase-protected key** is the default. **Key hidden in an image** asks for a cover image and saves a separate protected copy; the original image is unchanged. **Key hidden in text** generates a text carrier automatically, so no source text is needed. The image or generated text still requires your passphrase. **OpenPGP key or YubiKey** lets you choose an existing software OpenPGP encryption key or a compatible token; OctoVault generates the vault key and encrypts it for that recipient. GnuPG handles any private-key passphrase or token PIN/touch prompt. Merely attaching a USB device is not authentication.

OctoVault chooses the folder where the unlocked contents appear automatically. This is the vault's mount location; it is separate from the folder holding the encrypted container and does not need to be configured in the creation form. An existing vault can be registered without converting its format. Automatic unlock and lock policies are available in the creation form's **Advanced options** and later in vault settings.

Keep a separate recovery copy of the generated key or carrier using **Export key**, together with the passphrase in your password manager. Automatic key management means you do not have to locate the key for everyday unlocking; the passphrase alone cannot recover a vault if its only key copy is lost. Software OpenPGP keys and hardware tokens need their own recovery arrangements.

Vaults can open manually, at desktop login, when a selected drive is mounted, or when a configured OpenPGP token becomes available. Closing policies are independently selectable for screen lock, logout, sleep, and shutdown. Policies run through the background services even when the application window is closed. A busy vault is reported as busy; force closing is a separate explicit setting because it can terminate applications and lose unsaved work.

To protect an existing folder or file, open the vault and choose its migration action. OctoVault retains a staging original, copies the content, creates the native mapping and original-path placeholder, then closes and reopens the vault to verify the mapping. It removes staging only after successful verification. Interrupted migrations retain recovery material and remain visible for recovery. Do not manually delete that staging material until the operation has completed or you have recovered it.

The ordinary directory or file underneath a closed vault's mapping remains independent and writable. OctoVault does not monitor, erase, merge, or reconcile content written there while the vault is closed. Reopening the vault temporarily covers that underlying content with the encrypted contents; closing reveals it again.

## Backups and recovery

Choose **Create backup** for guided setup. Give the backup a name, choose an existing storage location or add one, save the generated recovery information, then select the files and folders to protect. You can select multiple files and multiple folders and add more selections before saving. New guided backups default to a daily schedule; you can choose a different schedule or run them manually. The final step offers to run the first backup immediately.

Storage can be a local directory, an S3-compatible endpoint and bucket, an SFTP server, or a REST server. Each type shows its relevant connection fields. Local storage uses a folder picker; server paths refer to folders on the remote server. Remote access is separate from the repository's encryption password. For SFTP, verify the server host-key fingerprint with the server administrator or provider.

Create a repository within that destination, or register an existing repository with its password. A new repository receives a generated password. Save the recovery information into your own password manager when it is shown: it includes the repository address and the credentials needed to access and decrypt it. The explicit **Recovery** action reveals it again after administrator authentication. Keep that copy outside this computer; encrypted local credential files alone are not a portable recovery kit.

The **Advanced options** checkbox exposes optional tuning when needed, including exclusions, filesystem boundaries, vault integration, power and network preferences, and retention. Leaving advanced options hidden uses the normal defaults for new records and preserves existing settings when editing. Retention keeps all snapshots until you choose a policy; pruning is a separate action.

Plans can run manually, on a calendar, after boot, while idle, after a configured drive arrives, or following a vault opening or closing. Schedule-specific fields appear when that schedule is selected. Calendar schedules offer hourly, daily, weekly and monthly choices; custom calendar expressions are available under Advanced options. Power and metered-network preferences apply to automatic runs. Timed plans become systemd units, so scheduling does not require leaving the GUI open. Experienced users can also manage destinations, repositories and plans separately.

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

For a new passphrase-protected vault, the CLI can also generate and manage the key:

```bash
octovault vault create --name Personal --directory "$HOME" --size-gb 10 --password
```

`--password` prompts securely. To reuse a key, add `--use-existing-key --key-file /absolute/path/to/key`. New image protection uses `--auth image --image-source /absolute/path/to/cover.jpg`; text uses `--auth text`. A new OpenPGP-protected key uses `--auth gpg --recipient FINGERPRINT` and GnuPG's authentication instead of `--password`. Advanced callers may use `--file` for an explicit container filename instead of `--directory`.

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
