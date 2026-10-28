# OctoVault

**Encrypted local vaults and independent encrypted backups, managed from a native GNOME application or the command line.** Developed by [Vast Development Method](https://www.vdm.io), part of the [OctoLeo Suite](https://github.com/octoleo).

OctoVault provides two independent tracks. Vaults protect local working folders; backups preserve recoverable versions in local, SFTP, S3-compatible, or REST repositories. A backup can also follow a vault event, but neither track requires the other.

## Install

Download the `.deb` matching **your Ubuntu release and CPU architecture** from [Releases](https://github.com/octoleo/octovault/releases). CI builds Ubuntu 26.04 amd64 packages. The initial baseline is Ubuntu 26.04 LTS with GNOME. Open the matching package in the desktop package installer, or use APT:

```bash
sha256sum --check SHA256SUMS-ubuntu26.04
sudo apt install ./octovault_1.3.0_ubuntu26.04_amd64.deb
```

APT installs the required encryption, backup, desktop, and system-integration dependencies. The checksum detects damaged or changed downloads; it is not an independent publisher signature. A downloaded Debian package does not enroll the computer into an automatic update repository.

Launch **OctoVault** from GNOME, or run `octovault-gtk`. Run both interfaces as your regular user. Running `sudo octovault` selects the root account's configuration, not your normal account; an administrator approving your request does not become the owner of your vaults or backups.

## Authorization and personal access

Opening the desktop application starts authorization for a working session. **Authorize management** uses the operating system's administrator prompt once for ordinary management operations in that session. Cancelling leaves your saved metadata and diagnostic reports available for inspection. The header shows **Management authorized**, **Personal access**, or **Read-only**. A saved automatic-unlock policy starts this authorization flow when its unlock prompts arrive, so you do not need to open the dashboard first. Ordinary background refreshes do not request administrator approval.

An administrator can open **Settings → Manage personal access…** to select an eligible local account and grant access without adding it to sudo. The enrolled account can use **Use personal access** without another administrator prompt to work with its own personal vaults and backups. Personal backup and restore processes run as that account, so they cannot read protected system files or restore into locations the account cannot write. Administrator-managed resources and forced vault closure require management authorization. Each grant or revocation requires fresh administrator approval.

Authorization belongs to this application connection and its active, local, unlocked login session. It lasts at most eight hours and ends on **End authorization**, application disconnection, desktop lock, logout, suspension, loss of the active session, service restart, access-policy change, revocation, or expiry. Ending authorization prevents new protected operations; it does not close an open vault or cancel work already running. Use the vault's lock action to close it and check its displayed state. Vault passphrases and YubiKey PIN/touch prompts remain separate from operating-system authorization.

Saved schedules do not need an open management session. Personal schedules still require the owner's administrator-approved personal grant. Revocation prevents future personal scheduled backups; running jobs finish, and saved vault safety-close policies remain in effect. Existing records retain their original execution scope: records created before this feature remain administrator-managed, and granting personal access does not silently convert them. See the [authorization model](docs/authorization.md) for the boundaries.

## Vaults

Creating a vault makes an **empty encrypted container**. It does not select, move, or protect your existing Documents folder. Give the container a **Vault file name**, choose the **Folder for the encrypted vault file**, and set its capacity in decimal GB. For example, `Document_vault` saved in `/home/alex` creates `/home/alex/Document_vault.tomb`. Your protected folders can have different names; `Documents` does not need to be renamed to `Document_vault`.

The vault card lists its protected locations separately from storage capacity. Available space is reduced by the filesystem and reserved space even before documents are added; it does not establish that Documents has been protected.

These locations serve different purposes:

| Item | What it contains | Where it is used |
| --- | --- | --- |
| Encrypted container, such as `Document_vault.tomb` | The encrypted filesystem and its protected files | Stays in the storage folder chosen during creation, whether the vault is locked or unlocked |
| Encrypted key file or image/text key carrier | The key needed to unlock that container | Stored separately; OctoVault manages its location automatically by default |
| Unlocked vault folder | The decrypted view of the container while it is open | Managed automatically under `~/.local/share/octovault/mounts/` |
| Protected original path, such as `~/Documents` | The protected folder while unlocked; a separate ordinary folder while locked | Remains the familiar path your applications use after folder protection succeeds |

OctoVault generates a new encryption key automatically. Choose a passphrase and confirm it; OctoVault remembers the encrypted key's location. Passphrases are not stored in plaintext; optional FIDO2 enrollment stores a hardware-protected encrypted copy for unlocking. The private managed key folder is accessible only to your account. Select **Reuse an existing vault key file** only when you want to reuse an existing compatible vault key or protected carrier. Capacity is converted to whole MiB for the underlying engine; filesystem overhead reduces usable space.

Choose how the generated key is protected. **Passphrase (encrypted key file)** is the default. **Key hidden in an image** asks for a cover image and saves a separate protected copy; the original image is unchanged. **Key hidden in text** generates a text carrier automatically, so no source text is needed. The image or generated text still requires your passphrase. **Software OpenPGP key** and **OpenPGP security key** are separate choices. OctoVault generates the vault key and encrypts it for the selected recipient. GnuPG handles the private-key passphrase or token PIN; touch the token when its policy requires it.

The OpenPGP security key option requires a usable OpenPGP encryption key and its matching public key in your GnuPG keyring. FIDO-only devices, including the Security Key NFC, use the separate FIDO2 option described below. An SSH security-key credential is a signing credential and cannot be selected as a Tomb key file. OctoVault checks the selected key, token when required, and an actual decryption challenge before allocating a new vault. A detected USB device or a public key alone does not establish that you can unlock it. Resolve the specific authentication error before trying creation again.

**FIDO2 security key** supports devices advertising the `hmac-secret` extension, including compatible FIDO-only security keys. Create a passphrase-protected vault, then choose **Add FIDO2 security key…** in its ready dialog or vault menu. The same menu action enrolls an existing passphrase-protected vault. Enter the current vault passphrase and the device's existing FIDO2 PIN, then touch when requested. Enrollment creates a dedicated OctoVault credential and protects an encrypted copy of that passphrase using the device. Your original passphrase remains the recovery method, and your SSH credentials are unchanged. The unlock dialog offers **Use the recovery passphrase instead** when the hardware is unavailable. After changing the passphrase, enroll FIDO2 again. See [FIDO2 recovery](docs/recovery.md#fido2-security-keys).

**Reuse an existing vault key file** refers to an existing encrypted vault key file or carrier created by Tomb or OctoVault. It does not mean that you already own a YubiKey or an OpenPGP key. Leave it unchecked when creating a new vault using your existing token; OctoVault will create and manage the vault key file for you. When reusing a vault key, OctoVault first checks that it can be decrypted.

To share a key when creating another vault, select **Use the key from another vault** and choose the existing vault. Both containers then use that encrypted key and its passphrase. The unlock dialog can **Also unlock other vaults using this key** and lists the matching vaults. This choice applies only to the current sequence; the passphrase stays in memory while those unlocks run and is cleared afterward. For vaults with different keys but the same passphrase, explicitly select **Use this passphrase for the remaining vaults** in the current sequence. A failed unlock returns to that vault's own prompt.

OctoVault chooses the folder where the unlocked contents appear automatically. This is the vault's mount location; it is separate from the folder holding the encrypted container and does not need to be configured in the creation form. An existing vault can be registered without converting its format. Automatic unlock and lock policies are available in the creation form's **Advanced options** and later in vault settings.

Keep a separate recovery copy of the generated key or carrier using **Export key**, together with the passphrase in your password manager. Automatic key management means you do not have to locate the key for everyday unlocking; the passphrase alone cannot recover a vault if its only key copy is lost. Software OpenPGP keys and hardware tokens need their own recovery arrangements.

**Offer to unlock → After desktop login** starts the unlock flow when you sign in, without opening OctoVault yourself. Any required operating-system authorization appears first; configured closed vaults then prompt in sequence. Screen unlock and waking from sleep have their own prompt settings. These offers do not store or guess passphrases, and already open vaults do not need another unlock prompt.

Closing policies are independently selectable for screen lock, logout, sleep, and shutdown. Policies run through the background services even when the application window is closed. A busy vault is reported as busy; force closing is a separate explicit setting because it can terminate applications and lose unsaved work.

Unlock dialogs show the selected vault and its required authentication. Press **Enter** after entering a passphrase to unlock. Automatic prompts let you skip the current vault or cancel the remaining requests.

To protect an existing folder or file:

1. Create the empty vault, then unlock it.
2. Close applications using the folder or file. Choose **Protect a folder or file…** and select the existing path, such as `~/Documents`.
3. OctoVault keeps the folder or file name automatically, such as `Documents`. **Advanced options** lets you choose a different name inside the vault when needed.
4. Let OctoVault finish copying, mapping, closing, reopening, and checking the files. Keep the application running until it reports completion. A temporary original remains available until the verification succeeds.
5. Work through `~/Documents` while the vault is unlocked. Lock the vault to hide that protected view; unlock it to show those same protected files at `~/Documents` again.

**Browse files** opens the protected original path when exactly one mapping is active. With multiple mappings, or none, it opens the vault folder. A new or unlinked vault may contain only `lost+found`; locking that empty container does not hide ordinary files in `~/Documents`.

OctoVault creates the folder mapping automatically. You do not need to configure bind hooks or custom scripts. Advanced script hooks run user-provided programs on vault events and are optional; they are separate from folder protection.

After successful protection, the original folder remains present when the vault locks. It starts empty. You can put separate files there while locked, but those files are **outside the encrypted vault**. Unlocking covers that ordinary folder with the protected contents; locking reveals the ordinary folder again. OctoVault does not monitor, erase, merge, or reconcile files written there. A mapped individual file similarly has a separate underlying file while locked.

If the original folder disappears or a `.octovault-staging-…` folder remains, protection has not finished normally. That staging folder is a retained, unencrypted original, not the encrypted container. Do not delete it or repeat protection on it. Open **Folder protection & recovery** for the recorded operation and follow the [interrupted protection guidance](docs/recovery.md#interrupted-folder-protection). **Resume protection…** finishes the move into the vault. **Restore original location…** cancels protection and leaves ordinary files at their original path; choose **Protect a folder or file…** again to protect those restored files.

A vault protects the working copy in its container. It does not create versioned backups or protect against losing the only container and key. Configure a separate backup plan for recoverable copies. When copying a closed vault for recovery, preserve both its `.tomb` container and its encrypted key or carrier, with the required passphrase or OpenPGP recovery arrangement.

## Backups and recovery

Choose **Create backup** for guided setup. Give the backup a name, choose an existing storage location or add one, save the generated recovery information, then select the files and folders to protect. You can select multiple files and multiple folders and add more selections before saving. New guided backups default to a daily schedule; you can choose a different schedule or run them manually. The final step offers to run the first backup immediately.

Storage can be a local directory, an S3-compatible endpoint and bucket, an SFTP server, or a REST server. Each type shows its relevant connection fields. Local storage uses a folder picker; server paths refer to folders on the remote server. Remote access is separate from the repository's encryption password. For SFTP, verify the server host-key fingerprint with the server administrator or provider.

Create a repository within that destination, or register an existing repository with its password. A new repository receives a generated password. Save the recovery information into your own password manager when it is shown: it includes the repository address and the credentials needed to access and decrypt it. The explicit **Recovery** action requires fresh authentication: your own authentication when using personal access to a personal repository, administrator authentication when using management access. Keep that copy outside this computer; encrypted local credential files alone are not a portable recovery kit.

The **Advanced options** checkbox exposes optional tuning when needed, including exclusions, filesystem boundaries, vault integration, power and network preferences, and retention. Leaving advanced options hidden uses the normal defaults for new records and preserves existing settings when editing. Retention keeps all snapshots until you choose a policy; pruning is a separate action.

Plans can run manually, on a calendar, after boot, while idle, after a configured drive arrives, or following a vault opening or closing. Schedule-specific fields appear when that schedule is selected. Calendar schedules offer hourly, daily, weekly and monthly choices; custom calendar expressions are available under Advanced options. Power and metered-network preferences apply to automatic runs. Timed plans become systemd units, so scheduling does not require leaving the GUI open. Experienced users can also manage destinations, repositories and plans separately.

For an open-vault plan, back up the accessible plaintext content: Restic encrypts it independently in the repository. For a closed-vault plan, back up the closed encrypted container. Do not copy a changing, mounted container and assume that copy is consistent. Application databases also need their own quiescing or application-consistent export when a consistent transaction boundary matters.

Browse snapshots and files, compare snapshots, search paths, restore into a chosen target, inspect repository statistics, check repository integrity, preview retention, and prune unreferenced data. These data operations require authorization even when they do not modify a repository. Prefer restoring into an empty directory before replacing working files. Personal restores use your account's permissions and cannot restore arbitrary system ownership; administrator-managed restores can preserve ownership with system privileges. Carefully review the destination and overwrite choice. Unregistering a destination, repository, or vault removes its OctoVault record, not the underlying data.

## Command line

```bash
octovault --help
octovault access status
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

The CLI starts authorization automatically when an operation requires it. It uses approved personal access when available; add `--system` to request administrator authorization for administrator-managed resources. For example, `octovault --system schedule sync` synchronizes schedules with system access. The CLI can start a PolicyKit terminal agent when needed; the operating system still decides which account may approve the request. Supported headless or remote operations request fresh administrator approval for each operation, without creating a reusable desktop authorization session.

`access status` inspects the current connection, `access users` lists eligible local accounts, and `access list` lists personal grants. `access grant --user LOGIN` and `access revoke --user LOGIN` select an account by its actual login name and require fresh administrator approval. `access unlock` and `access lock` affect only the calling connection: a standalone `octovault access unlock` exits immediately and does not authorize later CLI invocations or the desktop application. Normally run the operation you need and let the CLI authorize its own connection.

GUI and CLI share the same service, records, authorization checks, asynchronous jobs, and adapters. See `man octovault` for available groups. An error returns a nonzero status; cancellation requests stop the worker and its subprocesses while preserving recovery material.

Backend failures include the specific error and any recorded retained-file locations. Open **Technical details** or choose **Copy diagnostic report** in the error dialog. The most recent 100 private summaries remain available through **Activity → Saved diagnostic reports**, including after restarting the application. The CLI can also read them:

```bash
octovault diagnostic list
octovault --json vault list
```

These summaries describe the failed stage and recovery locations without saving passwords, PINs, decrypted keys, or raw engine output. An authentication failure before allocation creates no new container. If a later failure retained files, inspect the reported paths and vault state before retrying; do not delete the only copy of a key or container to clear an error. See [failed vault creation](docs/recovery.md#failed-vault-creation) for recovery details.

## Security and maintenance

OctoVault uses encrypted systemd credentials rather than compiling secrets into a script. Host-bound protection is used where available; TPM-backed protection depends on the computer's support and systemd configuration. Secrets still have to be available to the authorized process during use. **A fully compromised running root account can access active secrets and decrypted data.** No local unattended-backup design can honestly guarantee otherwise. The [security guide](docs/security.md) describes the boundaries.

Upgrading with a newer matching `.deb` preserves configuration, encrypted credentials, vaults, repositories, personal access grants, and migration recovery state. Existing vault and backup records remain administrator-managed unless they were explicitly created with personal scope. Removal and purge remove the software without intentionally deleting your data. Generated backup schedules are disabled when the program is removed. Installing the software does not create vaults or backup repositories, migrate folders, grant personal access, or grant access to remote servers.

## Development and release

Read [packaging and release](docs/packaging.md), [security](docs/security.md), and [recovery](docs/recovery.md). CI builds the real GUI and CLI, tests the backend and service, runs native GTK smoke checks as an ordinary user, and verifies Debian install/upgrade/removal behavior. Tests run on pull requests; public release publication occurs only after a new version is merged into `main` and the required workflow jobs pass. Existing published versions are never overwritten.

GitHub releases use the built-in workflow token and require no store or signing credentials. An optional, separate job publishes a signed APT repository through GitHub Pages when its signing key, fingerprint, and public URL are configured. Without that configuration, APT deployment is skipped and versioned GitHub downloads remain available. This is native Debian/APT distribution, not a Snap Store upload; see the [publisher setup](docs/packaging.md).

## Credits and licenses

OctoVault is licensed under [Apache-2.0](LICENSE). Its independently installed engines are [Tomb](https://github.com/dyne/Tomb) (GPL-3.0-or-later) and [Restic](https://github.com/restic/restic) (BSD-2-Clause). Desktop integration uses GTK, libadwaita, GLib, D-Bus, PolicyKit, and systemd under their respective licenses. Installed dependency notices remain in `/usr/share/doc/PACKAGE/copyright`. OctoVault orchestrates these tools and preserves their native data formats.
