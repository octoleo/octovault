# Recovery and portability

## Before a failure

Save each repository's recovery information outside this computer. Preserve the repository address, endpoint and bucket or server path, region when applicable, remote credentials, SSH private key and its passphrase when applicable, trusted server fingerprint, and repository encryption password. A backup password and its remote access key have different purposes; both may be needed.

Keep an independently stored copy of a vault's key or supported key carrier and its passphrase. For hardware-token authentication, keep your own tested OpenPGP recovery arrangement. OctoVault cannot recreate a lost private key, hardware token, or passphrase. Do not put the only vault key inside the vault that it opens.

Keys generated during creation are stored under your private `~/.local/share/octovault/keys/` directory; the vault record remembers the exact path. Use **Export key** to save a recovery copy independently of this computer. For an image key, preserve the generated carrier, not just the original cover image. For a text key, preserve the generated text and its word map. The application never saves your vault-key passphrase. Remembering that passphrase is sufficient for everyday unlocking while the key remains available, but cannot replace a lost key during recovery. A software OpenPGP private key is supported as well as a compatible hardware token.

Text key carriers also require the exact word map used to create them. OctoVault includes its original 66-word map at `/usr/share/octovault/cloak-ciphers/words`; preserve a copy with your recovery materials, especially when using a custom map. This stable data file only translates the already encrypted key into words. The distribution's Tomb helpers perform the conversion, and the key still requires its passphrase.

## Authorization and recovery credentials

Operating-system authorization and encryption credentials serve different purposes. **Authorize management** permits administrative operations during the application's session; it cannot replace a vault passphrase, YubiKey PIN, OpenPGP private key, or repository password. An administrator's approval does not transfer ownership of your data to that administrator. The **Recovery** action asks for fresh authentication before disclosing stored repository credentials: your own authentication when using personal access to a personal repository, administrator authentication when using management access.

If the header shows **Read-only** after a lock, session change, or expiry, authorize again before attempting a protected operation. Populated setup forms retain their nonsecret entries. Ending management authorization does not close an open vault or cancel work already running. Use the vault's lock action and check its actual state; saved safety-close policies remain independent of the header's authorization status.

A revoked personal grant prevents new personal sessions and future personal scheduled backups, but does not delete containers, repositories, or recovery material. Ask an administrator to review the account's access. Already-running jobs finish and saved vault safety-close policies remain in effect. Records created before personal access was introduced remain administrator-managed; enabling personal access does not convert them. Use management authorization for those records, or `--system` for the CLI operation that needs them.

## Failed vault creation

Read the specific error and failed stage before retrying. OctoVault checks OpenPGP authentication before allocating a new container: a missing public key, unavailable token, failed PIN prompt, or unsuccessful decryption challenge must be resolved first. **Software OpenPGP key** uses your local OpenPGP private key; **YubiKey / OpenPGP security key** requires the matching OpenPGP encryption key on the connected token. Having used a YubiKey for web sign-in does not by itself configure its OpenPGP application.

For a new vault, leave **Reuse an existing vault key file** unchecked even if you already own the token. That checkbox means that you are supplying an existing encrypted vault key file or carrier, not an existing OpenPGP identity. A token's private key decrypts the vault key file; both are needed to open the vault.

Use **Technical details** or **Copy diagnostic report** in the error dialog. Backend failure summaries are stored privately under `/var/lib/octovault/users/UID/diagnostics/`, where `UID` is your account's numeric user ID. The most recent 100 reports are available through **Activity → Saved diagnostic reports**. The application exposes them through the service; run the following as your regular user to review them and the registered vaults:

```bash
octovault diagnostic list
octovault --json vault list
```

A summary records the error code, readable explanation, failed stage when available, and any known retained-file paths. It does not contain the PIN, passphrase, private key, decrypted vault key, or raw engine output. Its location is a diagnostic report, not a replacement recovery key. Service logs in the system journal can help with service startup or authorization problems, but are not an archive of raw Tomb or GnuPG errors.

If authentication failed before allocation, correct the reported problem and retry. If creation already allocated files, keep the reported container and key until you have checked their state. The container is in the folder selected during setup; automatically managed encrypted keys are under `~/.local/share/octovault/keys/`. A vault marked incomplete has not completed initialization. Retrying the same name will not overwrite an existing container, and importing an uninitialized container cannot make it a usable vault. Do not delete or rename files as a blind retry procedure.

Older versions displayed “Existing recovery material has been retained” for unrelated validation errors, even when no recovery files had been created. That message alone does not establish that any files exist or that a diagnostic report was saved. Inspect the selected storage folder, the managed key folder, and the vault list before deciding how to recover an earlier attempt.

## Restore on another computer

Install OctoVault and its dependencies. Obtain management authorization or have an administrator grant your local account personal access. Recreate the destination using the saved remote credentials, then import the existing repository with its saved repository password. List snapshots, choose files, and restore into a new empty directory. Check the restored contents and ownership before replacing existing files. This process does not require the original machine's encrypted credential store.

Personal repositories and their destinations and plans must all use personal scope. Personal restore runs as your account and can write only where that account is allowed; it cannot restore arbitrary system ownership. Restoring protected system files requires an administrator-managed repository and system authorization. Existing personal records keep their scope even when operated from a management session.

The underlying repository can also be accessed directly with Restic and the saved credentials. Likewise, a vault can be opened directly with a compatible Tomb version and its key. OctoVault records add management information; they are not a proprietary data format required to decrypt the content.

## Interrupted folder migration

Do not delete the staging original or overwrite either side. OctoVault records the migration stage and retains the original until it has copied the data, installed the mapping, reopened the vault, and verified the mounted result. Use the migration recovery action to inspect and finish or roll back the recorded operation. If a close or reopen failed because files are busy or credentials were unavailable, resolve that condition first.

When the vault is closed, its mapped original path is an ordinary underlying folder or file. New content written there is independent of the content in the vault. OctoVault deliberately does not delete or merge it. Review both views independently before any manual reconciliation.

## Busy vaults

Close applications using the vault and retry normal locking. Requesting forced locking or enabling its policy requires management authorization and may terminate processes. An administrator-approved saved force-close policy can run independently of an open management session. Personal access cannot enable that policy or request forced closure. Check the actual mounted state after a failed close; a failed command must not be interpreted as a securely closed vault. Native engine tools remain available for diagnosis and recovery.

## Upgrades, removal, and machine migration

Package upgrades retain private state under `/var/lib/octovault`, including personal access grants, and do not intentionally close vaults or remove repositories. A restarted service requires a new authorization session. Existing record execution scope remains unchanged; records without an explicit scope retain system access. Installing a newer compatible package upgrades the application through Debian's package manager. Removing or purging OctoVault retains encrypted data, secrets, and configuration. Generated backup timers are disabled so they do not repeatedly invoke missing software; reinstall and synchronize schedules to restore them.

Copying `/var/lib/octovault` alone is not a portable credentials migration. Encrypted systemd credentials can be bound to the original host and TPM. Use your saved recovery information to register repositories on the replacement system. If you intentionally migrate the original operating system and its host credential keys, assess that migration's security implications separately.

Personal access grants match local account names and numeric user IDs. Have an administrator review enrollment on the replacement computer; copying an access-policy file is not a substitute for checking that the intended local accounts exist and have the correct permissions.

Deleting an OctoVault registration is different from deleting its actual container or remote repository. Verify which action you are taking before removing data. No recovery procedure can recover deliberately deleted repository data without another surviving copy.
