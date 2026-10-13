# Recovery and portability

## Before a failure

Save each repository's recovery information outside this computer. Preserve the repository address, endpoint and bucket or server path, region when applicable, remote credentials, SSH private key and its passphrase when applicable, trusted server fingerprint, and repository encryption password. A backup password and its remote access key have different purposes; both may be needed.

Keep an independently stored copy of a vault's key or supported key carrier and its passphrase. For hardware-token authentication, keep your own tested OpenPGP recovery arrangement. OctoVault cannot recreate a lost private key, hardware token, or passphrase. Do not put the only vault key inside the vault that it opens.

## Restore on another computer

Install OctoVault and its dependencies. Recreate the destination using the saved remote credentials, then import the existing repository with its saved repository password. List snapshots, choose files, and restore into a new empty directory. Check the restored contents and ownership before replacing existing files. This process does not require the original machine's encrypted credential store.

The underlying repository can also be accessed directly with Restic and the saved credentials. Likewise, a vault can be opened directly with a compatible Tomb version and its key. OctoVault records add management information; they are not a proprietary data format required to decrypt the content.

## Interrupted folder migration

Do not delete the staging original or overwrite either side. OctoVault records the migration stage and retains the original until it has copied the data, installed the mapping, reopened the vault, and verified the mounted result. Use the migration recovery action to inspect and finish or roll back the recorded operation. If a close or reopen failed because files are busy or credentials were unavailable, resolve that condition first.

When the vault is closed, its mapped original path is an ordinary underlying folder or file. New content written there is independent of the content in the vault. OctoVault deliberately does not delete or merge it. Review both views independently before any manual reconciliation.

## Busy vaults

Close applications using the vault and retry normal locking. Forced locking is available only by explicit request or saved force-close policy, and may terminate processes. Check the actual mounted state after a failed close; a failed command must not be interpreted as a securely closed vault. Native engine tools remain available for diagnosis and recovery.

## Upgrades, removal, and machine migration

Package upgrades retain private state under `/var/lib/octovault` and do not intentionally close vaults or remove repositories. Installing a newer compatible package upgrades the application through Debian's package manager. Removing or purging OctoVault retains encrypted data, secrets, and configuration. Generated backup timers are disabled so they do not repeatedly invoke missing software; reinstall and synchronize schedules to restore them.

Copying `/var/lib/octovault` alone is not a portable credentials migration. Encrypted systemd credentials can be bound to the original host and TPM. Use your saved recovery information to register repositories on the replacement system. If you intentionally migrate the original operating system and its host credential keys, assess that migration's security implications separately.

Deleting an OctoVault registration is different from deleting its actual container or remote repository. Verify which action you are taking before removing data. No recovery procedure can recover deliberately deleted repository data without another surviving copy.
