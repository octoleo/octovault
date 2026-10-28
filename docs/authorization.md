# Authorization sessions and personal access

OctoVault's desktop interface and command-line client run as the signed-in user. The system service derives that user's identity from the system bus and performs a fixed set of privileged operations. Administrator authentication never changes the owner of a vault to the administrator who supplied credentials.

## Management sessions

An explicitly opened desktop application requests administrator authorization once for a working session. Cancelling leaves inspection and diagnostics available. A saved automatic-unlock policy can also start the required authorization flow when its configured vault prompts arrive. Ordinary background refreshes do not open administrator prompts. The native Polkit agent chooses eligible administrator identities according to the operating system's policy; OctoVault never reads or stores an administrator password.

A management grant belongs to the verified caller UID, its unique system-bus connection, and its actual local login session. The service verifies each operation against that grant and the operation's resource permissions. Grants end on explicit cancellation, connection loss, desktop lock or loss of the active session, logout, suspend, service restart, policy change, revocation, or expiry. The default maximum lifetime is eight hours. Desktop lock monitoring is distinct from merely checking whether any session of a user is active.

Ending management authorization prevents new privileged work. It does not claim that an open vault has been closed. Already-running jobs finish safely; saved automation has an independent execution policy. The interface displays actual vault state separately from management authorization.

The command-line client obtains authorization on the same connection as its operation. That authorization ends when the command exits; `access unlock` does not create a password cache shared with later commands. Enrolled users normally receive personal scope, and `--system` explicitly requests management scope. Headless or remote callers cannot obtain a reusable desktop grant: supported commands retain fresh per-operation administrator authentication.

## Administrator-approved personal access

An administrator can grant a selected local account personal access without adding it to sudo. The service stores the grant in root-owned state and verifies it when starting a personal session. Revocation invalidates active personal sessions.

Changing enrollment also ends current management authorization so the next operation uses the updated policy. Personal scheduled backups check enrollment when starting; revocation prevents future starts. Previously approved safety policies may still close a vault, including after its owner's desktop locks.

Personal backup and restore processes run with the owner's operating-system identity. Their source reads, repository writes, SSH connections, and restore targets therefore remain subject to that user's permissions. Credential preparation and state persistence stay in the privileged service; credentials needed by a permitted user process are temporarily accessible to that identity. This does not protect secrets against other malicious code already running as that same user or as root.

Records retain their execution scope. Existing records without a scope retain administrator-managed behavior. Personal access cannot silently upgrade a resource to system execution or modify a system-scope plan. The same checks apply when a saved plan runs unattended. Imported vault filesystems must be mounted with nodev and nosuid so their contents cannot grant privileges through devices, setuid executables, or file capabilities.

## Separate sensitive operations

Changing another account's access requires fresh administrator authorization. Recovery disclosure has its own authentication action; a personal session recovering a personal-scope repository authenticates the owner, while a management session requires administrator authentication. Forced closure and operations that affect protected system resources require administrator scope and explicit confirmation. OpenPGP and FIDO2 PIN/touch requirements remain independent of operating-system authorization. A login unlock offer does not bypass either boundary.

The interface obtains its capabilities from the service. It explains unavailable actions before submission, preserves populated forms if permission expires, and distinguishes unavailable authorization infrastructure from an ordinary refusal as far as the operating system reports that distinction.

## Verification requirements

The implementation must be tested with a real system D-Bus, Polkit, PAM, and logind using distinct administrator and non-sudo accounts. A compile-time Polkit bypass is suitable for isolated framing tests, but does not validate authorization behavior.

Required integration coverage includes one administrator authentication serving multiple operations; denial and cancellation; personal enrollment and revocation; isolation between users and bus connections; expiry and session lock; rejection of protected filesystem access and symlink escapes; safe personal backup and restore; retained execution scope in schedules; and unchanged YubiKey cryptographic authentication.
