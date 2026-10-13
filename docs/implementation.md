# OctoVault 1.0.0 implementation contract

OctoVault is a native GNOME vault and independent backup manager by Vast Development Method, part of the OctoLeo Suite.

## Accepted behaviour

- Vault size input is decimal GB; convert internally to whole MiB.
- Migration retains a staging original, copies into the open vault, writes native bind-hooks, creates empty original placeholders, closes and reopens, verifies mounted content, then deletes staging only on successful verification. Interrupted or failed verification retains recovery material.
- Closed-vault underlying locations are independent writable contents. Never monitor, block, erase or reconcile their changes.
- Tests belong in CI. Hardware/manual testing is optional user work, not an approval gate.
- Tomb and Restic remain dependencies and portable recovery formats. Secrets are encrypted using systemd credentials; no SHC security claims.

## Runtime contract

D-Bus service `io.vdm.OctoVault1`, object `/io/vdm/OctoVault1`, interface `io.vdm.OctoVault1`. Methods `Submit(s request)->s job_id`, `GetJob(s job_id)->s job_json`, `Cancel(s job_id)->b`. The service derives UID from the sender, authorizes mutating operations with Polkit, and invokes `/usr/libexec/octovault/backend UID` with the complete request on stdin. Only the daemon chooses UID. Service jobs are asynchronous and results are private to their owner. Never put secrets in argv/logs. Completed results containing secrets expire.

Worker request: `{"op":"vault.list","params":{}}`. Response: `{"ok":true,"data":...}` or `{"ok":false,"error":{"code":"...","message":"..."}}`; one compact JSON document on stdout. Progress on stderr is JSON `{"stage":"...","message":"...","percent":0}` without secrets. Workers return nonzero on errors. All external commands use arrays and a fixed PATH, never eval.

State root `/var/lib/octovault/users/UID`; collections `vaults`, `destinations`, `repositories`, `plans`, with UUID-like safe IDs matching `[a-zA-Z0-9_-]{1,64}`. JSON files are root-owned mode 0600, directories 0700. Root service jobs and backend operations run with per-user locking. Parameters must never supply UID/home or executable overrides. Names and original paths may contain spaces. State schema version 1; each record has `id`, `name`, `schema_version:1`, `created_at`, `updated_at`.

Shared Bash `lib/octovault/common.sh`: worker variables `OV_UID`, `OV_USER`, `OV_HOME`, `OV_ROOT`, `OV_PARAMS`, `OV_OP`; functions `ov_fail CODE MESSAGE`, `ov_ok JSON`, `ov_progress STAGE MESSAGE [PERCENT]`, `ov_param NAME [DEFAULT]`, `ov_require NAME`, `ov_id ID`, `ov_load COLLECTION ID` (sets OV_RECORD), `ov_save COLLECTION ID JSON`, `ov_list COLLECTION`, `ov_now`, `ov_new_id`, `ov_as_user COMMAND...`, `ov_run COMMAND...` (stdout diverted to stderr), `ov_credential_set NAME VALUE`, `ov_credential_get NAME` (stdout plaintext, callers never log). Backend sources root-owned modules, routes vault.* and migration.* to `ov_vault_dispatch`, destination.*, repository.*, backup.* to `ov_backup_dispatch`, event.* / schedule.* to `ov_event_dispatch`.

## Objects and operations

Vault fields: name,file,key_file,auth (`key`,`gpg`,`image`,`text`),recipient,cipher_file,mountpoint,size_gb,open_on (`manual`,`login`,`drive`,`token`),drive_uuid,close_on (array of `screen-lock`,`logout`,`sleep`,`shutdown`),force_close boolean,hooks object. Native bind-hooks remain in vault.
`vault.list`, `vault.get {id}`, `vault.create` (fields above), `vault.import` (same fields without size), `vault.open {id}`, `vault.close {id,force}`, `vault.update {id,...fields}`, `vault.remove {id}` (unregister only), `vault.resize {id,size_gb}`, `vault.passwd {id}`, `vault.setkey {id,new_key_file}`, `vault.key-export {id,format,output}`, `vault.index {id}`, `vault.search {id,query}`, `migration.add {id,source,relative}`, `migration.list {id}`, `migration.recover {id,migration_id,action}`.

Destination fields: name,type (`s3`,`sftp`,`local`,`rest`),endpoint,region,bucket,host,port,user,path,host_fingerprint. Secrets supplied only in params: access_key,secret_key,ssh_private_key,ssh_passphrase,rest_username,rest_password. Encrypted credential references persisted, never plaintext secrets.
`destination.list`, `.get {id}`, `.save` (optional id), `.test {id}`, `.remove {id}`.
Repository fields: name,destination_id,path,repository,credential_id,repository_id. `repository.list`, `.create {name,destination_id,path}`, `.import {name,destination_id,path,password}`, `.recovery {id}` (explicit authorized reveal), `.check {id,read_data}`, `.stats {id}`, `.snapshots {id}`, `.files {id,snapshot,path}`, `.find {id,pattern}`, `.diff {id,snapshot_a,snapshot_b}`, `.restore {id,snapshot,target,include,overwrite}`, `.forget {id,keep_daily,keep_weekly,keep_monthly,dry_run}`, `.prune {id}`, `.password {id,password}`, `.copy {id,target_id,snapshot}`, `.remove {id}` (unregister only).
Plan fields: name,repository_id,sources (array),excludes (array),one_file_system boolean,vault_id,vault_mode (`none`,`open-files`,`closed-container`),trigger (`manual`,`calendar`,`boot`,`idle`,`vault-open`,`vault-close`,`drive`),calendar,boot_delay_sec,idle_sec,drive_uuid,on_battery boolean,metered boolean,retention object.
`backup.list`, `.save` (optional id), `.remove {id}`, `.run {id}`, `.history {id}`.
`schedule.sync` rebuilds owner timers from approved plans; `event.handle {event,id}` is internal daemon-only authorization; session sends `event.session {event}` for login/screen-lock/logout/idle/drive/token; backend validates policies. Event completion must verify actual mount/device state.

GUI offers native forms for all public operations, readable JSON-free lists/details, cancellable jobs and recovery reveal/copy. CLI maps `GROUP ACTION --hyphenated-key VALUE` to underscore keys in params; supports arrays through repeated source/include/exclude/close-on options and explicit JSON request input. `--json` emits machine output; errors preserve nonzero exit. Passwords/secrets prompt securely or come from stdin JSON, not secret CLI values.
