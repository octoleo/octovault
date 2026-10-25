/* SPDX-License-Identifier: Apache-2.0 */
/* Included by daemon.c. Authorization belongs to the service. */
#include "access-store.c"
#include "access-recovery.c"

typedef struct {
    guint32 uid;
    gchar *scope, *session_path, *session_id;
    gint64 expires, expires_at;
    guint64 policy_revision, sender_revision, session_revision;
} AccessLease;
static GHashTable *access_leases, *access_sender_revisions, *access_session_revisions;
static guint64 access_policy_revision = 1;
static guint64 access_transition_revision;
static GFileMonitor *access_monitor;
static guint access_subscriptions[5];
static const gchar *access_managed_operations[] = {
    "vault.create", "vault.import", "vault.open", "vault.close", "vault.update", "vault.resize",
    "vault.passwd", "vault.setkey", "vault.key-export", "vault.index", "vault.search", "vault.remove",
    "migration.add", "migration.recover", "destination.save", "destination.test", "destination.remove",
    "repository.create", "repository.import", "repository.check", "repository.restore", "repository.forget",
    "repository.prune", "repository.password", "repository.copy", "repository.remove", "repository.recovery",
    "repository.snapshots", "repository.files", "repository.find", "repository.diff", "repository.stats",
    "backup.save", "backup.run", "backup.remove", "schedule.sync", NULL
};
static const gchar *access_read_operations[] = {
    "vault.list", "vault.get", "vault.auth-check", "destination.list", "destination.get",
    "repository.list", "repository.get", "backup.list", "backup.get", "backup.history", "migration.list",
    "diagnostic.list", "diagnostic.get", "system.info", "access.status", "access.unlock", "access.lock", "access.users", NULL
};
static gboolean access_contains(const gchar *op, const gchar *const *list)
{
    for (guint i = 0; list[i]; i++) if (g_str_equal(op, list[i])) return TRUE;
    return FALSE;
}
static void access_lease_free(gpointer data)
{
    AccessLease *lease = data;
    g_free(lease->scope); g_free(lease->session_path); g_free(lease->session_id); g_free(lease);
}
static void access_runtime_init(void)
{
    if (access_leases) return;
    access_leases = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, access_lease_free);
    access_sender_revisions = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, g_free);
    access_session_revisions = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, g_free);
}
static guint64 access_revision(GHashTable *table, const gchar *key)
{
    guint64 *revision = table && key ? g_hash_table_lookup(table, key) : NULL;
    return revision ? *revision : 0;
}
static void access_bump(GHashTable *table, const gchar *key)
{
    if (!key) return;
    guint64 *revision = g_new(guint64, 1);
    *revision = access_revision(table, key) + 1;
    g_hash_table_replace(table, g_strdup(key), revision);
}
static AccessLease *access_lease_for(const gchar *sender, guint32 uid)
{
    if (connection && (!access_monitor || g_file_monitor_is_cancelled(access_monitor))) return NULL;
    AccessLease *lease = access_leases && sender ? g_hash_table_lookup(access_leases, sender) : NULL;
    if (!lease || lease->uid != uid || lease->expires <= g_get_monotonic_time() ||
        lease->policy_revision != access_policy_revision ||
        lease->sender_revision != access_revision(access_sender_revisions, sender) ||
        lease->session_revision != access_revision(access_session_revisions, lease->session_path)) return NULL;
    GError *error = NULL;
    JsonObject *store = access_store_load(&error);
    gboolean entitled = store && (g_str_equal(lease->scope, "system") || access_store_granted(store, uid));
    if (store) json_object_unref(store);
    g_clear_error(&error);
    return entitled ? lease : NULL;
}
static gboolean access_job_valid(Job *j)
{
    if (j->auth_invalidated && (j->requires_session || j->one_shot)) return FALSE;
    if (j->one_shot) return j->policy_revision == access_policy_revision &&
        j->sender_revision == access_revision(access_sender_revisions, j->sender) &&
        j->session_revision == access_revision(access_session_revisions, j->session_path);
    if (!j->requires_session) return TRUE;
    AccessLease *lease = access_lease_for(j->sender, j->uid);
    return lease && g_str_equal(lease->scope, j->scope) && !g_strcmp0(lease->session_path, j->session_path) &&
        j->policy_revision == access_policy_revision &&
        j->sender_revision == access_revision(access_sender_revisions, j->sender) &&
        j->session_revision == access_revision(access_session_revisions, j->session_path);
}
static gboolean access_result_visible(Job *j, Pending *p)
{
    if (j->one_shot && !g_strcmp0(j->sender, p->sender)) return access_job_valid(j);
    if (j->one_shot && g_str_equal(j->op, "repository.recovery")) return FALSE;
    if (!j->requires_session && !j->one_shot) return TRUE;
    AccessLease *lease = access_lease_for(p->sender, p->uid);
    if (!lease || (g_str_equal(j->scope, "system") && !g_str_equal(lease->scope, "system"))) return FALSE;
    if (g_str_equal(j->op, "repository.recovery")) return !g_strcmp0(j->sender, p->sender) && access_job_valid(j);
    return TRUE;
}
static void access_protect_result(Job *j)
{
    if (j->result && (j->requires_session || j->one_shot) && g_str_equal(j->op, "repository.recovery") && !access_job_valid(j)) {
        json_node_unref(j->result);
        j->result = failure("AUTH_REVOKED", "Authorization ended. Request recovery information again after unlocking OctoVault.");
    }
}
static void access_clear_recovery(void)
{
    if (!jobs) return;
    GHashTableIter iter; gpointer value;
    g_hash_table_iter_init(&iter, jobs);
    while (g_hash_table_iter_next(&iter, NULL, &value)) access_protect_result(value);
}
static void access_revoke_sender(const gchar *sender)
{
    access_bump(access_sender_revisions, sender);
    g_hash_table_remove(access_leases, sender);
    if (jobs) {
        GHashTableIter iter; gpointer value; g_hash_table_iter_init(&iter, jobs);
        while (g_hash_table_iter_next(&iter, NULL, &value)) {
            Job *j = value; if (!g_strcmp0(j->sender, sender)) j->auth_invalidated = TRUE;
        }
    }
    access_clear_recovery();
}
static void access_revoke_session(const gchar *path)
{
    access_transition_revision++;
    if (g_hash_table_contains(access_session_revisions, path)) access_bump(access_session_revisions, path);
    GHashTableIter iter; gpointer value;
    g_hash_table_iter_init(&iter, access_leases);
    while (g_hash_table_iter_next(&iter, NULL, &value))
        if (!g_strcmp0(((AccessLease *)value)->session_path, path)) g_hash_table_iter_remove(&iter);
    if (jobs) {
        g_hash_table_iter_init(&iter, jobs);
        while (g_hash_table_iter_next(&iter, NULL, &value)) {
            Job *j = value; if (!g_strcmp0(j->session_path, path)) j->auth_invalidated = TRUE;
        }
    }
    access_clear_recovery();
}
static void access_revoke_all(void)
{
    access_policy_revision++;
    g_hash_table_remove_all(access_leases);
    access_clear_recovery();
}
static JsonNode *access_success(JsonObject *data)
{
    JsonObject *root = json_object_new();
    json_object_set_boolean_member(root, "ok", TRUE);
    json_object_set_object_member(root, "data", data);
    JsonNode *node = json_node_new(JSON_NODE_OBJECT); json_node_take_object(node, root);
    return node;
}
static void access_reply(Pending *p, JsonNode *result)
{
    p->immediate_result = result; p->requires_session = FALSE; p->one_shot = FALSE; submit_authorized(p);
}
static void access_error(Pending *p, const gchar *code, const gchar *message)
{
    access_reply(p, failure(code, message));
}
static JsonObject *access_params(Pending *p)
{
    JsonParser *parser = json_parser_new(); JsonObject *params = NULL;
    if (json_parser_load_from_data(parser, p->request, -1, NULL))
        params = json_object_ref(json_object_get_object_member(json_node_get_object(json_parser_get_root(parser)), "params"));
    g_object_unref(parser); return params;
}
static const gchar *access_string(JsonObject *object, const gchar *key)
{
    JsonNode *node = object ? json_object_get_member(object, key) : NULL;
    return node && JSON_NODE_HOLDS_VALUE(node) && json_node_get_value_type(node) == G_TYPE_STRING ? json_node_get_string(node) : "";
}
static gboolean access_pending_current(Pending *p)
{
    return g_hash_table_contains(access_sender_revisions, p->sender) &&
        p->transition_revision == access_transition_revision && p->policy_revision == access_policy_revision &&
        p->sender_revision == access_revision(access_sender_revisions, p->sender) &&
        (!p->auth_session_path || (g_hash_table_contains(access_session_revisions, p->auth_session_path) &&
         p->session_revision == access_revision(access_session_revisions, p->auth_session_path)));
}

static JsonObject *access_status_data(Pending *p, JsonObject *store)
{
    AccessLease *lease = p->session_active ? access_lease_for(p->sender, p->uid) : NULL;
    if (lease && g_strcmp0(lease->session_path, p->session_path)) lease = NULL;
    JsonObject *data = json_object_new();
    json_object_set_boolean_member(data, "authorized", lease != NULL);
    json_object_set_string_member(data, "scope", lease ? lease->scope : "none");
    if (lease) json_object_set_int_member(data, "expires_at", lease->expires_at);
    else json_object_set_null_member(data, "expires_at");
    json_object_set_boolean_member(data, "delegated_personal", access_store_granted(store, p->uid));
    json_object_set_boolean_member(data, "available", p->session_active);
    json_object_set_string_member(data, "reason", p->availability_reason ? p->availability_reason : "");
    json_object_set_boolean_member(data, "can_request_system", p->session_active && p->can_request_system);
    json_object_set_int_member(data, "max_duration_seconds", access_store_duration(store));
    JsonArray *capabilities = json_array_new();
    for (guint i = 0; access_read_operations[i]; i++) json_array_add_string_element(capabilities, access_read_operations[i]);
    if (lease) {
        for (guint i = 0; access_managed_operations[i]; i++) json_array_add_string_element(capabilities, access_managed_operations[i]);
        if (g_str_equal(lease->scope, "system")) {
            json_array_add_string_element(capabilities, "access.list");
            json_array_add_string_element(capabilities, "access.grant");
            json_array_add_string_element(capabilities, "access.revoke");
        }
    }
    json_object_set_array_member(data, "capabilities", capabilities);
    return data;
}
static void access_send_status(Pending *p)
{
    GError *error = NULL;
    JsonObject *store = access_store_load(&error);
    if (!store) { g_clear_error(&error); access_error(p, "ACCESS_STORAGE_ERROR", "The administrator access settings could not be read safely."); return; }
    JsonObject *status = access_status_data(p, store);
    json_object_unref(store); access_reply(p, access_success(status));
}
static void access_session_ready(Pending *p);
static void access_resolve_session(Pending *p);

static void access_polkit_done(GObject *bus, GAsyncResult *result, gpointer user_data)
{
    Pending *p = user_data;
    GError *error = NULL;
    GVariant *reply = g_dbus_connection_call_finish(G_DBUS_CONNECTION(bus), result, &error);
    gboolean authorized = FALSE, challenge = FALSE, dismissed = FALSE;
    if (reply) {
        GVariant *details = NULL; const gchar *dismissal = NULL;
        g_variant_get(reply, "((bb@a{ss}))", &authorized, &challenge, &details);
        if (g_variant_lookup(details, "polkit.dismissed", "&s", &dismissal)) dismissed = g_str_equal(dismissal, "true");
        g_variant_unref(details); g_variant_unref(reply);
    }
    if (!strcmp(p->op, "access.status")) {
        p->can_request_system = authorized || challenge;
        if (error && !p->availability_reason) p->availability_reason = g_strdup("The system authorization service is unavailable.");
        g_clear_error(&error); access_send_status(p); return;
    }
    if (!access_pending_current(p)) {
        g_clear_error(&error); access_error(p, "AUTH_REVOKED", "Authorization was cancelled because the session or access policy changed."); return;
    }
    if (!authorized) {
        gchar *remote = error ? g_dbus_error_get_remote_error(error) : NULL;
        const gchar *code = "AUTH_DENIED", *message = "Authentication was not authorized.";
        if (dismissed || (remote && g_str_has_suffix(remote, ".Cancelled"))) {
            code = "AUTH_CANCELLED"; message = "Authentication was cancelled. No authorization was retained.";
        } else if (error && (g_strrstr(error->message, "No authentication agent found") ||
                   (remote && g_str_has_suffix(remote, ".NoAuthenticationAgent")))) {
            code = "AUTH_AGENT_UNAVAILABLE"; message = "The desktop authentication agent is unavailable. Start your desktop's PolicyKit agent and try again.";
        } else if (error) {
            code = "AUTH_SERVICE_UNAVAILABLE"; message = "The system authorization service could not complete authentication.";
        } else if (challenge) {
            code = "AUTH_REQUIRED"; message = "Authentication was not completed. Unlock OctoVault when you are ready to authenticate.";
        }
        g_free(remote); g_clear_error(&error); access_error(p, code, message); return;
    }
    g_clear_error(&error); p->auth_completed = TRUE;
    access_resolve_session(p);
}
static void access_check_polkit(Pending *p, const gchar *action, gboolean interactive)
{
    g_free(p->auth_action); p->auth_action = g_strdup(action);
    if (!p->auth_session_path) p->auth_session_path = g_strdup(p->session_path);
    GVariantBuilder subject, details;
    g_variant_builder_init(&subject, G_VARIANT_TYPE("a{sv}"));
    g_variant_builder_add(&subject, "{sv}", "name", g_variant_new_string(p->sender));
    g_variant_builder_init(&details, G_VARIANT_TYPE("a{ss}"));
    g_dbus_connection_call(connection, "org.freedesktop.PolicyKit1", "/org/freedesktop/PolicyKit1/Authority",
        "org.freedesktop.PolicyKit1.Authority", "CheckAuthorization",
        g_variant_new("((s@a{sv})s@a{ss}us)", "system-bus-name", g_variant_builder_end(&subject),
            action, g_variant_builder_end(&details), interactive ? 1u : 0u, ""),
        G_VARIANT_TYPE("((bba{ss}))"), G_DBUS_CALL_FLAGS_NONE, interactive ? 180000 : 5000, NULL, access_polkit_done, p);
}
static void access_session_failed(Pending *p, const gchar *message)
{
    p->session_active = FALSE;
    g_free(p->availability_reason); p->availability_reason = g_strdup(message);
    access_revoke_sender(p->sender);
    if (!strcmp(p->op, "access.status") || !strcmp(p->op, "access.lock")) access_send_status(p);
    else access_error(p, "AUTH_SESSION_UNAVAILABLE", message);
}
/* Headless/SSH callers retain explicit per-operation PolicyKit authorization.
 * They never receive a reusable lease; a locked local desktop cannot use this. */
static void access_one_shot(Pending *p)
{
    if (!access_contains(p->op, access_managed_operations)) {
        access_session_failed(p, "Reusable authorization requires an active, unlocked local login session."); return;
    }
    p->one_shot = TRUE;
    if (!p->auth_completed) {
        p->session_revision = access_revision(access_session_revisions, p->session_path);
        access_check_polkit(p, !strcmp(p->op, "repository.recovery") ? "io.vdm.octovault.recovery" : "io.vdm.octovault.manage", TRUE);
        return;
    }
    if (!access_pending_current(p)) { access_error(p, "AUTH_REVOKED", "Authorization ended before the operation could start."); return; }
    g_free(p->scope); p->scope = g_strdup("system"); submit_authorized(p);
}
static gboolean access_closing_event(Pending *p)
{
    if (strcmp(p->op, "event.session")) return FALSE;
    JsonObject *params = access_params(p); const gchar *event = access_string(params, "event");
    gboolean closing = !strcmp(event, "logout") || !strcmp(event, "shutdown") || !strcmp(event, "screen-lock") || !strcmp(event, "sleep");
    if (params) json_object_unref(params);
    return closing;
}
static gboolean access_session_properties(Pending *p, GVariant *properties)
{
    GVariant *user = g_variant_lookup_value(properties, "User", G_VARIANT_TYPE("(uo)"));
    const gchar *id = NULL, *state = NULL; gboolean active = FALSE, locked = TRUE; guint32 uid = G_MAXUINT32;
    if (user) { const gchar *path; g_variant_get(user, "(u&o)", &uid, &path); g_variant_unref(user); }
    gboolean valid = uid == p->uid && g_variant_lookup(properties, "Id", "&s", &id) && id && *id &&
        g_variant_lookup(properties, "Active", "b", &active) &&
        g_variant_lookup(properties, "LockedHint", "b", &locked) &&
        g_variant_lookup(properties, "State", "&s", &state) &&
        g_variant_lookup(properties, "Remote", "b", &p->session_remote);
    gboolean closing_event = valid && access_closing_event(p);
    if (!valid || ((!active || locked || strcmp(state, "active")) && !closing_event)) return FALSE;
    g_free(p->session_id); p->session_id = g_strdup(id); p->session_active = TRUE;
    return TRUE;
}
static void access_properties_done(GObject *bus, GAsyncResult *result, gpointer user_data)
{
    Pending *p = user_data;
    GVariant *reply = g_dbus_connection_call_finish(G_DBUS_CONNECTION(bus), result, NULL), *properties = NULL;
    gboolean valid = FALSE;
    if (reply) { g_variant_get(reply, "(@a{sv})", &properties); valid = access_session_properties(p, properties); g_variant_unref(properties); g_variant_unref(reply); }
    if (!valid) { access_session_failed(p, "OctoVault authorization requires your active, unlocked login session."); return; }
    /* Saved-policy closing events remain useful when the very lock/sleep
     * transition they report invalidates in-flight authorization requests. */
    if ((!access_pending_current(p) && !access_closing_event(p)) ||
        (p->auth_session_path && g_strcmp0(p->auth_session_path, p->session_path))) {
        access_error(p, "AUTH_REVOKED", "Your login session changed during authentication. Unlock OctoVault again."); return;
    }
    if (p->session_remote) { access_one_shot(p); return; }
    access_session_ready(p);
}
static void access_session_path_done(GObject *bus, GAsyncResult *result, gpointer user_data)
{
    Pending *p = user_data;
    GError *error = NULL;
    GVariant *reply = g_dbus_connection_call_finish(G_DBUS_CONNECTION(bus), result, &error);
    if (!reply) {
        gchar *remote = error ? g_dbus_error_get_remote_error(error) : NULL;
        gboolean no_session = remote && g_str_has_suffix(remote, ".NoSessionForPID");
        g_free(remote); g_clear_error(&error);
        if (no_session && access_contains(p->op, access_managed_operations)) access_one_shot(p);
        else access_session_failed(p, "The calling application is not attached to a login session recognized by logind.");
        return;
    }
    const gchar *path; g_variant_get(reply, "(&o)", &path);
    g_free(p->session_path); p->session_path = g_strdup(path); g_variant_unref(reply);
    if (!p->auth_session_path) {
        p->auth_session_path = g_strdup(p->session_path);
        if (!g_hash_table_contains(access_session_revisions, p->session_path))
            g_hash_table_insert(access_session_revisions, g_strdup(p->session_path), g_new0(guint64, 1));
        p->session_revision = access_revision(access_session_revisions, p->session_path);
    }
    g_dbus_connection_call(connection, "org.freedesktop.login1", p->session_path, "org.freedesktop.DBus.Properties", "GetAll",
        g_variant_new("(s)", "org.freedesktop.login1.Session"), G_VARIANT_TYPE("(a{sv})"), G_DBUS_CALL_FLAGS_NONE,
        5000, NULL, access_properties_done, p);
}
static void access_pid_done(GObject *bus, GAsyncResult *result, gpointer user_data)
{
    Pending *p = user_data;
    GVariant *reply = g_dbus_connection_call_finish(G_DBUS_CONNECTION(bus), result, NULL);
    if (!reply) { access_session_failed(p, "The calling application has disconnected."); return; }
    g_variant_get(reply, "(u)", &p->pid); g_variant_unref(reply);
    g_dbus_connection_call(connection, "org.freedesktop.login1", "/org/freedesktop/login1", "org.freedesktop.login1.Manager", "GetSessionByPID",
        g_variant_new("(u)", p->pid), G_VARIANT_TYPE("(o)"), G_DBUS_CALL_FLAGS_NONE, 5000, NULL, access_session_path_done, p);
}
static void access_resolve_session(Pending *p)
{
    g_dbus_connection_call(connection, "org.freedesktop.DBus", "/org/freedesktop/DBus", "org.freedesktop.DBus", "GetConnectionUnixProcessID",
        g_variant_new("(s)", p->sender), G_VARIANT_TYPE("(u)"), G_DBUS_CALL_FLAGS_NONE, 5000, NULL, access_pid_done, p);
}
static void access_create_lease(Pending *p, const gchar *scope)
{
    /* A renewed lease must never resurrect queued work or retained recovery
     * results from its predecessor, even if expiry was not polled yet. */
    access_revoke_sender(p->sender);
    AccessLease *lease = g_new0(AccessLease, 1);
    lease->uid = p->uid; lease->scope = g_strdup(scope); lease->session_path = g_strdup(p->session_path); lease->session_id = g_strdup(p->session_id);
    lease->expires = g_get_monotonic_time() + (gint64)p->duration * G_USEC_PER_SEC;
    lease->expires_at = g_get_real_time() / G_USEC_PER_SEC + p->duration;
    lease->policy_revision = access_policy_revision;
    lease->sender_revision = access_revision(access_sender_revisions, p->sender);
    lease->session_revision = access_revision(access_session_revisions, p->session_path);
    g_hash_table_replace(access_leases, g_strdup(p->sender), lease);
}

static void access_require_lease(Pending *p)
{
    AccessLease *lease = access_lease_for(p->sender, p->uid);
    if (!lease || g_strcmp0(lease->session_path, p->session_path)) {
        AccessLease *old = g_hash_table_lookup(access_leases, p->sender);
        gboolean expired = old && old->expires <= g_get_monotonic_time();
        dbus_error(p, expired ? "AuthorizationExpired" : "AuthorizationRequired",
            expired ? "Your OctoVault authorization expired. Unlock the application to continue." : "Unlock OctoVault before starting this operation.");
        return;
    }
    g_free(p->scope); p->scope = g_strdup(lease->scope); p->requires_session = TRUE;
    p->policy_revision = lease->policy_revision; p->sender_revision = lease->sender_revision; p->session_revision = lease->session_revision;
    if (!strcmp(p->op, "repository.recovery") && !strcmp(p->scope, "personal")) {
        JsonObject *params = access_params(p);
        gboolean allowed = access_personal_recovery_allowed(p->uid, access_string(params, "id"));
        if (params) json_object_unref(params);
        if (!allowed) {
            access_error(p, "admin_required", "Personal recovery requires a repository and destination created with your personal access. Unlock system administration for a system resource."); return;
        }
    }
    if (!strcmp(p->op, "repository.recovery") && !p->auth_completed) {
        access_check_polkit(p, !strcmp(p->scope, "personal") ? "io.vdm.octovault.personal-recovery" : "io.vdm.octovault.recovery", TRUE); return;
    }
    submit_authorized(p);
}
static void access_session_ready(Pending *p)
{
    if (!strcmp(p->op, "access.status")) { access_check_polkit(p, "io.vdm.octovault.session", FALSE); return; }
    if (!strcmp(p->op, "access.lock")) { access_send_status(p); return; }
    if (!strcmp(p->op, "event.session")) {
        p->scope = g_strdup("personal"); submit_authorized(p); return;
    }
    GError *error = NULL;
    JsonObject *store = access_store_load(&error);
    if (!store) { g_clear_error(&error); access_error(p, "ACCESS_STORAGE_ERROR", "The administrator access settings could not be read safely."); return; }
    if (!strcmp(p->op, "access.unlock")) {
        JsonObject *params = access_params(p);
        const gchar *scope = access_string(params, "scope");
        guint maximum = access_store_duration(store);
        if (!*scope) scope = "system";
        gboolean valid = !strcmp(scope, "system") || !strcmp(scope, "personal");
        p->duration = maximum;
        if (json_object_has_member(params, "duration_seconds")) {
            JsonNode *duration = json_object_get_member(params, "duration_seconds");
            valid = valid && JSON_NODE_HOLDS_VALUE(duration) && json_node_get_value_type(duration) == G_TYPE_INT64 &&
                json_node_get_int(duration) >= 60 && json_node_get_int(duration) <= maximum;
            if (valid) p->duration = (guint)json_node_get_int(duration);
        }
        if (!valid) { json_object_unref(params); json_object_unref(store); access_error(p, "INVALID_ACCESS_REQUEST", "Choose personal or system authorization with a duration between one minute and the administrator limit."); return; }
        gboolean personal = !strcmp(scope, "personal");
        if (personal && !access_store_granted(store, p->uid)) {
            json_object_unref(params); json_object_unref(store); access_error(p, "PERSONAL_ACCESS_REQUIRED", "An administrator has not granted personal OctoVault access to your account."); return;
        }
        if (!personal && !p->auth_completed) {
            json_object_unref(params); json_object_unref(store); access_check_polkit(p, "io.vdm.octovault.session", TRUE); return;
        }
        access_create_lease(p, personal ? "personal" : "system"); p->can_request_system = !personal;
        JsonObject *status = access_status_data(p, store);
        json_object_unref(params); json_object_unref(store); access_reply(p, access_success(status)); return;
    }
    if (!strcmp(p->op, "access.list") || !strcmp(p->op, "access.grant") || !strcmp(p->op, "access.revoke")) {
        AccessLease *lease = access_lease_for(p->sender, p->uid);
        if (!lease || strcmp(lease->scope, "system") || g_strcmp0(lease->session_path, p->session_path)) {
            json_object_unref(store); dbus_error(p, "AuthorizationRequired", "Unlock system administration before managing account access."); return;
        }
        if (!strcmp(p->op, "access.list")) {
            JsonObject *result = json_object_new();
            json_object_set_array_member(result, "grants", json_array_ref(json_object_get_array_member(store, "grants")));
            json_object_set_int_member(result, "max_duration_seconds", access_store_duration(store));
            json_object_unref(store); access_reply(p, access_success(result)); return;
        }
        if (!p->auth_completed) { json_object_unref(store); access_check_polkit(p, "io.vdm.octovault.delegate", TRUE); return; }
        JsonObject *params = access_params(p); const gchar *user = access_string(params, "user");
        gboolean grant = !strcmp(p->op, "access.grant");
        if (!access_store_change(store, user, grant, p->uid, &error) || !access_store_save(store, &error)) {
            g_clear_error(&error); json_object_unref(params); json_object_unref(store);
            access_error(p, "ACCESS_STORAGE_ERROR", "Access settings were not changed. Select an eligible local account and check that the access policy can be saved safely."); return;
        }
        JsonObject *result = json_object_new(); json_object_set_string_member(result, "user", user);
        json_object_set_boolean_member(result, "delegated_personal", grant);
        json_object_set_string_member(result, "message", grant ? "Personal access granted. Unlock OctoVault again to continue administration." : "Personal access revoked. Future personal backups are blocked; already running operations may finish.");
        json_object_unref(params); json_object_unref(store); access_revoke_all();
        access_reply(p, access_success(result)); return;
    }
    json_object_unref(store); access_require_lease(p);
}
static void access_authorize(Pending *p)
{
    access_runtime_init();
    if (!g_hash_table_contains(access_sender_revisions, p->sender))
        g_hash_table_insert(access_sender_revisions, g_strdup(p->sender), g_new0(guint64, 1));
    p->transition_revision = access_transition_revision;
    p->policy_revision = access_policy_revision; p->sender_revision = access_revision(access_sender_revisions, p->sender);
    if (!strcmp(p->op, "access.lock")) {
        access_revoke_sender(p->sender); p->sender_revision = access_revision(access_sender_revisions, p->sender);
        access_resolve_session(p); return;
    }
    if (!strcmp(p->op, "access.users")) {
        GError *error = NULL; JsonObject *store = access_store_load(&error);
        if (!store) { g_clear_error(&error); access_error(p, "ACCESS_STORAGE_ERROR", "The administrator access settings could not be read safely."); return; }
        JsonObject *result = json_object_new(); json_object_set_array_member(result, "users", access_store_users(store));
        json_object_unref(store); access_reply(p, access_success(result)); return;
    }
    if (config_read(p->op)) { p->scope = g_strdup("personal"); submit_authorized(p); return; }
    if (connection && (!access_monitor || g_file_monitor_is_cancelled(access_monitor)) && strcmp(p->op, "event.session")) {
        access_revoke_all();
        access_error(p, "ACCESS_STORAGE_ERROR", "The service cannot monitor administrator access settings safely. Restart the OctoVault service after repairing its state directory."); return;
    }
    const gchar *access_ops[] = { "access.status", "access.unlock", "access.list", "access.grant", "access.revoke", "event.session", NULL };
    if (!access_contains(p->op, access_managed_operations) && !access_contains(p->op, access_ops)) {
        access_error(p, "UNSUPPORTED_OPERATION", "This operation is not supported by the authorization policy."); return;
    }
    access_resolve_session(p);
}
static void access_signal(GDBusConnection *bus, const gchar *sender, const gchar *path,
                          const gchar *interface, const gchar *signal, GVariant *parameters, gpointer data)
{
    (void)bus; (void)sender; (void)data;
    if (!strcmp(interface, "org.freedesktop.DBus")) {
        const gchar *name, *old, *current; g_variant_get(parameters, "(&s&s&s)", &name, &old, &current);
        if (*old && strcmp(old, current) && (!strcmp(name, "org.freedesktop.login1") || !strcmp(name, "org.freedesktop.PolicyKit1"))) access_revoke_all();
        if (*old && !*current && *name == ':' && g_hash_table_contains(access_sender_revisions, name)) {
            access_revoke_sender(name); g_hash_table_remove(access_sender_revisions, name);
        }
        return;
    }
    if (!strcmp(interface, "org.freedesktop.PolicyKit1.Authority") && !strcmp(signal, "Changed")) { access_revoke_all(); return; }
    if (!strcmp(signal, "SessionRemoved")) {
        const gchar *id, *session; g_variant_get(parameters, "(&s&o)", &id, &session); access_revoke_session(session);
        g_hash_table_remove(access_session_revisions, session); return;
    }
    if (!strcmp(signal, "PrepareForSleep") || !strcmp(signal, "PrepareForShutdown")) {
        gboolean preparing; g_variant_get(parameters, "(b)", &preparing); if (preparing) access_revoke_all(); return;
    }
    if (!strcmp(signal, "Lock")) { access_revoke_session(path); return; }
    if (!strcmp(signal, "PropertiesChanged")) {
        const gchar *changed_interface; GVariant *changed, *invalidated;
        g_variant_get(parameters, "(&s@a{sv}@as)", &changed_interface, &changed, &invalidated);
        if (!strcmp(changed_interface, "org.freedesktop.login1.Session")) {
            gboolean active, locked, revoke = FALSE; const gchar *state;
            if (g_variant_lookup(changed, "Active", "b", &active) && !active) revoke = TRUE;
            if (g_variant_lookup(changed, "LockedHint", "b", &locked) && locked) revoke = TRUE;
            if (g_variant_lookup(changed, "State", "&s", &state) && strcmp(state, "active")) revoke = TRUE;
            const gchar *identity_keys[] = { "User", "Id", "Remote", NULL };
            for (guint i = 0; identity_keys[i]; i++) {
                GVariant *value = g_variant_lookup_value(changed, identity_keys[i], NULL);
                if (value) { revoke = TRUE; g_variant_unref(value); }
            }
            GVariantIter iter; const gchar *key; g_variant_iter_init(&iter, invalidated);
            while (g_variant_iter_next(&iter, "&s", &key))
                if (!strcmp(key, "Active") || !strcmp(key, "LockedHint") || !strcmp(key, "State") || !strcmp(key, "User") || !strcmp(key, "Id") || !strcmp(key, "Remote")) revoke = TRUE;
            if (revoke) access_revoke_session(path);
        }
        g_variant_unref(changed); g_variant_unref(invalidated);
    }
}
static void access_policy_changed(GFileMonitor *monitor, GFile *file, GFile *other, GFileMonitorEvent event, gpointer data)
{
    (void)monitor; (void)event; (void)data;
    gchar *path = file ? g_file_get_path(file) : NULL, *other_path = other ? g_file_get_path(other) : NULL;
    if (!g_strcmp0(path, OV_ACCESS_PATH) || !g_strcmp0(other_path, OV_ACCESS_PATH)) access_revoke_all();
    g_free(path); g_free(other_path);
}
static void access_initialize(void)
{
    access_runtime_init();
    access_subscriptions[0] = g_dbus_connection_signal_subscribe(connection, "org.freedesktop.DBus", "org.freedesktop.DBus",
        "NameOwnerChanged", "/org/freedesktop/DBus", NULL, G_DBUS_SIGNAL_FLAGS_NONE, access_signal, NULL, NULL);
    access_subscriptions[1] = g_dbus_connection_signal_subscribe(connection, "org.freedesktop.login1", "org.freedesktop.DBus.Properties",
        "PropertiesChanged", NULL, "org.freedesktop.login1.Session", G_DBUS_SIGNAL_FLAGS_NONE, access_signal, NULL, NULL);
    access_subscriptions[2] = g_dbus_connection_signal_subscribe(connection, "org.freedesktop.login1", "org.freedesktop.login1.Manager",
        NULL, "/org/freedesktop/login1", NULL, G_DBUS_SIGNAL_FLAGS_NONE, access_signal, NULL, NULL);
    access_subscriptions[3] = g_dbus_connection_signal_subscribe(connection, "org.freedesktop.login1", "org.freedesktop.login1.Session",
        "Lock", NULL, NULL, G_DBUS_SIGNAL_FLAGS_NONE, access_signal, NULL, NULL);
    access_subscriptions[4] = g_dbus_connection_signal_subscribe(connection, "org.freedesktop.PolicyKit1", "org.freedesktop.PolicyKit1.Authority",
        "Changed", "/org/freedesktop/PolicyKit1/Authority", NULL, G_DBUS_SIGNAL_FLAGS_NONE, access_signal, NULL, NULL);
    gchar *directory = g_path_get_dirname(OV_ACCESS_PATH); GFile *parent = g_file_new_for_path(directory);
    access_monitor = g_file_monitor_directory(parent, G_FILE_MONITOR_WATCH_MOVES, NULL, NULL);
    if (access_monitor) g_signal_connect(access_monitor, "changed", G_CALLBACK(access_policy_changed), NULL);
    g_object_unref(parent); g_free(directory);
}
static void access_shutdown(void)
{
    if (access_monitor) { g_file_monitor_cancel(access_monitor); g_clear_object(&access_monitor); }
    for (guint i = 0; i < G_N_ELEMENTS(access_subscriptions); i++)
        if (access_subscriptions[i]) g_dbus_connection_signal_unsubscribe(connection, access_subscriptions[i]);
    g_clear_pointer(&access_leases, g_hash_table_destroy);
    g_clear_pointer(&access_sender_revisions, g_hash_table_destroy);
    g_clear_pointer(&access_session_revisions, g_hash_table_destroy);
}
