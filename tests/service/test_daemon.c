/* SPDX-License-Identifier: Apache-2.0 */
#define _GNU_SOURCE
#include <glib.h>
#include <glib/gstdio.h>
static gchar *test_directory, *test_access_path, *test_passwd_path, *test_defs_path;
#define OV_ACCESS_PATH test_access_path
#define OV_ACCESS_PASSWD_PATH test_passwd_path
#define OV_ACCESS_LOGIN_DEFS_PATH test_defs_path
#define main octovault_daemon_entrypoint
#include "../../src/service/daemon.c"
#undef main

static void identity_overrides(void)
{
    const gchar *requests[] = {
        "{\"op\":\"vault.list\",\"params\":{\"uid\":0}}",
        "{\"op\":\"vault.list\",\"params\":{\"home\":\"/root\"}}",
        "{\"op\":\"vault.list\",\"params\":{\"executable\":\"/bin/sh\"}}",
        "{\"op\":\"vault.list\",\"params\":[]}",
        "{\"op\":\"vault.list;sh\",\"params\":{}}",
        "{\"op\":42,\"params\":{}}",
        "{\"op\":\"vault.close\",\"params\":{\"force\":\"true\"}}"
    };
    for (guint i = 0; i < G_N_ELEMENTS(requests); i++) {
        Pending pending = { .request = (gchar *)requests[i] };
        g_assert_false(parse_request(&pending)); g_free(pending.op);
    }
}

static void valid_request(void)
{
    Pending pending = { .request = "{\"op\":\"vault.open\",\"params\":{\"id\":\"mine\",\"password\":\"test-secret\"}}" };
    g_assert_true(parse_request(&pending)); g_assert_cmpstr(pending.op, ==, "vault.open"); g_free(pending.op);
    g_assert_false(config_read("repository.snapshots"));
    g_assert_false(config_read("repository.files"));
    g_assert_false(config_read("vault.search"));
    g_assert_true(config_read("repository.get"));
    g_assert_true(config_read("backup.history"));
    g_assert_false(config_read("repository.recovery"));
    g_assert_false(config_read("repository.restore"));
    g_assert_false(config_read("vault.open"));
    g_assert_true(config_read("vault.auth-check"));
    g_assert_true(config_read("diagnostic.list"));
    g_assert_true(config_read("diagnostic.get"));
    g_assert_false(config_read("diagnostic.delete"));
}

static void session_allowlist(void)
{
    const gchar *invalid[] = {
        "{\"op\":\"vault.auth-check\",\"params\":{},\"session\":[]}",
        "{\"op\":\"vault.auth-check\",\"params\":{},\"session\":{\"PATH\":\"/untrusted\"}}",
        "{\"op\":\"vault.auth-check\",\"params\":{},\"session\":{\"LD_PRELOAD\":\"/untrusted.so\"}}",
        "{\"op\":\"vault.auth-check\",\"params\":{},\"session\":{\"home\":\"/root\"}}",
        "{\"op\":\"vault.auth-check\",\"params\":{},\"session\":{\"display\":42}}",
        "{\"op\":\"vault.auth-check\",\"params\":{},\"session\":{\"display\":\"\"}}",
        "{\"op\":\"vault.auth-check\",\"params\":{},\"session\":{\"display\":\":1\\nother\"}}"
    };
    for (guint i = 0; i < G_N_ELEMENTS(invalid); i++) {
        Pending pending = { .request = (gchar *)invalid[i] };
        g_assert_false(parse_request(&pending)); g_free(pending.op);
    }
    Pending pending = { .request = "{\"op\":\"vault.auth-check\",\"params\":{\"require_token\":true},\"session\":{\"display\":\":1\",\"wayland_display\":\"wayland-0\",\"gpg_tty\":\"/dev/pts/3\",\"gnupg_home\":\"/home/person/.gnupg\"}}" };
    g_assert_true(parse_request(&pending));
    g_assert_cmpstr(pending.op, ==, "vault.auth-check");
    g_free(pending.op);
}

static void bounded_request(void)
{
    Pending pending = { .request = g_malloc0(OV_REQUEST_LIMIT + 2) };
    memset(pending.request, ' ', OV_REQUEST_LIMIT + 1);
    g_assert_false(parse_request(&pending)); g_free(pending.request);
}

static void reset_access(void)
{
    if (jobs) g_hash_table_destroy(jobs);
    jobs = g_hash_table_new_full(g_str_hash, g_str_equal, NULL, job_free);
    access_shutdown(); access_runtime_init();
    access_policy_revision = 1; access_transition_revision = 0;
    g_unlink(test_access_path);
    g_assert_true(g_file_set_contents(test_passwd_path, "alice:x:1000:1000:Alice:/home/alice:/bin/bash\n", -1, NULL));
    g_assert_true(g_file_set_contents(test_defs_path, "UID_MIN 1000\n", -1, NULL));
}
static Pending access_pending(const gchar *sender)
{
    if (!g_hash_table_contains(access_sender_revisions, sender))
        g_hash_table_insert(access_sender_revisions, g_strdup(sender), g_new0(guint64, 1));
    const gchar *path = "/org/freedesktop/login1/session/c1";
    if (!g_hash_table_contains(access_session_revisions, path))
        g_hash_table_insert(access_session_revisions, g_strdup(path), g_new0(guint64, 1));
    Pending p = { .sender = (gchar *)sender, .uid = 1000, .duration = 60,
        .op = "access.unlock", .request = "{\"params\":{\"scope\":\"personal\"}}",
        .session_path = (gchar *)path, .auth_session_path = (gchar *)path, .session_id = "c1", .session_active = TRUE,
        .policy_revision = access_policy_revision, .sender_revision = access_revision(access_sender_revisions, sender),
        .session_revision = access_revision(access_session_revisions, path), .transition_revision = access_transition_revision };
    return p;
}
static gboolean prepare_policy(void)
{
    if (geteuid() != 0) { g_test_skip("Root-owned access policy required for lease checks."); return FALSE; }
    JsonObject *store = access_store_empty(); GError *error = NULL;
    g_assert_true(access_store_change(store, "alice", TRUE, 0, &error));
    g_assert_true(access_store_save(store, &error)); g_assert_no_error(error); json_object_unref(store);
    return TRUE;
}
static Job *access_test_job(Pending *p, const gchar *op)
{
    AccessLease *lease = access_lease_for(p->sender, p->uid); g_assert_nonnull(lease);
    Job *j = g_new0(Job, 1); j->id = g_uuid_string_random(); j->op = g_strdup(op); j->uid = p->uid;
    j->sender = g_strdup(p->sender); j->session_path = g_strdup(p->session_path); j->scope = g_strdup(lease->scope);
    j->requires_session = TRUE; j->policy_revision = lease->policy_revision;
    j->sender_revision = lease->sender_revision; j->session_revision = lease->session_revision;
    g_hash_table_insert(jobs, j->id, j); return j;
}
static GVariant *session_properties(guint32 uid, gboolean active, gboolean locked, gboolean remote)
{
    GVariantBuilder b; g_variant_builder_init(&b, G_VARIANT_TYPE("a{sv}"));
    g_variant_builder_add(&b, "{sv}", "User", g_variant_new("(uo)", uid, "/org/freedesktop/login1/user/_1000"));
    g_variant_builder_add(&b, "{sv}", "Id", g_variant_new_string("c1"));
    g_variant_builder_add(&b, "{sv}", "State", g_variant_new_string(active ? "active" : "closing"));
    g_variant_builder_add(&b, "{sv}", "Active", g_variant_new_boolean(active));
    g_variant_builder_add(&b, "{sv}", "LockedHint", g_variant_new_boolean(locked));
    g_variant_builder_add(&b, "{sv}", "Remote", g_variant_new_boolean(remote));
    return g_variant_ref_sink(g_variant_builder_end(&b));
}
static void session_binding_and_safety_events(void)
{
    reset_access();
    Pending p = { .uid = 1000, .op = "access.unlock" };
    GVariant *props = session_properties(1000, TRUE, FALSE, FALSE);
    g_assert_true(access_session_properties(&p, props)); g_assert_false(p.session_remote); g_variant_unref(props);
    props = session_properties(1000, TRUE, FALSE, TRUE);
    g_assert_true(access_session_properties(&p, props)); g_assert_true(p.session_remote); g_variant_unref(props);
    props = session_properties(1001, TRUE, FALSE, FALSE);
    g_assert_false(access_session_properties(&p, props)); g_variant_unref(props);
    props = session_properties(1000, TRUE, TRUE, FALSE);
    g_assert_false(access_session_properties(&p, props));
    p.op = "event.session"; p.request = "{\"params\":{\"event\":\"screen-lock\"}}";
    g_assert_true(access_session_properties(&p, props));
    p.request = "{\"params\":{\"event\":\"screen-unlock\"}}";
    g_assert_false(access_session_properties(&p, props)); g_variant_unref(props);
    props = session_properties(1001, FALSE, TRUE, FALSE);
    p.request = "{\"params\":{\"event\":\"logout\"}}";
    g_assert_false(access_session_properties(&p, props)); g_variant_unref(props);
    g_free(p.session_id);
}
static void pending_revocation(void)
{
    reset_access(); Pending p = access_pending(":1.1");
    g_assert_true(access_pending_current(&p));
    access_revoke_sender(p.sender); g_assert_false(access_pending_current(&p));
    p = access_pending(":1.1"); access_revoke_session(p.session_path); g_assert_false(access_pending_current(&p));
    p = access_pending(":1.1"); access_revoke_all(); g_assert_false(access_pending_current(&p));
    p = access_pending(":1.1");
    p.auth_session_path = NULL; /* Lock racing with GetSessionByPID must also invalidate the request. */
    access_revoke_session("/org/freedesktop/login1/session/another");
    g_assert_false(access_pending_current(&p));
}
static void lease_scope_and_expiry(void)
{
    reset_access(); if (!prepare_policy()) return;
    Pending p = access_pending(":1.1"); access_create_lease(&p, "personal");
    AccessLease *lease = access_lease_for(p.sender, 1000); g_assert_nonnull(lease);
    g_assert_null(access_lease_for(p.sender, 1001)); g_assert_null(access_lease_for(":1.2", 1000));
    Job *j = access_test_job(&p, "vault.open"); g_assert_true(access_job_valid(j));
    lease->expires = g_get_monotonic_time() - 1; g_assert_false(access_job_valid(j));
    p = access_pending(":1.1"); access_create_lease(&p, "personal");
    g_assert_nonnull(access_lease_for(p.sender, 1000)); g_assert_false(access_job_valid(j));
    JsonObject *store = access_store_load(NULL); g_assert_true(access_store_change(store, "alice", FALSE, 0, NULL));
    g_assert_true(access_store_save(store, NULL)); json_object_unref(store);
    g_assert_null(access_lease_for(p.sender, 1000));
}
static void recovery_result_lifetime(void)
{
    reset_access(); if (!prepare_policy()) return;
    Pending p = access_pending(":1.1"), other = access_pending(":1.2");
    access_create_lease(&p, "personal"); access_create_lease(&other, "personal");
    Job *j = access_test_job(&p, "repository.recovery");
    j->result = access_success(json_object_new());
    g_assert_true(access_result_visible(j, &p)); g_assert_false(access_result_visible(j, &other));
    Job *routine = access_test_job(&p, "repository.files");
    g_assert_true(access_result_visible(routine, &other));
    access_revoke_sender(p.sender); g_assert_false(access_job_valid(j));
    g_assert_cmpstr(json_object_get_string_member(json_object_get_object_member(json_node_get_object(j->result), "error"), "code"), ==, "AUTH_REVOKED");
    /* Late completion after lock is scrubbed, and a later unlock cannot resurrect it. */
    json_node_unref(j->result); j->result = access_success(json_object_new());
    access_protect_result(j);
    p = access_pending(":1.1"); access_create_lease(&p, "personal");
    g_assert_false(access_result_visible(j, &p));
    g_assert_true(access_result_visible(routine, &p));
    g_assert_true(access_result_visible(routine, &other));
    access_revoke_session(p.session_path);
    g_hash_table_remove(access_session_revisions, p.session_path);
    p = access_pending(":1.1"); access_create_lease(&p, "personal");
    g_assert_false(access_job_valid(j));
}
static void signal_revocation_and_bounded_tracking(void)
{
    reset_access(); Pending p = access_pending(":1.1");
    GVariant *v = g_variant_ref_sink(g_variant_new("(sss)", ":1.unrelated", ":1.unrelated", ""));
    access_signal(NULL, NULL, NULL, "org.freedesktop.DBus", "NameOwnerChanged", v, NULL); g_variant_unref(v);
    g_assert_cmpuint(g_hash_table_size(access_sender_revisions), ==, 1);
    const gchar *services[] = { "org.freedesktop.login1", "org.freedesktop.PolicyKit1" };
    for (guint i = 0; i < G_N_ELEMENTS(services); i++) {
        p = access_pending(":1.1"); v = g_variant_ref_sink(g_variant_new("(sss)", services[i], ":1.service", ""));
        access_signal(NULL, NULL, NULL, "org.freedesktop.DBus", "NameOwnerChanged", v, NULL); g_variant_unref(v);
        g_assert_false(access_pending_current(&p));
    }
    p = access_pending(":1.1"); v = g_variant_ref_sink(g_variant_new("()"));
    access_signal(NULL, NULL, NULL, "org.freedesktop.PolicyKit1.Authority", "Changed", v, NULL); g_variant_unref(v);
    g_assert_false(access_pending_current(&p));
    v = g_variant_ref_sink(g_variant_new("(sss)", ":1.1", ":1.1", ""));
    access_signal(NULL, NULL, NULL, "org.freedesktop.DBus", "NameOwnerChanged", v, NULL); g_variant_unref(v);
    g_assert_cmpuint(g_hash_table_size(access_sender_revisions), ==, 0);
    g_assert_false(access_pending_current(&p));
}
static void explicit_operation_allowlist(void)
{
    g_assert_true(access_contains("repository.recovery", access_managed_operations));
    g_assert_false(access_contains("repository.arbitrary-root-action", access_managed_operations));
    g_assert_false(access_contains("event.handle", access_managed_operations));
    g_assert_false(access_contains("access.grant", access_managed_operations));
    g_assert_false(config_read("access.grant"));
}
static void one_shot_session_removed(void)
{
    reset_access(); Pending p = access_pending(":1.1");
    Job *j = g_new0(Job, 1); j->id = g_strdup("one-shot"); j->sender = g_strdup(p.sender);
    j->op = g_strdup("repository.recovery"); j->scope = g_strdup("system"); j->session_path = g_strdup(p.session_path);
    j->one_shot = TRUE; j->policy_revision = access_policy_revision;
    g_hash_table_insert(jobs, j->id, j);
    g_assert_true(access_job_valid(j));
    access_revoke_session(p.session_path); g_hash_table_remove(access_session_revisions, p.session_path);
    g_assert_false(access_job_valid(j));
    p = access_pending(":1.1"); g_assert_false(access_job_valid(j));
    g_assert_true(access_pending_current(&p));
}
static void hidden_terminal_result_is_typed(void)
{
    Job j = { .id = "job", .op = "repository.recovery", .state = "succeeded", .stage = "done", .message = "Complete" };
    JsonObject *secret = json_object_new(); json_object_set_string_member(secret, "password", "never-expose-this");
    j.result = access_success(secret);
    gchar *encoded = serialize_job(&j, FALSE);
    g_assert_null(strstr(encoded, "never-expose-this"));
    JsonParser *parser = json_parser_new(); g_assert_true(json_parser_load_from_data(parser, encoded, -1, NULL));
    JsonObject *result = json_object_get_object_member(json_node_get_object(json_parser_get_root(parser)), "result");
    g_assert_false(json_object_get_boolean_member(result, "ok"));
    g_assert_cmpstr(json_object_get_string_member(json_object_get_object_member(result, "error"), "code"), ==, "AUTH_REVOKED");
    g_free(encoded); g_object_unref(parser); json_node_unref(j.result);
}

int main(int argc, char **argv)
{
    g_test_init(&argc, &argv, NULL);
    test_directory = g_strdup(geteuid() == 0 ? "/run/octovault-daemon-test-XXXXXX" : "/tmp/octovault-daemon-test-XXXXXX");
    g_assert_nonnull(g_mkdtemp(test_directory));
    test_access_path = g_build_filename(test_directory, "access.json", NULL);
    test_passwd_path = g_build_filename(test_directory, "passwd", NULL);
    test_defs_path = g_build_filename(test_directory, "login.defs", NULL);
    g_test_add_func("/daemon/identity-overrides", identity_overrides);
    g_test_add_func("/daemon/request-and-authorization", valid_request);
    g_test_add_func("/daemon/bounded-request", bounded_request);
    g_test_add_func("/daemon/session-allowlist", session_allowlist);
    g_test_add_func("/daemon/access/session-binding-and-safety-events", session_binding_and_safety_events);
    g_test_add_func("/daemon/access/pending-revocation", pending_revocation);
    g_test_add_func("/daemon/access/lease-scope-and-expiry", lease_scope_and_expiry);
    g_test_add_func("/daemon/access/recovery-result-lifetime", recovery_result_lifetime);
    g_test_add_func("/daemon/access/signals-and-bounded-tracking", signal_revocation_and_bounded_tracking);
    g_test_add_func("/daemon/access/explicit-operation-allowlist", explicit_operation_allowlist);
    g_test_add_func("/daemon/access/one-shot-session-removed", one_shot_session_removed);
    g_test_add_func("/daemon/access/hidden-terminal-result", hidden_terminal_result_is_typed);
    int status = g_test_run();
    g_clear_pointer(&jobs, g_hash_table_destroy); access_shutdown();
    g_unlink(test_access_path); g_unlink(test_passwd_path); g_unlink(test_defs_path); g_rmdir(test_directory);
    g_free(test_access_path); g_free(test_passwd_path); g_free(test_defs_path); g_free(test_directory);
    return status;
}
