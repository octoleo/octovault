/* SPDX-License-Identifier: Apache-2.0 */
#include <gio/gio.h>
#include <json-glib/json-glib.h>
static void test_bus_call(GDBusConnection *, const gchar *, const gchar *, const gchar *, const gchar *, GVariant *, const GVariantType *, GDBusCallFlags, gint, GCancellable *, GAsyncReadyCallback, gpointer);
static gboolean test_spawn(const gchar *, gchar **, gchar **, GSpawnFlags, GSpawnChildSetupFunc, gpointer, GPid *, GError **);
#define g_dbus_connection_call test_bus_call
#define g_spawn_async test_spawn
#define main observer_main
#include "../../src/session/main.c"
#undef main
#undef g_dbus_connection_call
#undef g_spawn_async
static GPtrArray *events, *launches;
static void test_bus_call(GDBusConnection *connection, const gchar *name, const gchar *path, const gchar *interface, const gchar *method, GVariant *parameters, const GVariantType *reply_type, GDBusCallFlags flags, gint timeout, GCancellable *cancel, GAsyncReadyCallback callback, gpointer data) {
    (void)connection; (void)name; (void)path; (void)interface; (void)reply_type;
    (void)flags; (void)timeout; (void)cancel; (void)callback;
    g_assert_cmpstr(method, ==, "Submit");
    const gchar *document;
    g_variant_ref_sink(parameters); g_variant_get(parameters, "(&s)", &document);
    JsonParser *parser = json_parser_new();
    g_assert_true(json_parser_load_from_data(parser, document, -1, NULL));
    JsonObject *params = json_object_get_object_member(json_node_get_object(json_parser_get_root(parser)), "params");
    g_ptr_array_add(events, g_strdup(json_object_get_string_member(params, "event")));
    g_object_unref(parser); g_variant_unref(parameters); event_job_free(data);
}
static gboolean test_spawn(const gchar *directory, gchar **argv, gchar **environment, GSpawnFlags flags, GSpawnChildSetupFunc setup, gpointer data, GPid *pid, GError **error) {
    (void)directory; (void)environment; (void)flags; (void)setup; (void)data; (void)pid; (void)error;
    g_assert_cmpstr(argv[0], ==, "/usr/bin/octovault-gtk"); g_assert_cmpstr(argv[1], ==, "--unlock");
    g_ptr_array_add(launches, g_strdup(argv[2])); return TRUE;
}
static void properties(gboolean active, gboolean locked) {
    GVariantBuilder builder; g_variant_builder_init(&builder, G_VARIANT_TYPE("a{sv}"));
    g_variant_builder_add(&builder, "{sv}", "Active", g_variant_new_boolean(active));
    g_variant_builder_add(&builder, "{sv}", "LockedHint", g_variant_new_boolean(locked));
    GVariant *value = g_variant_ref_sink(g_variant_builder_end(&builder)); session_properties(value); g_variant_unref(value);
}
static void screen(gboolean locked) {
    GVariant *value = g_variant_ref_sink(g_variant_new("(b)", locked)); lock_signal(NULL, NULL, NULL, NULL, NULL, value, NULL); g_variant_unref(value);
}
static void reset(void) {
    session_known = desktop_active = screensaver_locked = login_offered = was_locked = resume_pending = exiting = FALSE;
    logind_locked = TRUE; desktop_generation = pending_jobs = 0;
    g_hash_table_remove_all(pending_unlock_ids); g_ptr_array_set_size(events, 0); g_ptr_array_set_size(launches, 0);
}
static void login_waits_for_desktop(void) {
    reset(); properties(FALSE, TRUE); properties(TRUE, TRUE); g_assert_cmpuint(events->len, ==, 0);
    properties(TRUE, FALSE); properties(TRUE, FALSE); g_assert_cmpuint(events->len, ==, 1);
    g_assert_cmpstr(g_ptr_array_index(events, 0), ==, "login");
}
static void lock_sources_are_deduplicated(void) {
    reset(); properties(TRUE, FALSE); screen(TRUE); properties(TRUE, TRUE);
    g_assert_cmpuint(events->len, ==, 2); g_assert_cmpstr(g_ptr_array_index(events, 1), ==, "screen-lock");
    screen(FALSE); g_assert_cmpuint(events->len, ==, 2);
    properties(TRUE, FALSE); screen(FALSE); g_assert_cmpuint(events->len, ==, 3);
    g_assert_cmpstr(g_ptr_array_index(events, 2), ==, "screen-unlock");
}
static void requests_wait_and_launch_once(void) {
    reset(); properties(TRUE, FALSE); screen(TRUE); properties(TRUE, TRUE);
    g_hash_table_insert(pending_unlock_ids, g_strdup("documents"), NULL); launch_pending_unlocks();
    g_assert_cmpuint(launches->len, ==, 0);
    properties(TRUE, FALSE); screen(FALSE); launch_pending_unlocks();
    g_assert_cmpuint(launches->len, ==, 1); g_assert_cmpstr(g_ptr_array_index(launches, 0), ==, "documents");
    screen(TRUE); g_assert_cmpuint(g_hash_table_size(pending_unlock_ids), ==, 0);
}
static void resume_waits_for_unlock(void) {
    reset(); properties(TRUE, FALSE); screen(TRUE); properties(TRUE, TRUE);
    resume_pending = TRUE; desktop_state_changed(); g_assert_cmpuint(events->len, ==, 2);
    properties(TRUE, FALSE); screen(FALSE); g_assert_cmpuint(events->len, ==, 4);
    g_assert_cmpstr(g_ptr_array_index(events, 2), ==, "screen-unlock");
    g_assert_cmpstr(g_ptr_array_index(events, 3), ==, "resume");
}
static void primary_display_checks_owner(void) {
    GVariantBuilder builder;
    g_variant_builder_init(&builder, G_VARIANT_TYPE("a{sv}"));
    g_variant_builder_add(&builder, "{sv}", "UID", g_variant_new_uint32((guint32)getuid()));
    g_variant_builder_add(&builder, "{sv}", "Display", g_variant_new("(so)", "c1", "/org/freedesktop/login1/session/c1"));
    GVariant *value = g_variant_ref_sink(g_variant_builder_end(&builder));
    gchar *path = primary_display_path(value);
    g_assert_cmpstr(path, ==, "/org/freedesktop/login1/session/c1"); g_free(path); g_variant_unref(value);
    g_variant_builder_init(&builder, G_VARIANT_TYPE("a{sv}"));
    g_variant_builder_add(&builder, "{sv}", "UID", g_variant_new_uint32((guint32)getuid() + 1));
    g_variant_builder_add(&builder, "{sv}", "Display", g_variant_new("(so)", "c1", "/org/freedesktop/login1/session/c1"));
    value = g_variant_ref_sink(g_variant_builder_end(&builder));
    g_assert_null(primary_display_path(value)); g_variant_unref(value);
}
int main(int argc, char **argv) {
    g_test_init(&argc, &argv, NULL); events = g_ptr_array_new_with_free_func(g_free); launches = g_ptr_array_new_with_free_func(g_free);
    pending_unlock_ids = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, NULL);
    g_test_add_func("/session/login-waits-for-desktop", login_waits_for_desktop);
    g_test_add_func("/session/lock-source-deduplication", lock_sources_are_deduplicated);
    g_test_add_func("/session/unlock-request-gating", requests_wait_and_launch_once);
    g_test_add_func("/session/resume-waits-for-unlock", resume_waits_for_unlock);
    g_test_add_func("/session/user-manager-display", primary_display_checks_owner);
    int status = g_test_run(); g_ptr_array_unref(events); g_ptr_array_unref(launches); g_hash_table_unref(pending_unlock_ids); return status;
}
