/* SPDX-License-Identifier: Apache-2.0 */
#define _GNU_SOURCE
#include <gio/gio.h>
#include <json-glib/json-glib.h>
#include <glib/gstdio.h>

static gchar *test_directory, *test_access_path, *test_passwd_path, *test_defs_path;
#define OV_ACCESS_PATH test_access_path
#define OV_ACCESS_PASSWD_PATH test_passwd_path
#define OV_ACCESS_LOGIN_DEFS_PATH test_defs_path
#include "../../src/service/access-store.c"

static const gchar accounts[] =
    "root:x:0:0:Root:/root:/bin/bash\n"
    "service:x:999:999:Service:/srv/service:/bin/bash\n"
    "alice:x:1000:1000:Alice Example,Office:/home/alice:/bin/bash\n"
    "bob:x:1001:1001:Bob Example:/home/bob:/bin/sh\n"
    "disabled:x:2000:2000:Disabled:/home/disabled:/usr/sbin/nologin\n"
    "false-shell:x:2001:2001:Disabled:/home/false:/bin/false\n"
    "nobody:x:65534:65534:Nobody:/nonexistent:/bin/bash\n";

static void reset_policy(void)
{
    g_unlink(test_access_path);
    gchar *parent = g_path_get_dirname(test_access_path);
    g_assert_cmpint(g_mkdir_with_parents(parent, 0700), ==, 0);
    g_assert_cmpint(g_chmod(parent, 0700), ==, 0);
    g_free(parent);
    g_assert_true(g_file_set_contents(test_passwd_path, accounts, -1, NULL));
    g_assert_true(g_file_set_contents(test_defs_path, "UID_MIN 1000\n", -1, NULL));
}

static gboolean root_storage(void)
{
    if (geteuid() == 0) return TRUE;
    g_test_skip("Persistent policy tests require the same root ownership as the service.");
    return FALSE;
}

static void eligible_accounts_and_reassignment(void)
{
    reset_policy();
    JsonObject *store = access_store_empty();
    JsonArray *users = access_store_users(store);
    g_assert_cmpuint(json_array_get_length(users), ==, 2);
    JsonObject *alice = json_array_get_object_element(users, 0);
    g_assert_cmpstr(json_object_get_string_member(alice, "user"), ==, "alice");
    g_assert_cmpstr(json_object_get_string_member(alice, "display_name"), ==, "Alice Example");
    g_assert_false(json_object_get_boolean_member(alice, "delegated_personal"));
    json_array_unref(users);
    const gchar *rejected[] = { "root", "service", "disabled", "false-shell", "nobody", "missing" };
    for (guint i = 0; i < G_N_ELEMENTS(rejected); i++) {
        GError *error = NULL;
        g_assert_false(access_store_change(store, rejected[i], TRUE, 0, &error));
        g_assert_nonnull(error); g_clear_error(&error);
    }
    GError *error = NULL;
    g_assert_true(access_store_change(store, "alice", TRUE, 0, &error));
    g_assert_no_error(error);
    g_assert_true(access_store_granted(store, 1000));
    g_assert_false(access_store_granted(store, 1001));
    g_assert_false(access_store_granted(store, 0));
    users = access_store_users(store);
    g_assert_true(json_object_get_boolean_member(json_array_get_object_element(users, 0), "delegated_personal"));
    json_array_unref(users);
    /* Reusing a deleted account's UID must not inherit its grant. */
    g_assert_true(g_file_set_contents(test_passwd_path, "replacement:x:1000:1000:Replacement:/home/replacement:/bin/bash\n", -1, NULL));
    g_assert_false(access_store_granted(store, 1000));
    g_assert_true(access_store_change(store, "alice", FALSE, 0, &error));
    g_assert_no_error(error);
    g_assert_cmpuint(json_array_get_length(json_object_get_array_member(store, "grants")), ==, 0);
    json_object_unref(store);
}

static void policy_validation_and_duration(void)
{
    reset_policy();
    JsonObject *store = access_store_empty();
    g_assert_true(access_store_valid(store));
    g_assert_cmpuint(access_store_duration(store), ==, 28800);
    json_object_set_int_member(store, "max_duration_seconds", 900000);
    g_assert_cmpuint(access_store_duration(store), ==, 28800);
    json_object_set_int_member(store, "max_duration_seconds", 1);
    g_assert_cmpuint(access_store_duration(store), ==, 60);
    json_object_set_int_member(store, "max_duration_seconds", 3600);
    g_assert_cmpuint(access_store_duration(store), ==, 3600);
    json_object_set_int_member(store, "max_duration_seconds", 0);
    g_assert_false(access_store_valid(store));
    json_object_set_int_member(store, "max_duration_seconds", 28800);
    GError *error = NULL;
    g_assert_true(access_store_change(store, "alice", TRUE, 0, &error));
    JsonArray *grants = json_object_get_array_member(store, "grants");
    json_array_add_element(grants, json_node_copy(json_array_get_element(grants, 0)));
    g_assert_false(access_store_valid(store));
    json_array_remove_element(grants, 1);
    g_assert_true(access_store_valid(store));
    json_object_set_int_member(json_array_get_object_element(grants, 0), "uid", 0);
    g_assert_false(access_store_valid(store));
    json_object_unref(store);
}

static void private_atomic_round_trip(void)
{
    if (!root_storage()) return;
    reset_policy();
    GError *error = NULL;
    JsonObject *store = access_store_load(&error);
    g_assert_no_error(error); g_assert_nonnull(store);
    g_assert_cmpuint(access_store_duration(store), ==, 28800);
    g_assert_true(access_store_change(store, "alice", TRUE, 1001, &error));
    g_assert_true(access_store_save(store, &error));
    g_assert_no_error(error); json_object_unref(store);
    struct stat metadata;
    g_assert_cmpint(lstat(test_access_path, &metadata), ==, 0);
    g_assert_cmpuint(metadata.st_uid, ==, 0);
    g_assert_cmpuint(metadata.st_mode & 07777, ==, 0600);
    store = access_store_load(&error);
    g_assert_no_error(error); g_assert_nonnull(store);
    g_assert_true(access_store_granted(store, 1000));
    g_assert_true(access_store_change(store, "alice", FALSE, 1001, &error));
    g_assert_true(access_store_save(store, &error));
    g_assert_no_error(error); json_object_unref(store);
    store = access_store_load(&error);
    g_assert_no_error(error); g_assert_false(access_store_granted(store, 1000));
    json_object_unref(store);
    gchar *parent = g_path_get_dirname(test_access_path);
    GDir *directory = g_dir_open(parent, 0, &error);
    g_assert_no_error(error);
    const gchar *name;
    while ((name = g_dir_read_name(directory))) g_assert_cmpstr(name, ==, "access.json");
    g_dir_close(directory); g_free(parent);
}

static void expect_load_rejected(void)
{
    GError *error = NULL;
    JsonObject *store = access_store_load(&error);
    g_assert_null(store); g_assert_nonnull(error); g_clear_error(&error);
}

static void unsafe_policy_files(void)
{
    if (!root_storage()) return;
    reset_policy();
    GError *error = NULL;
    JsonObject *store = access_store_empty();
    g_assert_true(access_store_save(store, &error));
    g_assert_no_error(error);
    g_assert_cmpint(g_chmod(test_access_path, 0644), ==, 0);
    expect_load_rejected();
    g_assert_false(access_store_save(store, &error));
    g_assert_nonnull(error); g_clear_error(&error);
    g_assert_cmpint(g_chmod(test_access_path, 0600), ==, 0);
    gchar *target = g_strconcat(test_access_path, ".original", NULL);
    g_assert_cmpint(g_rename(test_access_path, target), ==, 0);
    g_assert_cmpint(symlink(target, test_access_path), ==, 0);
    expect_load_rejected();
    g_assert_false(access_store_save(store, &error));
    g_assert_nonnull(error); g_clear_error(&error);
    g_assert_cmpint(g_unlink(test_access_path), ==, 0);
    g_assert_cmpint(link(target, test_access_path), ==, 0);
    expect_load_rejected();
    g_assert_cmpint(g_unlink(test_access_path), ==, 0);
    g_assert_cmpint(g_unlink(target), ==, 0); g_free(target);
    g_assert_cmpint(mkfifo(test_access_path, 0600), ==, 0);
    expect_load_rejected();
    g_assert_cmpint(g_unlink(test_access_path), ==, 0);
    g_assert_true(g_file_set_contents(test_access_path, "{\"schema_version\":1,\"grants\":\"invalid\"}", -1, NULL));
    g_assert_cmpint(g_chmod(test_access_path, 0600), ==, 0);
    expect_load_rejected();
    gchar *large = g_malloc0(OV_ACCESS_LIMIT + 2);
    memset(large, ' ', OV_ACCESS_LIMIT + 1);
    g_assert_true(g_file_set_contents(test_access_path, large, OV_ACCESS_LIMIT + 1, NULL));
    g_free(large);
    g_assert_cmpint(g_chmod(test_access_path, 0600), ==, 0);
    expect_load_rejected();
    json_object_unref(store);
}

static void unsafe_policy_directories(void)
{
    if (!root_storage()) return;
    reset_policy();
    JsonObject *store = access_store_empty();
    GError *error = NULL;
    gchar *parent = g_path_get_dirname(test_access_path);
    g_assert_cmpint(g_chmod(parent, 0777), ==, 0);
    expect_load_rejected();
    g_assert_false(access_store_save(store, &error));
    g_assert_nonnull(error); g_clear_error(&error);
    g_assert_cmpint(g_chmod(parent, 0700), ==, 0);
    gchar *real = g_strconcat(parent, ".real", NULL);
    g_assert_cmpint(g_rename(parent, real), ==, 0);
    g_assert_cmpint(symlink(real, parent), ==, 0);
    expect_load_rejected();
    g_assert_false(access_store_save(store, &error));
    g_assert_nonnull(error); g_clear_error(&error);
    g_assert_cmpint(g_unlink(parent), ==, 0);
    g_assert_cmpint(g_rename(real, parent), ==, 0);
    g_free(real); g_free(parent); json_object_unref(store);
}

int main(int argc, char **argv)
{
    g_test_init(&argc, &argv, NULL);
    test_directory = g_strdup(geteuid() == 0 ? "/run/octovault-access-test-XXXXXX" : "/tmp/octovault-access-test-XXXXXX");
    g_assert_nonnull(g_mkdtemp(test_directory));
    test_access_path = g_build_filename(test_directory, "policy", "access.json", NULL);
    test_passwd_path = g_build_filename(test_directory, "passwd", NULL);
    test_defs_path = g_build_filename(test_directory, "login.defs", NULL);
    g_test_add_func("/access-store/eligible-users-and-uid-reassignment", eligible_accounts_and_reassignment);
    g_test_add_func("/access-store/schema-and-duration", policy_validation_and_duration);
    g_test_add_func("/access-store/private-atomic-round-trip", private_atomic_round_trip);
    g_test_add_func("/access-store/unsafe-files", unsafe_policy_files);
    g_test_add_func("/access-store/unsafe-directories", unsafe_policy_directories);
    int status = g_test_run();
    g_unlink(test_access_path); g_unlink(test_passwd_path); g_unlink(test_defs_path);
    gchar *parent = g_path_get_dirname(test_access_path); g_rmdir(parent); g_free(parent);
    g_rmdir(test_directory);
    g_free(test_access_path); g_free(test_passwd_path); g_free(test_defs_path); g_free(test_directory);
    return status;
}
