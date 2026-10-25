/* SPDX-License-Identifier: Apache-2.0 */
#define _GNU_SOURCE
#include <gio/gio.h>
#include <json-glib/json-glib.h>
#include <glib/gstdio.h>

static gchar *recovery_test_root;
#define OV_ACCESS_STATE_ROOT recovery_test_root
#include "../../src/service/access-recovery.c"

static const gchar personal_repository[] = "{\"schema_version\":1,\"id\":\"repo\",\"execution_scope\":\"personal\",\"destination_id\":\"dest\"}";
static const gchar personal_destination[] = "{\"schema_version\":1,\"id\":\"dest\",\"execution_scope\":\"personal\"}";

static gchar *record_path(const gchar *collection, const gchar *id)
{
    gchar *filename = g_strconcat(id, ".json", NULL);
    gchar *path = g_build_filename(recovery_test_root, "1000", collection, filename, NULL);
    g_free(filename);
    return path;
}

static void write_record(const gchar *collection, const gchar *id, const gchar *text)
{
    gchar *path = record_path(collection, id);
    g_unlink(path);
    g_assert_true(g_file_set_contents(path, text, -1, NULL));
    g_assert_cmpint(g_chmod(path, 0600), ==, 0);
    g_free(path);
}

static void reset_records(void)
{
    gchar *path = g_build_filename(recovery_test_root, "1000", "repositories", NULL);
    g_assert_cmpint(g_mkdir_with_parents(path, 0700), ==, 0); g_free(path);
    path = g_build_filename(recovery_test_root, "1000", "destinations", NULL);
    g_assert_cmpint(g_mkdir_with_parents(path, 0700), ==, 0); g_free(path);
    write_record("repositories", "repo", personal_repository);
    write_record("destinations", "dest", personal_destination);
}

static gboolean root_storage(void)
{
    if (geteuid() == 0) return TRUE;
    g_test_skip("Recovery policy metadata must have the daemon's root ownership.");
    return FALSE;
}

static void record_identifier_validation(void)
{
    g_assert_true(access_recovery_id("valid-ID_012"));
    g_assert_false(access_recovery_id(NULL));
    g_assert_false(access_recovery_id(""));
    g_assert_false(access_recovery_id("../repo"));
    g_assert_false(access_recovery_id("repo/other"));
    g_assert_false(access_recovery_id("repo\n"));
    g_assert_false(access_personal_recovery_allowed(0, "repo"));
}

static void personal_scope_and_namespace(void)
{
    if (!root_storage()) return;
    reset_records();
    g_assert_true(access_personal_recovery_allowed(1000, "repo"));
    g_assert_false(access_personal_recovery_allowed(1001, "repo"));
    g_assert_false(access_personal_recovery_allowed(1000, "missing"));
    write_record("repositories", "repo", "{\"schema_version\":1,\"id\":\"repo\",\"destination_id\":\"dest\"}");
    g_assert_false(access_personal_recovery_allowed(1000, "repo"));
    write_record("repositories", "repo", "{\"schema_version\":1,\"id\":\"repo\",\"execution_scope\":\"system\",\"destination_id\":\"dest\"}");
    g_assert_false(access_personal_recovery_allowed(1000, "repo"));
    write_record("repositories", "repo", personal_repository);
    write_record("destinations", "dest", "{\"schema_version\":1,\"id\":\"dest\",\"execution_scope\":\"system\"}");
    g_assert_false(access_personal_recovery_allowed(1000, "repo"));
    write_record("destinations", "dest", personal_destination);
    write_record("repositories", "repo", "{\"schema_version\":1,\"id\":\"repo\",\"execution_scope\":\"personal\",\"destination_id\":\"dest\",\"owner_uid\":1001}");
    g_assert_false(access_personal_recovery_allowed(1000, "repo"));
    write_record("repositories", "repo", "{\"schema_version\":1,\"id\":\"repo\",\"execution_scope\":\"personal\",\"destination_id\":\"dest\",\"owner_uid\":1000}");
    g_assert_true(access_personal_recovery_allowed(1000, "repo"));
}

static void invalid_linked_metadata(void)
{
    if (!root_storage()) return;
    reset_records();
    const gchar *invalid[] = {
        "{}", "[]", "invalid JSON",
        "{\"schema_version\":2,\"id\":\"repo\",\"execution_scope\":\"personal\",\"destination_id\":\"dest\"}",
        "{\"schema_version\":1,\"id\":\"different\",\"execution_scope\":\"personal\",\"destination_id\":\"dest\"}",
        "{\"schema_version\":1,\"id\":\"repo\",\"execution_scope\":\"personal\"}",
        "{\"schema_version\":1,\"id\":\"repo\",\"execution_scope\":\"personal\",\"destination_id\":\"../dest\"}"
    };
    for (guint i = 0; i < G_N_ELEMENTS(invalid); i++) {
        write_record("repositories", "repo", invalid[i]);
        g_assert_false(access_personal_recovery_allowed(1000, "repo"));
    }
    write_record("repositories", "repo", personal_repository);
    gchar *destination = record_path("destinations", "dest");
    g_assert_cmpint(g_unlink(destination), ==, 0); g_free(destination);
    g_assert_false(access_personal_recovery_allowed(1000, "repo"));
}

static void unsafe_metadata_files(void)
{
    if (!root_storage()) return;
    reset_records();
    gchar *path = record_path("repositories", "repo");
    g_assert_cmpint(g_chmod(path, 0644), ==, 0);
    g_assert_false(access_personal_recovery_allowed(1000, "repo"));
    g_assert_cmpint(g_chmod(path, 0600), ==, 0);
    struct stat metadata;
    g_assert_cmpint(lstat(path, &metadata), ==, 0);
    g_assert_true(access_recovery_file_secure(&metadata));
    metadata.st_uid = 1000;
    g_assert_false(access_recovery_file_secure(&metadata));
    gchar *target = g_strconcat(path, ".original", NULL);
    g_assert_cmpint(g_rename(path, target), ==, 0);
    g_assert_cmpint(symlink(target, path), ==, 0);
    g_assert_false(access_personal_recovery_allowed(1000, "repo"));
    g_assert_cmpint(g_unlink(path), ==, 0);
    g_assert_cmpint(link(target, path), ==, 0);
    g_assert_false(access_personal_recovery_allowed(1000, "repo"));
    g_assert_cmpint(g_unlink(path), ==, 0);
    g_assert_cmpint(g_unlink(target), ==, 0); g_free(target);
    g_assert_cmpint(mkfifo(path, 0600), ==, 0);
    g_assert_false(access_personal_recovery_allowed(1000, "repo"));
    g_assert_cmpint(g_unlink(path), ==, 0);
    gchar *oversize = g_malloc0(OV_ACCESS_RECOVERY_LIMIT + 2);
    memset(oversize, ' ', OV_ACCESS_RECOVERY_LIMIT + 1);
    g_assert_true(g_file_set_contents(path, oversize, OV_ACCESS_RECOVERY_LIMIT + 1, NULL));
    g_free(oversize); g_assert_cmpint(g_chmod(path, 0600), ==, 0);
    g_assert_false(access_personal_recovery_allowed(1000, "repo"));
    g_free(path);
}

static void unsafe_metadata_directories(void)
{
    if (!root_storage()) return;
    reset_records();
    gchar *directory = g_build_filename(recovery_test_root, "1000", "repositories", NULL);
    g_assert_cmpint(g_chmod(directory, 0777), ==, 0);
    g_assert_false(access_personal_recovery_allowed(1000, "repo"));
    g_assert_cmpint(g_chmod(directory, 0700), ==, 0);
    gchar *real = g_strconcat(directory, ".real", NULL);
    g_assert_cmpint(g_rename(directory, real), ==, 0);
    g_assert_cmpint(symlink(real, directory), ==, 0);
    g_assert_false(access_personal_recovery_allowed(1000, "repo"));
    g_assert_cmpint(g_unlink(directory), ==, 0);
    g_assert_cmpint(g_rename(real, directory), ==, 0);
    g_free(real); g_free(directory);
    directory = g_build_filename(recovery_test_root, "1000", NULL);
    real = g_strconcat(directory, ".real", NULL);
    g_assert_cmpint(g_rename(directory, real), ==, 0);
    g_assert_cmpint(symlink(real, directory), ==, 0);
    g_assert_false(access_personal_recovery_allowed(1000, "repo"));
    g_assert_cmpint(g_unlink(directory), ==, 0);
    g_assert_cmpint(g_rename(real, directory), ==, 0);
    g_free(real); g_free(directory);
}

int main(int argc, char **argv)
{
    g_test_init(&argc, &argv, NULL);
    recovery_test_root = g_strdup(geteuid() == 0 ? "/run/octovault-recovery-test-XXXXXX" : "/tmp/octovault-recovery-test-XXXXXX");
    g_assert_nonnull(g_mkdtemp(recovery_test_root));
    g_test_add_func("/access-recovery/identifier-validation", record_identifier_validation);
    g_test_add_func("/access-recovery/personal-scope-and-namespace", personal_scope_and_namespace);
    g_test_add_func("/access-recovery/invalid-linked-metadata", invalid_linked_metadata);
    g_test_add_func("/access-recovery/unsafe-files", unsafe_metadata_files);
    g_test_add_func("/access-recovery/unsafe-directories", unsafe_metadata_directories);
    int status = g_test_run();
    gchar *path = record_path("repositories", "repo"); g_unlink(path); g_free(path);
    path = record_path("destinations", "dest"); g_unlink(path); g_free(path);
    path = g_build_filename(recovery_test_root, "1000", "repositories", NULL); g_rmdir(path); g_free(path);
    path = g_build_filename(recovery_test_root, "1000", "destinations", NULL); g_rmdir(path); g_free(path);
    path = g_build_filename(recovery_test_root, "1000", NULL); g_rmdir(path); g_free(path);
    g_rmdir(recovery_test_root); g_free(recovery_test_root);
    return status;
}
