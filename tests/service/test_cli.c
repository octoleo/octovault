/* SPDX-License-Identifier: Apache-2.0 */
#define main octovault_cli_entrypoint
#include "../../src/service/cli.c"
#undef main

static void typed_options(void)
{
    gchar *args[] = { "backup", "save", "--source", "/path with spaces", "--source", "/etc",
        "--one-file-system", "--no-metered", "--boot-delay-sec", "3600", "--retention", "{\"keep_daily\":7}" };
    GError *error = NULL;
    gchar *encoded = make_request(G_N_ELEMENTS(args), args, &error);
    g_assert_no_error(error); g_assert_nonnull(encoded);
    JsonParser *parser = json_parser_new();
    g_assert_true(json_parser_load_from_data(parser, encoded, -1, &error));
    JsonObject *root = json_node_get_object(json_parser_get_root(parser));
    g_assert_cmpstr(json_object_get_string_member(root, "op"), ==, "backup.save");
    JsonObject *params = json_object_get_object_member(root, "params");
    JsonArray *sources = json_object_get_array_member(params, "sources");
    g_assert_cmpuint(json_array_get_length(sources), ==, 2);
    g_assert_cmpstr(json_array_get_string_element(sources, 0), ==, "/path with spaces");
    g_assert_true(json_object_get_boolean_member(params, "one_file_system"));
    g_assert_false(json_object_get_boolean_member(params, "metered"));
    g_assert_cmpint(json_object_get_int_member(params, "boot_delay_sec"), ==, 3600);
    g_assert_cmpint(json_object_get_int_member(json_object_get_object_member(params, "retention"), "keep_daily"), ==, 7);
    g_object_unref(parser); g_free(encoded);
}

static void restore_policy(void)
{
    gchar *args[] = { "repository", "restore", "--overwrite", "if-newer" };
    GError *error = NULL;
    gchar *encoded = make_request(G_N_ELEMENTS(args), args, &error);
    g_assert_no_error(error); g_assert_nonnull(strstr(encoded, "\"overwrite\":\"if-newer\""));
    g_free(encoded);
    args[3] = "true";
    encoded = make_request(G_N_ELEMENTS(args), args, &error);
    g_assert_null(encoded); g_assert_error(error, G_IO_ERROR, G_IO_ERROR_INVALID_ARGUMENT); g_clear_error(&error);
}

static void invalid_secret_argument(void)
{
    gchar *args[] = { "vault", "open", "--password", "never-print-this" };
    GError *error = NULL;
    gchar *encoded = make_request(G_N_ELEMENTS(args), args, &error);
    g_assert_null(encoded); g_assert_error(error, G_IO_ERROR, G_IO_ERROR_INVALID_ARGUMENT);
    g_assert_null(strstr(error->message, "never-print-this")); g_clear_error(&error);
}

static void numeric_rejection(void)
{
    gchar *args[] = { "vault", "create", "--size-gb", "NaN" };
    GError *error = NULL;
    gchar *encoded = make_request(G_N_ELEMENTS(args), args, &error);
    g_assert_null(encoded); g_assert_error(error, G_IO_ERROR, G_IO_ERROR_INVALID_ARGUMENT); g_clear_error(&error);
    args[3] = "1.25";
    encoded = make_request(G_N_ELEMENTS(args), args, &error);
    g_assert_no_error(error); g_assert_nonnull(strstr(encoded, "1.25")); g_free(encoded);
}

static void guided_vault_options(void)
{
    gchar *args[] = { "vault", "create", "--name", "Personal files", "--directory", "/home/person/Vaults",
        "--size-gb", "2.5", "--use-existing-key", "--key-file", "/home/person/existing.key" };
    GError *error = NULL;
    gchar *encoded = make_request(G_N_ELEMENTS(args), args, &error);
    g_assert_no_error(error);
    JsonParser *parser = json_parser_new();
    g_assert_true(json_parser_load_from_data(parser, encoded, -1, &error));
    JsonObject *params = json_object_get_object_member(json_node_get_object(json_parser_get_root(parser)), "params");
    g_assert_true(json_object_get_boolean_member(params, "use_existing_key"));
    g_assert_cmpstr(json_object_get_string_member(params, "directory"), ==, "/home/person/Vaults");
    g_assert_cmpstr(json_object_get_string_member(params, "key_file"), ==, "/home/person/existing.key");
    g_assert_false(json_object_has_member(params, "password"));
    g_free(encoded);
    args[8] = "--no-use-existing-key";
    encoded = make_request(G_N_ELEMENTS(args), args, &error);
    g_assert_no_error(error);
    g_assert_true(json_parser_load_from_data(parser, encoded, -1, &error));
    params = json_object_get_object_member(json_node_get_object(json_parser_get_root(parser)), "params");
    g_assert_false(json_object_get_boolean_member(params, "use_existing_key"));
    g_object_unref(parser);
    g_free(encoded);
}

static void yubikey_and_diagnostic_options(void)
{
    gchar *args[] = { "vault", "auth-check", "--recipient", "1111111111111111111111111111111111111111!", "--require-token" };
    GError *error = NULL;
    gchar *encoded = make_request(G_N_ELEMENTS(args), args, &error);
    g_assert_no_error(error);
    JsonParser *parser = json_parser_new();
    g_assert_true(json_parser_load_from_data(parser, encoded, -1, &error));
    JsonObject *root = json_node_get_object(json_parser_get_root(parser));
    g_assert_cmpstr(json_object_get_string_member(root, "op"), ==, "vault.auth-check");
    g_assert_true(json_object_get_boolean_member(json_object_get_object_member(root, "params"), "require_token"));
    g_free(encoded);
    gchar *diagnostic[] = { "diagnostic", "get", "--id", "failure-id" };
    encoded = make_request(G_N_ELEMENTS(diagnostic), diagnostic, &error);
    g_assert_no_error(error);
    g_assert_true(json_parser_load_from_data(parser, encoded, -1, &error));
    root = json_node_get_object(json_parser_get_root(parser));
    g_assert_cmpstr(json_object_get_string_member(root, "op"), ==, "diagnostic.get");
    g_assert_cmpstr(json_object_get_string_member(json_object_get_object_member(root, "params"), "id"), ==, "failure-id");
    g_object_unref(parser); g_free(encoded);
}

static void decimal_capacity(void)
{
    gchar *args[] = { "vault", "create", "--size-gb", "0.05" };
    GError *error = NULL;
    gchar *encoded = make_request(G_N_ELEMENTS(args), args, &error);
    g_assert_no_error(error);
    JsonParser *parser = json_parser_new();
    g_assert_true(json_parser_load_from_data(parser, encoded, -1, &error));
    JsonObject *params = json_object_get_object_member(json_node_get_object(json_parser_get_root(parser)), "params");
    g_assert_cmpstr(json_object_get_string_member(params, "size_gb"), ==, "0.05");
    g_object_unref(parser); g_free(encoded);
}

static void client_session_context(void)
{
    const gchar *names[] = { "DISPLAY", "XAUTHORITY", "WAYLAND_DISPLAY", "GPG_TTY", "GNUPGHOME" };
    gchar *saved[G_N_ELEMENTS(names)];
    for (guint i = 0; i < G_N_ELEMENTS(names); i++) { saved[i] = g_strdup(g_getenv(names[i])); g_unsetenv(names[i]); }
    GError *error = NULL;
    const gchar *request = "{\"op\":\"vault.auth-check\",\"params\":{\"recipient\":\"fingerprint\"},\"session\":{\"display\":\"untrusted:99\",\"PATH\":\"/untrusted\"}}";
    gchar *encoded = ov_client_prepare_request(request, &error);
    g_assert_no_error(error); g_assert_nonnull(encoded);
    JsonParser *parser = json_parser_new();
    g_assert_true(json_parser_load_from_data(parser, encoded, -1, &error));
    JsonObject *root = json_node_get_object(json_parser_get_root(parser));
    g_assert_false(json_object_has_member(root, "session"));
    g_assert_cmpstr(json_object_get_string_member(json_object_get_object_member(root, "params"), "recipient"), ==, "fingerprint");
    g_free(encoded);

    g_setenv("DISPLAY", ":1", TRUE);
    g_setenv("XAUTHORITY", "/run/user/1000/gdm/Xauthority", TRUE);
    g_setenv("WAYLAND_DISPLAY", "wayland-0", TRUE);
    g_setenv("GPG_TTY", "/dev/pts/3", TRUE);
    g_setenv("GNUPGHOME", "/home/person/Private keyring", TRUE);
    encoded = ov_client_prepare_request(request, &error);
    g_assert_no_error(error);
    g_assert_true(json_parser_load_from_data(parser, encoded, -1, &error));
    root = json_node_get_object(json_parser_get_root(parser));
    JsonObject *session = json_object_get_object_member(root, "session");
    g_assert_cmpuint(json_object_get_size(session), ==, 5);
    g_assert_cmpstr(json_object_get_string_member(session, "display"), ==, ":1");
    g_assert_cmpstr(json_object_get_string_member(session, "xauthority"), ==, "/run/user/1000/gdm/Xauthority");
    g_assert_cmpstr(json_object_get_string_member(session, "wayland_display"), ==, "wayland-0");
    g_assert_cmpstr(json_object_get_string_member(session, "gpg_tty"), ==, "/dev/pts/3");
    g_assert_cmpstr(json_object_get_string_member(session, "gnupg_home"), ==, "/home/person/Private keyring");
    g_assert_true(ov_session_valid(json_object_get_member(root, "session")));
    g_assert_null(strstr(encoded, "untrusted"));
    g_free(encoded);

    g_setenv("DISPLAY", ":1\nnever-print-this", TRUE);
    encoded = ov_client_prepare_request(request, &error);
    g_assert_null(encoded); g_assert_error(error, G_IO_ERROR, G_IO_ERROR_INVALID_ARGUMENT);
    g_assert_null(strstr(error->message, "never-print-this")); g_clear_error(&error);
    encoded = ov_client_prepare_request("[]", &error);
    g_assert_null(encoded); g_assert_error(error, G_IO_ERROR, G_IO_ERROR_INVALID_ARGUMENT); g_clear_error(&error);
    g_object_unref(parser);
    for (guint i = 0; i < G_N_ELEMENTS(names); i++) {
        if (saved[i]) g_setenv(names[i], saved[i], TRUE); else g_unsetenv(names[i]);
        g_free(saved[i]);
    }
}

int main(int argc, char **argv)
{
    g_test_init(&argc, &argv, NULL);
    g_test_add_func("/cli/typed-options", typed_options);
    g_test_add_func("/cli/restore-policy", restore_policy);
    g_test_add_func("/cli/secret-argv-rejection", invalid_secret_argument);
    g_test_add_func("/cli/numeric-validation", numeric_rejection);
    g_test_add_func("/cli/guided-vault-options", guided_vault_options);
    g_test_add_func("/cli/yubikey-and-diagnostic-options", yubikey_and_diagnostic_options);
    g_test_add_func("/cli/decimal-capacity", decimal_capacity);
    g_test_add_func("/client/session-context", client_session_context);
    return g_test_run();
}
