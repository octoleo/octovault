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

int main(int argc, char **argv)
{
    g_test_init(&argc, &argv, NULL);
    g_test_add_func("/cli/typed-options", typed_options);
    g_test_add_func("/cli/restore-policy", restore_policy);
    g_test_add_func("/cli/secret-argv-rejection", invalid_secret_argument);
    g_test_add_func("/cli/numeric-validation", numeric_rejection);
    return g_test_run();
}
