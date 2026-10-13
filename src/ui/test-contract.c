/* SPDX-License-Identifier: Apache-2.0
 * Exercise the GUI/service serialization boundary without requiring a display.
 */
#define main octovault_gui_program_main
#include "main.c"
#undef main

static void test_request_round_trip(void)
{
    JsonObject *params = json_object_new();
    const char *path = "/home/person/Documents/A folder with 'quotes' and spaces ";
    const char *password = "sample-only:\"\\\nnot-a-real-credential";
    json_object_set_string_member(params, "source", path);
    json_object_set_string_member(params, "password", password);
    json_object_set_double_member(params, "size_gb", 1.125);
    JsonArray *events = json_array_new();
    json_array_add_string_element(events, "sleep");
    json_array_add_string_element(events, "shutdown");
    json_object_set_array_member(params, "close_on", events);

    char *request = serialize_request("vault.create", params);
    GError *error = NULL;
    JsonNode *parsed = parse_json(request, &error);
    g_assert_no_error(error);
    g_assert_nonnull(parsed);
    JsonObject *root = json_node_get_object(parsed);
    g_assert_cmpstr(str(root, "op"), ==, "vault.create");
    JsonObject *received = json_object_get_object_member(root, "params");
    g_assert_cmpstr(str(received, "source"), ==, path);
    g_assert_cmpstr(str(received, "password"), ==, password);
    g_assert_cmpfloat(json_object_get_double_member(received, "size_gb"), ==, 1.125);
    g_assert_true(string_array_has(json_object_get_member(received, "close_on"), "sleep"));
    g_assert_false(string_array_has(json_object_get_member(received, "close_on"), "screen-lock"));
    gsize length = strlen(request);
    wipe(request);
    for (gsize i = 0; i < length; i++) g_assert_cmpint(request[i], ==, 0);
    g_free(request);
    json_node_free(parsed);
    json_object_unref(params);
}

static void test_nested_policies(void)
{
    JsonObject *record = json_object_new();
    JsonNode *daily = json_node_new(JSON_NODE_VALUE);
    json_node_set_int(daily, 7);
    set_nested(record, "retention.keep_daily", daily);
    JsonNode *monthly = json_node_new(JSON_NODE_VALUE);
    json_node_set_int(monthly, 12);
    set_nested(record, "retention.keep_monthly", monthly);
    JsonNode *hook = json_node_new(JSON_NODE_VALUE);
    json_node_set_string(hook, "/home/person/scripts/after open.sh");
    set_nested(record, "hooks.open", hook);
    g_assert_cmpint(json_node_get_int(lookup(record, "retention.keep_daily")), ==, 7);
    g_assert_cmpint(json_node_get_int(lookup(record, "retention.keep_monthly")), ==, 12);
    g_assert_cmpstr(json_node_get_string(lookup(record, "hooks.open")), ==,
                    "/home/person/scripts/after open.sh");
    g_assert_null(lookup(record, "hooks.unknown"));
    json_object_unref(record);
}

static void test_restore_and_retention_contract(void)
{
    const Spec *spec = specifications("repository.restore");
    gboolean found = FALSE;
    for (guint i = 0; spec[i].key; i++) {
        if (!strcmp(spec[i].key, "overwrite")) {
            g_assert_cmpstr(spec[i].kind, ==, "choice");
            g_assert_cmpstr(spec[i].options, ==, "never|if-newer|if-changed|always");
            found = TRUE;
        }
    }
    g_assert_true(found);
    spec = specifications("backup.save");
    for (guint i = 0; spec[i].key; i++) {
        if (g_str_has_prefix(spec[i].key, "retention."))
            g_assert_cmpstr(spec[i].options, ==, "0");
    }
    spec = specifications("vault.create");
    for (guint i = 0; spec[i].key; i++) {
        if (!strcmp(spec[i].key, "size_gb"))
            g_assert_cmpstr(spec[i].kind, ==, "number");
        if (!strcmp(spec[i].key, "open_on"))
            g_assert_true(g_str_has_prefix(spec[i].options, "login|"));
    }
}

static void test_readable_recovery(void)
{
    JsonObject *record = json_object_new();
    json_object_set_string_member(record, "RESTIC_REPOSITORY", "sftp:server:/backup");
    json_object_set_string_member(record, "RESTIC_PASSWORD", "sample-only-password");
    json_object_set_string_member(record, "ssh_private_key", "BEGIN\nbody\nEND");
    JsonNode *node = json_node_new(JSON_NODE_OBJECT);
    json_node_take_object(node, record);
    GString *text = g_string_new(NULL);
    recovery_flatten(text, NULL, node);
    g_assert_nonnull(strstr(text->str, "RESTIC_REPOSITORY: sftp:server:/backup\n"));
    g_assert_nonnull(strstr(text->str, "RESTIC_PASSWORD: sample-only-password\n"));
    g_assert_nonnull(strstr(text->str, "ssh_private_key: BEGIN\nbody\nEND\n"));
    wipe(text->str);
    g_string_free(text, TRUE);
    json_node_free(node);
}

static void test_openpgp_card_selection(void)
{
    const char *signing = "1111111111111111111111111111111111111111";
    const char *encryption = "2222222222222222222222222222222222222222";
    char *status = g_strdup_printf("Reader:Test:AID:1234:openpgp-card:\nfpr:%s:%s:3333333333333333333333333333333333333333:\n", signing, encryption);
    char *selected = card_encryption_fingerprint(status);
    g_assert_cmpstr(selected, ==, encryption);
    g_free(selected);
    g_free(status);
    /* A signing-only card must not be mistaken for an encryption token. */
    selected = card_encryption_fingerprint("fpr:1111111111111111111111111111111111111111::3333333333333333333333333333333333333333:\n");
    g_assert_null(selected);
    selected = card_encryption_fingerprint("fpr:1111111111111111111111111111111111111111:0000000000000000000000000000000000000000::\n");
    g_assert_null(selected);
    g_assert_false(valid_fingerprint("not-a-fingerprint"));
}

static void test_usable_encryption_keys(void)
{
    const char *listing =
        "pub:u:4096:1:1111111111111111:1700000000:0::u:::scSC:\n"
        "fpr:::::::::1111111111111111111111111111111111111111:\n"
        "uid:u::::::::Person <person@example.test>:\n"
        "sub:u:4096:1:2222222222222222:1700000000:0:::::e:\n"
        "fpr:::::::::2222222222222222222222222222222222222222:\n"
        "sub:r:4096:1:3333333333333333:1700000000:0:::::e:\n"
        "fpr:::::::::3333333333333333333333333333333333333333:\n"
        "sub:u:4096:1:4444444444444444:1700000000:1:::::e:\n"
        "fpr:::::::::4444444444444444444444444444444444444444:\n"
        "pub:u:4096:1:5555555555555555:1700000000:0::u:::eD:\n"
        "fpr:::::::::5555555555555555555555555555555555555555:\n";
    GPtrArray *keys = parse_encryption_keys(listing);
    g_assert_cmpuint(keys->len, ==, 1);
    GpgKey *key = g_ptr_array_index(keys, 0);
    g_assert_cmpstr(key->fingerprint, ==, "2222222222222222222222222222222222222222");
    g_assert_cmpstr(key->identity, ==, "Person <person@example.test>");
    g_ptr_array_unref(keys);
}

int main(int argc, char **argv)
{
    g_test_init(&argc, &argv, NULL);
    g_test_add_func("/ui/request-round-trip", test_request_round_trip);
    g_test_add_func("/ui/nested-policies", test_nested_policies);
    g_test_add_func("/ui/restore-retention-contract", test_restore_and_retention_contract);
    g_test_add_func("/ui/readable-recovery", test_readable_recovery);
    g_test_add_func("/ui/openpgp-card-selection", test_openpgp_card_selection);
    g_test_add_func("/ui/usable-encryption-keys", test_usable_encryption_keys);
    return g_test_run();
}
