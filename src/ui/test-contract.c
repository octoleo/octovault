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

static const Spec *find_spec(const Spec *spec,const char *key)
{
    for(guint i=0;spec[i].key;i++)if(!strcmp(spec[i].key,key))return &spec[i];
    return NULL;
}

static void test_guided_creation_fields(void)
{
    const Spec *create=specifications("vault.create");
    const Spec *import=specifications("vault.import");
    g_assert_true(create!=import);
    g_assert_cmpstr(find_spec(create,"directory")->kind,==,"folder");
    g_assert_null(find_spec(create,"file"));
    g_assert_null(find_spec(create,"mountpoint"));
    g_assert_cmpstr(find_spec(create,"key_file")->kind,==,"file");
    g_assert_cmpstr(find_spec(create,"image_source")->kind,==,"file");
    g_assert_null(find_spec(create,"use_existing_key")->options);
    g_assert_cmpstr(find_spec(import,"file")->kind,==,"file");
    g_assert_cmpstr(find_spec(import,"key_file")->kind,==,"file");
    g_assert_null(find_spec(import,"password"));
    const char *methods[]={"key","image","text","gpg","token"};
    for(guint i=0;i<G_N_ELEMENTS(methods);i++)for(guint existing=0;existing<2;existing++){
        const char *auth=methods[i];
        g_assert_cmpint(vault_create_field_visible("key_file",auth,existing),==,(gboolean)existing);
        g_assert_cmpint(vault_create_field_visible("image_source",auth,existing),==,!existing&&!strcmp(auth,"image"));
        g_assert_cmpint(vault_create_field_visible("recipient",auth,existing),==,!existing&&openpgp_auth(auth));
        g_assert_cmpint(vault_create_field_visible("cipher_file",auth,existing),==,existing&&!strcmp(auth,"text"));
        g_assert_cmpint(vault_create_field_visible("password",auth,existing),==,!openpgp_auth(auth));
        g_assert_cmpint(vault_create_field_visible("_confirm_password",auth,existing),==,!existing&&!openpgp_auth(auth));
        g_assert_nonnull(vault_create_guidance(auth,existing));
    }
}

static void test_guided_creation_validation(void)
{
    JsonObject *params=json_object_new();
    json_object_set_string_member(params,"name","Personal");
    json_object_set_string_member(params,"directory",g_get_tmp_dir());
    json_object_set_double_member(params,"size_gb",10);
    json_object_set_string_member(params,"auth","key");
    json_object_set_boolean_member(params,"use_existing_key",FALSE);
    g_assert_nonnull(vault_creation_error(params));
    json_object_set_string_member(params,"password","test-only-passphrase");
    g_assert_null(vault_creation_error(params));
    json_object_set_string_member(params,"name","../Personal");
    g_assert_nonnull(vault_creation_error(params));
    json_object_set_string_member(params,"name","Personal\nDocuments");
    g_assert_nonnull(vault_creation_error(params));
    json_object_set_string_member(params,"name","Personal");
    json_object_set_string_member(params,"directory","relative/path");
    g_assert_nonnull(vault_creation_error(params));
    json_object_set_string_member(params,"directory",g_get_tmp_dir());
    json_object_set_boolean_member(params,"use_existing_key",TRUE);
    g_assert_nonnull(vault_creation_error(params));
    json_object_set_boolean_member(params,"use_existing_key",FALSE);
    json_object_set_string_member(params,"auth","image");
    g_assert_nonnull(vault_creation_error(params));
    json_object_set_string_member(params,"auth","text");
    g_assert_null(vault_creation_error(params));
    json_object_remove_member(params,"password");
    json_object_set_string_member(params,"auth","gpg");
    g_assert_nonnull(vault_creation_error(params));
    json_object_set_string_member(params,"recipient","1111111111111111111111111111111111111111!");
    g_assert_null(vault_creation_error(params));
    json_object_unref(params);
}

static void test_decimal_size_serialization(void)
{
    const double sizes[]={0.05,0.1,0.2,0.3,1.1,10,100.01};
    const char *expected[]={"0.050","0.100","0.200","0.300","1.100","10.000","100.010"};
    for(guint i=0;i<G_N_ELEMENTS(sizes);i++){
        JsonObject *params=json_object_new();JsonNode *size=json_node_new(JSON_NODE_VALUE);
        set_decimal_size(size,sizes[i]);json_object_set_member(params,"size_gb",size);
        char *request=serialize_request("vault.create",params);GError *error=NULL;
        JsonNode *parsed=parse_json(request,&error);g_assert_no_error(error);
        JsonObject *received=json_object_get_object_member(json_node_get_object(parsed),"params");
        g_assert_cmpstr(str(received,"size_gb"),==,expected[i]);
        g_assert_true(g_regex_match_simple("^[0-9]+([.][0-9]{1,6})?$",str(received,"size_gb"),0,0));
        g_assert_cmpfloat(decimal_size(received),==,sizes[i]);
        g_free(request);json_node_free(parsed);json_object_unref(params);
    }
}

static void test_token_authentication_contract(void)
{
    JsonObject *params=json_object_new();
    json_object_set_string_member(params,"auth","token");
    normalize_vault_auth(params);
    g_assert_cmpstr(str(params,"auth"),==,"gpg");g_assert_true(boolean(params,"require_token"));
    json_object_set_string_member(params,"auth","gpg");normalize_vault_auth(params);
    g_assert_false(boolean(params,"require_token"));
    json_object_set_string_member(params,"auth","key");normalize_vault_auth(params);
    g_assert_cmpstr(str(params,"auth"),==,"key");g_assert_false(boolean(params,"require_token"));
    json_object_unref(params);
}

static void test_safe_error_details(void)
{
    Operation operation={.id="job-test",.stage="queued"};JsonObject *error=json_object_new();
    json_object_set_string_member(error,"code","authentication_failed");
    json_object_set_string_member(error,"stage","authentication");
    json_object_set_string_member(error,"diagnostic_id","report-test");
    json_object_set_string_member(error,"diagnostic_file","/var/lib/octovault/report-test.json");
    json_object_set_string_member(error,"password","never-display-this");
    json_object_set_string_member(error,"stderr","raw-engine-secret");
    JsonArray *retained=json_array_new();json_array_add_string_element(retained,"/home/person/Personal.tomb");
    json_object_set_array_member(error,"retained_paths",retained);
    char *details=operation_error_details(&operation,error);
    g_assert_nonnull(strstr(details,"Error: authentication_failed"));
    g_assert_nonnull(strstr(details,"Stage: authentication"));g_assert_null(strstr(details,"queued"));
    g_assert_nonnull(strstr(details,"Job: job-test"));g_assert_nonnull(strstr(details,"Report: report-test"));
    g_assert_nonnull(strstr(details,"Retained file: /home/person/Personal.tomb"));
    g_assert_null(strstr(details,"never-display-this"));g_assert_null(strstr(details,"raw-engine-secret"));
    g_free(details);json_object_unref(error);
    details=operation_error_details(&operation,NULL);
    g_assert_nonnull(strstr(details,"Stage: queued"));g_assert_null(strstr(details,"Retained"));g_free(details);
}

static void test_advanced_defaults_and_preservation(void)
{
    Form form={0};form.original=json_object_new();
    const Spec*plan=specifications("backup.save");
    const Spec*retention=find_spec(plan,"retention.keep_daily");
    JsonNode*value=hidden_advanced_value(&form,retention);
    g_assert_cmpint(json_node_get_int(value),==,0);json_node_free(value);
    JsonObject*saved_retention=json_object_new();json_object_set_int_member(saved_retention,"keep_daily",31);json_object_set_object_member(form.original,"retention",saved_retention);
    value=hidden_advanced_value(&form,retention);g_assert_cmpint(json_node_get_int(value),==,31);json_node_free(value);
    json_object_set_string_member(form.original,"path","octovault-existing-storage");
    value=hidden_advanced_value(&form,find_spec(specifications("repository.create"),"path"));
    g_assert_cmpstr(json_node_get_string(value),==,"octovault-existing-storage");json_node_free(value);
    json_object_set_string_member(form.original,"password","never-restore-this-secret");
    value=hidden_advanced_value(&form,find_spec(specifications("repository.password"),"password"));
    g_assert_cmpstr(json_node_get_string(value),==,"");json_node_free(value);
    value=field_default(find_spec(specifications("vault.create"),"close_on"));
    g_assert_true(string_array_has(value,"shutdown"));g_assert_false(string_array_has(value,"sleep"));json_node_free(value);
    value=field_default(find_spec(specifications("destination.save"),"port"));
    g_assert_cmpint(json_node_get_int(value),==,22);json_node_free(value);
    g_assert_false(advanced_field("backup.save","calendar"));
    g_assert_false(advanced_field("backup.save","drive_uuid"));
    g_assert_false(advanced_field("backup.save","vault_id"));
    g_assert_false(advanced_field("destination.save","host_fingerprint"));
    g_assert_false(advanced_field("destination.save","ssh_private_key"));
    json_object_unref(form.original);
}

static void test_destination_guidance(void)
{
    JsonObject*params=json_object_new(),*original=json_object_new();
    json_object_set_string_member(params,"type","local");
    g_assert_nonnull(destination_setup_error(params,original));
    json_object_set_string_member(params,"path",g_get_tmp_dir());
    g_assert_null(destination_setup_error(params,original));
    json_object_set_string_member(params,"type","s3");
    json_object_set_string_member(params,"endpoint","https://storage.example.test");
    json_object_set_string_member(params,"bucket","my-backups");
    g_assert_nonnull(destination_setup_error(params,original));
    json_object_set_string_member(params,"access_key","test-only-id");
    json_object_set_string_member(params,"secret_key","test-only-secret");
    g_assert_null(destination_setup_error(params,original));
    json_object_set_string_member(params,"type","sftp");
    json_object_set_string_member(params,"host","example.test");
    json_object_set_string_member(params,"user","backup");
    g_assert_nonnull(destination_setup_error(params,original));
    json_object_set_string_member(params,"host_fingerprint","SHA256:test-only");
    g_assert_nonnull(destination_setup_error(params,original));
    json_object_set_string_member(params,"ssh_private_key","test-only-private-key");
    g_assert_null(destination_setup_error(params,original));
    json_object_unref(params);json_object_unref(original);
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
    g_test_add_func("/ui/guided-creation-fields", test_guided_creation_fields);
    g_test_add_func("/ui/guided-creation-validation", test_guided_creation_validation);
    g_test_add_func("/ui/decimal-size-serialization", test_decimal_size_serialization);
    g_test_add_func("/ui/token-authentication-contract", test_token_authentication_contract);
    g_test_add_func("/ui/safe-error-details", test_safe_error_details);
    g_test_add_func("/ui/advanced-defaults-preservation", test_advanced_defaults_and_preservation);
    g_test_add_func("/ui/destination-guidance", test_destination_guidance);
    return g_test_run();
}
