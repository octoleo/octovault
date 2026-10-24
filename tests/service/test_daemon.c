/* SPDX-License-Identifier: Apache-2.0 */
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
        "{\"op\":42,\"params\":{}}"
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
    g_assert_true(config_read("repository.snapshots"));
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

int main(int argc, char **argv)
{
    g_test_init(&argc, &argv, NULL);
    g_test_add_func("/daemon/identity-overrides", identity_overrides);
    g_test_add_func("/daemon/request-and-authorization", valid_request);
    g_test_add_func("/daemon/bounded-request", bounded_request);
    g_test_add_func("/daemon/session-allowlist", session_allowlist);
    return g_test_run();
}
