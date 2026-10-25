/* SPDX-License-Identifier: Apache-2.0 */
#include "client.h"
#include <string.h>

/* Only user-session hints needed by the user's GnuPG agent cross D-Bus.
 * These values are never installed in the privileged worker environment. */
static const struct { const gchar *name; const gchar *environment; } session_fields[] = {
    { "display", "DISPLAY" },
    { "xauthority", "XAUTHORITY" },
    { "wayland_display", "WAYLAND_DISPLAY" },
    { "gpg_tty", "GPG_TTY" },
    { "gnupg_home", "GNUPGHOME" }
};

static gboolean session_text_valid(const gchar *value)
{
    if (!value || !*value || strlen(value) > 4096 || !g_utf8_validate(value, -1, NULL)) return FALSE;
    for (const guchar *p = (const guchar *)value; *p; p++)
        if (*p < 32 || *p == 127) return FALSE;
    return TRUE;
}

gboolean ov_session_valid(JsonNode *session)
{
    if (!session) return TRUE;
    if (!JSON_NODE_HOLDS_OBJECT(session)) return FALSE;
    JsonObject *object = json_node_get_object(session);
    GList *members = json_object_get_members(object);
    gboolean valid = TRUE;
    for (GList *item = members; valid && item; item = item->next) {
        gboolean known = FALSE;
        for (guint i = 0; i < G_N_ELEMENTS(session_fields); i++)
            if (g_str_equal(item->data, session_fields[i].name)) { known = TRUE; break; }
        JsonNode *value = json_object_get_member(object, item->data);
        valid = known && JSON_NODE_HOLDS_VALUE(value) && json_node_get_value_type(value) == G_TYPE_STRING &&
            session_text_valid(json_node_get_string(value));
    }
    g_list_free(members);
    return valid;
}

gchar *ov_client_prepare_request(const gchar *request, GError **error)
{
    if (!request || strlen(request) > OV_REQUEST_LIMIT) {
        g_set_error_literal(error, G_IO_ERROR, G_IO_ERROR_INVALID_ARGUMENT, "Request exceeds the supported size.");
        return NULL;
    }
    JsonParser *parser = json_parser_new();
    if (!json_parser_load_from_data(parser, request, -1, NULL) ||
        !JSON_NODE_HOLDS_OBJECT(json_parser_get_root(parser))) {
        g_object_unref(parser);
        g_set_error_literal(error, G_IO_ERROR, G_IO_ERROR_INVALID_ARGUMENT, "Request must be a valid JSON object.");
        return NULL;
    }
    JsonNode *root = json_parser_get_root(parser);
    JsonObject *object = json_node_get_object(root);
    /* A pasted request must not silently redirect authentication to another
     * display or keyring. Session hints always come from this client. */
    json_object_remove_member(object, "session");
    JsonObject *session = json_object_new();
    for (guint i = 0; i < G_N_ELEMENTS(session_fields); i++) {
        const gchar *value = g_getenv(session_fields[i].environment);
        if (!value || !*value) continue;
        if (!session_text_valid(value)) {
            g_set_error(error, G_IO_ERROR, G_IO_ERROR_INVALID_ARGUMENT,
                "The %s session setting is invalid. Correct it before starting authentication.", session_fields[i].environment);
            json_object_unref(session); g_object_unref(parser);
            return NULL;
        }
        json_object_set_string_member(session, session_fields[i].name, value);
    }
    if (json_object_get_size(session)) json_object_set_object_member(object, "session", session);
    else json_object_unref(session);
    gchar *encoded = ov_json_encode(root, FALSE);
    g_object_unref(parser);
    if (strlen(encoded) > OV_REQUEST_LIMIT) {
        volatile gchar *p = encoded;
        for (gsize n = strlen(encoded); n; n--) *p++ = 0;
        g_free(encoded);
        g_set_error_literal(error, G_IO_ERROR, G_IO_ERROR_INVALID_ARGUMENT, "Request and session settings exceed the supported size.");
        return NULL;
    }
    return encoded;
}

GDBusConnection *ov_client_connect(GError **error)
{
#ifdef OCTOVAULT_TEST
    return g_bus_get_sync(G_BUS_TYPE_SESSION, NULL, error);
#else
    return g_bus_get_sync(G_BUS_TYPE_SYSTEM, NULL, error);
#endif
}

static GVariant *call(GDBusConnection *bus, const gchar *method, GVariant *parameters,
                      const GVariantType *type, GError **error)
{
    return g_dbus_connection_call_sync(bus, OV_BUS_NAME, OV_OBJECT_PATH, OV_INTERFACE,
                                      method, parameters, type,
                                      G_DBUS_CALL_FLAGS_ALLOW_INTERACTIVE_AUTHORIZATION,
                                      180000, NULL, error);
}

gchar *ov_client_submit(GDBusConnection *bus, const gchar *request, GError **error)
{
    return ov_client_submit_cancellable(bus, request, NULL, error);
}

gchar *ov_client_submit_cancellable(GDBusConnection *bus, const gchar *request, GCancellable *cancellable, GError **error)
{
    if (cancellable && g_cancellable_set_error_if_cancelled(cancellable, error)) return NULL;
    gchar *prepared = ov_client_prepare_request(request, error);
    if (!prepared) return NULL;
    GVariant *reply = g_dbus_connection_call_sync(bus, OV_BUS_NAME, OV_OBJECT_PATH, OV_INTERFACE,
        "Submit", g_variant_new("(s)", prepared), G_VARIANT_TYPE("(s)"),
        G_DBUS_CALL_FLAGS_ALLOW_INTERACTIVE_AUTHORIZATION, 180000, cancellable, error);
    volatile gchar *p = prepared;
    for (gsize n = strlen(prepared); n; n--) *p++ = 0;
    g_free(prepared);
    if (!reply) return NULL;
    gchar *id = NULL;
    g_variant_get(reply, "(s)", &id);
    g_variant_unref(reply);
    return id;
}

JsonNode *ov_client_get_job(GDBusConnection *bus, const gchar *id, GError **error)
{
    GVariant *reply = call(bus, "GetJob", g_variant_new("(s)", id), G_VARIANT_TYPE("(s)"), error);
    if (!reply) return NULL;
    const gchar *data;
    g_variant_get(reply, "(&s)", &data);
    JsonParser *parser = json_parser_new();
    JsonNode *result = NULL;
    if (json_parser_load_from_data(parser, data, -1, error))
        result = json_node_copy(json_parser_get_root(parser));
    g_object_unref(parser);
    g_variant_unref(reply);
    return result;
}

gboolean ov_client_cancel(GDBusConnection *bus, const gchar *id, GError **error)
{
    GVariant *reply = call(bus, "Cancel", g_variant_new("(s)", id), G_VARIANT_TYPE("(b)"), error);
    gboolean cancelled = FALSE;
    if (reply) {
        g_variant_get(reply, "(b)", &cancelled);
        g_variant_unref(reply);
    }
    return cancelled;
}

gchar *ov_json_encode(JsonNode *node, gboolean pretty)
{
    JsonGenerator *generator = json_generator_new();
    json_generator_set_root(generator, node);
    json_generator_set_pretty(generator, pretty);
    gchar *result = json_generator_to_data(generator, NULL);
    g_object_unref(generator);
    return result;
}
