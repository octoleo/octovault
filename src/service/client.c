/* SPDX-License-Identifier: Apache-2.0 */
#include "client.h"

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
    GVariant *reply = call(bus, "Submit", g_variant_new("(s)", request), G_VARIANT_TYPE("(s)"), error);
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
