/* SPDX-License-Identifier: Apache-2.0 */
#ifndef OCTOVAULT_CLIENT_H
#define OCTOVAULT_CLIENT_H
#include <gio/gio.h>
#include <json-glib/json-glib.h>
#define OV_BUS_NAME "io.vdm.OctoVault1"
#define OV_OBJECT_PATH "/io/vdm/OctoVault1"
#define OV_INTERFACE "io.vdm.OctoVault1"
#define OV_REQUEST_LIMIT (1024 * 1024)
#define OV_RESULT_LIMIT (4 * 1024 * 1024)
GDBusConnection *ov_client_connect(GError **error);
gchar *ov_client_submit(GDBusConnection *bus, const gchar *request, GError **error);
JsonNode *ov_client_get_job(GDBusConnection *bus, const gchar *id, GError **error);
gboolean ov_client_cancel(GDBusConnection *bus, const gchar *id, GError **error);
gchar *ov_json_encode(JsonNode *node, gboolean pretty);
#endif
