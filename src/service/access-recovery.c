/* SPDX-License-Identifier: Apache-2.0 */
/* Read-only preflight before offering personal recovery authentication.
 * Backend records are owned through their authenticated UID namespace, not
 * through a caller-supplied owner field. The worker repeats the scope check. */
#include <fcntl.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>

#ifndef OV_ACCESS_STATE_ROOT
#define OV_ACCESS_STATE_ROOT "/var/lib/octovault/users"
#endif
#define OV_ACCESS_RECOVERY_LIMIT (1024 * 1024)

static gboolean access_recovery_id(const gchar *id)
{
    if (!id || !*id || strlen(id) > 64) return FALSE;
    for (const guchar *p = (const guchar *)id; *p; p++)
        if (!g_ascii_isalnum(*p) && *p != '_' && *p != '-') return FALSE;
    return TRUE;
}

static gboolean access_recovery_directory_secure(int descriptor, gboolean private)
{
    struct stat metadata;
    return fstat(descriptor, &metadata) == 0 && S_ISDIR(metadata.st_mode) && metadata.st_uid == 0 &&
        !(metadata.st_mode & 0022) && (!private || (metadata.st_mode & 07777) == 0700);
}

static int access_recovery_open_root(void)
{
    if (!g_path_is_absolute(OV_ACCESS_STATE_ROOT) || strlen(OV_ACCESS_STATE_ROOT) > 4096) return -1;
    int current = open("/", O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (current < 0) return -1;
    gchar **parts = g_strsplit(OV_ACCESS_STATE_ROOT, "/", -1);
    gboolean valid = access_recovery_directory_secure(current, FALSE);
    for (guint i = 0; valid && parts[i]; i++) {
        if (!*parts[i]) continue;
        if (!strcmp(parts[i], ".") || !strcmp(parts[i], "..")) { valid = FALSE; break; }
        int next = openat(current, parts[i], O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
        if (next < 0) { valid = FALSE; break; }
        close(current); current = next;
        valid = access_recovery_directory_secure(current, FALSE);
    }
    g_strfreev(parts);
    if (!valid) { close(current); return -1; }
    return current;
}

static int access_recovery_open_private(int directory, const gchar *name)
{
    int descriptor = openat(directory, name, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (descriptor >= 0 && !access_recovery_directory_secure(descriptor, TRUE)) {
        close(descriptor); descriptor = -1;
    }
    return descriptor;
}

static void access_recovery_wipe(gchar *data, gsize length)
{
    volatile gchar *p = data;
    while (length--) *p++ = 0;
}

static gboolean access_recovery_file_secure(const struct stat *metadata)
{
    return S_ISREG(metadata->st_mode) && metadata->st_uid == 0 && (metadata->st_mode & 07777) == 0600 &&
        metadata->st_nlink == 1 && metadata->st_size > 0 && metadata->st_size <= OV_ACCESS_RECOVERY_LIMIT;
}

/* Returns only the linked destination ID when requested. No credential field
 * leaves this helper, and raw metadata is never printed or retained. */
static gboolean access_recovery_record(int directory, const gchar *id, guint32 uid, gchar **destination_id)
{
    if (!access_recovery_id(id)) return FALSE;
    gchar *filename = g_strconcat(id, ".json", NULL);
    int descriptor = openat(directory, filename, O_RDONLY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK);
    g_free(filename);
    if (descriptor < 0) return FALSE;
    struct stat metadata;
    if (fstat(descriptor, &metadata) < 0 || !access_recovery_file_secure(&metadata)) { close(descriptor); return FALSE; }
    GString *content = g_string_sized_new((gsize)metadata.st_size);
    gchar buffer[4096];
    ssize_t count;
    while ((count = read(descriptor, buffer, sizeof(buffer))) != 0) {
        if (count < 0) { if (errno == EINTR) continue; break; }
        if (content->len + (gsize)count > OV_ACCESS_RECOVERY_LIMIT) { count = -1; break; }
        g_string_append_len(content, buffer, count);
    }
    access_recovery_wipe(buffer, sizeof(buffer)); close(descriptor);
    JsonParser *parser = json_parser_new();
    gboolean allowed = FALSE;
    if (count == 0 && json_parser_load_from_data(parser, content->str, content->len, NULL)) {
        JsonNode *root = json_parser_get_root(parser);
        if (JSON_NODE_HOLDS_OBJECT(root)) {
            JsonObject *record = json_node_get_object(root);
            JsonNode *schema = json_object_get_member(record, "schema_version");
            JsonNode *name = json_object_get_member(record, "id");
            JsonNode *scope = json_object_get_member(record, "execution_scope");
            JsonNode *owner = json_object_get_member(record, "owner_uid");
            allowed = schema && JSON_NODE_HOLDS_VALUE(schema) && json_node_get_value_type(schema) == G_TYPE_INT64 && json_node_get_int(schema) == 1 &&
                name && JSON_NODE_HOLDS_VALUE(name) && json_node_get_value_type(name) == G_TYPE_STRING && !strcmp(json_node_get_string(name), id) &&
                scope && JSON_NODE_HOLDS_VALUE(scope) && json_node_get_value_type(scope) == G_TYPE_STRING && !strcmp(json_node_get_string(scope), "personal");
            if (allowed && owner) allowed = JSON_NODE_HOLDS_VALUE(owner) && json_node_get_value_type(owner) == G_TYPE_INT64 && json_node_get_int(owner) == uid;
            if (allowed && destination_id) {
                JsonNode *destination = json_object_get_member(record, "destination_id");
                allowed = destination && JSON_NODE_HOLDS_VALUE(destination) && json_node_get_value_type(destination) == G_TYPE_STRING &&
                    access_recovery_id(json_node_get_string(destination));
                if (allowed) *destination_id = g_strdup(json_node_get_string(destination));
            }
        }
    }
    access_recovery_wipe(content->str, content->len);
    g_string_free(content, TRUE); g_object_unref(parser);
    return allowed;
}

static gboolean access_personal_recovery_allowed(guint32 uid, const gchar *id)
{
    if (uid == 0 || !access_recovery_id(id)) return FALSE;
    int root = access_recovery_open_root();
    if (root < 0) return FALSE;
    gchar account[32];
    g_snprintf(account, sizeof(account), "%u", uid);
    int owner = access_recovery_open_private(root, account);
    close(root);
    if (owner < 0) return FALSE;
    int repositories = access_recovery_open_private(owner, "repositories");
    int destinations = access_recovery_open_private(owner, "destinations");
    close(owner);
    if (repositories < 0 || destinations < 0) {
        if (repositories >= 0) close(repositories);
        if (destinations >= 0) close(destinations);
        return FALSE;
    }
    gchar *destination_id = NULL;
    gboolean allowed = access_recovery_record(repositories, id, uid, &destination_id) &&
        access_recovery_record(destinations, destination_id, uid, NULL);
    g_free(destination_id); close(repositories); close(destinations);
    return allowed;
}
