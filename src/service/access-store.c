/* SPDX-License-Identifier: Apache-2.0 */
/* Included by the daemon. This file stores grants; it never authorizes them. */
#include <fcntl.h>
#include <pwd.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>

#ifndef OV_ACCESS_PATH
#define OV_ACCESS_PATH "/var/lib/octovault/access.json"
#endif
#ifndef OV_ACCESS_PASSWD_PATH
#define OV_ACCESS_PASSWD_PATH "/etc/passwd"
#endif
#ifndef OV_ACCESS_LOGIN_DEFS_PATH
#define OV_ACCESS_LOGIN_DEFS_PATH "/etc/login.defs"
#endif
#define OV_ACCESS_LIMIT (1024 * 1024)
#define OV_ACCESS_DEFAULT_DURATION 28800u

static void access_store_error(GError **error, const gchar *message)
{
    g_set_error_literal(error, G_IO_ERROR, G_IO_ERROR_FAILED, message);
}

static gboolean access_store_integer(JsonObject *object, const gchar *member, gint64 minimum, gint64 maximum)
{
    JsonNode *node = json_object_get_member(object, member);
    if (!node || !JSON_NODE_HOLDS_VALUE(node) || json_node_get_value_type(node) != G_TYPE_INT64) return FALSE;
    gint64 value = json_node_get_int(node);
    return value >= minimum && value <= maximum;
}

static gboolean access_store_name(const gchar *value)
{
    if (!value || !*value || strlen(value) > 255 || !g_utf8_validate(value, -1, NULL)) return FALSE;
    for (const guchar *p = (const guchar *)value; *p; p++)
        if (*p < 32 || *p == 127 || *p == ':' || *p == '/') return FALSE;
    return TRUE;
}

static guint32 access_store_uid_min(void)
{
    guint32 minimum = 1000;
    FILE *file = fopen(OV_ACCESS_LOGIN_DEFS_PATH, "re");
    if (!file) return minimum;
    gchar *line = NULL;
    size_t capacity = 0;
    while (getline(&line, &capacity, file) >= 0) {
        gchar key[64], value[64];
        if (sscanf(line, " %63s %63s", key, value) != 2 || strcmp(key, "UID_MIN")) continue;
        gchar *end = NULL;
        errno = 0;
        guint64 parsed = g_ascii_strtoull(value, &end, 10);
        if (!errno && end != value && !*end && parsed > 0 && parsed < G_MAXUINT32) minimum = (guint32)parsed;
        break;
    }
    free(line); fclose(file);
    return minimum;
}

static gboolean access_store_eligible(const struct passwd *account, guint32 minimum)
{
    if (!account || account->pw_uid < minimum || account->pw_uid == 0 || account->pw_uid == 65534 ||
        !access_store_name(account->pw_name) || !account->pw_dir || account->pw_dir[0] != '/') return FALSE;
    const gchar *shell = account->pw_shell ? account->pw_shell : "";
    const gchar *base = strrchr(shell, '/');
    base = base ? base + 1 : shell;
    return strcmp(base, "nologin") && strcmp(base, "false");
}

static JsonObject *access_store_account(const gchar *user, guint32 uid, gboolean by_uid)
{
    FILE *file = fopen(OV_ACCESS_PASSWD_PATH, "re");
    if (!file) return NULL;
    guint32 minimum = access_store_uid_min();
    struct passwd *account;
    JsonObject *result = NULL;
    while ((account = fgetpwent(file))) {
        if (!(by_uid ? account->pw_uid == uid : g_strcmp0(account->pw_name, user) == 0)) continue;
        if (access_store_eligible(account, minimum)) {
            result = json_object_new();
            json_object_set_int_member(result, "uid", account->pw_uid);
            json_object_set_string_member(result, "user", account->pw_name);
            gchar *gecos = g_utf8_make_valid(account->pw_gecos ? account->pw_gecos : "", -1);
            gchar *comma = strchr(gecos, ',');
            if (comma) *comma = 0;
            json_object_set_string_member(result, "display_name", gecos);
            g_free(gecos);
        }
        break;
    }
    fclose(file);
    return result;
}

static guint access_store_duration(JsonObject *store)
{
    if (!access_store_integer(store, "max_duration_seconds", 1, G_MAXINT64)) return OV_ACCESS_DEFAULT_DURATION;
    gint64 value = json_object_get_int_member(store, "max_duration_seconds");
    return (guint)CLAMP(value, 60, OV_ACCESS_DEFAULT_DURATION);
}

static gboolean access_store_valid(JsonObject *store)
{
    if (!access_store_integer(store, "schema_version", 1, 1)) return FALSE;
    if (json_object_has_member(store, "max_duration_seconds") &&
        !access_store_integer(store, "max_duration_seconds", 1, G_MAXINT64)) return FALSE;
    JsonNode *node = json_object_get_member(store, "grants");
    if (!node || !JSON_NODE_HOLDS_ARRAY(node)) return FALSE;
    JsonArray *grants = json_node_get_array(node);
    if (json_array_get_length(grants) > 4096) return FALSE;
    GHashTable *uids = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, NULL);
    GHashTable *users = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, NULL);
    gboolean valid = TRUE;
    for (guint i = 0; valid && i < json_array_get_length(grants); i++) {
        JsonNode *grant = json_array_get_element(grants, i);
        if (!JSON_NODE_HOLDS_OBJECT(grant)) { valid = FALSE; break; }
        JsonObject *entry = json_node_get_object(grant);
        JsonNode *name = json_object_get_member(entry, "user");
        if (!access_store_integer(entry, "uid", 1, G_MAXUINT32 - 1) ||
            !access_store_integer(entry, "granted_by", 0, G_MAXUINT32 - 1) ||
            !access_store_integer(entry, "granted_at", 1, G_MAXINT64) ||
            !name || !JSON_NODE_HOLDS_VALUE(name) || json_node_get_value_type(name) != G_TYPE_STRING ||
            !access_store_name(json_node_get_string(name))) { valid = FALSE; break; }
        gchar *uid = g_strdup_printf("%" G_GINT64_FORMAT, json_object_get_int_member(entry, "uid"));
        const gchar *user = json_node_get_string(name);
        if (g_hash_table_contains(uids, uid) || g_hash_table_contains(users, user)) { g_free(uid); valid = FALSE; break; }
        g_hash_table_add(uids, uid);
        g_hash_table_add(users, g_strdup(user));
    }
    g_hash_table_unref(uids); g_hash_table_unref(users);
    return valid;
}

static JsonObject *access_store_empty(void)
{
    JsonObject *store = json_object_new();
    json_object_set_int_member(store, "schema_version", 1);
    json_object_set_int_member(store, "max_duration_seconds", OV_ACCESS_DEFAULT_DURATION);
    json_object_set_array_member(store, "grants", json_array_new());
    return store;
}

static gboolean access_store_secure_directory(int descriptor)
{
    struct stat metadata;
    return fstat(descriptor, &metadata) == 0 && S_ISDIR(metadata.st_mode) && metadata.st_uid == 0 && !(metadata.st_mode & 0022);
}

/* Traverse from / using pinned directory descriptors. A symlink or writable
 * ancestor cannot redirect a privileged policy read or replacement. */
static int access_store_directory(gboolean create, gboolean *missing, GError **error)
{
    *missing = FALSE;
    if (!g_path_is_absolute(OV_ACCESS_PATH) || strlen(OV_ACCESS_PATH) > 4096) {
        access_store_error(error, "The administrator access policy path is invalid."); return -1;
    }
    gchar *parent = g_path_get_dirname(OV_ACCESS_PATH);
    gchar **parts = g_strsplit(parent, "/", -1);
    g_free(parent);
    int descriptor = open("/", O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    if (descriptor < 0 || !access_store_secure_directory(descriptor)) goto unsafe;
    for (guint i = 0; parts[i]; i++) {
        if (!*parts[i]) continue;
        if (!strcmp(parts[i], ".") || !strcmp(parts[i], "..")) goto unsafe;
        int next = openat(descriptor, parts[i], O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
        if (next < 0 && errno == ENOENT && create) {
            if (mkdirat(descriptor, parts[i], 0700) < 0 && errno != EEXIST) goto unsafe;
            next = openat(descriptor, parts[i], O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
        }
        if (next < 0 && errno == ENOENT && !create) {
            *missing = TRUE; close(descriptor); g_strfreev(parts); return -1;
        }
        if (next < 0) goto unsafe;
        close(descriptor); descriptor = next;
        if (!access_store_secure_directory(descriptor)) goto unsafe;
    }
    g_strfreev(parts);
    return descriptor;
unsafe:
    if (descriptor >= 0) close(descriptor);
    g_strfreev(parts);
    access_store_error(error, "The administrator access policy directory is unavailable or unsafe.");
    return -1;
}

static gboolean access_store_secure_file(const struct stat *metadata)
{
    return S_ISREG(metadata->st_mode) && metadata->st_uid == 0 && (metadata->st_mode & 07777) == 0600 &&
        metadata->st_nlink == 1 && metadata->st_size >= 0 && metadata->st_size <= OV_ACCESS_LIMIT;
}

static JsonObject *access_store_load(GError **error)
{
    gboolean missing;
    int directory = access_store_directory(FALSE, &missing, error);
    if (directory < 0) return missing ? access_store_empty() : NULL;
    gchar *name = g_path_get_basename(OV_ACCESS_PATH);
    int descriptor = openat(directory, name, O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK);
    int open_error = errno;
    g_free(name); close(directory);
    if (descriptor < 0) {
        if (open_error == ENOENT) return access_store_empty();
        access_store_error(error, "The administrator access policy file is unavailable or unsafe."); return NULL;
    }
    struct stat metadata;
    if (fstat(descriptor, &metadata) < 0 || !access_store_secure_file(&metadata)) {
        close(descriptor); access_store_error(error, "The administrator access policy must be a private root-owned regular file."); return NULL;
    }
    GString *content = g_string_sized_new((gsize)metadata.st_size);
    gchar buffer[4096];
    ssize_t count;
    while ((count = read(descriptor, buffer, sizeof(buffer))) != 0) {
        if (count < 0) { if (errno == EINTR) continue; break; }
        if (content->len + (gsize)count > OV_ACCESS_LIMIT) { count = -1; break; }
        g_string_append_len(content, buffer, count);
    }
    close(descriptor);
    JsonParser *parser = json_parser_new();
    JsonObject *store = NULL;
    if (count == 0 && json_parser_load_from_data(parser, content->str, content->len, NULL)) {
        JsonNode *root = json_parser_get_root(parser);
        if (JSON_NODE_HOLDS_OBJECT(root) && access_store_valid(json_node_get_object(root)))
            store = json_object_ref(json_node_get_object(root));
    }
    g_string_free(content, TRUE); g_object_unref(parser);
    if (!store) access_store_error(error, "The administrator access policy is invalid or could not be read.");
    return store;
}

static gboolean access_store_save(JsonObject *store, GError **error)
{
    if (!access_store_valid(store)) { access_store_error(error, "The administrator access policy is invalid."); return FALSE; }
    JsonNode *node = json_node_new(JSON_NODE_OBJECT);
    json_node_set_object(node, store);
    JsonGenerator *generator = json_generator_new();
    json_generator_set_root(generator, node);
    gsize size;
    gchar *content = json_generator_to_data(generator, &size);
    g_object_unref(generator); json_node_unref(node);
    if (size > OV_ACCESS_LIMIT) { g_free(content); access_store_error(error, "The administrator access policy is too large."); return FALSE; }
    gboolean missing;
    int directory = access_store_directory(TRUE, &missing, error);
    if (directory < 0) { g_free(content); return FALSE; }
    gchar *name = g_path_get_basename(OV_ACCESS_PATH);
    struct stat metadata;
    if (fstatat(directory, name, &metadata, AT_SYMLINK_NOFOLLOW) == 0) {
        if (!access_store_secure_file(&metadata)) goto failed;
    } else if (errno != ENOENT) goto failed;
    gchar *uuid = g_uuid_string_random();
    gchar *temporary = g_strdup_printf(".access-%s.tmp", uuid);
    g_free(uuid);
    int descriptor = openat(directory, temporary, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW, 0600);
    gboolean saved = descriptor >= 0;
    if (saved && fchmod(descriptor, 0600) < 0) saved = FALSE;
    for (gsize offset = 0; saved && offset < size;) {
        ssize_t written = write(descriptor, content + offset, size - offset);
        if (written < 0 && errno == EINTR) continue;
        if (written <= 0) saved = FALSE;
        else offset += (gsize)written;
    }
    if (saved && fsync(descriptor) < 0) saved = FALSE;
    if (descriptor >= 0 && close(descriptor) < 0) saved = FALSE;
    if (saved && renameat(directory, temporary, directory, name) < 0) saved = FALSE;
    if (saved && fsync(directory) < 0) saved = FALSE;
    if (!saved) unlinkat(directory, temporary, 0);
    g_free(temporary); g_free(name); g_free(content); close(directory);
    if (!saved) access_store_error(error, "The administrator access policy could not be saved and synchronized.");
    return saved;
failed:
    g_free(name); g_free(content); close(directory);
    access_store_error(error, "The administrator access policy file is unavailable or unsafe.");
    return FALSE;
}

static gboolean access_store_granted(JsonObject *store, guint32 uid)
{
    JsonObject *account = access_store_account(NULL, uid, TRUE);
    if (!account) return FALSE;
    const gchar *user = json_object_get_string_member(account, "user");
    JsonArray *grants = json_object_get_array_member(store, "grants");
    gboolean granted = FALSE;
    for (guint i = 0; i < json_array_get_length(grants); i++) {
        JsonObject *entry = json_array_get_object_element(grants, i);
        if ((guint32)json_object_get_int_member(entry, "uid") == uid &&
            !strcmp(json_object_get_string_member(entry, "user"), user)) { granted = TRUE; break; }
    }
    json_object_unref(account);
    return granted;
}

static JsonArray *access_store_users(JsonObject *store)
{
    JsonArray *users = json_array_new();
    FILE *file = fopen(OV_ACCESS_PASSWD_PATH, "re");
    if (!file) return users;
    guint32 minimum = access_store_uid_min();
    struct passwd *account;
    while ((account = fgetpwent(file))) {
        if (!access_store_eligible(account, minimum)) continue;
        /* Copy before a nested passwd read can reuse libc's static buffer. */
        guint32 uid = account->pw_uid;
        JsonObject *entry = json_object_new();
        json_object_set_int_member(entry, "uid", uid);
        json_object_set_string_member(entry, "user", account->pw_name);
        gchar *name = g_utf8_make_valid(account->pw_gecos ? account->pw_gecos : "", -1);
        gchar *comma = strchr(name, ','); if (comma) *comma = 0;
        json_object_set_string_member(entry, "display_name", name); g_free(name);
        json_object_set_boolean_member(entry, "delegated_personal", access_store_granted(store, uid));
        json_array_add_object_element(users, entry);
    }
    fclose(file);
    return users;
}

static gboolean access_store_change(JsonObject *store, const gchar *user, gboolean grant, guint32 granted_by, GError **error)
{
    if (!access_store_name(user) || !access_store_valid(store)) {
        access_store_error(error, "Select a valid local account."); return FALSE;
    }
    JsonObject *account = access_store_account(user, 0, FALSE);
    if (grant && !account) {
        access_store_error(error, "Personal access can only be granted to an existing local interactive user."); return FALSE;
    }
    JsonArray *grants = json_object_get_array_member(store, "grants");
    guint32 uid = account ? (guint32)json_object_get_int_member(account, "uid") : G_MAXUINT32;
    for (guint i = json_array_get_length(grants); i > 0; i--) {
        JsonObject *entry = json_array_get_object_element(grants, i - 1);
        if (!strcmp(json_object_get_string_member(entry, "user"), user) ||
            (grant && (guint32)json_object_get_int_member(entry, "uid") == uid)) json_array_remove_element(grants, i - 1);
    }
    if (grant) {
        JsonObject *entry = json_object_new();
        json_object_set_int_member(entry, "uid", uid);
        json_object_set_string_member(entry, "user", user);
        json_object_set_int_member(entry, "granted_at", g_get_real_time() / G_USEC_PER_SEC);
        json_object_set_int_member(entry, "granted_by", granted_by);
        json_array_add_object_element(grants, entry);
    }
    if (account) json_object_unref(account);
    return TRUE;
}
