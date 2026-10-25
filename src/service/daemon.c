/* SPDX-License-Identifier: Apache-2.0 */
#define _GNU_SOURCE
#include "client.h"
#include <errno.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/resource.h>
#include <sys/prctl.h>
#include <unistd.h>
#include <glib-unix.h>

#ifndef OV_BACKEND_PATH
#define OV_BACKEND_PATH "/usr/libexec/octovault/backend"
#endif
#ifndef OV_PRIORITY_BACKEND_PATH
#ifdef OCTOVAULT_TEST
#define OV_PRIORITY_BACKEND_PATH OV_BACKEND_PATH
#else
#define OV_PRIORITY_BACKEND_PATH "/usr/libexec/octovault/priority-backend"
#endif
#endif
#define RESULT_TTL 300
#define MAX_JOBS 64
#define MAX_OWNER_JOBS 16
#define MAX_PROGRESS_LINE 8192

typedef struct {
    gchar *id, *op, *request, *state, *stage, *message;
    gchar *sender, *scope, *session_path, *display_user_path;
    guint32 uid;
    guint64 policy_revision, sender_revision, session_revision, display_revision;
    gint percent;
    gint64 created, created_at, finished, expires;
    GSubprocess *process;
    GString *output, *errors;
    JsonNode *result;
    gboolean stdin_done, stdout_done, stderr_done, process_done, success, cancelled, overflow, priority;
    gboolean requires_session, one_shot, auth_invalidated;
    guint kill_timer;
    GPid pid;
} Job;

typedef struct {
    GDBusMethodInvocation *invocation;
    gchar *sender, *request, *op, *id, *method;
    gchar *scope, *session_path, *session_id, *auth_session_path, *auth_action, *availability_reason;
    gchar *display_user_path, *display_session_id;
    guint32 uid;
    guint32 pid;
    guint duration;
    guint64 policy_revision, sender_revision, session_revision, display_revision, transition_revision;
    JsonNode *immediate_result;
    gboolean session_active, session_remote, session_user_class, auth_completed, requires_session, one_shot, can_request_system;
    gboolean session_manager_class, resolving_display;
    gboolean counted;
} Pending;

static GHashTable *jobs;
static GMainLoop *loop;
static GDBusConnection *connection;
static gboolean shutting_down;
static int service_exit_status;
static guint owner_id;
static guint pending_count;
static gboolean access_job_valid(Job *j);
static gboolean access_result_visible(Job *j, Pending *p);
static void access_protect_result(Job *j);
static const gchar introspection[] =
    "<node><interface name='io.vdm.OctoVault1'>"
    "<method name='Submit'><arg type='s' direction='in'/><arg type='s' direction='out'/></method>"
    "<method name='GetJob'><arg type='s' direction='in'/><arg type='s' direction='out'/></method>"
    "<method name='Cancel'><arg type='s' direction='in'/><arg type='b' direction='out'/></method>"
    "</interface></node>";

static void wipe(gchar *data)
{
    if (!data) return;
    volatile gchar *p = data;
    gsize n = strlen(data);
    while (n--) *p++ = 0;
}

static void pending_free(Pending *p)
{
    if (p->counted) pending_count--;
    g_object_unref(p->invocation);
    wipe(p->request);
    g_free(p->scope); g_free(p->session_path); g_free(p->session_id); g_free(p->auth_session_path);
    g_free(p->auth_action); g_free(p->availability_reason);
    g_free(p->display_user_path); g_free(p->display_session_id);
    if (p->immediate_result) json_node_unref(p->immediate_result);
    g_free(p->request); g_free(p->sender); g_free(p->op); g_free(p->id); g_free(p->method); g_free(p);
}

static void job_free(gpointer pointer)
{
    Job *j = pointer;
    if (j->kill_timer) g_source_remove(j->kill_timer);
    wipe(j->request); g_free(j->request);
    if (j->output) { wipe(j->output->str); g_string_free(j->output, TRUE); }
    if (j->errors) { wipe(j->errors->str); g_string_free(j->errors, TRUE); }
    if (j->result) json_node_unref(j->result);
    g_free(j->sender); g_free(j->scope); g_free(j->session_path); g_free(j->display_user_path);
    g_clear_object(&j->process);
    g_free(j->id); g_free(j->op); g_free(j->state); g_free(j->stage); g_free(j->message); g_free(j);
}

static void dbus_error(Pending *p, const gchar *code, const gchar *message)
{
    gchar *name = g_strconcat(OV_INTERFACE, ".", code, NULL);
    g_dbus_method_invocation_return_dbus_error(p->invocation, name, message);
    g_free(name); pending_free(p);
}

static JsonNode *failure(const gchar *code, const gchar *message)
{
    JsonBuilder *b = json_builder_new();
    json_builder_begin_object(b);
    json_builder_set_member_name(b, "ok"); json_builder_add_boolean_value(b, FALSE);
    json_builder_set_member_name(b, "error"); json_builder_begin_object(b);
    json_builder_set_member_name(b, "code"); json_builder_add_string_value(b, code);
    json_builder_set_member_name(b, "message"); json_builder_add_string_value(b, message);
    json_builder_end_object(b); json_builder_end_object(b);
    JsonNode *node = json_builder_get_root(b); g_object_unref(b); return node;
}

static gboolean terminal(Job *j) { return j->finished != 0; }
static void start_next(guint32 uid);

static void complete(Job *j)
{
    if (!j->stdin_done || !j->process_done || !j->stdout_done || !j->stderr_done || terminal(j)) return;
    /* Queued cancellation or a spawn failure has no stdin callback to scrub it. */
    wipe(j->request); g_clear_pointer(&j->request, g_free);
    if (j->kill_timer) { g_source_remove(j->kill_timer); j->kill_timer = 0; }
    if (j->cancelled) j->result = failure("CANCELLED", "Operation cancelled. Check its state before retrying.");
    else if (j->overflow) j->result = failure("OUTPUT_LIMIT", "The operation exceeded the safe output limit. Narrow the request.");
    else {
        JsonParser *parser = json_parser_new();
        if (json_parser_load_from_data(parser, j->output->str, j->output->len, NULL)) {
            JsonNode *node = json_parser_get_root(parser);
            if (JSON_NODE_HOLDS_OBJECT(node)) {
                JsonObject *obj = json_node_get_object(node);
                JsonNode *ok = json_object_get_member(obj, "ok");
                if (ok && JSON_NODE_HOLDS_VALUE(ok) && json_node_get_value_type(ok) == G_TYPE_BOOLEAN)
                    j->result = json_node_copy(node);
            }
        }
        g_object_unref(parser);
        if (!j->result) j->result = failure("BACKEND_FAILURE", "The operation did not return a valid result. Check the activity status.");
        else if (!j->success && json_object_get_boolean_member(json_node_get_object(j->result), "ok")) {
            json_node_unref(j->result);
            j->result = failure("BACKEND_FAILURE", "The operation exited unsuccessfully.");
        }
    }
    access_protect_result(j);
    gboolean ok = json_object_get_boolean_member(json_node_get_object(j->result), "ok");
    g_free(j->state); j->state = g_strdup(j->cancelled ? "cancelled" : ok ? "succeeded" : "failed");
    j->finished = g_get_real_time() / G_USEC_PER_SEC;
    j->expires = g_get_monotonic_time() + RESULT_TTL * G_USEC_PER_SEC;
    if (ok) j->percent = 100;
    wipe(j->output->str); g_string_truncate(j->output, 0);
    wipe(j->errors->str); g_string_truncate(j->errors, 0);
    start_next(j->uid);
}

static gboolean force_kill(gpointer data)
{
    Job *j = data; j->kill_timer = 0;
    if (!terminal(j) && j->pid > 1) {
        kill(-j->pid, SIGKILL);
        if (!j->process_done) g_subprocess_force_exit(j->process);
    }
    return G_SOURCE_REMOVE;
}

static void stop_process(Job *j)
{
    if (j->pid > 1 && !terminal(j)) {
        kill(-j->pid, SIGTERM);
        if (!j->kill_timer) j->kill_timer = g_timeout_add_seconds(3, force_kill, j);
    }
}

static void progress_line(Job *j, const gchar *line, gsize length)
{
    JsonParser *parser = json_parser_new();
    if (length > 0 && json_parser_load_from_data(parser, line, length, NULL)) {
        JsonNode *root = json_parser_get_root(parser);
        if (JSON_NODE_HOLDS_OBJECT(root)) {
            JsonObject *obj = json_node_get_object(root);
            JsonNode *stage = json_object_get_member(obj, "stage");
            JsonNode *message = json_object_get_member(obj, "message");
            JsonNode *percent = json_object_get_member(obj, "percent");
            if (stage && JSON_NODE_HOLDS_VALUE(stage) && json_node_get_value_type(stage) == G_TYPE_STRING &&
                message && JSON_NODE_HOLDS_VALUE(message) && json_node_get_value_type(message) == G_TYPE_STRING) {
                g_free(j->stage); g_free(j->message);
                j->stage = g_strndup(json_node_get_string(stage), 128);
                j->message = g_strndup(json_node_get_string(message), 1024);
                if (percent && JSON_NODE_HOLDS_VALUE(percent) &&
                    (json_node_get_value_type(percent) == G_TYPE_INT64 || json_node_get_value_type(percent) == G_TYPE_DOUBLE))
                    j->percent = CLAMP((gint) json_node_get_int(percent), -1, 100);
            }
        }
    }
    g_object_unref(parser);
}

static void read_output(GObject *stream, GAsyncResult *result, gpointer data)
{
    Job *j = data;
    gboolean out = G_INPUT_STREAM(stream) == g_subprocess_get_stdout_pipe(j->process);
    GBytes *bytes = g_input_stream_read_bytes_finish(G_INPUT_STREAM(stream), result, NULL);
    gsize n = 0;
    const gchar *buffer = bytes ? g_bytes_get_data(bytes, &n) : NULL;
    if (!n) {
        if (out) j->stdout_done = TRUE;
        else { j->stderr_done = TRUE; if (j->errors->len) progress_line(j, j->errors->str, j->errors->len); }
        if (bytes) g_bytes_unref(bytes);
        complete(j); return;
    }
    if (out) {
        if (j->output->len + n <= OV_RESULT_LIMIT) g_string_append_len(j->output, buffer, n);
        else { j->overflow = TRUE; stop_process(j); }
    } else {
        for (gsize i = 0; i < n; i++) {
            if (buffer[i] == '\n') {
                if (j->errors->len < MAX_PROGRESS_LINE) progress_line(j, j->errors->str, j->errors->len);
                wipe(j->errors->str); g_string_truncate(j->errors, 0);
            } else if (j->errors->len < MAX_PROGRESS_LINE) g_string_append_c(j->errors, buffer[i]);
        }
    }
    g_bytes_unref(bytes);
    g_input_stream_read_bytes_async(G_INPUT_STREAM(stream), 4096, G_PRIORITY_DEFAULT, NULL, read_output, j);
}

static void process_done(GObject *process, GAsyncResult *result, gpointer data)
{
    Job *j = data;
    j->success = g_subprocess_wait_check_finish(G_SUBPROCESS(process), result, NULL);
    j->process_done = TRUE; complete(j);
}

static void stdin_written(GObject *stream, GAsyncResult *result, gpointer data)
{
    Job *j = data;
    g_output_stream_write_all_finish(G_OUTPUT_STREAM(stream), result, NULL, NULL);
    g_output_stream_close(G_OUTPUT_STREAM(stream), NULL, NULL);
    wipe(j->request); g_clear_pointer(&j->request, g_free);
    j->stdin_done = TRUE; complete(j);
}

static void child_setup(gpointer data)
{
    (void) data;
    if (setsid() < 0) _exit(126);
    umask(0077);
}

static void start_job(Job *j)
{
    if (!access_job_valid(j)) {
        JsonNode *denied = failure("AUTH_REVOKED", "Authorization ended before this queued operation could start. Unlock OctoVault and submit it again.");
        gchar *encoded = ov_json_encode(denied, FALSE);
        g_string_assign(j->output, encoded); g_free(encoded); json_node_unref(denied);
        j->stdin_done = j->process_done = j->stdout_done = j->stderr_done = TRUE;
        complete(j); return;
    }
    g_free(j->state); j->state = g_strdup("running");
    gchar uid[32]; g_snprintf(uid, sizeof(uid), "%u", j->uid);
    GSubprocessLauncher *launcher = g_subprocess_launcher_new(
        G_SUBPROCESS_FLAGS_STDIN_PIPE | G_SUBPROCESS_FLAGS_STDOUT_PIPE | G_SUBPROCESS_FLAGS_STDERR_PIPE);
    const gchar *env[] = { "PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LANG=C.UTF-8", "LC_ALL=C.UTF-8", NULL };
    g_subprocess_launcher_set_environ(launcher, (gchar **)env);
    g_subprocess_launcher_set_cwd(launcher, "/");
    g_subprocess_launcher_set_child_setup(launcher, child_setup, NULL, NULL);
    j->process = g_subprocess_launcher_spawn(launcher, NULL,
        j->priority ? OV_PRIORITY_BACKEND_PATH : OV_BACKEND_PATH, uid, j->scope, NULL);
    g_object_unref(launcher);
    if (!j->process) {
        j->stdin_done = j->process_done = j->stdout_done = j->stderr_done = TRUE;
        complete(j); return;
    }
    j->pid = (GPid) g_ascii_strtoll(g_subprocess_get_identifier(j->process), NULL, 10);
    GOutputStream *input = g_subprocess_get_stdin_pipe(j->process);
    g_output_stream_write_all_async(input, j->request, strlen(j->request), G_PRIORITY_DEFAULT, NULL, stdin_written, j);
    g_input_stream_read_bytes_async(g_subprocess_get_stdout_pipe(j->process), 4096, G_PRIORITY_DEFAULT, NULL, read_output, j);
    g_input_stream_read_bytes_async(g_subprocess_get_stderr_pipe(j->process), 4096, G_PRIORITY_DEFAULT, NULL, read_output, j);
    g_subprocess_wait_check_async(j->process, NULL, process_done, j);
}

static void start_next(guint32 uid)
{
    if (shutting_down) return;
    GHashTableIter iter; gpointer value; Job *next = NULL;
    g_hash_table_iter_init(&iter, jobs);
    while (g_hash_table_iter_next(&iter, NULL, &value)) {
        Job *j = value;
        if (j->uid != uid || terminal(j)) continue;
        if (g_str_equal(j->state, "running")) return;
        if (!next || (j->priority && !next->priority) || (j->priority == next->priority && j->created < next->created)) next = j;
    }
    if (next) start_job(next);
}

static gboolean has_close_policy(guint32 uid, const gchar *event)
{
    gchar *directory = g_strdup_printf("/var/lib/octovault/users/%u/vaults", uid);
    GDir *dir = g_dir_open(directory, 0, NULL);
    gboolean matched = FALSE;
    const gchar *name;
    while (dir && !matched && (name = g_dir_read_name(dir))) {
        if (!g_str_has_suffix(name, ".json")) continue;
        gchar *path = g_build_filename(directory, name, NULL);
        struct stat metadata;
        if (lstat(path, &metadata) == 0 && S_ISREG(metadata.st_mode) && metadata.st_uid == 0 &&
            !(metadata.st_mode & 0022) && metadata.st_size <= OV_REQUEST_LIMIT) {
            JsonParser *parser = json_parser_new();
            if (json_parser_load_from_file(parser, path, NULL) && JSON_NODE_HOLDS_OBJECT(json_parser_get_root(parser))) {
                JsonObject *vault = json_node_get_object(json_parser_get_root(parser));
                JsonNode *rules = json_object_get_member(vault, "close_on");
                if (rules && JSON_NODE_HOLDS_ARRAY(rules)) {
                    JsonArray *array = json_node_get_array(rules);
                    for (guint i = 0; i < json_array_get_length(array); i++) {
                        JsonNode *rule = json_array_get_element(array, i);
                        if (JSON_NODE_HOLDS_VALUE(rule) && json_node_get_value_type(rule) == G_TYPE_STRING &&
                            g_str_equal(json_node_get_string(rule), event)) matched = TRUE;
                    }
                }
            }
            g_object_unref(parser);
        }
        g_free(path);
    }
    if (dir) g_dir_close(dir);
    g_free(directory); return matched;
}

static gboolean closes_vaults(guint32 uid, const gchar *op, const gchar *request)
{
    if (g_str_equal(op, "vault.close")) return TRUE;
    if (!g_str_equal(op, "event.session")) return FALSE;
    JsonParser *parser = json_parser_new(); gboolean closes = FALSE;
    if (json_parser_load_from_data(parser, request, -1, NULL)) {
        JsonObject *object = json_node_get_object(json_parser_get_root(parser));
        JsonObject *params = json_object_get_object_member(object, "params");
        JsonNode *node = json_object_get_member(params, "event");
        if (node && JSON_NODE_HOLDS_VALUE(node) && json_node_get_value_type(node) == G_TYPE_STRING) {
            const gchar *event = json_node_get_string(node);
            closes = (g_str_equal(event, "screen-lock") || g_str_equal(event, "sleep") ||
                     g_str_equal(event, "shutdown") || g_str_equal(event, "logout")) && has_close_policy(uid, event);
        }
    }
    g_object_unref(parser); return closes;
}

static void submit_authorized(Pending *p)
{
    if (shutting_down) { dbus_error(p, "Unavailable", "The service is stopping."); return; }
    guint count = 0;
    GHashTableIter iter; gpointer value;
    g_hash_table_iter_init(&iter, jobs);
    while (g_hash_table_iter_next(&iter, NULL, &value)) if (((Job *)value)->uid == p->uid && !terminal(value)) count++;
    if (g_hash_table_size(jobs) >= MAX_JOBS) {
        Job *oldest = NULL;
        g_hash_table_iter_init(&iter, jobs);
        while (g_hash_table_iter_next(&iter, NULL, &value)) {
            Job *candidate = value;
            if (terminal(candidate) && (!oldest || candidate->finished < oldest->finished)) oldest = candidate;
        }
        if (oldest) g_hash_table_remove(jobs, oldest->id);
    }
    if (count >= MAX_OWNER_JOBS || g_hash_table_size(jobs) >= MAX_JOBS) {
        dbus_error(p, "Busy", "The job limit was reached. Completed jobs expire after five minutes."); return;
    }
    Job *j = g_new0(Job, 1);
    j->id = g_uuid_string_random(); j->uid = p->uid; j->op = g_strdup(p->op);
    j->sender = g_strdup(p->sender); j->scope = g_strdup(p->scope ? p->scope : "personal");
    j->session_path = g_strdup(p->session_path); j->requires_session = p->requires_session;
    j->display_user_path = g_strdup(p->display_user_path); j->display_revision = p->display_revision;
    j->one_shot = p->one_shot;
    j->policy_revision = p->policy_revision; j->sender_revision = p->sender_revision; j->session_revision = p->session_revision;
    j->request = g_steal_pointer(&p->request); j->state = g_strdup("queued");
    j->priority = closes_vaults(j->uid, j->op, j->request);
    j->stage = g_strdup("queued"); j->message = g_strdup("Waiting to start"); j->percent = -1;
    j->created = g_get_monotonic_time(); j->created_at = g_get_real_time() / G_USEC_PER_SEC;
    j->output = g_string_new(NULL); j->errors = g_string_new(NULL);
    g_hash_table_insert(jobs, j->id, j);
    g_dbus_method_invocation_return_value(p->invocation, g_variant_new("(s)", j->id));
    if (p->immediate_result) {
        j->result = g_steal_pointer(&p->immediate_result);
        gboolean ok = json_object_get_boolean_member(json_node_get_object(j->result), "ok");
        g_free(j->state); j->state = g_strdup(ok ? "succeeded" : "failed");
        j->finished = g_get_real_time() / G_USEC_PER_SEC;
        j->expires = g_get_monotonic_time() + RESULT_TTL * G_USEC_PER_SEC;
        j->percent = ok ? 100 : 0;
        wipe(j->request); g_clear_pointer(&j->request, g_free);
        pending_free(p); return;
    }
    if (j->priority) {
        g_hash_table_iter_init(&iter, jobs);
        while (g_hash_table_iter_next(&iter, NULL, &value)) {
            Job *running = value;
            if (running->uid == j->uid && !terminal(running) && running->process &&
                g_str_equal(running->op, "backup.run")) {
                running->cancelled = TRUE;
                stop_process(running);
            }
        }
    }
    start_next(j->uid); pending_free(p);
}

static gboolean config_read(const gchar *op)
{
    const gchar *allowed[] = { "vault.list", "vault.get", "destination.list", "destination.get",
        "repository.list", "repository.get", "backup.list", "backup.get", "backup.history", "migration.list", "system.info",
        "diagnostic.list", "diagnostic.get", "vault.auth-check", NULL };
    for (guint i = 0; allowed[i]; i++) if (g_str_equal(op, allowed[i])) return TRUE;
    return FALSE;
}

#include "access.c"

static void authorize(Pending *p)
{
    if (g_str_equal(p->op, "event.handle")) { dbus_error(p, "NotAuthorized", "Internal events cannot be submitted over D-Bus."); return; }
#ifdef OCTOVAULT_TEST
    p->scope = g_strdup("system");
    submit_authorized(p); return;
#endif
    access_authorize(p);
}

static gchar *serialize_job(Job *j, gboolean reveal_result)
{
    JsonBuilder *b = json_builder_new();
    json_builder_begin_object(b);
#define STRING_FIELD(key, val) json_builder_set_member_name(b, key); json_builder_add_string_value(b, val)
    STRING_FIELD("id", j->id); STRING_FIELD("op", j->op); STRING_FIELD("state", j->state);
    json_builder_set_member_name(b, "created_at"); json_builder_add_int_value(b, j->created_at);
    if (j->finished) { json_builder_set_member_name(b, "finished_at"); json_builder_add_int_value(b, j->finished); }
    json_builder_set_member_name(b, "progress"); json_builder_begin_object(b);
    STRING_FIELD("stage", j->stage); STRING_FIELD("message", j->message);
    json_builder_set_member_name(b, "percent"); json_builder_add_int_value(b, j->percent);
    json_builder_end_object(b);
    if (j->result || (terminal(j) && !reveal_result)) {
        json_builder_set_member_name(b, "result");
        json_builder_add_value(b, reveal_result ? json_node_copy(j->result) :
            failure("AUTH_REVOKED", "Authorization ended. Unlock OctoVault to view this result; request sensitive recovery information again."));
    }
    json_builder_end_object(b);
#undef STRING_FIELD
    JsonNode *root = json_builder_get_root(b); gchar *json = ov_json_encode(root, FALSE);
    json_node_unref(root); g_object_unref(b); return json;
}

static void uid_done(GObject *bus, GAsyncResult *result, gpointer data)
{
    Pending *p = data;
    GVariant *reply = g_dbus_connection_call_finish(G_DBUS_CONNECTION(bus), result, NULL);
    if (!reply) { dbus_error(p, "NotAuthorized", "The calling identity could not be verified."); return; }
    g_variant_get(reply, "(u)", &p->uid); g_variant_unref(reply);
    if (g_str_equal(p->method, "Submit")) { authorize(p); return; }
    Job *j = g_hash_table_lookup(jobs, p->id);
    if (j && terminal(j) && g_get_monotonic_time() >= j->expires) {
        g_hash_table_remove(jobs, p->id); j = NULL;
    }
    if (!j || j->uid != p->uid) { dbus_error(p, "NotFound", "This job is not available or has expired."); return; }
    if (g_str_equal(p->method, "GetJob")) {
        access_protect_result(j);
        gchar *json = serialize_job(j, access_result_visible(j, p));
        g_dbus_method_invocation_return_value(p->invocation, g_variant_new("(s)", json));
        wipe(json); g_free(json);
    } else {
        gboolean cancelled = !terminal(j);
        if (cancelled) {
            j->cancelled = TRUE;
            if (j->process) stop_process(j);
            else { j->stdin_done = j->process_done = j->stdout_done = j->stderr_done = TRUE; complete(j); }
        }
        g_dbus_method_invocation_return_value(p->invocation, g_variant_new("(b)", cancelled));
    }
    pending_free(p);
}

static gboolean parse_request(Pending *p)
{
    if (strlen(p->request) > OV_REQUEST_LIMIT) return FALSE;
    JsonParser *parser = json_parser_new(); gboolean valid = FALSE;
    if (json_parser_load_from_data(parser, p->request, -1, NULL)) {
        JsonNode *node = json_parser_get_root(parser);
        if (JSON_NODE_HOLDS_OBJECT(node)) {
            JsonObject *obj = json_node_get_object(node);
            JsonNode *op = json_object_get_member(obj, "op"), *params = json_object_get_member(obj, "params");
            if (op && JSON_NODE_HOLDS_VALUE(op) && json_node_get_value_type(op) == G_TYPE_STRING && params && JSON_NODE_HOLDS_OBJECT(params) &&
                ov_session_valid(json_object_get_member(obj, "session"))) {
                const gchar *name = json_node_get_string(op);
                if (strlen(name) <= 64 && g_regex_match_simple("^[a-z]+\\.[a-z][a-z-]*$", name, 0, 0)) {
                    JsonObject *par = json_node_get_object(params);
                    valid = !json_object_has_member(par, "uid") && !json_object_has_member(par, "home") && !json_object_has_member(par, "executable");
                    if (json_object_has_member(par, "force")) {
                        JsonNode *force = json_object_get_member(par, "force");
                        valid = valid && JSON_NODE_HOLDS_VALUE(force) && json_node_get_value_type(force) == G_TYPE_BOOLEAN;
                    }
                    if (valid) p->op = g_strdup(name);
                }
            }
        }
    }
    g_object_unref(parser); return valid;
}

static void method_call(GDBusConnection *bus, const gchar *sender, const gchar *path,
                        const gchar *interface, const gchar *method, GVariant *parameters,
                        GDBusMethodInvocation *invocation, gpointer data)
{
    (void) path; (void) interface; (void) data;
    if (pending_count >= MAX_JOBS) {
        g_dbus_method_invocation_return_dbus_error(invocation, OV_INTERFACE ".Busy", "Too many requests are awaiting authorization. Try again shortly.");
        return;
    }
    Pending *p = g_new0(Pending, 1);
    pending_count++; p->counted = TRUE;
    p->invocation = g_object_ref(invocation); p->sender = g_strdup(sender); p->method = g_strdup(method);
    if (g_str_equal(method, "Submit")) {
        g_variant_get(parameters, "(s)", &p->request);
        if (!parse_request(p)) { dbus_error(p, "InvalidRequest", "Expected a bounded JSON operation and params object without identity overrides."); return; }
    } else if (g_str_equal(method, "GetJob") || g_str_equal(method, "Cancel")) {
        g_variant_get(parameters, "(s)", &p->id);
        if (strlen(p->id) > 64) { dbus_error(p, "InvalidRequest", "Invalid job identifier."); return; }
    } else { dbus_error(p, "InvalidRequest", "Unknown method."); return; }
    g_dbus_connection_call(bus, "org.freedesktop.DBus", "/org/freedesktop/DBus", "org.freedesktop.DBus",
        "GetConnectionUnixUser", g_variant_new("(s)", sender), G_VARIANT_TYPE("(u)"),
        G_DBUS_CALL_FLAGS_NONE, 5000, NULL, uid_done, p);
}

static gboolean reap(gpointer data)
{
    (void) data;
    gint64 now = g_get_monotonic_time();
    GHashTableIter iter; gpointer value;
    g_hash_table_iter_init(&iter, jobs);
    while (g_hash_table_iter_next(&iter, NULL, &value)) {
        Job *j = value;
        if (terminal(j) && now >= j->expires) g_hash_table_iter_remove(&iter);
    }
    return G_SOURCE_CONTINUE;
}

static void bus_acquired(GDBusConnection *bus, const gchar *name, gpointer data)
{
    (void) name; (void) data;
    connection = g_object_ref(bus);
    access_initialize();
    GDBusNodeInfo *info = g_dbus_node_info_new_for_xml(introspection, NULL);
    static const GDBusInterfaceVTable table = { .method_call = method_call };
    guint registered = g_dbus_connection_register_object(bus, OV_OBJECT_PATH, info->interfaces[0], &table, NULL, NULL, NULL);
    g_dbus_node_info_unref(info);
    if (!registered) { service_exit_status = 1; g_printerr("Unable to register the service interface.\n"); g_main_loop_quit(loop); }
}

static void name_lost(GDBusConnection *bus, const gchar *name, gpointer data)
{
    (void) bus; (void) name; (void) data;
    service_exit_status = 1;
    g_printerr("OctoVault could not own its D-Bus service name.\n"); g_main_loop_quit(loop);
}

static gboolean quit_loop(gpointer data) { g_main_loop_quit(data); return G_SOURCE_REMOVE; }
static gboolean shutdown_service(gpointer data)
{
    (void) data;
    if (shutting_down) return G_SOURCE_CONTINUE;
    shutting_down = TRUE;
    GHashTableIter iter; gpointer value;
    g_hash_table_iter_init(&iter, jobs);
    while (g_hash_table_iter_next(&iter, NULL, &value)) {
        Job *j = value;
        if (!terminal(j) && j->process) { j->cancelled = TRUE; stop_process(j); }
    }
    g_timeout_add_seconds(4, quit_loop, loop); return G_SOURCE_CONTINUE;
}

int main(void)
{
    const struct rlimit no_core = { 0, 0 };
    (void)setrlimit(RLIMIT_CORE, &no_core);
    (void)prctl(PR_SET_DUMPABLE, 0);
    /* An early worker exit must fail its job, not terminate the D-Bus service. */
    signal(SIGPIPE, SIG_IGN);
#ifndef OCTOVAULT_TEST
    if (geteuid() != 0) { g_printerr("octovaultd must be started by the system service.\n"); return 1; }
#endif
    umask(0077);
    jobs = g_hash_table_new_full(g_str_hash, g_str_equal, NULL, job_free);
    loop = g_main_loop_new(NULL, FALSE);
    g_unix_signal_add(SIGTERM, shutdown_service, NULL); g_unix_signal_add(SIGINT, shutdown_service, NULL);
    g_timeout_add_seconds(30, reap, NULL);
#ifdef OCTOVAULT_TEST
    GBusType bus_type = G_BUS_TYPE_SESSION;
#else
    GBusType bus_type = G_BUS_TYPE_SYSTEM;
#endif
    owner_id = g_bus_own_name(bus_type, OV_BUS_NAME, G_BUS_NAME_OWNER_FLAGS_NONE, bus_acquired, NULL, name_lost, NULL, NULL);
    g_main_loop_run(loop);
    g_bus_unown_name(owner_id);
    GHashTableIter iter; gpointer value;
    g_hash_table_iter_init(&iter, jobs);
    while (g_hash_table_iter_next(&iter, NULL, &value)) {
        Job *j = value;
        if (!terminal(j) && j->pid > 1) kill(-j->pid, SIGKILL);
    }
    /* The process exits here: asynchronous callbacks cannot outlive its address space. */
    access_shutdown();
    g_clear_object(&connection); g_main_loop_unref(loop);
    g_hash_table_destroy(jobs);
    return service_exit_status;
}
