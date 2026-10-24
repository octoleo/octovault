/* SPDX-License-Identifier: Apache-2.0 */
#define _GNU_SOURCE
#include "client.h"
#include <errno.h>
#include <math.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <termios.h>
#include <unistd.h>
#include <sys/wait.h>
#include <sys/resource.h>
#include <sys/prctl.h>
#include <poll.h>

#ifndef OCTOVAULT_VERSION
#define OCTOVAULT_VERSION "1.0.0"
#endif
static volatile sig_atomic_t interrupted;
static void signal_handler(int signo) { (void) signo; interrupted = 1; }
static void wipe(gchar *data) { if (data) { volatile gchar *p = data; gsize n = strlen(data); while (n--) *p++ = 0; } }

static void usage(void)
{
    puts("OctoVault " OCTOVAULT_VERSION " — encrypted vaults and independent backups\n"
         "Usage: octovault [--json] GROUP ACTION [--option VALUE ...]\n"
         "       octovault [--json] request [FILE|-]\n"
         "       octovault [--json] job get|cancel ID\n\n"
         "Groups: vault, migration, destination, repository, backup, schedule, event, system, diagnostic\n"
         "Use --id ID to select a registered item. Use --size-gb 10 for vault capacity.\n"
         "Create with --directory FOLDER and --name NAME; a new encrypted key is managed automatically.\n"
         "Use --use-existing-key --key-file FILE to reuse a key or protected carrier.\n"
         "For --auth image, --image-source FILE selects a cover image; its original is preserved.\n"
         "For a YubiKey use --auth gpg --recipient FINGERPRINT --require-token.\n"
         "Use vault auth-check with --recipient and --require-token to test authentication before creation.\n"
         "Use diagnostic list or diagnostic get --id ID to inspect saved failure details.\n"
         "Repeat --source, --exclude, --include or --close-on for array values.\n"
         "Boolean options accept true/false, a bare --flag, or --no-flag.\n"
         "Secrets (for example --password or --secret-key) take NO value: they prompt\n"
         "securely on the terminal. Structured requests may supply secrets on stdin.\n"
         "Object options (--retention, --hooks) accept JSON objects.\n"
         "Run as your regular user; privileged actions use Polkit authorization.\n"
         "Examples:\n"
         "  octovault vault list\n"
         "  octovault vault create --name Personal --directory /home/me --size-gb 10 --password\n"
         "  octovault vault open --id ID --password\n"
         "  octovault backup save --name Documents --repository-id ID --source /home/me/Documents\n"
         "  octovault repository recovery --id ID\n"
         "  octovault --json request - < request.json\n");
}

static gboolean in_list(const gchar *key, const gchar *const *keys)
{
    for (guint i = 0; keys[i]; i++) if (g_str_equal(key, keys[i])) return TRUE;
    return FALSE;
}

static gboolean is_secret(const gchar *key)
{
    const gchar *keys[] = { "password", "old_password", "new_password", "access_key", "secret_key", "ssh_private_key",
        "ssh_passphrase", "rest_username", "rest_password", "session_token", "pin", NULL };
    return in_list(key, keys);
}

static gchar *prompt_secret(const gchar *name, GError **error)
{
    FILE *tty = fopen("/dev/tty", "r+");
    if (!tty) { g_set_error(error, G_IO_ERROR, G_IO_ERROR_FAILED, "A terminal is required for %s; use a request on stdin for automation.", name); return NULL; }
    struct termios original, hidden;
    if (tcgetattr(fileno(tty), &original) < 0) { fclose(tty); g_set_error_literal(error, G_IO_ERROR, G_IO_ERROR_FAILED, "Cannot safely read terminal credentials."); return NULL; }
    hidden = original; hidden.c_lflag &= ~(ECHO | ECHONL);
    if (tcsetattr(fileno(tty), TCSAFLUSH, &hidden) < 0) { fclose(tty); g_set_error_literal(error, G_IO_ERROR, G_IO_ERROR_FAILED, "Cannot disable terminal echo."); return NULL; }
    gboolean multiline = g_str_equal(name, "ssh_private_key");
    fprintf(tty, "%s%s: ", name, multiline ? " (paste key; finish with a line containing only .)" : ""); fflush(tty);
    gchar *line = NULL; size_t capacity = 0;
    ssize_t length = getline(&line, &capacity, tty);
    if (multiline && length > 0) {
        GString *key = g_string_new(NULL);
        while (length > 0 && !interrupted) {
            if (g_str_equal(line, ".\n") || g_str_equal(line, ".\r\n")) break;
            if (key->len + (gsize)length > 65536) { length = -1; break; }
            g_string_append_len(key, line, length);
            wipe(line);
            length = getline(&line, &capacity, tty);
        }
        wipe(line); free(line);
        line = g_string_free(key, FALSE);
        if (length >= 0) length = strlen(line);
    }
    tcsetattr(fileno(tty), TCSAFLUSH, &original);
    fprintf(tty, "\n"); fclose(tty);
    if (length < 0 || interrupted) { wipe(line); free(line); g_set_error_literal(error, G_IO_ERROR, G_IO_ERROR_CANCELLED, "Credential entry cancelled."); return NULL; }
    while (length > 0 && (line[length - 1] == '\n' || line[length - 1] == '\r')) line[--length] = 0;
    if (length > 65536) { wipe(line); free(line); g_set_error_literal(error, G_IO_ERROR, G_IO_ERROR_INVALID_ARGUMENT, "Credential is too large."); return NULL; }
    return line;
}

static gchar *read_request(const gchar *path, GError **error)
{
    FILE *file = !path || g_str_equal(path, "-") ? stdin : fopen(path, "r");
    if (!file) { g_set_error(error, G_FILE_ERROR, g_file_error_from_errno(errno), "Cannot read request: %s", g_strerror(errno)); return NULL; }
    GString *text = g_string_new(NULL); gchar buffer[4096]; size_t n;
    while ((n = fread(buffer, 1, sizeof(buffer), file)) > 0) {
        if (text->len + n > OV_REQUEST_LIMIT) { g_set_error_literal(error, G_IO_ERROR, G_IO_ERROR_INVALID_ARGUMENT, "Request exceeds 1 MiB."); break; }
        g_string_append_len(text, buffer, n);
    }
    if (ferror(file) && !*error) g_set_error_literal(error, G_IO_ERROR, G_IO_ERROR_FAILED, "Cannot read request data.");
    if (file != stdin) fclose(file);
    if (*error) { wipe(text->str); g_string_free(text, TRUE); return NULL; }
    JsonParser *parser = json_parser_new();
    if (!json_parser_load_from_data(parser, text->str, text->len, error) || !JSON_NODE_HOLDS_OBJECT(json_parser_get_root(parser))) {
        if (!*error) g_set_error_literal(error, G_IO_ERROR, G_IO_ERROR_INVALID_ARGUMENT, "Request must be a JSON object.");
        wipe(text->str); g_string_free(text, TRUE); g_object_unref(parser); return NULL;
    }
    g_object_unref(parser); return g_string_free(text, FALSE);
}

static gchar *make_request(int argc, char **argv, GError **error)
{
    if (argc > 0 && g_str_equal(argv[0], "request")) {
        if (argc > 2) { g_set_error_literal(error, G_IO_ERROR, G_IO_ERROR_INVALID_ARGUMENT, "request accepts one file or -."); return NULL; }
        return read_request(argc == 2 ? argv[1] : "-", error);
    }
    if (argc < 2) { g_set_error_literal(error, G_IO_ERROR, G_IO_ERROR_INVALID_ARGUMENT, "Specify a group and action; see --help."); return NULL; }
    const gchar *groups[] = { "vault", "migration", "destination", "repository", "backup", "schedule", "event", "system", "diagnostic", NULL };
    if (!in_list(argv[0], groups)) { g_set_error_literal(error, G_IO_ERROR, G_IO_ERROR_INVALID_ARGUMENT, "Unknown operation group."); return NULL; }
    JsonObject *params = json_object_new();
    const gchar *boolean_keys[] = { "force", "force_close", "read_data", "dry_run", "one_file_system", "on_battery", "metered", "use_existing_key", "require_token", NULL };
    const gchar *number_keys[] = { "size_gb", "port", "keep_daily", "keep_weekly", "keep_monthly", "keep_yearly", "keep_last", "boot_delay_sec", "idle_sec", "idle_seconds", "upload_limit", "download_limit", NULL };
    const gchar *array_keys[] = { "sources", "excludes", "include", "close_on", NULL };
    for (int i = 2; i < argc; i++) {
        if (!g_str_has_prefix(argv[i], "--") || strchr(argv[i], '=')) {
            g_set_error_literal(error, G_IO_ERROR, G_IO_ERROR_INVALID_ARGUMENT, "Options use --name VALUE; credentials take no value."); break;
        }
        gchar *key = g_strdup(argv[i] + 2); for (gchar *c = key; *c; c++) if (*c == '-') *c = '_';
        gboolean negative = g_str_has_prefix(key, "no_") && in_list(key + 3, boolean_keys);
        if (negative) memmove(key, key + 3, strlen(key + 3) + 1);
        if (g_str_equal(key, "source")) { g_free(key); key = g_strdup("sources"); }
        if (g_str_equal(key, "exclude")) { g_free(key); key = g_strdup("excludes"); }
        if (is_secret(key)) {
            if (i + 1 < argc && !g_str_has_prefix(argv[i + 1], "--"))
                g_set_error(error, G_IO_ERROR, G_IO_ERROR_INVALID_ARGUMENT, "Never supply %s on the command line. Use --%s without a value or a stdin request.", key, key);
            else {
                gchar *secret = prompt_secret(key, error);
                if (secret) { json_object_set_string_member(params, key, secret); wipe(secret); g_free(secret); }
            }
        } else if (in_list(key, boolean_keys)) {
            gboolean value = !negative;
            if (i + 1 < argc && (g_str_equal(argv[i + 1], "true") || g_str_equal(argv[i + 1], "false")))
                value = g_str_equal(argv[++i], "true");
            json_object_set_boolean_member(params, key, value);
        } else if (i + 1 >= argc || g_str_has_prefix(argv[i + 1], "--")) {
            g_set_error(error, G_IO_ERROR, G_IO_ERROR_INVALID_ARGUMENT, "Option %s requires a value.", key);
        } else {
            const gchar *value = argv[++i];
            if (g_str_equal(key, "overwrite")) {
                const gchar *policies[] = { "never", "always", "if-changed", "if-newer", NULL };
                if (!in_list(value, policies)) g_set_error_literal(error, G_IO_ERROR, G_IO_ERROR_INVALID_ARGUMENT, "overwrite must be never, always, if-changed, or if-newer.");
                else json_object_set_string_member(params, key, value);
            } else if (in_list(key, array_keys)) {
                JsonArray *array = json_object_has_member(params, key) ? json_object_get_array_member(params, key) : NULL;
                if (!array) { array = json_array_new(); json_object_set_array_member(params, key, array); }
                json_array_add_string_element(array, value);
            } else if (in_list(key, number_keys)) {
                gchar *end = NULL; errno = 0;
                if (g_str_equal(key, "size_gb")) {
                    double number = g_ascii_strtod(value, &end);
                    if (errno || !end || end == value || *end || !isfinite(number) || number <= 0 || number > 1000000) g_set_error(error, G_IO_ERROR, G_IO_ERROR_INVALID_ARGUMENT, "Invalid number for %s.", key);
                    /* Preserve decimal text; JSON doubles can expand 0.05 into
                     * 0.050000000000000003 before backend size validation. */
                    else json_object_set_string_member(params, key, value);
                } else {
                    gint64 number = g_ascii_strtoll(value, &end, 10);
                    if (errno || !end || end == value || *end || number < 0) g_set_error(error, G_IO_ERROR, G_IO_ERROR_INVALID_ARGUMENT, "Invalid integer for %s.", key);
                    else json_object_set_int_member(params, key, number);
                }
            } else if (g_str_equal(key, "hooks") || g_str_equal(key, "retention")) {
                JsonParser *parser = json_parser_new();
                if (!json_parser_load_from_data(parser, value, -1, error) || !JSON_NODE_HOLDS_OBJECT(json_parser_get_root(parser))) {
                    if (!*error) g_set_error(error, G_IO_ERROR, G_IO_ERROR_INVALID_ARGUMENT, "%s must be a JSON object.", key);
                } else json_object_set_member(params, key, json_node_copy(json_parser_get_root(parser)));
                g_object_unref(parser);
            } else json_object_set_string_member(params, key, value);
        }
        g_free(key);
        if (*error) break;
    }
    if (*error) { json_object_unref(params); return NULL; }
    gchar *op = g_strdup_printf("%s.%s", argv[0], argv[1]);
    JsonObject *request = json_object_new();
    json_object_set_string_member(request, "op", op); json_object_set_object_member(request, "params", params);
    JsonNode *root = json_node_new(JSON_NODE_OBJECT); json_node_take_object(root, request);
    gchar *encoded = ov_json_encode(root, FALSE);
    json_node_unref(root); g_free(op); return encoded;
}

static GPid start_agent(void)
{
    if (!isatty(STDIN_FILENO) || g_getenv("DISPLAY") || g_getenv("WAYLAND_DISPLAY")) return 0;
    gchar *program = g_find_program_in_path("pkttyagent");
    if (!program) return 0;
    int ready[2];
    if (pipe(ready) < 0) { g_free(program); return 0; }
    pid_t pid = fork();
    if (pid == 0) {
        close(ready[0]);
        gchar process[32], fd[32];
        g_snprintf(process, sizeof(process), "%ld", (long)getppid());
        g_snprintf(fd, sizeof(fd), "%d", ready[1]);
        execl(program, program, "--process", process, "--notify-fd", fd, "--fallback", (char *)NULL);
        _exit(127);
    }
    close(ready[1]); g_free(program);
    if (pid > 0) { struct pollfd descriptor = { .fd = ready[0], .events = POLLIN | POLLHUP }; poll(&descriptor, 1, 3000); }
    close(ready[0]); return pid > 0 ? pid : 0;
}

static void print_value(JsonNode *node, guint indent)
{
    if (JSON_NODE_HOLDS_OBJECT(node)) {
        JsonObject *object = json_node_get_object(node);
        GList *members = json_object_get_members(object);
        for (GList *item = members; item; item = item->next) {
            const gchar *key = item->data;
            JsonNode *value = json_object_get_member(object, key);
            gchar *label = g_strdup(key);
            for (gchar *p = label; *p; p++) if (*p == '_') *p = ' ';
            g_print("%*s%s: ", (int)indent, "", label);
            g_free(label);
            if (JSON_NODE_HOLDS_OBJECT(value) || JSON_NODE_HOLDS_ARRAY(value)) {
                g_print("\n"); print_value(value, indent + 2);
            } else print_value(value, 0);
        }
        g_list_free(members);
    } else if (JSON_NODE_HOLDS_ARRAY(node)) {
        JsonArray *array = json_node_get_array(node);
        if (!json_array_get_length(array)) g_print("%*sNone\n", (int)indent, "");
        for (guint i = 0; i < json_array_get_length(array); i++) {
            JsonNode *value = json_array_get_element(array, i);
            g_print("%*s%u. ", (int)indent, "", i + 1);
            if (JSON_NODE_HOLDS_OBJECT(value) || JSON_NODE_HOLDS_ARRAY(value)) {
                g_print("\n"); print_value(value, indent + 2);
            } else print_value(value, 0);
        }
    } else if (JSON_NODE_HOLDS_NULL(node)) g_print("—\n");
    else if (json_node_get_value_type(node) == G_TYPE_STRING) g_print("%s\n", json_node_get_string(node));
    else if (json_node_get_value_type(node) == G_TYPE_BOOLEAN) g_print("%s\n", json_node_get_boolean(node) ? "yes" : "no");
    else {
        gchar *encoded = ov_json_encode(node, FALSE);
        g_print("%s\n", encoded); g_free(encoded);
    }
}

static void print_response(JsonNode *node, gboolean json)
{
    if (json) {
        gchar *out = ov_json_encode(node, FALSE);
        puts(out); wipe(out); g_free(out);
    } else print_value(node, 0);
}

int main(int argc, char **argv)
{
    const struct rlimit no_core = { 0, 0 };
    (void)setrlimit(RLIMIT_CORE, &no_core);
    (void)prctl(PR_SET_DUMPABLE, 0);
    gboolean json = FALSE;
    GPtrArray *args = g_ptr_array_new();
    for (int i = 1; i < argc; i++) {
        if (g_str_equal(argv[i], "--json")) json = TRUE;
        else if (g_str_equal(argv[i], "--help") || g_str_equal(argv[i], "-h")) { usage(); g_ptr_array_unref(args); return 0; }
        else if (g_str_equal(argv[i], "--version")) { puts("OctoVault " OCTOVAULT_VERSION); g_ptr_array_unref(args); return 0; }
        else g_ptr_array_add(args, argv[i]);
    }
    struct sigaction action = { .sa_handler = signal_handler };
    sigemptyset(&action.sa_mask); sigaction(SIGINT, &action, NULL); sigaction(SIGTERM, &action, NULL);
    GError *error = NULL;
    gboolean job_command = args->len == 3 && g_str_equal(args->pdata[0], "job");
    gchar *request = NULL;
    if (!job_command) {
        request = make_request((int)args->len, (char **)args->pdata, &error);
    }
    if (error) goto failed;
    GPid agent = start_agent();
    GDBusConnection *bus = ov_client_connect(&error);
    if (!bus) { if (agent) { kill(agent, SIGTERM); waitpid(agent, NULL, 0); } goto failed; }
    if (job_command) {
        if (g_str_equal(args->pdata[1], "cancel")) {
            gboolean cancelled = ov_client_cancel(bus, args->pdata[2], &error);
            if (!error) puts(json ? (cancelled ? "{\"cancelled\":true}" : "{\"cancelled\":false}") : (cancelled ? "Cancellation requested." : "Job already complete."));
        } else if (g_str_equal(args->pdata[1], "get")) {
            JsonNode *job = ov_client_get_job(bus, args->pdata[2], &error);
            if (job) { print_response(job, json); json_node_unref(job); }
        } else g_set_error_literal(&error, G_IO_ERROR, G_IO_ERROR_INVALID_ARGUMENT, "Use job get or job cancel.");
        g_object_unref(bus); if (agent) { kill(agent, SIGTERM); waitpid(agent, NULL, 0); }
        if (error) goto failed;
        g_ptr_array_unref(args); return 0;
    }
    gchar *id = ov_client_submit(bus, request, &error);
    wipe(request); g_clear_pointer(&request, g_free);
    if (agent) { kill(agent, SIGTERM); waitpid(agent, NULL, 0); }
    if (!id) { g_object_unref(bus); goto failed; }
    int exit_code = 1; gboolean cancellation_sent = FALSE;
    gchar *last_message = NULL;
    for (;;) {
        if (interrupted && !cancellation_sent) { ov_client_cancel(bus, id, NULL); cancellation_sent = TRUE; }
        JsonNode *job = ov_client_get_job(bus, id, &error);
        if (!job) break;
        if (!JSON_NODE_HOLDS_OBJECT(job)) { json_node_unref(job); g_set_error_literal(&error, G_IO_ERROR, G_IO_ERROR_INVALID_DATA, "Invalid job response."); break; }
        JsonObject *obj = json_node_get_object(job);
        JsonNode *result = json_object_get_member(obj, "result");
        if (result) {
            print_response(result, json);
            JsonObject *result_obj = json_node_get_object(result);
            exit_code = json_object_get_boolean_member(result_obj, "ok") ? 0 : cancellation_sent ? 130 : 1;
            json_node_unref(job); break;
        }
        if (!json && isatty(STDERR_FILENO) && json_object_has_member(obj, "progress")) {
            JsonObject *progress = json_object_get_object_member(obj, "progress");
            const gchar *message = json_object_get_string_member(progress, "message");
            if (g_strcmp0(last_message, message) != 0) { g_printerr("%s\n", message); g_free(last_message); last_message = g_strdup(message); }
        }
        json_node_unref(job); g_usleep(200000);
    }
    g_free(last_message); g_free(id); g_object_unref(bus);
    if (error) goto failed;
    g_ptr_array_unref(args); return exit_code;
failed:
    wipe(request); g_free(request);
    if (json) {
        JsonObject *obj = json_object_new(); json_object_set_boolean_member(obj, "ok", FALSE);
        JsonObject *detail = json_object_new(); json_object_set_string_member(detail, "code", "CLIENT_ERROR");
        json_object_set_string_member(detail, "message", error ? error->message : "Operation failed.");
        json_object_set_object_member(obj, "error", detail);
        JsonNode *root = json_node_new(JSON_NODE_OBJECT); json_node_take_object(root, obj);
        gchar *out = ov_json_encode(root, FALSE); puts(out); g_free(out); json_node_unref(root);
    } else g_printerr("OctoVault: %s\n", error ? error->message : "Operation failed.");
    g_clear_error(&error); g_ptr_array_unref(args); return interrupted ? 130 : 1;
}
