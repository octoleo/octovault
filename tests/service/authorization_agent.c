/* SPDX-License-Identifier: Apache-2.0
 * Disposable-system integration driver. This is never installed. It registers
 * a real polkit authentication agent and answers the real PAM conversation with
 * credentials created solely for this test. No authorization is manufactured.
 */
#define _GNU_SOURCE
#define POLKIT_AGENT_I_KNOW_API_IS_SUBJECT_TO_CHANGE
#include <polkitagent/polkitagent.h>
#include <pwd.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include "client.h"

typedef struct {
    PolkitAgentListener parent;
    uid_t administrator;
    gchar *admin_password;
    gchar *self_password;
    gint mode; /* 0: authenticate, 1: wrong password, 2: cancel */
    gint challenges;
    gint authentications;
} TestAgent;
typedef struct { PolkitAgentListenerClass parent; } TestAgentClass;
G_DEFINE_TYPE(TestAgent, test_agent, POLKIT_AGENT_TYPE_LISTENER)

typedef struct {
    GTask *task;
    PolkitAgentSession *session;
    GCancellable *cancellable;
    gulong cancellation;
    TestAgent *agent;
    gboolean administrator;
} Conversation;

static void erase(gchar *value)
{
    if (!value) return;
    for (volatile gchar *p = value; *p; p++) *p = 0;
    g_free(value);
}

static void authentication_cancelled(GCancellable *cancellable, gpointer data)
{
    (void)cancellable;
    polkit_agent_session_cancel(((Conversation *)data)->session);
}

static void authentication_request(PolkitAgentSession *session, const gchar *message,
                                   gboolean echo_on, gpointer data)
{
    (void)message; (void)echo_on;
    Conversation *conversation = data;
    const gchar *password = conversation->administrator
        ? conversation->agent->admin_password : conversation->agent->self_password;
    if (g_atomic_int_get(&conversation->agent->mode) == 1)
        password = "deliberately-incorrect-integration-test-response";
    polkit_agent_session_response(session, password);
}

static void authentication_completed(PolkitAgentSession *session, gboolean gained, gpointer data)
{
    Conversation *conversation = data;
    if (gained) g_atomic_int_inc(&conversation->agent->authentications);
    if (conversation->cancellation)
        g_signal_handler_disconnect(conversation->cancellable, conversation->cancellation);
    g_clear_object(&conversation->cancellable);
    /* PAM tells polkit whether authentication succeeded. Returning successfully
     * here only says that the agent conversation has finished. */
    g_task_return_boolean(conversation->task, TRUE);
    g_object_unref(conversation->task);
    g_object_unref(session);
    g_free(conversation);
}

static void initiate(PolkitAgentListener *listener, const gchar *action,
                     const gchar *message, const gchar *icon, PolkitDetails *details,
                     const gchar *cookie, GList *identities, GCancellable *cancellable,
                     GAsyncReadyCallback callback, gpointer user_data)
{
    (void)action; (void)message; (void)icon; (void)details;
    TestAgent *agent = (TestAgent *)listener;
    GTask *task = g_task_new(listener, cancellable, callback, user_data);
    g_atomic_int_inc(&agent->challenges);
    if (g_atomic_int_get(&agent->mode) == 2 || g_cancellable_is_cancelled(cancellable)) {
        g_task_return_new_error(task, POLKIT_ERROR, POLKIT_ERROR_CANCELLED,
                               "The disposable test user cancelled authentication.");
        g_object_unref(task);
        return;
    }
    PolkitIdentity *identity = NULL;
    for (GList *item = identities; item; item = item->next) {
        if (!POLKIT_IS_UNIX_USER(item->data)) continue;
        uid_t uid = (uid_t)polkit_unix_user_get_uid(POLKIT_UNIX_USER(item->data));
        if (uid == agent->administrator || uid == getuid()) {
            identity = item->data;
            break;
        }
    }
    if (!identity) {
        g_task_return_new_error(task, POLKIT_ERROR, POLKIT_ERROR_FAILED,
                               "No expected disposable account is an eligible identity.");
        g_object_unref(task);
        return;
    }
    Conversation *conversation = g_new0(Conversation, 1);
    conversation->task = task;
    conversation->agent = agent;
    conversation->administrator = (uid_t)polkit_unix_user_get_uid(POLKIT_UNIX_USER(identity)) == agent->administrator;
    conversation->session = polkit_agent_session_new(identity, cookie);
    conversation->cancellable = g_object_ref(cancellable);
    conversation->cancellation = g_signal_connect(cancellable, "cancelled", G_CALLBACK(authentication_cancelled), conversation);
    g_signal_connect(conversation->session, "request", G_CALLBACK(authentication_request), conversation);
    g_signal_connect(conversation->session, "completed", G_CALLBACK(authentication_completed), conversation);
    polkit_agent_session_initiate(conversation->session);
}

static gboolean finish(PolkitAgentListener *listener, GAsyncResult *result, GError **error)
{
    (void)listener;
    return g_task_propagate_boolean(G_TASK(result), error);
}

static void test_agent_class_init(TestAgentClass *klass)
{
    PolkitAgentListenerClass *listener = POLKIT_AGENT_LISTENER_CLASS(klass);
    listener->initiate_authentication = initiate;
    listener->initiate_authentication_finish = finish;
}
static void test_agent_init(TestAgent *agent) { (void)agent; }

static GDBusConnection *connect_client(GError **error)
{
    gchar *address = g_dbus_address_get_for_bus_sync(G_BUS_TYPE_SYSTEM, NULL, error);
    if (!address) return NULL;
    GDBusConnection *bus = g_dbus_connection_new_for_address_sync(address,
        G_DBUS_CONNECTION_FLAGS_AUTHENTICATION_CLIENT | G_DBUS_CONNECTION_FLAGS_MESSAGE_BUS_CONNECTION,
        NULL, NULL, error);
    g_free(address);
    if (bus) g_dbus_connection_set_exit_on_close(bus, FALSE);
    return bus;
}

static JsonNode *failure(GError *error)
{
    JsonObject *object = json_object_new(), *detail = json_object_new();
    gchar *remote = error ? g_dbus_error_get_remote_error(error) : NULL;
    json_object_set_string_member(detail, "code", remote ? remote : "integration_error");
    json_object_set_string_member(detail, "message", error ? error->message : "The operation ended without a result.");
    g_free(remote);
    json_object_set_boolean_member(object, "ok", FALSE);
    json_object_set_object_member(object, "error", detail);
    JsonNode *node = json_node_new(JSON_NODE_OBJECT);
    json_node_take_object(node, object);
    return node;
}

static JsonNode *request(GDBusConnection *bus, const gchar *line)
{
    GError *error = NULL;
    gchar *id = ov_client_submit(bus, line, &error);
    if (!id) { JsonNode *node = failure(error); g_clear_error(&error); return node; }
    JsonNode *result = NULL;
    gint64 deadline = g_get_monotonic_time() + 120 * G_TIME_SPAN_SECOND;
    while (g_get_monotonic_time() < deadline) {
        JsonNode *job = ov_client_get_job(bus, id, &error);
        if (!job) break;
        JsonObject *object = json_node_get_object(job);
        const gchar *state = json_object_get_string_member(object, "state");
        if (!strcmp(state, "succeeded") || !strcmp(state, "failed") || !strcmp(state, "cancelled")) {
            if (json_object_has_member(object, "result"))
                result = json_node_copy(json_object_get_member(object, "result"));
            json_node_free(job);
            break;
        }
        json_node_free(job);
        g_usleep(20000);
    }
    g_free(id);
    if (!result) result = failure(error);
    g_clear_error(&error);
    return result;
}

static void output(TestAgent *agent, JsonNode *response)
{
    JsonObject *object = json_object_new();
    json_object_set_member(object, "response", response);
    json_object_set_int_member(object, "challenges", g_atomic_int_get(&agent->challenges));
    json_object_set_int_member(object, "authentications", g_atomic_int_get(&agent->authentications));
    JsonNode *node = json_node_new(JSON_NODE_OBJECT);
    json_node_take_object(node, object);
    gchar *encoded = ov_json_encode(node, FALSE);
    puts(encoded);
    fflush(stdout);
    erase(encoded);
    json_node_free(node);
}

static JsonNode *cli_request(JsonObject *command)
{
    JsonArray *arguments = json_object_get_array_member(command, "arguments");
    guint count = json_array_get_length(arguments);
    gboolean manager = !g_strcmp0(json_object_get_string_member(command, "test"), "manager-cli");
    const gchar *manager_prefix[] = { "/usr/bin/systemd-run", "--user", "--quiet", "--wait", "--pipe", "--collect", "/usr/bin/octovault" };
    guint prefix = manager ? G_N_ELEMENTS(manager_prefix) : 1;
    gchar **argv = g_new0(gchar *, count + prefix + 1);
    for (guint i = 0; i < prefix; i++) argv[i] = g_strdup(manager ? manager_prefix[i] : "/usr/bin/octovault");
    for (guint i = 0; i < count; i++) argv[i + prefix] = g_strdup(json_array_get_string_element(arguments, i));
    gchar *stdout_data = NULL, *stderr_data = NULL;
    gint status;
    GError *error = NULL;
    JsonNode *result = NULL;
    if (g_spawn_sync(NULL, argv, NULL, G_SPAWN_DEFAULT, NULL, NULL,
                     &stdout_data, &stderr_data, &status, &error)) {
        JsonParser *parser = json_parser_new();
        if (json_parser_load_from_data(parser, stdout_data, -1, &error))
            result = json_node_copy(json_parser_get_root(parser));
        g_object_unref(parser);
    }
    if (!result) result = failure(error);
    g_clear_error(&error);
    erase(stdout_data); erase(stderr_data); g_strfreev(argv);
    return result;
}

static JsonNode *set_locked(GDBusConnection *bus, gboolean locked)
{
    GError *error = NULL;
    GVariant *reply = g_dbus_connection_call_sync(bus, "org.freedesktop.login1", "/org/freedesktop/login1",
        "org.freedesktop.login1.Manager", "GetSessionByPID", g_variant_new("(u)", (guint32)getpid()),
        G_VARIANT_TYPE("(o)"), G_DBUS_CALL_FLAGS_NONE, 5000, NULL, &error);
    if (reply) {
        const gchar *path;
        g_variant_get(reply, "(&o)", &path);
        GVariant *changed = g_dbus_connection_call_sync(bus, "org.freedesktop.login1", path,
            "org.freedesktop.login1.Session", "SetLockedHint", g_variant_new("(b)", locked),
            NULL, G_DBUS_CALL_FLAGS_NONE, 5000, NULL, &error);
        g_variant_unref(reply);
        if (changed) g_variant_unref(changed);
    }
    if (error) { JsonNode *result = failure(error); g_clear_error(&error); return result; }
    JsonObject *object = json_object_new();
    json_object_set_boolean_member(object, "ok", TRUE);
    JsonNode *result = json_node_new(JSON_NODE_OBJECT);
    json_node_take_object(result, object);
    return result;
}

int main(int argc, char **argv)
{
    if (argc != 3 || getuid() == 0 || g_strcmp0(g_getenv("OCTOVAULT_DISPOSABLE_TEST"), "1")) {
        fputs("This driver requires a non-root disposable test session and two fixture arguments.\n", stderr);
        return 2;
    }
    struct passwd *administrator = getpwnam(argv[1]);
    if (!administrator) return 2;
    TestAgent *agent = g_object_new(test_agent_get_type(), NULL);
    agent->administrator = administrator->pw_uid;
    GError *error = NULL;
    JsonParser *credentials = json_parser_new();
    if (!json_parser_load_from_file(credentials, argv[2], &error))
        g_error("Cannot read disposable credential fixture: %s", error->message);
    JsonObject *secrets = json_node_get_object(json_parser_get_root(credentials));
    agent->admin_password = g_strdup(json_object_get_string_member(secrets, "administrator"));
    agent->self_password = g_strdup(json_object_get_string_member(secrets, "self"));
    g_object_unref(credentials);
    gboolean headless = !g_strcmp0(g_getenv("OCTOVAULT_AUTH_TEST_HEADLESS"), "1");
    PolkitSubject *subject = headless
        ? polkit_unix_process_new_for_owner(getpid(), 0, getuid())
        : polkit_unix_session_new_for_process_sync(getpid(), NULL, &error);
    if (!subject) g_error("Cannot identify the real authentication subject: %s", error ? error->message : "unknown process");
    gpointer registration = polkit_agent_listener_register(POLKIT_AGENT_LISTENER(agent),
        POLKIT_AGENT_REGISTER_FLAGS_RUN_IN_THREAD, subject, NULL, NULL, &error);
    if (!registration) g_error("Real polkit agent registration failed: %s", error->message);
    GDBusConnection *bus = connect_client(&error);
    if (!bus) g_error("Cannot connect to the real system bus: %s", error->message);
    JsonObject *ready = json_object_new();
    json_object_set_boolean_member(ready, "ready", TRUE);
    json_object_set_int_member(ready, "uid", getuid());
    json_object_set_string_member(ready, "session", headless ? "" : polkit_unix_session_get_session_id(POLKIT_UNIX_SESSION(subject)));
    JsonNode *node = json_node_new(JSON_NODE_OBJECT);
    json_node_take_object(node, ready);
    output(agent, node);

    gchar *line = NULL;
    size_t length = 0;
    while (getline(&line, &length, stdin) > 0) {
        JsonParser *parser = json_parser_new();
        if (!json_parser_load_from_data(parser, line, -1, &error))
            g_error("Invalid test command: %s", error->message);
        JsonObject *command = json_node_get_object(json_parser_get_root(parser));
        const gchar *control = json_object_has_member(command, "test")
            ? json_object_get_string_member(command, "test") : NULL;
        if (control && !strcmp(control, "quit")) { g_object_unref(parser); break; }
        if (control && !strcmp(control, "mode")) {
            const gchar *mode = json_object_get_string_member(command, "value");
            g_atomic_int_set(&agent->mode, !strcmp(mode, "cancel") ? 2 : !strcmp(mode, "wrong") ? 1 : 0);
            output(agent, json_node_copy(json_parser_get_root(parser)));
        } else if (control && !strcmp(control, "reconnect")) {
            g_dbus_connection_close_sync(bus, NULL, NULL);
            g_object_unref(bus);
            bus = connect_client(&error);
            if (!bus) g_error("Reconnect failed: %s", error->message);
            output(agent, json_node_copy(json_parser_get_root(parser)));
        } else if (control && !strcmp(control, "set-locked")) {
            output(agent, set_locked(bus, json_object_get_boolean_member(command, "value")));
        } else if (control && (!strcmp(control, "cli") || !strcmp(control, "manager-cli"))) {
            output(agent, cli_request(command));
        } else {
            output(agent, request(bus, line));
        }
        memset(line, 0, strlen(line));
        g_object_unref(parser);
    }
    erase(line);
    g_dbus_connection_close_sync(bus, NULL, NULL);
    g_object_unref(bus);
    polkit_agent_listener_unregister(registration);
    g_object_unref(subject);
    erase(agent->admin_password);
    erase(agent->self_password);
    g_object_unref(agent);
    return 0;
}
