/* OctoVault desktop event agent. SPDX-License-Identifier: Apache-2.0 */
#include <gio/gio.h>
#include <gio/gunixfdlist.h>
#include <glib-unix.h>
#include <json-glib/json-glib.h>
#include <signal.h>
#include <string.h>
#include <unistd.h>

#define SERVICE "io.vdm.OctoVault1"
#define OBJECT "/io/vdm/OctoVault1"
#define INTERFACE "io.vdm.OctoVault1"

static GMainLoop *loop;
static GDBusConnection *system_bus;
static GDBusConnection *session_bus;
static GVolumeMonitor *volumes;
static int inhibitor_fd = -1;
static guint64 inhibitor_generation;
static gboolean exiting;
static gboolean card_pending;
static guint card_timeout_id;
static gchar *card_identity;
static gchar *session_client;
static guint pending_jobs;
static gchar *login_session_path;
static gboolean session_known, desktop_active, logind_locked = TRUE, screensaver_locked;
static gboolean login_offered, was_locked, resume_pending;
static guint64 desktop_generation;
static GHashTable *pending_unlock_ids;

typedef struct {
    gchar *id;
    gchar *event;
    gint64 deadline;
    gboolean release_inhibitor;
    guint64 inhibitor_generation;
    gboolean end_session;
    guint64 desktop_generation;
} EventJob;

static void notify_failure(const gchar *event) {
    GVariantBuilder hints;
    const gchar *actions[] = { NULL };
    gchar *body;
    if (g_str_equal(event, "idle")) return;
    body = g_strdup_printf("The %s operation did not complete. Open OctoVault to inspect the current vault and backup status.", event);
    g_variant_builder_init(&hints, G_VARIANT_TYPE("a{sv}"));
    g_variant_builder_add(&hints, "{sv}", "urgency", g_variant_new_byte(1));
    g_dbus_connection_call(session_bus, "org.freedesktop.Notifications", "/org/freedesktop/Notifications",
        "org.freedesktop.Notifications", "Notify",
        g_variant_new("(susss^asa{sv}i)", "OctoVault", 0u, "io.vdm.OctoVault",
                      "OctoVault needs attention", body, actions, &hints, 10000),
        NULL, G_DBUS_CALL_FLAGS_NONE, 3000, NULL, NULL, NULL);
    g_free(body);
}

static void release_inhibitor(void) {
    if (inhibitor_fd >= 0) { close(inhibitor_fd); inhibitor_fd = -1; }
}

static void acquire_inhibitor(void) {
    GError *error = NULL;
    GUnixFDList *fds = NULL;
    GVariant *result;
    gint handle;
    if (inhibitor_fd >= 0 || exiting) return;
    result = g_dbus_connection_call_with_unix_fd_list_sync(system_bus,
        "org.freedesktop.login1", "/org/freedesktop/login1",
        "org.freedesktop.login1.Manager", "Inhibit",
        g_variant_new("(ssss)", "sleep:shutdown", "OctoVault",
                      "Close configured encrypted vaults before leaving the session", "delay"),
        G_VARIANT_TYPE("(h)"), G_DBUS_CALL_FLAGS_NONE, 3000, NULL, &fds, NULL, &error);
    if (result) {
        g_variant_get(result, "(h)", &handle);
        inhibitor_fd = g_unix_fd_list_get(fds, handle, &error);
        if (inhibitor_fd >= 0) inhibitor_generation++;
        g_variant_unref(result);
    }
    if (error) {
        g_warning("Desktop delay inhibitor is unavailable: %s", error->message);
        g_error_free(error);
    }
    g_clear_object(&fds);
}

static void end_session_response(void) {
    if (!session_client || !session_bus) return;
    g_dbus_connection_call(session_bus, "org.gnome.SessionManager", session_client,
        "org.gnome.SessionManager.ClientPrivate", "EndSessionResponse",
        g_variant_new("(bs)", TRUE, ""), NULL, G_DBUS_CALL_FLAGS_NONE,
        3000, NULL, NULL, NULL);
}

static void event_job_free(EventJob *job) {
    if (job->release_inhibitor && job->inhibitor_generation == inhibitor_generation) release_inhibitor();
    if (job->end_session) end_session_response();
    g_free(job->id); g_free(job->event); g_free(job);
    if (pending_jobs > 0) pending_jobs--;
    if (exiting && pending_jobs == 0) g_main_loop_quit(loop);
}

static gboolean poll_job(gpointer data);
static void launch_pending_unlocks(void);

static void poll_finished(GObject *source, GAsyncResult *async, gpointer data) {
    EventJob *job = data;
    GError *error = NULL;
    GVariant *reply = g_dbus_connection_call_finish(G_DBUS_CONNECTION(source), async, &error);
    gboolean finished = FALSE;
    if (reply) {
        const gchar *document;
        JsonParser *parser = json_parser_new();
        g_variant_get(reply, "(&s)", &document);
        if (json_parser_load_from_data(parser, document, -1, NULL)) {
            JsonNode *root = json_parser_get_root(parser);
            if (JSON_NODE_HOLDS_OBJECT(root)) {
                JsonObject *object = json_node_get_object(root);
                const gchar *status = json_object_get_string_member_with_default(object, "status", "");
                const gchar *state = json_object_get_string_member_with_default(object, "state", "");
                if (g_str_equal(state, "failed") || g_str_equal(state, "cancelled")) notify_failure(job->event);
                if (g_str_equal(state, "succeeded") && json_object_has_member(object, "result")) {
                    JsonObject *result_object = json_object_get_object_member(object, "result");
                    if (result_object && json_object_has_member(result_object, "data")) {
                        JsonObject *payload = json_object_get_object_member(result_object, "data");
                        if (payload && json_object_has_member(payload, "unlock_requests")) {
                            JsonArray *requests = json_object_get_array_member(payload, "unlock_requests");
                            if (requests && job->desktop_generation == desktop_generation) {
                                for (guint i = 0; i < json_array_get_length(requests); i++) {
                                    const gchar *id = json_array_get_string_element(requests, i);
                                    if (!id || !*id || strlen(id) > 64 || strspn(id, "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-") != strlen(id)) continue;
                                    if (!g_hash_table_contains(pending_unlock_ids, id))
                                        g_hash_table_insert(pending_unlock_ids, g_strdup(id), GINT_TO_POINTER(0));
                                }
                                launch_pending_unlocks();
                            }
                        }
                    }
                }
                finished = g_str_equal(status, "completed") || g_str_equal(status, "failed") ||
                           g_str_equal(status, "cancelled") || g_str_equal(status, "done") ||
                           g_str_equal(state, "succeeded") || g_str_equal(state, "completed") || g_str_equal(state, "failed") ||
                           g_str_equal(state, "cancelled") || g_str_equal(state, "done");
            }
        }
        g_object_unref(parser); g_variant_unref(reply);
    } else {
        g_warning("Could not obtain OctoVault event status: %s", error->message);
        g_error_free(error); finished = TRUE;
    }
    if (finished || g_get_monotonic_time() >= job->deadline) {
        if (!finished) g_warning("OctoVault desktop event %s is still running; the system guard determines sleep eligibility.", job->event);
        event_job_free(job);
    } else g_timeout_add(150, poll_job, job);
}

static gboolean poll_job(gpointer data) {
    EventJob *job = data;
    g_dbus_connection_call(system_bus, SERVICE, OBJECT, INTERFACE, "GetJob",
        g_variant_new("(s)", job->id), G_VARIANT_TYPE("(s)"), G_DBUS_CALL_FLAGS_NONE,
        3000, NULL, poll_finished, job);
    return G_SOURCE_REMOVE;
}

static void event_submitted(GObject *source, GAsyncResult *async, gpointer data) {
    EventJob *job = data;
    GError *error = NULL;
    GVariant *reply = g_dbus_connection_call_finish(G_DBUS_CONNECTION(source), async, &error);
    if (!reply) {
        g_warning("OctoVault event %s was not accepted: %s", job->event, error->message);
        notify_failure(job->event);
        g_error_free(error); event_job_free(job); return;
    }
    g_variant_get(reply, "(s)", &job->id);
    g_variant_unref(reply);
    poll_job(job);
}

static void submit_event(const gchar *event, const gchar *uuid, guint64 idle,
                         gboolean release_after, gboolean end_session) {
    JsonBuilder *builder = json_builder_new();
    JsonGenerator *generator = json_generator_new();
    JsonNode *root;
    gchar *document;
    EventJob *job = g_new0(EventJob, 1);
    job->event = g_strdup(event);
    job->deadline = g_get_monotonic_time() + 30 * G_TIME_SPAN_SECOND;
    job->release_inhibitor = release_after;
    job->inhibitor_generation = inhibitor_generation;
    job->end_session = end_session;
    job->desktop_generation = desktop_generation;
    json_builder_begin_object(builder);
    json_builder_set_member_name(builder, "op"); json_builder_add_string_value(builder, "event.session");
    json_builder_set_member_name(builder, "params"); json_builder_begin_object(builder);
    json_builder_set_member_name(builder, "event"); json_builder_add_string_value(builder, event);
    if (uuid) { json_builder_set_member_name(builder, "drive_uuid"); json_builder_add_string_value(builder, uuid); }
    if (g_str_equal(event, "idle")) {
        json_builder_set_member_name(builder, "idle_seconds"); json_builder_add_int_value(builder, (gint64)idle);
    }
    json_builder_end_object(builder); json_builder_end_object(builder);
    root = json_builder_get_root(builder);
    json_generator_set_root(generator, root);
    document = json_generator_to_data(generator, NULL);
    pending_jobs++;
    g_dbus_connection_call(system_bus, SERVICE, OBJECT, INTERFACE, "Submit",
        g_variant_new("(s)", document), G_VARIANT_TYPE("(s)"), G_DBUS_CALL_FLAGS_NONE,
        5000, NULL, event_submitted, job);
    g_free(document); json_node_free(root); g_object_unref(generator); g_object_unref(builder);
}

/* Unlock offers belong to an active, unlocked desktop. Both logind and the
 * screen saver can report a transition; keeping their state avoids racing one
 * signal against the other and showing a prompt over the lock screen. */
static gboolean desktop_ready(void) {
    return session_known && desktop_active && !logind_locked && !screensaver_locked && !exiting;
}

static void launch_pending_unlocks(void) {
    if (!desktop_ready()) return;
    GHashTableIter iter;
    gpointer key, delivered;
    g_hash_table_iter_init(&iter, pending_unlock_ids);
    while (g_hash_table_iter_next(&iter, &key, &delivered)) {
        if (delivered) continue;
        const gchar *argv[] = { "/usr/bin/octovault-gtk", "--unlock", key, NULL };
        GError *error = NULL;
        if (!g_spawn_async(NULL, (gchar **)argv, NULL, G_SPAWN_DEFAULT, NULL, NULL, NULL, &error)) {
            g_warning("Could not display the vault unlock prompt: %s", error->message);
            g_error_free(error);
        }
        g_hash_table_iter_replace(&iter, GINT_TO_POINTER(1));
    }
}

static void desktop_state_changed(void) {
    gboolean locked = logind_locked || screensaver_locked;
    if (locked && !was_locked && login_offered) {
        desktop_generation++;
        g_hash_table_remove_all(pending_unlock_ids);
        submit_event("screen-lock", NULL, 0, FALSE, FALSE);
    }
    if (!desktop_ready()) { was_locked = locked; return; }
    if (!login_offered) {
        login_offered = TRUE;
        submit_event("login", NULL, 0, FALSE, FALSE);
    } else if (was_locked) submit_event("screen-unlock", NULL, 0, FALSE, FALSE);
    was_locked = FALSE;
    if (resume_pending) {
        resume_pending = FALSE;
        submit_event("resume", NULL, 0, FALSE, FALSE);
    }
    launch_pending_unlocks();
}

static void session_properties(GVariant *properties) {
    gboolean active, locked;
    if (g_variant_lookup(properties, "Active", "b", &active)) desktop_active = active;
    if (g_variant_lookup(properties, "LockedHint", "b", &locked)) logind_locked = locked;
    session_known = TRUE;
    desktop_state_changed();
}

static void logind_properties_changed(GDBusConnection *connection, const gchar *sender,
                                     const gchar *path, const gchar *interface,
                                     const gchar *signal, GVariant *parameters, gpointer data) {
    const gchar *changed;
    GVariant *properties, *invalidated;
    (void)connection; (void)sender; (void)interface; (void)signal; (void)data;
    if (!login_session_path || strcmp(path, login_session_path)) return;
    g_variant_get(parameters, "(&s@a{sv}@as)", &changed, &properties, &invalidated);
    if (!strcmp(changed, "org.freedesktop.login1.Session")) session_properties(properties);
    g_variant_unref(properties); g_variant_unref(invalidated);
}

static gchar *primary_display_path(GVariant *properties) {
    guint32 uid;
    if (!g_variant_lookup(properties, "UID", "u", &uid) || uid != (guint32)getuid()) return NULL;
    GVariant *display = g_variant_lookup_value(properties, "Display", G_VARIANT_TYPE("(so)"));
    if (!display) return NULL;
    const gchar *id, *path;
    g_variant_get(display, "(&s&o)", &id, &path);
    gchar *result = *id && g_str_has_prefix(path, "/org/freedesktop/login1/session/") ? g_strdup(path) : NULL;
    g_variant_unref(display);
    return result;
}

static gboolean refresh_session_state(gpointer data) {
    GVariant *reply;
    (void)data;
    if (exiting) return G_SOURCE_REMOVE;
    if (!login_session_path) {
        reply = g_dbus_connection_call_sync(system_bus, "org.freedesktop.login1", "/org/freedesktop/login1",
            "org.freedesktop.login1.Manager", "GetSessionByPID", g_variant_new("(u)", (guint32)getpid()),
            G_VARIANT_TYPE("(o)"), G_DBUS_CALL_FLAGS_NONE, 1500, NULL, NULL);
        if (reply) { g_variant_get(reply, "(o)", &login_session_path); g_variant_unref(reply); }
    }
    if (!login_session_path) {
        /* XDG autostart is often launched by the systemd user manager rather
         * than inside a logind session. Follow that user's primary display. */
        reply = g_dbus_connection_call_sync(system_bus, "org.freedesktop.login1", "/org/freedesktop/login1",
            "org.freedesktop.login1.Manager", "GetUserByPID", g_variant_new("(u)", (guint32)getpid()),
            G_VARIANT_TYPE("(o)"), G_DBUS_CALL_FLAGS_NONE, 1500, NULL, NULL);
        if (reply) {
            gchar *path;
            g_variant_get(reply, "(o)", &path); g_variant_unref(reply);
            reply = g_dbus_connection_call_sync(system_bus, "org.freedesktop.login1", path,
                "org.freedesktop.DBus.Properties", "GetAll", g_variant_new("(s)", "org.freedesktop.login1.User"),
                G_VARIANT_TYPE("(a{sv})"), G_DBUS_CALL_FLAGS_NONE, 1500, NULL, NULL);
            g_free(path);
            if (reply) {
                GVariant *properties;
                g_variant_get(reply, "(@a{sv})", &properties);
                login_session_path = primary_display_path(properties);
                g_variant_unref(properties); g_variant_unref(reply);
            }
        }
    }
    if (login_session_path) {
        reply = g_dbus_connection_call_sync(system_bus, "org.freedesktop.login1", login_session_path,
            "org.freedesktop.DBus.Properties", "GetAll", g_variant_new("(s)", "org.freedesktop.login1.Session"),
            G_VARIANT_TYPE("(a{sv})"), G_DBUS_CALL_FLAGS_NONE, 1500, NULL, NULL);
        if (reply) {
            GVariant *properties;
            g_variant_get(reply, "(@a{sv})", &properties);
            session_properties(properties);
            g_variant_unref(properties); g_variant_unref(reply);
        } else {
            session_known = FALSE;
            g_clear_pointer(&login_session_path, g_free);
        }
    }
    return G_SOURCE_CONTINUE;
}

static void login_signal(GDBusConnection *connection, const gchar *sender, const gchar *path,
                         const gchar *interface, const gchar *signal, GVariant *parameters,
                         gpointer user_data) {
    gboolean preparing;
    (void)connection; (void)sender; (void)path; (void)interface; (void)user_data;
    g_variant_get(parameters, "(b)", &preparing);
    if (preparing) {
        desktop_generation++;
        g_hash_table_remove_all(pending_unlock_ids);
        submit_event(g_str_equal(signal, "PrepareForSleep") ? "sleep" : "shutdown", NULL, 0, TRUE, FALSE);
    }
    else {
        /* The previous transition may finish after resume. Give the next
         * inhibitor a distinct generation so stale job completion cannot close it. */
        release_inhibitor();
        acquire_inhibitor();
        if (g_str_equal(signal, "PrepareForSleep")) {
            resume_pending = TRUE;
            refresh_session_state(NULL);
        }
    }
}

static void lock_signal(GDBusConnection *connection, const gchar *sender, const gchar *path,
                        const gchar *interface, const gchar *signal, GVariant *parameters,
                        gpointer user_data) {
    gboolean active;
    (void)connection; (void)sender; (void)path; (void)interface; (void)signal; (void)user_data;
    g_variant_get(parameters, "(b)", &active);
    screensaver_locked = active;
    desktop_state_changed();
}

static void mount_added(GVolumeMonitor *monitor, GMount *mount, gpointer user_data) {
    gchar *uuid = g_mount_get_uuid(mount);
    GVolume *volume;
    (void)monitor; (void)user_data;
    if (!uuid && (volume = g_mount_get_volume(mount))) {
        uuid = g_volume_get_identifier(volume, G_VOLUME_IDENTIFIER_KIND_UUID);
        g_object_unref(volume);
    }
    if (uuid && *uuid) submit_event("drive", uuid, 0, FALSE, FALSE);
    g_free(uuid);
}

static gboolean idle_tick(gpointer data) {
    GVariant *reply;
    guint64 milliseconds = 0;
    (void)data;
    if (exiting) return G_SOURCE_REMOVE;
    reply = g_dbus_connection_call_sync(session_bus, "org.gnome.Mutter.IdleMonitor",
        "/org/gnome/Mutter/IdleMonitor/Core", "org.gnome.Mutter.IdleMonitor", "GetIdletime",
        NULL, G_VARIANT_TYPE("(t)"), G_DBUS_CALL_FLAGS_NONE, 1500, NULL, NULL);
    if (reply) {
        g_variant_get(reply, "(t)", &milliseconds); g_variant_unref(reply);
        submit_event("idle", NULL, milliseconds / 1000, FALSE, FALSE);
    }
    return G_SOURCE_CONTINUE;
}

static void card_finished(GObject *source, GAsyncResult *async, gpointer data) {
    gchar *output = NULL;
    gchar *identity = NULL;
    gchar **lines;
    GError *error = NULL;
    (void)data;
    if (card_timeout_id) { g_source_remove(card_timeout_id); card_timeout_id = 0; }
    if (g_subprocess_communicate_utf8_finish(G_SUBPROCESS(source), async, &output, NULL, &error) &&
        g_subprocess_get_successful(G_SUBPROCESS(source)) && output) {
        lines = g_strsplit(output, "\n", -1);
        for (guint i = 0; lines[i]; i++) {
            if (g_str_has_prefix(lines[i], "serialno:")) { identity = g_strdup(lines[i]); break; }
        }
        g_strfreev(lines);
    }
    if (identity && g_strcmp0(identity, card_identity) != 0 && !exiting)
        submit_event("token", NULL, 0, FALSE, FALSE);
    g_free(card_identity); card_identity = identity;
    g_free(output); g_clear_error(&error);
    card_pending = FALSE; g_object_unref(source);
}

static gboolean card_timeout(gpointer data) {
    card_timeout_id = 0;
    g_subprocess_force_exit(G_SUBPROCESS(data));
    return G_SOURCE_REMOVE;
}

static gboolean card_tick(gpointer data) {
    GSubprocess *process;
    (void)data;
    if (exiting) return G_SOURCE_REMOVE;
    if (card_pending) return G_SOURCE_CONTINUE;
    process = g_subprocess_new(G_SUBPROCESS_FLAGS_STDOUT_PIPE | G_SUBPROCESS_FLAGS_STDERR_SILENCE,
        NULL, "/usr/bin/gpg", "--batch", "--with-colons", "--card-status", NULL);
    if (process) {
        card_pending = TRUE;
        card_timeout_id = g_timeout_add_seconds_full(G_PRIORITY_DEFAULT, 5, card_timeout,
                                                     g_object_ref(process), g_object_unref);
        g_subprocess_communicate_utf8_async(process, NULL, NULL, card_finished, NULL);
    }
    return G_SOURCE_CONTINUE;
}

static gboolean terminate_agent(gpointer data) {
    (void)data;
    if (!exiting) {
        exiting = TRUE;
        submit_event("logout", NULL, 0, TRUE, FALSE);
    }
    return G_SOURCE_REMOVE;
}

static void session_signal(GDBusConnection *connection, const gchar *sender, const gchar *path,
                           const gchar *interface, const gchar *signal, GVariant *parameters,
                           gpointer user_data) {
    (void)connection; (void)sender; (void)path; (void)interface; (void)parameters; (void)user_data;
    if (g_str_equal(signal, "QueryEndSession")) end_session_response();
    else if (g_str_equal(signal, "EndSession")) {
        exiting = TRUE;
        submit_event("logout", NULL, 0, TRUE, TRUE);
    } else if (g_str_equal(signal, "Stop")) terminate_agent(NULL);
}

int main(int argc, char **argv) {
    GError *error = NULL;
    GVariant *reply;
    GList *mounts;
    (void)argc; (void)argv;
    system_bus = g_bus_get_sync(G_BUS_TYPE_SYSTEM, NULL, &error);
    if (!system_bus) { g_printerr("OctoVault: %s\n", error->message); g_error_free(error); return 1; }
    session_bus = g_bus_get_sync(G_BUS_TYPE_SESSION, NULL, &error);
    if (!session_bus) { g_printerr("OctoVault: %s\n", error->message); g_error_free(error); g_object_unref(system_bus); return 1; }
    /* One agent per desktop user, including when launched again from a terminal. */
    reply = g_dbus_connection_call_sync(session_bus, "org.freedesktop.DBus", "/org/freedesktop/DBus",
        "org.freedesktop.DBus", "RequestName", g_variant_new("(su)", "io.vdm.OctoVault.Session", 4u),
        G_VARIANT_TYPE("(u)"), G_DBUS_CALL_FLAGS_NONE, 3000, NULL, &error);
    if (!reply) { g_printerr("OctoVault: %s\n", error->message); g_error_free(error); return 1; }
    guint name_result; g_variant_get(reply, "(u)", &name_result); g_variant_unref(reply);
    if (name_result != 1) return 0;
    loop = g_main_loop_new(NULL, FALSE);
    pending_unlock_ids = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, NULL);
    g_dbus_connection_signal_subscribe(system_bus, "org.freedesktop.login1", "org.freedesktop.DBus.Properties",
        "PropertiesChanged", NULL, "org.freedesktop.login1.Session", G_DBUS_SIGNAL_FLAGS_NONE,
        logind_properties_changed, NULL, NULL);
    g_dbus_connection_signal_subscribe(system_bus, "org.freedesktop.login1", "org.freedesktop.login1.Manager",
        "PrepareForSleep", "/org/freedesktop/login1", NULL, G_DBUS_SIGNAL_FLAGS_NONE, login_signal, NULL, NULL);
    g_dbus_connection_signal_subscribe(system_bus, "org.freedesktop.login1", "org.freedesktop.login1.Manager",
        "PrepareForShutdown", "/org/freedesktop/login1", NULL, G_DBUS_SIGNAL_FLAGS_NONE, login_signal, NULL, NULL);
    g_dbus_connection_signal_subscribe(session_bus, "org.gnome.ScreenSaver", "org.gnome.ScreenSaver",
        "ActiveChanged", "/org/gnome/ScreenSaver", NULL, G_DBUS_SIGNAL_FLAGS_NONE, lock_signal, NULL, NULL);
    reply = g_dbus_connection_call_sync(session_bus, "org.gnome.SessionManager", "/org/gnome/SessionManager",
        "org.gnome.SessionManager", "RegisterClient", g_variant_new("(ss)", "io.vdm.OctoVault.Session", ""),
        G_VARIANT_TYPE("(o)"), G_DBUS_CALL_FLAGS_NONE, 3000, NULL, NULL);
    if (reply) {
        g_variant_get(reply, "(o)", &session_client); g_variant_unref(reply);
        g_dbus_connection_signal_subscribe(session_bus, "org.gnome.SessionManager", "org.gnome.SessionManager.ClientPrivate",
            NULL, session_client, NULL, G_DBUS_SIGNAL_FLAGS_NONE, session_signal, NULL, NULL);
    }
    g_unix_signal_add(SIGTERM, terminate_agent, NULL);
    g_unix_signal_add(SIGINT, terminate_agent, NULL);
    acquire_inhibitor();
    volumes = g_volume_monitor_get();
    g_signal_connect(volumes, "mount-added", G_CALLBACK(mount_added), NULL);
    refresh_session_state(NULL);
    g_timeout_add_seconds(5, refresh_session_state, NULL);
    mounts = g_volume_monitor_get_mounts(volumes);
    for (GList *item = mounts; item; item = item->next) mount_added(volumes, G_MOUNT(item->data), NULL);
    g_list_free_full(mounts, g_object_unref);
    idle_tick(NULL); card_tick(NULL);
    g_timeout_add_seconds(30, idle_tick, NULL);
    g_timeout_add_seconds(15, card_tick, NULL);
    g_main_loop_run(loop);
    release_inhibitor();
    g_free(card_identity); g_free(session_client); g_free(login_session_path);
    g_hash_table_unref(pending_unlock_ids);
    g_object_unref(volumes); g_object_unref(session_bus); g_object_unref(system_bus);
    g_main_loop_unref(loop);
    return 0;
}
