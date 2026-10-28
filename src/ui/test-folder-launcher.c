/* SPDX-License-Identifier: Apache-2.0
 * Exercise real desktop handoff calls over a private peer D-Bus connection.
 * Only session-bus acquisition is replaced; message encoding, delivery,
 * dispatch, replies and application launching use the actual GLib APIs. A
 * socketpair also works in build sandboxes that prohibit listening sockets.
 * No display, actual file manager, vault service or privileged action is used.
 */
#include <gio/gdesktopappinfo.h>
#include <glib/gstdio.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/socket.h>

static GDBusConnection *test_bus;

static void test_session_bus_get(GBusType type, GCancellable *cancellable,
                                 GAsyncReadyCallback callback, gpointer data) {
  g_assert_cmpint(type, ==, G_BUS_TYPE_SESSION);
  GTask *task = g_task_new(NULL, cancellable, callback, data);
  g_task_return_pointer(task, g_object_ref(test_bus), g_object_unref);
  g_object_unref(task);
}

static GDBusConnection *test_session_bus_get_finish(GAsyncResult *result, GError **error) {
  return g_task_propagate_pointer(G_TASK(result), error);
}

#define g_bus_get test_session_bus_get
#define g_bus_get_finish test_session_bus_get_finish
#include "folder-launcher.c"
#undef g_bus_get
#undef g_bus_get_finish

typedef struct {
  gboolean done, success;
  GError *error;
} Result;

static GDBusNodeInfo *manager_info;
static guint registration, calls;
static gboolean reject_open;
static char *last_uri, *workspace, *directory, *launched, *desktop_path;

static void opened(GObject *source, GAsyncResult *result, gpointer data) {
  (void)source;
  Result *state = data;
  state->success = g_task_propagate_boolean(G_TASK(result), &state->error);
  state->done = TRUE;
}

static void wait_result(Result *result) {
  gint64 deadline = g_get_monotonic_time() + 15 * G_TIME_SPAN_SECOND;
  while (!result->done && g_get_monotonic_time() < deadline) {
    while (g_main_context_iteration(NULL, FALSE)) {}
    g_usleep(1000);
  }
  g_assert_true(result->done);
  g_assert_cmpint(prctl(PR_GET_DUMPABLE, 0, 0, 0, 0), ==, 0);
}

static void manager_method(GDBusConnection *connection, const char *sender,
                           const char *path, const char *interface, const char *method,
                           GVariant *parameters, GDBusMethodInvocation *invocation,
                           gpointer data) {
  (void)connection; (void)sender; (void)path; (void)interface; (void)data;
  g_assert_cmpstr(method, ==, "ShowFolders");
  calls++;
  char **uris;
  const char *startup;
  g_variant_get(parameters, "(^as&s)", &uris, &startup);
  g_assert_cmpuint(g_strv_length(uris), ==, 1);
  g_assert_cmpstr(startup, ==, "");
  g_free(last_uri);
  last_uri = g_strdup(uris[0]);
  g_strfreev(uris);
  if (reject_open)
    g_dbus_method_invocation_return_dbus_error(invocation,
        "org.freedesktop.DBus.Error.NotSupported", "This desktop has no ShowFolders implementation");
  else
    g_dbus_method_invocation_return_value(invocation, g_variant_new("()"));
}

static const GDBusInterfaceVTable manager_vtable = { .method_call = manager_method };

typedef struct {
  GIOStream *stream;
  char *guid;
  GDBusConnection *connection;
  GError *error;
} ServerSetup;

static gpointer server_connect(gpointer data) {
  ServerSetup *setup = data;
  setup->connection = g_dbus_connection_new_sync(setup->stream, setup->guid,
      G_DBUS_CONNECTION_FLAGS_AUTHENTICATION_SERVER | G_DBUS_CONNECTION_FLAGS_AUTHENTICATION_ALLOW_ANONYMOUS,
      NULL, NULL, &setup->error);
  return NULL;
}

static GDBusConnection *create_bus_pair(void) {
  GError *error = NULL;
  int sockets[2];
  g_assert_cmpint(socketpair(AF_UNIX, SOCK_STREAM, 0, sockets), ==, 0);
  GSocket *client_socket = g_socket_new_from_fd(sockets[0], &error);
  g_assert_no_error(error);
  GSocket *server_socket = g_socket_new_from_fd(sockets[1], &error);
  g_assert_no_error(error);
  GSocketConnection *client_stream = g_socket_connection_factory_create_connection(client_socket);
  GSocketConnection *server_stream = g_socket_connection_factory_create_connection(server_socket);
  g_object_unref(client_socket);
  g_object_unref(server_socket);
  ServerSetup setup = { .stream = G_IO_STREAM(server_stream), .guid = g_dbus_generate_guid() };
  GThread *thread = g_thread_new("test-file-manager", server_connect, &setup);
  test_bus = g_dbus_connection_new_sync(G_IO_STREAM(client_stream), NULL,
      G_DBUS_CONNECTION_FLAGS_AUTHENTICATION_CLIENT, NULL, NULL, &error);
  g_assert_no_error(error);
  g_assert_nonnull(test_bus);
  g_thread_join(thread);
  g_assert_no_error(setup.error);
  g_assert_nonnull(setup.connection);
  g_object_unref(client_stream);
  g_object_unref(server_stream);
  g_free(setup.guid);
  return setup.connection;
}

static void test_direct(void) {
  reject_open = FALSE;
  guint previous = calls;
  Result result = {0};
  octovault_open_folder_async(directory, NULL, opened, &result);
  wait_result(&result);
  g_assert_no_error(result.error);
  g_assert_true(result.success);
  g_assert_cmpuint(calls, ==, previous + 1);
  char *expected = g_filename_to_uri(directory, NULL, NULL);
  g_assert_cmpstr(last_uri, ==, expected);
  g_assert_nonnull(strstr(last_uri, "%23"));
  g_assert_nonnull(strstr(last_uri, "%20"));
  g_free(expected);
  g_assert_false(g_file_test(launched, G_FILE_TEST_EXISTS));
}

static void test_invalid_and_cancelled(void) {
  guint previous = calls;
  const char *invalid[] = { NULL, "relative/folder", "/octovault-test-nonexistent-folder", NULL };
  for (guint i = 0; i < 3; i++) {
    Result result = {0};
    octovault_open_folder_async(invalid[i], NULL, opened, &result);
    wait_result(&result);
    g_assert_false(result.success);
    g_assert_error(result.error, G_IO_ERROR, G_IO_ERROR_NOT_DIRECTORY);
    g_clear_error(&result.error);
  }
  GCancellable *cancellable = g_cancellable_new();
  g_cancellable_cancel(cancellable);
  Result result = {0};
  octovault_open_folder_async(directory, cancellable, opened, &result);
  wait_result(&result);
  g_assert_false(result.success);
  g_assert_error(result.error, G_IO_ERROR, G_IO_ERROR_CANCELLED);
  g_clear_error(&result.error);
  g_object_unref(cancellable);
  g_assert_cmpuint(calls, ==, previous);
}

static void test_no_file_manager(void) {
  reject_open = TRUE;
  Result result = {0};
  octovault_open_folder_async(directory, NULL, opened, &result);
  wait_result(&result);
  g_assert_false(result.success);
  g_assert_error(result.error, G_IO_ERROR, G_IO_ERROR_NOT_FOUND);
  g_assert_nonnull(strstr(result.error->message, "No file manager is available"));
  g_clear_error(&result.error);
}

static void test_directory_handler(void) {
  GError *error = NULL;
  char *executable = g_build_filename(workspace, "file-manager", NULL);
  char *script = g_strdup_printf("#!/bin/sh\nprintf '%%s\\n' \"$@\" > '%s'\n", launched);
  g_assert_true(g_file_set_contents(executable, script, -1, &error));
  g_assert_no_error(error);
  g_assert_cmpint(g_chmod(executable, 0700), ==, 0);
  g_free(script);
  char *contents = g_strdup_printf("[Desktop Entry]\nType=Application\nName=Test directory handler\nExec=%s %%u\nMimeType=inode/directory;\nNoDisplay=true\n", executable);
  g_assert_true(g_file_set_contents(desktop_path, contents, -1, &error));
  g_assert_no_error(error);
  g_free(contents);
  GDesktopAppInfo *handler = g_desktop_app_info_new_from_filename(desktop_path);
  g_assert_nonnull(handler);
  g_assert_true(g_app_info_set_as_default_for_type(G_APP_INFO(handler), "inode/directory", &error));
  g_assert_no_error(error);
  g_object_unref(handler);
  reject_open = TRUE;
  Result result = {0};
  octovault_open_folder_async(directory, NULL, opened, &result);
  wait_result(&result);
  g_assert_no_error(result.error);
  g_assert_true(result.success);
  gint64 deadline = g_get_monotonic_time() + 5 * G_TIME_SPAN_SECOND;
  while (!g_file_test(launched, G_FILE_TEST_EXISTS) && g_get_monotonic_time() < deadline) {
    while (g_main_context_iteration(NULL, FALSE)) {}
    g_usleep(1000);
  }
  char *actual = NULL;
  g_assert_true(g_file_get_contents(launched, &actual, NULL, &error));
  g_assert_no_error(error);
  /* GLib converts local file URIs to paths for a native directory handler. */
  char *expected = g_strconcat(directory, "\n", NULL);
  g_assert_cmpstr(actual, ==, expected);
  g_free(expected);
  g_free(actual);
  g_free(executable);
}

int main(int argc, char **argv) {
  GError *error = NULL;
  workspace = g_dir_make_tmp("octovault-folder-launcher-XXXXXX", &error);
  g_assert_no_error(error);
  char *config = g_build_filename(workspace, "config", NULL);
  char *data = g_build_filename(workspace, "data", NULL);
  char *applications = g_build_filename(data, "applications", NULL);
  g_assert_cmpint(g_mkdir_with_parents(applications, 0700), ==, 0);
  g_assert_cmpint(g_mkdir(config, 0700), ==, 0);
  g_setenv("XDG_CONFIG_HOME", config, TRUE);
  g_setenv("XDG_CONFIG_DIRS", config, TRUE);
  g_setenv("XDG_DATA_HOME", data, TRUE);
  g_setenv("XDG_DATA_DIRS", data, TRUE);
  directory = g_build_filename(workspace, "Vault #1 with spaces", NULL);
  g_assert_cmpint(g_mkdir(directory, 0700), ==, 0);
  launched = g_build_filename(workspace, "launched", NULL);
  desktop_path = g_build_filename(applications, "octovault-test-file-manager.desktop", NULL);
  g_test_init(&argc, &argv, NULL);
  GDBusConnection *server = create_bus_pair();
  manager_info = g_dbus_node_info_new_for_xml("<node><interface name='org.freedesktop.FileManager1'><method name='ShowFolders'><arg type='as' direction='in'/><arg type='s' direction='in'/></method></interface></node>", &error);
  g_assert_no_error(error);
  registration = g_dbus_connection_register_object(server, "/org/freedesktop/FileManager1",
      manager_info->interfaces[0], &manager_vtable, NULL, NULL, &error);
  g_assert_no_error(error);
  g_assert_cmpuint(registration, >, 0);
  g_assert_cmpint(prctl(PR_SET_DUMPABLE, 0, 0, 0, 0), ==, 0);
  g_test_add_func("/folder-launcher/01-direct-nondumpable", test_direct);
  g_test_add_func("/folder-launcher/02-invalid-cancelled", test_invalid_and_cancelled);
  g_test_add_func("/folder-launcher/03-no-file-manager", test_no_file_manager);
  g_test_add_func("/folder-launcher/04-directory-handler", test_directory_handler);
  int status = g_test_run();
  g_dbus_connection_unregister_object(server, registration);
  g_dbus_node_info_unref(manager_info);
  g_dbus_connection_close_sync(test_bus, NULL, NULL);
  g_dbus_connection_close_sync(server, NULL, NULL);
  g_object_unref(server);
  g_clear_object(&test_bus);
  /* test-folder-launcher.sh owns and removes this temporary directory. */
  g_print("Test workspace: %s\n", workspace);
  g_free(last_uri);
  g_free(workspace);
  g_free(directory);
  g_free(launched);
  g_free(desktop_path);
  g_free(applications);
  g_free(config);
  g_free(data);
  return status;
}
