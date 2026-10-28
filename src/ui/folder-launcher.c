/* SPDX-License-Identifier: Apache-2.0
 * Included by main.c and the standalone folder-launcher regression test.
 *
 * This process holds secrets and is deliberately non-dumpable. The OpenURI
 * portal used by GtkFileLauncher cannot inspect /proc/PID/root in that state.
 * Ask the desktop's file manager directly, keeping the GUI's memory protected.
 * Desktops without FileManager1 use their registered directory application.
 */
#include <gio/gio.h>

typedef struct {
  char *uri;
  GAppInfo *handler;
} FolderLaunch;

static void folder_launch_free(gpointer data) {
  FolderLaunch *launch = data;
  g_free(launch->uri);
  g_clear_object(&launch->handler);
  g_free(launch);
}

static void folder_default_opened(GObject *source, GAsyncResult *result, gpointer data) {
  GTask *task = data;
  GError *error = NULL;
  if (g_app_info_launch_uris_finish(G_APP_INFO(source), result, &error))
    g_task_return_boolean(task, TRUE);
  else
    g_task_return_error(task, error);
  g_object_unref(task);
}

static void folder_launch_default(GTask *task) {
  FolderLaunch *launch = g_task_get_task_data(task);
  if (g_task_return_error_if_cancelled(task)) {
    g_object_unref(task);
    return;
  }
  launch->handler = g_app_info_get_default_for_type("inode/directory", FALSE);
  if (!launch->handler) {
    g_task_return_new_error(task, G_IO_ERROR, G_IO_ERROR_NOT_FOUND,
        "No file manager is available. Install a file manager and set it as the default application for folders.");
    g_object_unref(task);
    return;
  }
  /* Launch the known directory handler, rather than launch_default_for_uri:
   * the latter can select the same OpenURI portal that failed originally. */
  GList uris = { .data = launch->uri };
  g_app_info_launch_uris_async(launch->handler, &uris, NULL,
      g_task_get_cancellable(task), folder_default_opened, task);
}

static void folder_manager_opened(GObject *source, GAsyncResult *result, gpointer data) {
  GTask *task = data;
  GError *error = NULL;
  GVariant *reply = g_dbus_connection_call_finish(G_DBUS_CONNECTION(source), result, &error);
  if (reply) {
    g_variant_unref(reply);
    g_task_return_boolean(task, TRUE);
    g_object_unref(task);
  } else {
    g_clear_error(&error);
    folder_launch_default(task);
  }
}

static void folder_session_bus_ready(GObject *source, GAsyncResult *result, gpointer data) {
  (void)source;
  GTask *task = data;
  GError *error = NULL;
  GDBusConnection *bus = g_bus_get_finish(result, &error);
  if (!bus) {
    g_clear_error(&error);
    folder_launch_default(task);
    return;
  }
  FolderLaunch *launch = g_task_get_task_data(task);
  const char *uris[] = { launch->uri, NULL };
  g_dbus_connection_call(bus, "org.freedesktop.FileManager1",
      "/org/freedesktop/FileManager1", "org.freedesktop.FileManager1", "ShowFolders",
      g_variant_new("(^ass)", uris, ""), G_VARIANT_TYPE_UNIT,
      G_DBUS_CALL_FLAGS_NONE, 10000, g_task_get_cancellable(task),
      folder_manager_opened, task);
  g_object_unref(bus);
}

static void octovault_open_folder_async(const char *path, GCancellable *cancellable,
                                       GAsyncReadyCallback callback, gpointer data) {
  GTask *task = g_task_new(NULL, cancellable, callback, data);
  if (g_task_return_error_if_cancelled(task)) {
    g_object_unref(task);
    return;
  }
  if (!path || !g_path_is_absolute(path) || !g_file_test(path, G_FILE_TEST_IS_DIR)) {
    g_task_return_new_error(task, G_IO_ERROR, G_IO_ERROR_NOT_DIRECTORY,
        "The unlocked vault folder is unavailable. Unlock the vault and refresh its status, then try again.");
    g_object_unref(task);
    return;
  }
  GError *error = NULL;
  FolderLaunch *launch = g_new0(FolderLaunch, 1);
  launch->uri = g_filename_to_uri(path, NULL, &error);
  if (!launch->uri) {
    folder_launch_free(launch);
    g_task_return_error(task, error);
    g_object_unref(task);
    return;
  }
  g_task_set_task_data(task, launch, folder_launch_free);
  g_bus_get(G_BUS_TYPE_SESSION, cancellable, folder_session_bus_ready, task);
}
