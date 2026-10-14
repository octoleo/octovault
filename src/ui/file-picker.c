/* SPDX-License-Identifier: Apache-2.0
 * Included by main.c after the form helpers.
 *
 * The GUI handles secrets and deliberately stays non-dumpable. Desktop
 * portals cannot identify such a process through /proc/PID/root. Use GTK's
 * standard in-process chooser instead of GtkFileDialog/Native, which delegate
 * to that portal and can close without ever displaying a navigator.
 *
 * These public GTK4 APIs are deprecated in favour of the portal-capable API,
 * but remain the appropriate in-process implementation for our Debian app.
 * Keep the compatibility surface here; never relax process protection or set
 * global GTK debugging flags just to open a chooser.
 */
G_GNUC_BEGIN_IGNORE_DEPRECATIONS

typedef struct {
  GWeakRef widget, parent, button;
  GtkWindow *dialog;
  gboolean secret;
} Picker;

static void picker_detach(Picker *picker) {
  GObject *button = g_weak_ref_get(&picker->button);
  if (button) {
    if (g_object_get_data(button, "octovault-file-chooser") == picker->dialog)
      g_object_set_data(button, "octovault-file-chooser", NULL);
    g_object_unref(button);
  }
}

static void picker_free(gpointer data) {
  Picker *picker = data;
  picker_detach(picker);
  g_weak_ref_clear(&picker->widget);
  g_weak_ref_clear(&picker->parent);
  g_weak_ref_clear(&picker->button);
  g_free(picker);
}

static void picker_error(GtkWindow *parent, const char *message) {
  GtkAlertDialog *alert = gtk_alert_dialog_new("%s", message);
  gtk_alert_dialog_show(alert, parent);
  g_object_unref(alert);
}

static void picker_apply_files(Picker *picker, GListModel *files) {
  GtkWidget *widget = g_weak_ref_get(&picker->widget);
  GtkWindow *parent = g_weak_ref_get(&picker->parent);
  if (!widget || !parent || !gtk_widget_get_visible(GTK_WIDGET(parent))) goto done;
  for (guint index = 0; index < g_list_model_get_n_items(files); index++) {
    GFile *file = g_list_model_get_item(files, index);
    char *path = g_file_get_path(file);
    if (!path) {
      picker_error(parent, "Choose a local file or mounted drive. Remote document URLs are not supported for this operation.");
    } else if (picker->secret) {
      GError *error = NULL;
      GFileInfo *info = g_file_query_info(file, G_FILE_ATTRIBUTE_STANDARD_TYPE,
          G_FILE_QUERY_INFO_NOFOLLOW_SYMLINKS, NULL, &error);
      GFileInputStream *stream = info && g_file_info_get_file_type(info) == G_FILE_TYPE_REGULAR
          ? g_file_read(file, NULL, &error) : NULL;
      char *contents = g_malloc0(262146);
      gsize size = 0;
      gboolean read_ok = stream && g_input_stream_read_all(G_INPUT_STREAM(stream), contents,
          262145, &size, NULL, &error);
      if (read_ok && size <= 262144 && !memchr(contents, '\0', size) &&
          g_utf8_validate(contents, (gssize)size, NULL))
        gtk_text_buffer_set_text(gtk_text_view_get_buffer(GTK_TEXT_VIEW(widget)), contents, (int)size);
      else
        picker_error(parent, error ? error->message : "Select a regular UTF-8 private-key file no larger than 256 KiB.");
      volatile char *secret = (volatile char *)contents;
      for (gsize i = 0; i < 262146; i++) secret[i] = 0;
      g_free(contents);
      g_clear_object(&stream);
      g_clear_object(&info);
      g_clear_error(&error);
    } else if (GTK_IS_TEXT_VIEW(widget)) {
      if (strchr(path, '\n') || strchr(path, '\r')) {
        picker_error(parent, "Choose a path without a line break in its name.");
      } else {
        GtkTextBuffer *buffer = gtk_text_view_get_buffer(GTK_TEXT_VIEW(widget));
        GtkTextIter start, end;
        gtk_text_buffer_get_bounds(buffer, &start, &end);
        char *current = gtk_text_buffer_get_text(buffer, &start, &end, FALSE);
        char **lines = g_strsplit(current, "\n", -1);
        gboolean duplicate = FALSE;
        for (guint i = 0; lines[i]; i++) if (!strcmp(lines[i], path)) duplicate = TRUE;
        if (!duplicate) {
          if (*current && !g_str_has_suffix(current, "\n")) gtk_text_buffer_insert(buffer, &end, "\n", 1);
          gtk_text_buffer_insert(buffer, &end, path, -1);
        }
        g_strfreev(lines);
        g_free(current);
      }
    } else {
      gtk_editable_set_text(GTK_EDITABLE(widget), path);
    }
    g_free(path);
    g_object_unref(file);
  }
done:
  g_clear_object(&widget);
  g_clear_object(&parent);
}

static void picker_response(GtkDialog *dialog, int response, gpointer data) {
  picker_detach(data);
  if (response == GTK_RESPONSE_ACCEPT) {
    GListModel *files = gtk_file_chooser_get_files(GTK_FILE_CHOOSER(dialog));
    if (files) {
      picker_apply_files(data, files);
      g_object_unref(files);
    }
  }
  gtk_window_destroy(GTK_WINDOW(dialog));
}

static void choose_file(GtkButton *button, gpointer data) {
  GtkWindow *existing = g_object_get_data(G_OBJECT(button), "octovault-file-chooser");
  if (existing) {
    gtk_window_present(existing);
    return;
  }
  Field *field = data;
  const char *kind = field->spec->kind;
  GtkRoot *root = gtk_widget_get_root(GTK_WIDGET(button));
  if (!GTK_IS_WINDOW(root)) return;
  GtkWindow *parent = GTK_WINDOW(root);
  gboolean folder = !strcmp(kind, "folder") ||
      GPOINTER_TO_INT(g_object_get_data(G_OBJECT(button), "choose-folder"));
  gboolean multiple = !strcmp(kind, "paths");
  GtkFileChooserAction action = folder ? GTK_FILE_CHOOSER_ACTION_SELECT_FOLDER :
      !strcmp(kind, "save") ? GTK_FILE_CHOOSER_ACTION_SAVE : GTK_FILE_CHOOSER_ACTION_OPEN;
  const char *title = folder ? (multiple ? "Choose folders" : "Choose a folder") :
      action == GTK_FILE_CHOOSER_ACTION_SAVE ? "Save file" : multiple ? "Choose files" : "Choose a file";
  const char *accept = folder ? "_Select" : action == GTK_FILE_CHOOSER_ACTION_SAVE ? "_Save" : "_Open";
  GtkWidget *dialog = gtk_file_chooser_dialog_new(title, parent, action,
      "_Cancel", GTK_RESPONSE_CANCEL, accept, GTK_RESPONSE_ACCEPT, NULL);
  GtkFileChooser *chooser = GTK_FILE_CHOOSER(dialog);
  gtk_window_set_modal(GTK_WINDOW(dialog), TRUE);
  gtk_window_set_destroy_with_parent(GTK_WINDOW(dialog), TRUE);
  gtk_window_set_default_size(GTK_WINDOW(dialog), 820, 600);
  gtk_dialog_set_default_response(GTK_DIALOG(dialog), GTK_RESPONSE_ACCEPT);
  gtk_file_chooser_set_select_multiple(chooser, multiple);

  Picker *picker = g_new0(Picker, 1);
  picker->dialog = GTK_WINDOW(dialog);
  picker->secret = !strcmp(kind, "secret-file");
  g_weak_ref_init(&picker->widget, field->widget);
  g_weak_ref_init(&picker->parent, parent);
  g_weak_ref_init(&picker->button, button);
  g_object_set_data_full(G_OBJECT(dialog), "octovault-picker", picker, picker_free);
  g_object_set_data(G_OBJECT(button), "octovault-file-chooser", dialog);
  g_signal_connect(dialog, "response", G_CALLBACK(picker_response), picker);

  const char *current = GTK_IS_EDITABLE(field->widget) ? gtk_editable_get_text(GTK_EDITABLE(field->widget)) : "";
  char *initial = *current && g_path_is_absolute(current) ?
      (g_file_test(current, G_FILE_TEST_IS_DIR) ? g_strdup(current) : g_path_get_dirname(current)) :
      g_strdup(g_get_home_dir());
  if (g_file_test(initial, G_FILE_TEST_IS_DIR)) {
    GFile *start = g_file_new_for_path(initial);
    GError *error = NULL;
    if (!gtk_file_chooser_set_current_folder(chooser, start, &error) && error) {
      picker_error(parent, error->message);
      g_clear_error(&error);
    }
    g_object_unref(start);
  }
  g_free(initial);
  if (action == GTK_FILE_CHOOSER_ACTION_SAVE && *current && !g_file_test(current, G_FILE_TEST_IS_DIR)) {
    char *name = g_path_get_basename(current);
    gtk_file_chooser_set_current_name(chooser, name);
    g_free(name);
  }
  if (!strcmp(field->spec->key, "image_source")) {
    GtkFileFilter *filter = gtk_file_filter_new();
    if (g_object_is_floating(filter)) g_object_ref_sink(filter);
    gtk_file_filter_set_name(filter, "JPEG or BMP images");
    gtk_file_filter_add_mime_type(filter, "image/jpeg");
    gtk_file_filter_add_mime_type(filter, "image/bmp");
    const char *patterns[] = { "*.jpg", "*.jpeg", "*.bmp", "*.JPG", "*.JPEG", "*.BMP", NULL };
    for (guint i = 0; patterns[i]; i++) gtk_file_filter_add_pattern(filter, patterns[i]);
    gtk_file_chooser_add_filter(chooser, filter);
    gtk_file_chooser_set_filter(chooser, filter);
    g_object_unref(filter);
  }
  gtk_window_present(GTK_WINDOW(dialog));
}

G_GNUC_END_IGNORE_DEPRECATIONS
