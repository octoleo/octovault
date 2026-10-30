/* SPDX-License-Identifier: Apache-2.0
 * Native regression coverage for the actual form buttons and file choosers.
 * No application activation, privileged service, or backup operation is run.
 */
#define main octovault_gui_program_main
#include "main.c"
#undef main

/* OctoVault deliberately uses the in-process standard GTK chooser: the desktop
 * portal cannot inspect /proc/PID/root while secret-memory hardening is active. */
G_GNUC_BEGIN_IGNORE_DEPRECATIONS

#define WAIT_FOR(condition) do { \
    gint64 deadline = g_get_monotonic_time() + 8 * G_TIME_SPAN_SECOND; \
    while (!(condition) && g_get_monotonic_time() < deadline) { \
        while (g_main_context_iteration(NULL, FALSE)) {} \
        g_usleep(1000); \
    } \
    g_assert_true(condition); \
} while (0)

typedef struct {
    App app;
    GtkWindow *window;
    Form *form;
    char *directory, *folder_a, *folder_b, *file_a, *file_b, *private_key;
} Fixture;

static void fixture_init(Fixture *f, gconstpointer unused)
{
    (void)unused;
    GError *error = NULL;
    f->directory = g_dir_make_tmp("octovault-picker-XXXXXX", &error);
    g_assert_no_error(error);
    f->folder_a = g_build_filename(f->directory, "Folder one", NULL);
    f->folder_b = g_build_filename(f->directory, "Folder two", NULL);
    f->file_a = g_build_filename(f->directory, "First file.txt", NULL);
    f->file_b = g_build_filename(f->directory, "Second file.txt", NULL);
    f->private_key = g_build_filename(f->directory, "test-only-key", NULL);
    g_assert_cmpint(g_mkdir(f->folder_a, 0700), ==, 0);
    g_assert_cmpint(g_mkdir(f->folder_b, 0700), ==, 0);
    g_assert_true(g_file_set_contents(f->file_a, "fixture one\n", -1, &error));
    g_assert_no_error(error);
    g_assert_true(g_file_set_contents(f->file_b, "fixture two\n", -1, &error));
    g_assert_no_error(error);
    g_assert_true(g_file_set_contents(f->private_key, "TEST KEY\nnot a real credential\n", -1, &error));
    g_assert_no_error(error);
    f->app.smoke = TRUE;
    f->app.window = GTK_WINDOW(gtk_window_new());
    g_object_ref(f->app.window);
    gtk_window_set_default_size(f->app.window, 640, 480);
    gtk_window_present(f->app.window);
    WAIT_FOR(gtk_widget_get_mapped(GTK_WIDGET(f->app.window)));
}

static void fixture_clear(Fixture *f, gconstpointer unused)
{
    (void)unused;
    if (f->window) {
        gtk_window_destroy(f->window);
        g_object_unref(f->window);
    }
    gtk_window_destroy(f->app.window);
    g_object_unref(f->app.window);
    while (g_main_context_iteration(NULL, FALSE)) {}
    g_assert_cmpint(g_unlink(f->file_a), ==, 0);
    g_assert_cmpint(g_unlink(f->file_b), ==, 0);
    g_assert_cmpint(g_unlink(f->private_key), ==, 0);
    g_assert_cmpint(g_rmdir(f->folder_a), ==, 0);
    g_assert_cmpint(g_rmdir(f->folder_b), ==, 0);
    g_assert_cmpint(g_rmdir(f->directory), ==, 0);
    g_free(f->directory);
    g_free(f->folder_a);
    g_free(f->folder_b);
    g_free(f->file_a);
    g_free(f->file_b);
    g_free(f->private_key);
}

static void show_form(Fixture *f, const char *operation, JsonObject *record)
{
    open_form(&f->app, operation, "File navigation regression", record);
    GListModel *windows = gtk_window_get_toplevels();
    for (guint i = 0; i < g_list_model_get_n_items(windows); i++) {
        GtkWindow *window = g_list_model_get_item(windows, i);
        Form *form = g_object_get_data(G_OBJECT(window), "form");
        if (form && form->app == &f->app) {
            f->window = window;
            f->form = form;
            break;
        }
        g_object_unref(window);
    }
    g_assert_nonnull(f->window);
    WAIT_FOR(gtk_widget_get_mapped(GTK_WIDGET(f->window)));
}

static GtkWidget *find_button(GtkWidget *parent, const char *description)
{
    if (GTK_IS_BUTTON(parent) &&
        (!g_strcmp0(gtk_button_get_label(GTK_BUTTON(parent)), description) ||
         !g_strcmp0(gtk_widget_get_tooltip_text(parent), description))) return parent;
    for (GtkWidget *child = gtk_widget_get_first_child(parent); child;
         child = gtk_widget_get_next_sibling(child)) {
        GtkWidget *button = find_button(child, description);
        if (button) return button;
    }
    return NULL;
}

static GtkDialog *click_picker(Fixture *f, Field *field, const char *description,
                              GtkFileChooserAction action, gboolean multiple)
{
    GtkWidget *button = find_button(field->row, description);
    g_assert_nonnull(button);
    g_assert_true(gtk_widget_is_visible(button));
    g_assert_true(gtk_widget_is_sensitive(button));
    /* Emit the real button's signal, rather than calling the picker helper. */
    g_signal_emit_by_name(button, "clicked");
    GtkDialog *dialog = NULL;
    gint64 deadline = g_get_monotonic_time() + 8 * G_TIME_SPAN_SECOND;
    while (!dialog && g_get_monotonic_time() < deadline) {
        while (g_main_context_iteration(NULL, FALSE)) {}
        GListModel *windows = gtk_window_get_toplevels();
        for (guint i = 0; i < g_list_model_get_n_items(windows); i++) {
            GtkWindow *candidate = g_list_model_get_item(windows, i);
            if (GTK_IS_FILE_CHOOSER(candidate) && gtk_widget_get_mapped(GTK_WIDGET(candidate)) &&
                gtk_window_get_transient_for(candidate) == f->window) {
                dialog = GTK_DIALOG(candidate);
                break;
            }
            g_object_unref(candidate);
        }
        if (!dialog) g_usleep(1000);
    }
    g_assert_nonnull(dialog);
    g_assert_true(gtk_window_get_modal(GTK_WINDOW(dialog)));
    g_assert_cmpint(gtk_file_chooser_get_action(GTK_FILE_CHOOSER(dialog)), ==, action);
    g_assert_cmpint(gtk_file_chooser_get_select_multiple(GTK_FILE_CHOOSER(dialog)), ==, multiple);
    /* The security property that exposed the original bug must stay enabled. */
    g_assert_cmpint(prctl(PR_GET_DUMPABLE, 0, 0, 0, 0), ==, 0);
    return dialog;
}

static gboolean selected_path(GtkDialog *dialog, const char *path)
{
    GFile *file = gtk_file_chooser_get_file(GTK_FILE_CHOOSER(dialog));
    char *selected = file ? g_file_get_path(file) : NULL;
    gboolean same = !g_strcmp0(selected, path);
    g_free(selected);
    g_clear_object(&file);
    return same;
}

static void select_path(GtkDialog *dialog, const char *path)
{
    GFile *file = g_file_new_for_path(path);
    GError *error = NULL;
    g_assert_true(gtk_file_chooser_set_file(GTK_FILE_CHOOSER(dialog), file, &error));
    g_assert_no_error(error);
    g_object_unref(file);
    WAIT_FOR(selected_path(dialog, path));
}

static void respond(GtkDialog *dialog, gint response)
{
    gtk_dialog_response(dialog, response);
    WAIT_FOR(!gtk_widget_get_mapped(GTK_WIDGET(dialog)));
    g_object_unref(dialog);
}

static void assert_field(Field *field, const char *expected)
{
    char *actual = field_text(field);
    g_assert_cmpstr(actual, ==, expected);
    g_free(actual);
}

static void screenshot_picker(GtkDialog *dialog)
{
    const char *path = g_getenv("OCTOVAULT_PICKER_SCREENSHOT");
    if (!path || !*path) return;
    GtkWidget *widget = GTK_WIDGET(dialog);
    GskRenderNode *node = NULL;
    GdkPaintable *paintable = gtk_widget_paintable_new(widget);
    gint64 deadline = g_get_monotonic_time() + 3 * G_TIME_SPAN_SECOND;
    while (!node && g_get_monotonic_time() < deadline) {
        while (g_main_context_iteration(NULL, FALSE)) {}
        int width = gtk_widget_get_width(widget), height = gtk_widget_get_height(widget);
        GtkSnapshot *snapshot = gtk_snapshot_new();
        gdk_paintable_snapshot(paintable, GDK_SNAPSHOT(snapshot), width, height);
        node = gtk_snapshot_free_to_node(snapshot);
        if (!node) g_usleep(1000);
    }
    g_assert_nonnull(node);
    GskRenderer *renderer = gtk_native_get_renderer(GTK_NATIVE(dialog));
    graphene_rect_t bounds = GRAPHENE_RECT_INIT(0, 0, gtk_widget_get_width(widget), gtk_widget_get_height(widget));
    GdkTexture *texture = gsk_renderer_render_texture(renderer, node, &bounds);
    g_assert_true(gdk_texture_save_to_png(texture, path));
    g_object_unref(texture);
    gsk_render_node_unref(node);
    g_object_unref(paintable);
}

static void test_vault_directory(Fixture *f, gconstpointer unused)
{
    (void)unused;
    show_form(f, "vault.create", NULL);
    Field *field = find_field(f->form, "directory");
    gtk_editable_set_text(GTK_EDITABLE(field->widget), f->directory);
    GtkDialog *dialog = click_picker(f, field, "Choose a folder", GTK_FILE_CHOOSER_ACTION_SELECT_FOLDER, FALSE);
    select_path(dialog, f->folder_a);
    screenshot_picker(dialog);
    /* A double-click should present the existing chooser, not stack dialogs. */
    GtkWidget *button = find_button(field->row, "Choose a folder");
    g_signal_emit_by_name(button, "clicked");
    g_assert_true(g_object_get_data(G_OBJECT(button), "octovault-file-chooser") == dialog);
    respond(dialog, GTK_RESPONSE_ACCEPT);
    g_assert_null(g_object_get_data(G_OBJECT(button), "octovault-file-chooser"));
    assert_field(field, f->folder_a);
    /* Reopening and cancelling must preserve the previous selection. */
    for (guint i = 0; i < 3; i++) {
        dialog = click_picker(f, field, "Choose a folder", GTK_FILE_CHOOSER_ACTION_SELECT_FOLDER, FALSE);
        select_path(dialog, f->folder_b);
        respond(dialog, GTK_RESPONSE_CANCEL);
        assert_field(field, f->folder_a);
    }
}

typedef struct { const char *operation, *key, *description; GtkFileChooserAction action; } PickCase;
static void test_single_paths(Fixture *f, gconstpointer data)
{
    const PickCase *test = data;
    show_form(f, test->operation, NULL);
    Field *field = find_field(f->form, test->key);
    g_assert_nonnull(field);
    GtkDialog *dialog = click_picker(f, field, test->description, test->action, FALSE);
    const char *path = test->action == GTK_FILE_CHOOSER_ACTION_SELECT_FOLDER ? f->folder_a : f->file_a;
    select_path(dialog, path);
    respond(dialog, GTK_RESPONSE_ACCEPT);
    assert_field(field, path);
}

static void test_save_path(Fixture *f, gconstpointer unused)
{
    (void)unused;
    show_form(f, "vault.key-export", NULL);
    Field *field = find_field(f->form, "output");
    GtkDialog *dialog = click_picker(f, field, "Choose a file", GTK_FILE_CHOOSER_ACTION_SAVE, FALSE);
    GFile *directory = g_file_new_for_path(f->directory);
    GError *error = NULL;
    g_assert_true(gtk_file_chooser_set_current_folder(GTK_FILE_CHOOSER(dialog), directory, &error));
    g_assert_no_error(error);
    g_object_unref(directory);
    gtk_file_chooser_set_current_name(GTK_FILE_CHOOSER(dialog), "Exported key.key");
    char *path = g_build_filename(f->directory, "Exported key.key", NULL);
    WAIT_FOR(selected_path(dialog, path));
    respond(dialog, GTK_RESPONSE_ACCEPT);
    assert_field(field, path);
    /* Choosing an output location must not itself create or truncate a file. */
    g_assert_false(g_file_test(path, G_FILE_TEST_EXISTS));
    g_free(path);
}

/* Drive the native chooser's displayed file-list selection model. GTK 4 no
 * longer exposes a public select-file/add-to-selection chooser method. This
 * uses public GtkColumnView/GtkSelectionModel APIs, not a fake result callback. */
static GtkSelectionModel *find_file_model(GtkWidget *parent, const char *name)
{
    if (GTK_IS_COLUMN_VIEW(parent)) {
        GtkSelectionModel *model = gtk_column_view_get_model(GTK_COLUMN_VIEW(parent));
        if (model) for (guint i = 0; i < g_list_model_get_n_items(G_LIST_MODEL(model)); i++) {
            GObject *item = g_list_model_get_item(G_LIST_MODEL(model), i);
            gboolean match = G_IS_FILE_INFO(item) && !g_strcmp0(g_file_info_get_name(G_FILE_INFO(item)), name);
            g_object_unref(item);
            if (match) return model;
        }
    }
    for (GtkWidget *child = gtk_widget_get_first_child(parent); child; child = gtk_widget_get_next_sibling(child)) {
        GtkSelectionModel *model = find_file_model(child, name);
        if (model) return model;
    }
    return NULL;
}

static void select_pair(GtkDialog *dialog, const char *directory, const char *first, const char *second)
{
    GFile *folder = g_file_new_for_path(directory);
    GError *error = NULL;
    g_assert_true(gtk_file_chooser_set_current_folder(GTK_FILE_CHOOSER(dialog), folder, &error));
    g_assert_no_error(error);
    g_object_unref(folder);
    char *one = g_path_get_basename(first), *two = g_path_get_basename(second);
    GtkSelectionModel *model = NULL;
    WAIT_FOR((model = find_file_model(GTK_WIDGET(dialog), one)) != NULL);
    WAIT_FOR(find_file_model(GTK_WIDGET(dialog), two) != NULL);
    g_assert_true(gtk_selection_model_unselect_all(model));
    guint selected = 0;
    for (guint i = 0; i < g_list_model_get_n_items(G_LIST_MODEL(model)); i++) {
        GFileInfo *info = g_list_model_get_item(G_LIST_MODEL(model), i);
        const char *name = g_file_info_get_name(info);
        if (!g_strcmp0(name, one) || !g_strcmp0(name, two)) {
            g_assert_true(gtk_selection_model_select_item(model, i, FALSE));
            selected++;
        }
        g_object_unref(info);
    }
    g_assert_cmpuint(selected, ==, 2);
    GListModel *files = gtk_file_chooser_get_files(GTK_FILE_CHOOSER(dialog));
    g_assert_cmpuint(g_list_model_get_n_items(files), ==, 2);
    g_object_unref(files);
    g_free(one);
    g_free(two);
}

static void test_backup_multiple(Fixture *f, gconstpointer unused)
{
    (void)unused;
    show_form(f, "backup.save", NULL);
    Field *field = find_field(f->form, "sources");
    GtkDialog *dialog = click_picker(f, field, "Add files…", GTK_FILE_CHOOSER_ACTION_OPEN, TRUE);
    select_pair(dialog, f->directory, f->file_a, f->file_b);
    respond(dialog, GTK_RESPONSE_ACCEPT);
    dialog = click_picker(f, field, "Add folders…", GTK_FILE_CHOOSER_ACTION_SELECT_FOLDER, TRUE);
    select_pair(dialog, f->directory, f->folder_a, f->folder_b);
    respond(dialog, GTK_RESPONSE_ACCEPT);
    /* Select the files again: values must append without dropping folders or
     * introducing duplicate entries. Order follows the native chooser. */
    dialog = click_picker(f, field, "Add files…", GTK_FILE_CHOOSER_ACTION_OPEN, TRUE);
    select_pair(dialog, f->directory, f->file_a, f->file_b);
    respond(dialog, GTK_RESPONSE_ACCEPT);
    char *text = field_text(field);
    char **lines = g_strsplit(text, "\n", -1);
    g_assert_cmpuint(g_strv_length(lines), ==, 4);
    g_assert_true(g_strv_contains((const char *const *)lines, f->file_a));
    g_assert_true(g_strv_contains((const char *const *)lines, f->file_b));
    g_assert_true(g_strv_contains((const char *const *)lines, f->folder_a));
    g_assert_true(g_strv_contains((const char *const *)lines, f->folder_b));
    g_strfreev(lines);
    g_free(text);
}

static void test_secret_file(Fixture *f, gconstpointer unused)
{
    (void)unused;
    JsonObject *record = json_object_new();
    json_object_set_string_member(record, "type", "sftp");
    show_form(f, "destination.save", record);
    json_object_unref(record);
    Field *field = find_field(f->form, "ssh_private_key");
    GtkDialog *dialog = click_picker(f, field, "Load private key…", GTK_FILE_CHOOSER_ACTION_OPEN, FALSE);
    select_path(dialog, f->private_key);
    respond(dialog, GTK_RESPONSE_ACCEPT);
    assert_field(field, "TEST KEY\nnot a real credential\n");
    dialog = click_picker(f, field, "Load private key…", GTK_FILE_CHOOSER_ACTION_OPEN, FALSE);
    select_path(dialog, f->file_a);
    respond(dialog, GTK_RESPONSE_CANCEL);
    assert_field(field, "TEST KEY\nnot a real credential\n");
}

static void test_image_filter(Fixture *f, gconstpointer unused)
{
    (void)unused;
    JsonObject *record = json_object_new();
    json_object_set_string_member(record, "auth", "image");
    show_form(f, "vault.create", record);
    json_object_unref(record);
    Field *field = find_field(f->form, "image_source");
    GtkDialog *dialog = click_picker(f, field, "Choose a file", GTK_FILE_CHOOSER_ACTION_OPEN, FALSE);
    GtkFileFilter *filter = gtk_file_chooser_get_filter(GTK_FILE_CHOOSER(dialog));
    g_assert_nonnull(filter);
    g_assert_cmpstr(gtk_file_filter_get_name(filter), ==, "JPEG or BMP images");
    respond(dialog, GTK_RESPONSE_CANCEL);
    assert_field(field, "");
}

static void test_parent_close(Fixture *f, gconstpointer unused)
{
    (void)unused;
    show_form(f, "vault.create", NULL);
    Field *field = find_field(f->form, "directory");
    GtkDialog *dialog = click_picker(f, field, "Choose a folder", GTK_FILE_CHOOSER_ACTION_SELECT_FOLDER, FALSE);
    gpointer weak_dialog = dialog;
    g_object_add_weak_pointer(G_OBJECT(dialog), &weak_dialog);
    gtk_window_destroy(f->window);
    g_object_unref(f->window);
    f->window = NULL;
    f->form = NULL;
    WAIT_FOR(!gtk_widget_get_mapped(GTK_WIDGET(dialog)));
    g_assert_null(gtk_window_get_transient_for(GTK_WINDOW(dialog)));
    g_object_unref(dialog);
    WAIT_FOR(weak_dialog == NULL);
}

G_GNUC_END_IGNORE_DEPRECATIONS

int main(int argc, char **argv)
{
    const struct rlimit core_limit = {0, 0};
    g_assert_cmpint(setrlimit(RLIMIT_CORE, &core_limit), ==, 0);
    g_assert_cmpint(prctl(PR_SET_DUMPABLE, 0, 0, 0, 0), ==, 0);
    g_test_init(&argc, &argv, NULL);
    /* A minimal CI desktop may report unavailable portal settings services.
     * Log those warnings; assertion failures and GTK criticals still fail. */
    g_log_set_always_fatal(G_LOG_LEVEL_ERROR | G_LOG_LEVEL_CRITICAL);
    gtk_init();
    adw_init();
    static const PickCase cases[] = {
        {"vault.import", "file", "Choose a file", GTK_FILE_CHOOSER_ACTION_OPEN},
        {"vault.import", "key_file", "Choose a file", GTK_FILE_CHOOSER_ACTION_OPEN},
        {"migration.add", "source", "Choose a file", GTK_FILE_CHOOSER_ACTION_OPEN},
        {"migration.add", "source", "Choose a folder", GTK_FILE_CHOOSER_ACTION_SELECT_FOLDER},
        {"destination.save", "path", "Choose a backup folder", GTK_FILE_CHOOSER_ACTION_SELECT_FOLDER},
        {"repository.restore", "target", "Choose a folder", GTK_FILE_CHOOSER_ACTION_SELECT_FOLDER},
    };
    g_test_add("/picker/vault-directory", Fixture, NULL, fixture_init, test_vault_directory, fixture_clear);
    for (guint i = 0; i < G_N_ELEMENTS(cases); i++) {
        char *name = g_strdup_printf("/picker/fields/%u-%s-%s", i, cases[i].operation, cases[i].key);
        g_test_add(name, Fixture, &cases[i], fixture_init, test_single_paths, fixture_clear);
        g_free(name);
    }
    g_test_add("/picker/save-output", Fixture, NULL, fixture_init, test_save_path, fixture_clear);
    g_test_add("/picker/backup-multiple", Fixture, NULL, fixture_init, test_backup_multiple, fixture_clear);
    g_test_add("/picker/secret-file", Fixture, NULL, fixture_init, test_secret_file, fixture_clear);
    g_test_add("/picker/image-filter", Fixture, NULL, fixture_init, test_image_filter, fixture_clear);
    g_test_add("/picker/parent-close", Fixture, NULL, fixture_init, test_parent_close, fixture_clear);
    return g_test_run();
}
