/* Guided backup setup. Included by main.c after the reusable form helpers.
 * Copyright (C) 2026 Vast Development Method. Apache-2.0.
 * This controller remembers only labels and record identifiers. Passwords and
 * connection credentials stay in the existing short-lived form/job handling.
 */
typedef enum {
  BACKUP_SETUP_LOCATION,
  BACKUP_SETUP_DESTINATION,
  BACKUP_SETUP_STORAGE,
  BACKUP_SETUP_RECOVERY,
  BACKUP_SETUP_PLAN,
  BACKUP_SETUP_COMPLETE
} BackupSetupStage;

struct BackupSetup {
  App *app;
  GtkWindow *window;
  GtkWidget *name, *existing, *create, *repositories, *destinations;
  GtkWidget *repository_box, *destination_box, *location_box, *next, *cancel;
  GtkLabel *heading, *description, *status;
  GPtrArray *repository_ids, *destination_ids;
  char *backup_name, *destination_id, *repository_id, *repository_name, *plan_id;
  char *storage_path;
  const char *expected_operation;
  BackupSetupStage stage;
  gboolean waiting, recovery_pending;
};

static void backup_setup_continue(GtkButton *button, gpointer data);

static void backup_setup_free(gpointer data) {
  BackupSetup *setup = data;
  if (setup->app->backup_setup == setup) setup->app->backup_setup = NULL;
  g_ptr_array_unref(setup->repository_ids);
  g_ptr_array_unref(setup->destination_ids);
  g_free(setup->backup_name);
  g_free(setup->destination_id);
  g_free(setup->repository_id);
  g_free(setup->repository_name);
  g_free(setup->plan_id);
  g_free(setup->storage_path);
  g_free(setup);
}

static void backup_setup_show(BackupSetup *setup, const char *message) {
  static const char *headings[] = {
    "1. Choose a backup location", "1. Connect a backup location",
    "2. Create encrypted backup storage", "2. Save your recovery information",
    "3. Choose files and a schedule", "Your backup is ready"
  };
  static const char *descriptions[] = {
    "Give your backup a name, then choose where its encrypted copies will be kept. You can use a drive, a server, or cloud storage.",
    "Choose a local folder or enter the connection details supplied by your storage provider. Only settings for that location are shown.",
    "OctoVault creates a separate encrypted backup area and generates its password automatically. You will save the recovery information next.",
    "Save the complete recovery information in your password manager outside this computer. Then continue to select what to back up.",
    "Add any number of files and folders. Daily backups are selected for you; change the schedule or open advanced settings whenever needed.",
    "Your selected schedule has been saved. You can make the first backup now, or close this window and let the schedule run it."
  };
  gtk_label_set_text(setup->heading, headings[setup->stage]);
  gtk_label_set_text(setup->description, descriptions[setup->stage]);
  gtk_label_set_text(setup->status, message ? message : "");
  gtk_widget_set_visible(setup->location_box, setup->stage == BACKUP_SETUP_LOCATION);
  gtk_widget_set_sensitive(setup->next, !setup->waiting);
  const char *next = setup->stage == BACKUP_SETUP_COMPLETE ? "_Back up now" :
    setup->stage == BACKUP_SETUP_RECOVERY ? "_Show recovery information" : "_Continue";
  gtk_button_set_label(GTK_BUTTON(setup->next), next);
  gtk_button_set_use_underline(GTK_BUTTON(setup->next), TRUE);
  gtk_button_set_label(GTK_BUTTON(setup->cancel), setup->stage == BACKUP_SETUP_COMPLETE ? "_Done" : "_Finish later");
  gtk_button_set_use_underline(GTK_BUTTON(setup->cancel), TRUE);
  gtk_window_present(setup->window);
}

/* Insert newly created records immediately. Collection refreshes are async, so
 * the next step must not depend on whether its background list job has finished.
 * Only identifiers and display names are needed for reference selection. */
static void backup_setup_cache(App *app, guint index, const char *id, const char *name) {
  JsonArray *records = json_array_new();
  gboolean found = FALSE;
  if (app->collections[index] && JSON_NODE_HOLDS_ARRAY(app->collections[index])) {
    JsonArray *old = json_node_get_array(app->collections[index]);
    for (guint i = 0; i < json_array_get_length(old); i++) {
      JsonNode *item = json_array_get_element(old, i);
      if (JSON_NODE_HOLDS_OBJECT(item) && !strcmp(str(json_node_get_object(item), "id"), id)) found = TRUE;
      json_array_add_element(records, json_node_copy(item));
    }
  }
  if (!found) {
    JsonObject *record = json_object_new();
    json_object_set_string_member(record, "id", id);
    json_object_set_string_member(record, "name", name);
    json_array_add_object_element(records, record);
  }
  g_clear_pointer(&app->collections[index], json_node_free);
  app->collections[index] = json_node_new(JSON_NODE_ARRAY);
  json_node_take_array(app->collections[index], records);
}

static void backup_setup_open_form(BackupSetup *setup, const char *operation,
                                   const char *title, JsonObject *record) {
  if (setup->app->active) {
    backup_setup_show(setup, "Wait for the current operation to finish, then continue.");
    return;
  }
  setup->expected_operation = operation;
  setup->waiting = FALSE;
  backup_setup_show(setup, "Complete the next screen to continue. Settings already saved are kept if you finish later.");
  open_form(setup->app, operation, title, record);
  GListModel *windows = gtk_window_get_toplevels();
  for (guint i = g_list_model_get_n_items(windows); i > 0; i--) {
    GtkWindow *window = g_list_model_get_item(windows, i - 1);
    Form *form = g_object_get_data(G_OBJECT(window), "form");
    if (form && form->app == setup->app && !strcmp(form->operation, operation)) {
      form->guided_backup = TRUE;
      gtk_window_set_transient_for(window, setup->window);
      g_object_unref(window);
      return;
    }
    g_object_unref(window);
  }
  setup->expected_operation = NULL;
  backup_setup_show(setup, "The next screen could not be opened. Continue to try again.");
}

static void backup_setup_begin_recovery(BackupSetup *setup) {
  setup->stage = BACKUP_SETUP_RECOVERY;
  if (setup->app->active) {
    backup_setup_show(setup, "Wait for the current operation, then show your recovery information.");
    return;
  }
  setup->waiting = TRUE;
  setup->expected_operation = "repository.recovery";
  backup_setup_show(setup, "Opening your recovery information…");
  JsonObject *params = json_object_new();
  json_object_set_string_member(params, "id", setup->repository_id);
  start_operation(setup->app, "repository.recovery", params, "Save your recovery information", -1, TRUE);
  json_object_unref(params);
}

static void backup_setup_begin_plan(BackupSetup *setup) {
  setup->stage = BACKUP_SETUP_PLAN;
  backup_setup_cache(setup->app, 2, setup->repository_id, setup->repository_name);
  JsonObject *record = json_object_new();
  json_object_set_string_member(record, "name", setup->backup_name);
  json_object_set_string_member(record, "repository_id", setup->repository_id);
  json_object_set_string_member(record, "trigger", "calendar");
  json_object_set_string_member(record, "calendar", "daily");
  backup_setup_open_form(setup, "backup.save", "Choose files and schedule", record);
  json_object_unref(record);
}

static void backup_setup_continue(GtkButton *button, gpointer data) {
  (void)button;
  BackupSetup *setup = data;
  if (setup->waiting) return;
  if (setup->app->active) {
    backup_setup_show(setup, "Wait for the current operation to finish, then continue.");
    return;
  }
  if (setup->stage == BACKUP_SETUP_LOCATION) {
    const char *name = gtk_editable_get_text(GTK_EDITABLE(setup->name));
    if (!*name) {
      gtk_label_set_text(setup->status, "Give your backup a name, such as Documents or Family photos.");
      gtk_widget_grab_focus(setup->name);
      return;
    }
    g_free(setup->backup_name);
    setup->backup_name = g_strdup(name);
    if (gtk_check_button_get_active(GTK_CHECK_BUTTON(setup->existing))) {
      guint selected = gtk_drop_down_get_selected(GTK_DROP_DOWN(setup->repositories));
      if (selected >= setup->repository_ids->len) {
        gtk_label_set_text(setup->status, "Choose an existing backup storage area, or create a new one.");
        return;
      }
      g_free(setup->repository_id);
      setup->repository_id = g_strdup(g_ptr_array_index(setup->repository_ids, selected));
      GtkStringObject *item = gtk_drop_down_get_selected_item(GTK_DROP_DOWN(setup->repositories));
      g_free(setup->repository_name);
      setup->repository_name = g_strdup(gtk_string_object_get_string(item));
      backup_setup_begin_plan(setup);
      return;
    }
    guint selected = gtk_drop_down_get_selected(GTK_DROP_DOWN(setup->destinations));
    if (selected > 0 && selected < setup->destination_ids->len) {
      g_free(setup->destination_id);
      setup->destination_id = g_strdup(g_ptr_array_index(setup->destination_ids, selected));
      setup->stage = BACKUP_SETUP_STORAGE;
    } else setup->stage = BACKUP_SETUP_DESTINATION;
  }
  if (setup->stage == BACKUP_SETUP_DESTINATION) {
    JsonObject *record = json_object_new();
    json_object_set_string_member(record, "name", setup->backup_name);
    json_object_set_string_member(record, "type", "local");
    backup_setup_open_form(setup, "destination.save", "Where to keep your backups", record);
    json_object_unref(record);
  } else if (setup->stage == BACKUP_SETUP_STORAGE) {
    JsonObject *record = json_object_new();
    json_object_set_string_member(record, "name", setup->backup_name);
    json_object_set_string_member(record, "destination_id", setup->destination_id);
    json_object_set_string_member(record, "path", setup->storage_path);
    backup_setup_open_form(setup, "repository.create", "Create encrypted backup storage", record);
    json_object_unref(record);
  } else if (setup->stage == BACKUP_SETUP_RECOVERY) backup_setup_begin_recovery(setup);
  else if (setup->stage == BACKUP_SETUP_PLAN) backup_setup_begin_plan(setup);
  else if (setup->stage == BACKUP_SETUP_COMPLETE) {
    App *app = setup->app;
    JsonObject *params = json_object_new();
    json_object_set_string_member(params, "id", setup->plan_id);
    gtk_window_destroy(setup->window);
    start_operation(app, "backup.run", params, "Back up now", -1, FALSE);
    json_object_unref(params);
  }
}

static void backup_setup_form_closed(App *app, const char *operation, gboolean submitted) {
  BackupSetup *setup = app->backup_setup;
  if (!setup || !setup->expected_operation || strcmp(setup->expected_operation, operation)) return;
  setup->waiting = submitted;
  if (!submitted) setup->expected_operation = NULL;
  backup_setup_show(setup, submitted ? "Saving your settings… Progress is shown in the main window." :
    "This step was cancelled. Continue to try again, or finish later. Saved backup locations and storage remain available.");
}

static void backup_setup_recovery_closed(App *app, gboolean saved) {
  BackupSetup *setup = app->backup_setup;
  if (!setup || !setup->recovery_pending) return;
  setup->recovery_pending = FALSE;
  setup->waiting = FALSE;
  if (saved) backup_setup_begin_plan(setup);
  else backup_setup_show(setup, "Show the recovery information again and save it outside this computer before continuing.");
}

static gboolean backup_setup_handle_result(App *app, const char *operation,
                                          JsonNode *payload, const GError *error) {
  BackupSetup *setup = app->backup_setup;
  if (!setup || !setup->expected_operation || strcmp(setup->expected_operation, operation)) return FALSE;
  setup->expected_operation = NULL;
  setup->waiting = FALSE;
  if (error) {
    add_activity(app, error->message);
    backup_setup_show(setup, error->message);
    return TRUE;
  }
  if (!strcmp(operation, "repository.recovery")) {
    if (!payload) {
      backup_setup_show(setup, "Recovery information was not returned. Show it again before continuing.");
      return TRUE;
    }
    setup->recovery_pending = TRUE;
    setup->waiting = TRUE;
    backup_setup_show(setup, "Save and acknowledge the recovery record in the next window.");
    result_window(app, "Save your recovery information", payload, TRUE, TRUE);
    return TRUE;
  }
  JsonObject *record = payload && JSON_NODE_HOLDS_OBJECT(payload) ? json_node_get_object(payload) : NULL;
  const char *id = str(record, "id");
  if (!*id) {
    backup_setup_show(setup, "The service did not return the saved record. Finish later, refresh the main window, and inspect the saved items before retrying.");
    return TRUE;
  }
  if (!strcmp(operation, "destination.save")) {
    g_free(setup->destination_id);
    setup->destination_id = g_strdup(id);
    backup_setup_cache(app, 1, id, str(record, "name"));
    setup->stage = BACKUP_SETUP_STORAGE;
    backup_setup_continue(NULL, setup);
  } else if (!strcmp(operation, "repository.create")) {
    g_free(setup->repository_id);
    g_free(setup->repository_name);
    setup->repository_id = g_strdup(id);
    setup->repository_name = g_strdup(str(record, "name"));
    backup_setup_cache(app, 2, id, str(record, "name"));
    backup_setup_begin_recovery(setup);
  } else if (!strcmp(operation, "backup.save")) {
    g_free(setup->plan_id);
    setup->plan_id = g_strdup(id);
    setup->stage = BACKUP_SETUP_COMPLETE;
    backup_setup_show(setup, "You can edit files, scheduling, and advanced options from this backup's menu at any time.");
  }
  return TRUE;
}

static GtkWidget *backup_setup_choices(App *app, guint index, GPtrArray *ids,
                                      const char *first) {
  GtkStringList *model = gtk_string_list_new(NULL);
  if (first) {
    gtk_string_list_append(model, first);
    g_ptr_array_add(ids, g_strdup(""));
  }
  if (app->collections[index] && JSON_NODE_HOLDS_ARRAY(app->collections[index])) {
    JsonArray *records = json_node_get_array(app->collections[index]);
    for (guint i = 0; i < json_array_get_length(records); i++) {
      JsonNode *node = json_array_get_element(records, i);
      if (!JSON_NODE_HOLDS_OBJECT(node)) continue;
      JsonObject *record = json_node_get_object(node);
      if (!*str(record, "id")) continue;
      gtk_string_list_append(model, *str(record, "name") ? str(record, "name") : "Backup storage");
      g_ptr_array_add(ids, g_strdup(str(record, "id")));
    }
  }
  return gtk_drop_down_new(G_LIST_MODEL(model), NULL);
}

static void backup_setup_mode_changed(GtkCheckButton *button, gpointer data) {
  (void)button;
  BackupSetup *setup = data;
  gboolean existing = gtk_check_button_get_active(GTK_CHECK_BUTTON(setup->existing));
  gtk_widget_set_visible(setup->repository_box, existing);
  gtk_widget_set_visible(setup->destination_box, !existing);
}

static void open_backup_setup(App *app) {
  if (app->backup_setup) {
    gtk_window_present(app->backup_setup->window);
    return;
  }
  if (app->active) {
    error_window(app, "An operation is already running", "Wait for the current operation to finish, or cancel it, before setting up a backup.");
    return;
  }
  BackupSetup *setup = g_new0(BackupSetup, 1);
  setup->app = app;
  setup->repository_ids = g_ptr_array_new_with_free_func(g_free);
  setup->destination_ids = g_ptr_array_new_with_free_func(g_free);
  char *unique = g_uuid_string_random();
  setup->storage_path = g_strconcat("octovault-", unique, NULL);
  g_free(unique);
  setup->window = dialog_window(app, "Create a backup", 620, 650);
  app->backup_setup = setup;
  g_object_set_data_full(G_OBJECT(setup->window), "backup-setup", setup, backup_setup_free);
  GtkBox *root = GTK_BOX(gtk_box_new(GTK_ORIENTATION_VERTICAL, 16));
  margin(GTK_WIDGET(root), 24);
  setup->heading = GTK_LABEL(label("", "title-2"));
  setup->description = GTK_LABEL(label("", NULL));
  gtk_box_append(root, GTK_WIDGET(setup->heading));
  gtk_box_append(root, GTK_WIDGET(setup->description));
  GtkWidget *scroll = gtk_scrolled_window_new();
  gtk_widget_set_vexpand(scroll, TRUE);
  gtk_box_append(root, scroll);
  GtkBox *content = GTK_BOX(gtk_box_new(GTK_ORIENTATION_VERTICAL, 14));
  margin(GTK_WIDGET(content), 4);
  gtk_scrolled_window_set_child(GTK_SCROLLED_WINDOW(scroll), GTK_WIDGET(content));
  setup->location_box = GTK_WIDGET(content);
  GtkWidget *caption = gtk_label_new_with_mnemonic("_Backup name");
  gtk_widget_set_halign(caption, GTK_ALIGN_START);
  gtk_box_append(content, caption);
  setup->name = gtk_entry_new();
  gtk_entry_set_placeholder_text(GTK_ENTRY(setup->name), "For example, My documents");
  gtk_label_set_mnemonic_widget(GTK_LABEL(caption), setup->name);
  gtk_accessible_update_property(GTK_ACCESSIBLE(setup->name), GTK_ACCESSIBLE_PROPERTY_LABEL, "Backup name", -1);
  gtk_box_append(content, setup->name);
  setup->existing = gtk_check_button_new_with_mnemonic("Use _existing encrypted backup storage");
  setup->create = gtk_check_button_new_with_mnemonic("Create _new encrypted backup storage");
  gtk_check_button_set_group(GTK_CHECK_BUTTON(setup->create), GTK_CHECK_BUTTON(setup->existing));
  gtk_box_append(content, setup->existing);
  setup->repository_box = gtk_box_new(GTK_ORIENTATION_VERTICAL, 8);
  setup->repositories = backup_setup_choices(app, 2, setup->repository_ids, NULL);
  gtk_accessible_update_property(GTK_ACCESSIBLE(setup->repositories), GTK_ACCESSIBLE_PROPERTY_LABEL, "Existing encrypted backup storage", -1);
  gtk_box_append(GTK_BOX(setup->repository_box), setup->repositories);
  append_text(GTK_BOX(setup->repository_box), "Your new backup can share this storage and its recovery information.", "dim-label");
  gtk_box_append(content, setup->repository_box);
  gtk_box_append(content, setup->create);
  setup->destination_box = gtk_box_new(GTK_ORIENTATION_VERTICAL, 8);
  setup->destinations = backup_setup_choices(app, 1, setup->destination_ids, "Add a new backup location…");
  gtk_accessible_update_property(GTK_ACCESSIBLE(setup->destinations), GTK_ACCESSIBLE_PROPERTY_LABEL, "Backup location", -1);
  gtk_box_append(GTK_BOX(setup->destination_box), setup->destinations);
  append_text(GTK_BOX(setup->destination_box), "Choose a saved drive or server, or add a new location. OctoVault will create an encrypted backup area inside it.", "dim-label");
  gtk_box_append(content, setup->destination_box);
  gboolean has_repository = setup->repository_ids->len > 0;
  gtk_widget_set_sensitive(setup->existing, has_repository);
  gtk_check_button_set_active(GTK_CHECK_BUTTON(has_repository ? setup->existing : setup->create), TRUE);
  g_signal_connect(setup->existing, "toggled", G_CALLBACK(backup_setup_mode_changed), setup);
  backup_setup_mode_changed(NULL, setup);
  append_text(root, "Next: save recovery information → choose files and folders → set a schedule.", "dim-label");
  setup->status = GTK_LABEL(label("", NULL));
  gtk_label_set_selectable(setup->status, TRUE);
  gtk_box_append(root, GTK_WIDGET(setup->status));
  GtkBox *buttons = GTK_BOX(gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 10));
  gtk_widget_set_halign(GTK_WIDGET(buttons), GTK_ALIGN_END);
  gtk_box_append(root, GTK_WIDGET(buttons));
  setup->cancel = gtk_button_new_with_mnemonic("_Finish later");
  setup->next = gtk_button_new_with_mnemonic("_Continue");
  gtk_widget_add_css_class(setup->next, "suggested-action");
  gtk_box_append(buttons, setup->cancel);
  gtk_box_append(buttons, setup->next);
  g_signal_connect(setup->cancel, "clicked", G_CALLBACK(close_window), setup->window);
  g_signal_connect(setup->next, "clicked", G_CALLBACK(backup_setup_continue), setup);
  gtk_window_set_child(setup->window, GTK_WIDGET(root));
  backup_setup_show(setup, "");
  gtk_widget_grab_focus(setup->name);
}

/* Exercised by the native GTK smoke run in CI, with no privileged jobs. */
static GtkWindow *backup_setup_test_form(App *app, const char *operation) {
  GListModel *windows = gtk_window_get_toplevels();
  for (guint i = g_list_model_get_n_items(windows); i > 0; i--) {
    GtkWindow *window = g_list_model_get_item(windows, i - 1);
    Form *form = g_object_get_data(G_OBJECT(window), "form");
    if (form && form->app == app && !strcmp(form->operation, operation)) return window;
    g_object_unref(window);
  }
  g_assert_not_reached();
  return NULL;
}

static void backup_setup_smoke(App *app) {
  JsonNode *old_destinations = app->collections[1];
  JsonNode *old_repositories = app->collections[2];
  app->collections[1] = NULL;
  app->collections[2] = NULL;
  open_backup_setup(app);
  BackupSetup *setup = app->backup_setup;
  g_assert_nonnull(setup);
  g_assert_false(gtk_widget_get_sensitive(setup->existing));
  backup_setup_continue(NULL, setup);
  g_assert_cmpint(setup->stage, ==, BACKUP_SETUP_LOCATION);
  g_assert_null(setup->expected_operation);
  gtk_editable_set_text(GTK_EDITABLE(setup->name), "Family photographs");
  backup_setup_continue(NULL, setup);
  g_assert_cmpint(setup->stage, ==, BACKUP_SETUP_DESTINATION);
  GtkWindow *form_window = backup_setup_test_form(app, "destination.save");
  Form *form = g_object_get_data(G_OBJECT(form_window), "form");
  g_assert_true(form->guided_backup);
  Field *type = find_field(form, "type");
  g_assert_cmpstr(g_ptr_array_index(type->values, gtk_drop_down_get_selected(GTK_DROP_DOWN(type->widget))), ==, "local");
  gtk_window_destroy(form_window);
  g_object_unref(form_window);
  g_assert_false(setup->waiting);
  g_assert_null(setup->expected_operation);
  backup_setup_continue(NULL, setup);
  form_window = backup_setup_test_form(app, "destination.save");
  form = g_object_get_data(G_OBJECT(form_window), "form");
  form->submitted = TRUE;
  gtk_window_destroy(form_window);
  g_object_unref(form_window);
  g_assert_true(setup->waiting);
  JsonNode *saved = json_node_new(JSON_NODE_OBJECT);
  JsonObject *record = json_object_new();
  json_object_set_string_member(record, "id", "setup-test-destination");
  json_object_set_string_member(record, "name", "External drive");
  json_node_take_object(saved, record);
  g_assert_true(backup_setup_handle_result(app, "destination.save", saved, NULL));
  json_node_free(saved);
  g_assert_cmpint(setup->stage, ==, BACKUP_SETUP_STORAGE);
  form_window = backup_setup_test_form(app, "repository.create");
  form = g_object_get_data(G_OBJECT(form_window), "form");
  gboolean accepted = FALSE;
  JsonObject *params = form_parameters(form, &accepted);
  g_assert_true(accepted);
  g_assert_cmpstr(str(params, "destination_id"), ==, "setup-test-destination");
  g_assert_true(g_str_has_prefix(str(params, "path"), "octovault-"));
  g_assert_false(json_object_has_member(params, "password"));
  json_object_unref(params);
  gtk_window_destroy(form_window);
  g_object_unref(form_window);
  gtk_window_destroy(setup->window);
  g_assert_null(app->backup_setup);

  backup_setup_cache(app, 2, "setup-test-repository", "Encrypted family storage");
  open_backup_setup(app);
  setup = app->backup_setup;
  g_assert_true(gtk_check_button_get_active(GTK_CHECK_BUTTON(setup->existing)));
  gtk_editable_set_text(GTK_EDITABLE(setup->name), "Work documents");
  backup_setup_continue(NULL, setup);
  g_assert_cmpint(setup->stage, ==, BACKUP_SETUP_PLAN);
  form_window = backup_setup_test_form(app, "backup.save");
  form = g_object_get_data(G_OBJECT(form_window), "form");
  Field *sources = find_field(form, "sources");
  gtk_text_buffer_set_text(gtk_text_view_get_buffer(GTK_TEXT_VIEW(sources->widget)), g_get_home_dir(), -1);
  params = form_parameters(form, &accepted);
  g_assert_true(accepted);
  g_assert_cmpstr(str(params, "repository_id"), ==, "setup-test-repository");
  g_assert_cmpstr(str(params, "name"), ==, "Work documents");
  g_assert_cmpstr(str(params, "trigger"), ==, "calendar");
  g_assert_cmpstr(str(params, "calendar"), ==, "daily");
  json_object_unref(params);
  form->submitted = TRUE;
  gtk_window_destroy(form_window);
  g_object_unref(form_window);
  saved = json_node_new(JSON_NODE_OBJECT);
  record = json_object_new();
  json_object_set_string_member(record, "id", "setup-test-plan");
  json_node_take_object(saved, record);
  g_assert_true(backup_setup_handle_result(app, "backup.save", saved, NULL));
  json_node_free(saved);
  g_assert_cmpint(setup->stage, ==, BACKUP_SETUP_COMPLETE);
  g_assert_cmpstr(setup->plan_id, ==, "setup-test-plan");
  g_assert_null(app->active);
  gtk_window_destroy(setup->window);
  g_clear_pointer(&app->collections[1], json_node_free);
  g_clear_pointer(&app->collections[2], json_node_free);
  app->collections[1] = old_destinations;
  app->collections[2] = old_repositories;
}
