/* OctoVault — native GNOME application.
 * Copyright (C) 2026 Vast Development Method. Apache-2.0.
 * All operations go through the same authorized D-Bus service as the CLI.
 * Neither credentials nor privileged commands are passed on a command line.
 */
#include <adwaita.h>
#include <json-glib/json-glib.h>
#include <glib/gstdio.h>
#include <math.h>
#include <string.h>
#include <sys/resource.h>
#include <sys/prctl.h>

#define BUS_NAME "io.vdm.OctoVault1"
#define BUS_PATH "/io/vdm/OctoVault1"
#define BUS_IFACE "io.vdm.OctoVault1"
#ifndef OCTOVAULT_VERSION
#define OCTOVAULT_VERSION "1.0.0"
#endif

typedef struct App App;
typedef struct Operation Operation;
typedef struct Form Form;
typedef struct BackupSetup BackupSetup;
typedef struct { const char *key, *label, *kind, *options, *hint; gboolean required; } Spec;
typedef struct { const Spec *spec; GtkWidget *widget, *row, *picker; GtkLabel *name, *hint; GPtrArray *values; gboolean context_visible; } Field;
struct App {
  AdwApplication *application;
  GtkWindow *window;
  GtkBox *body;
  GtkLabel *title, *job_label;
  GtkProgressBar *progress;
  GtkWidget *job_box, *cancel, *refresh;
  GtkToggleButton *navigation[6];
  JsonNode *collections[4];
  GPtrArray *activity;
  char *page;
  char *screenshot;
  gboolean screenshot_create;
  gboolean screenshot_backup, screenshot_backup_files, screenshot_destination, screenshot_advanced;
  GtkWindow *screenshot_window;
  GQueue *pending_unlocks;
  gboolean automatic_prompt;
  JsonObject *priority_lock;
  Operation *active;
  BackupSetup *backup_setup;
  gboolean smoke;
  gboolean show_notifications;
  guint preferred_theme;
};
struct Operation {
  App *app;
  char *op, *request, *id, *title, *record_id, *snapshot;
  GMutex mutex;
  gint cancelled;
  gint collection;
  gboolean background, reveal, acknowledge;
};
struct Form {
  App *app;
  GtkWindow *window;
  GtkLabel *error;
  GtkLabel *guidance, *location_preview;
  char *operation;
  JsonObject *base;
  JsonObject *original;
  GPtrArray *fields;
  GtkCheckButton *advanced;
  gboolean acknowledge;
  gboolean automatic;
  gboolean submitted, guided_backup;
};

typedef struct { App *app; char *operation, *title; JsonObject *record; } Action;
static const char *collection_names[] = { "vault", "destination", "repository", "backup" };
static void render_page(App *app);
static void refresh_all(App *app);
static void open_form(App *app, const char *operation, const char *title, JsonObject *record);
static void start_operation(App *app, const char *op, JsonObject *params, const char *title, gint collection, gboolean acknowledge);
static void result_window(App *app, const char *title, JsonNode *node, gboolean reveal, gboolean acknowledge);
static void snapshots_window(App *app, const char *repository, JsonNode *node);
static void files_window(App *app, const char *repository, const char *snapshot, JsonNode *node);
static void migrations_window(App *app, const char *vault, JsonNode *node);
static gboolean unlock_registered(App *app, const char *id);
static gboolean drain_unlocks(gpointer data);
static void wipe(char *text);
static void open_backup_setup(App*app);
static gboolean backup_setup_handle_result(App*app,const char*operation,JsonNode*payload,const GError*error);
static void backup_setup_form_closed(App*app,const char*operation,gboolean submitted);
static void backup_setup_recovery_closed(App*app,gboolean saved);

static const char *str(JsonObject *o, const char *key) {
  if (!o || !json_object_has_member(o, key)) return "";
  JsonNode *n = json_object_get_member(o, key);
  return n && JSON_NODE_HOLDS_VALUE(n) && json_node_get_value_type(n) == G_TYPE_STRING ? json_node_get_string(n) : "";
}
static gboolean boolean(JsonObject *o, const char *key) {
  if (!o || !json_object_has_member(o, key)) return FALSE;
  JsonNode *n = json_object_get_member(o,key);
  return n && JSON_NODE_HOLDS_VALUE(n) && json_node_get_value_type(n) == G_TYPE_BOOLEAN && json_node_get_boolean(n);
}
static char *humanize(const char *key) {
  char *s = g_strdup(key ? key : "");
  for (char *p = s; *p; p++) if (*p == '_' || *p == '-') *p = ' ';
  if (*s) *s = g_ascii_toupper(*s);
  return s;
}
static char *node_text(JsonNode *n) {
  if (!n || JSON_NODE_HOLDS_NULL(n)) return g_strdup("—");
  if (JSON_NODE_HOLDS_VALUE(n)) {
    GType t = json_node_get_value_type(n);
    if (t == G_TYPE_STRING) return g_strdup(json_node_get_string(n));
    if (t == G_TYPE_BOOLEAN) return g_strdup(json_node_get_boolean(n) ? "Yes" : "No");
    if (t == G_TYPE_DOUBLE) {char value[G_ASCII_DTOSTR_BUF_SIZE];return g_strdup(g_ascii_dtostr(value,sizeof value,json_node_get_double(n)));}
    return g_strdup_printf("%" G_GINT64_FORMAT, json_node_get_int(n));
  }
  if (JSON_NODE_HOLDS_ARRAY(n)) {
    GString *s = g_string_new(NULL);
    JsonArray *a = json_node_get_array(n);
    for (guint i = 0; i < json_array_get_length(a); i++) {
      char *v = node_text(json_array_get_element(a,i));
      if (i) g_string_append(s, "\n");
      g_string_append(s,v); g_free(v);
    }
    return g_string_free(s,FALSE);
  }
  return g_strdup("Details");
}
static JsonObject *copy_object(JsonObject *o) {
  JsonObject *out = json_object_new();
  if (o) {
    GList *keys = json_object_get_members(o);
    for (GList *l=keys;l;l=l->next) json_object_set_member(out,l->data,json_node_copy(json_object_get_member(o,l->data)));
    g_list_free(keys);
  }
  return out;
}
static char *serialize_request(const char *op, JsonObject *params) {
  JsonObject *root = json_object_new();
  json_object_set_string_member(root,"op",op);
  json_object_set_object_member(root,"params",json_object_ref(params));
  JsonNode *n=json_node_new(JSON_NODE_OBJECT); json_node_take_object(n,root);
  char *s=json_to_string(n,FALSE); json_node_free(n); return s;
}
static void margin(GtkWidget *w, int n) {
  gtk_widget_set_margin_top(w,n); gtk_widget_set_margin_bottom(w,n);
  gtk_widget_set_margin_start(w,n); gtk_widget_set_margin_end(w,n);
}
static char *preferences_path(void){return g_build_filename(g_get_user_config_dir(),"octovault","desktop.ini",NULL);}
static void save_preferences(App *app){
  char *path=preferences_path(),*directory=g_path_get_dirname(path);
  if(g_mkdir_with_parents(directory,0700)==0){
    GKeyFile *settings=g_key_file_new();g_key_file_set_integer(settings,"Desktop","theme",(gint)app->preferred_theme);g_key_file_set_boolean(settings,"Desktop","notifications",app->show_notifications);
    if(g_key_file_save_to_file(settings,path,NULL))g_chmod(path,0600);
    g_key_file_unref(settings);
  }
  g_free(path);g_free(directory);
}
static void load_preferences(App *app){
  char *path=preferences_path();GKeyFile *settings=g_key_file_new();
  if(g_key_file_load_from_file(settings,path,G_KEY_FILE_NONE,NULL)){
    gint theme=g_key_file_get_integer(settings,"Desktop","theme",NULL);app->preferred_theme=(guint)CLAMP(theme,0,2);
    if(g_key_file_has_key(settings,"Desktop","notifications",NULL))app->show_notifications=g_key_file_get_boolean(settings,"Desktop","notifications",NULL);
  }
  g_key_file_unref(settings);g_free(path);
}
static GtkWidget *label(const char *text, const char *css) {
  GtkWidget *w=gtk_label_new(text); gtk_label_set_xalign(GTK_LABEL(w),0);
  gtk_label_set_wrap(GTK_LABEL(w),TRUE);
  if(css) gtk_widget_add_css_class(w,css);
  return w;
}
static void append_text(GtkBox *box,const char *text,const char *css) { gtk_box_append(box,label(text,css)); }
static GtkWindow *dialog_window(App *app,const char *title,int width,int height) {
  GtkWindow *w=GTK_WINDOW(gtk_window_new()); gtk_window_set_title(w,title);
  gtk_window_set_transient_for(w,app->window); gtk_window_set_modal(w,TRUE);
  gtk_window_set_default_size(w,width,height); return w;
}
static void close_window(GtkButton *b,gpointer data) { (void)b; gtk_window_destroy(GTK_WINDOW(data)); }
static void notify(App *app,const char *title,const char *body) {
  if(!app->show_notifications || app->smoke) return;
  GNotification *n=g_notification_new(title); g_notification_set_body(n,body);
  g_application_send_notification(G_APPLICATION(app->application),"operation",n); g_object_unref(n);
}
static void add_activity(App *app,const char *message) {
  GDateTime *now=g_date_time_new_now_local(); char *time=g_date_time_format(now,"%H:%M:%S");
  g_ptr_array_insert(app->activity,0,g_strdup_printf("%s  %s",time,message));
  if(app->activity->len>100) g_ptr_array_remove_index(app->activity,100);
  g_free(time);g_date_time_unref(now);
}
static void operation_free(Operation *o) {
  g_free(o->op);wipe(o->request);g_free(o->request);g_free(o->id);g_free(o->title);g_free(o->record_id);g_free(o->snapshot);g_mutex_clear(&o->mutex);g_free(o);
}
typedef struct { App *app; char *message; double percent; } Progress;
static gboolean show_progress(gpointer data) {
  Progress *p=data;
  gtk_label_set_text(p->app->job_label,p->message);
  if(p->percent>=0) gtk_progress_bar_set_fraction(p->app->progress,CLAMP(p->percent/100.,0.,1.));
  else gtk_progress_bar_pulse(p->app->progress);
  g_free(p->message);g_free(p);return G_SOURCE_REMOVE;
}
static JsonNode *parse_json(const char *s,GError **error) {
  JsonParser *p=json_parser_new();
  if(!json_parser_load_from_data(p,s,-1,error)){g_object_unref(p);return NULL;}
  JsonNode *n=json_node_copy(json_parser_get_root(p));g_object_unref(p);return n;
}
static GVariant *bus_call(GDBusConnection *bus,const char *method,GVariant *args,GError **error) {
  return g_dbus_connection_call_sync(bus,BUS_NAME,BUS_PATH,BUS_IFACE,method,args,NULL,
        G_DBUS_CALL_FLAGS_ALLOW_INTERACTIVE_AUTHORIZATION,180000,NULL,error);
}
static void operation_thread(GTask *task,gpointer source,gpointer data,GCancellable *cancel) {
  (void)source;(void)cancel;
  Operation *o=data;GError *error=NULL;
  GDBusConnection *bus=g_bus_get_sync(G_BUS_TYPE_SYSTEM,NULL,&error);
  if(!bus){g_task_return_error(task,error);return;}
  GVariant *reply=bus_call(bus,"Submit",g_variant_new("(s)",o->request),&error);
  /* Remove the serialized secret-bearing request as soon as submission completes. */
  if(o->request){volatile char *p=(volatile char *)o->request;gsize len=strlen(o->request);for(gsize i=0;i<len;i++)p[i]=0;}
  g_clear_pointer(&o->request,g_free);
  if(!reply){g_object_unref(bus);g_task_return_error(task,error);return;}
  const char *id;g_variant_get(reply,"(&s)",&id);
  g_mutex_lock(&o->mutex);o->id=g_strdup(id);g_mutex_unlock(&o->mutex);g_variant_unref(reply);
  gboolean sent_cancel=FALSE;
  for(;;){
    if(g_atomic_int_get(&o->cancelled)&&!sent_cancel){
      reply=bus_call(bus,"Cancel",g_variant_new("(s)",o->id),&error);
      if(!reply)goto failed;
      g_variant_unref(reply);sent_cancel=TRUE;
    }
    reply=bus_call(bus,"GetJob",g_variant_new("(s)",o->id),&error);
    if(!reply)goto failed;
    const char *s;g_variant_get(reply,"(&s)",&s);JsonNode *n=parse_json(s,&error);g_variant_unref(reply);
    if(!n)goto failed;
    if(!JSON_NODE_HOLDS_OBJECT(n)){json_node_free(n);g_set_error_literal(&error,G_IO_ERROR,G_IO_ERROR_INVALID_DATA,"The service returned an invalid job response.");goto failed;}
    JsonObject *job=json_node_get_object(n);const char *state=str(job,"state");
    if(!o->background&&json_object_has_member(job,"progress")){
      JsonNode *pn=json_object_get_member(job,"progress");
      if(JSON_NODE_HOLDS_OBJECT(pn)){
        JsonObject *po=json_node_get_object(pn);Progress *p=g_new0(Progress,1);p->app=o->app;
        p->message=g_strdup(*str(po,"message")?str(po,"message"):o->title);p->percent=-1;
        if(json_object_has_member(po,"percent")){JsonNode *v=json_object_get_member(po,"percent");if(JSON_NODE_HOLDS_VALUE(v)&&json_node_get_value_type(v)!=G_TYPE_STRING)p->percent=json_node_get_double(v);}
        g_main_context_invoke(NULL,show_progress,p);
      }
    }
    if(!strcmp(state,"succeeded")||!strcmp(state,"failed")||!strcmp(state,"cancelled")){
      JsonNode *result=json_object_has_member(job,"result")?json_object_get_member(job,"result"):NULL;
      if(result&&!JSON_NODE_HOLDS_NULL(result))g_task_return_pointer(task,json_node_copy(result),(GDestroyNotify)json_node_free);
      else g_task_return_new_error(task,G_IO_ERROR,!strcmp(state,"cancelled")?G_IO_ERROR_CANCELLED:G_IO_ERROR_FAILED,"%s",!strcmp(state,"cancelled")?"Operation cancelled. Any retained migration files remain available for recovery.":"The operation ended without a result. Check the system service journal.");
      json_node_free(n);g_object_unref(bus);return;
    }
    json_node_free(n);g_usleep(250000);
  }
failed:
  g_object_unref(bus);g_task_return_error(task,error);
}
static void error_window(App *app,const char *title,const char *message) {
  GtkWindow *w=dialog_window(app,title,540,240);
  GtkBox *box=GTK_BOX(gtk_box_new(GTK_ORIENTATION_VERTICAL,18));margin(GTK_WIDGET(box),24);
  append_text(box,title,"title-2");append_text(box,message,NULL);
  GtkWidget *close=gtk_button_new_with_mnemonic("_Close");gtk_widget_set_halign(close,GTK_ALIGN_END);
  g_signal_connect(close,"clicked",G_CALLBACK(close_window),w);gtk_box_append(box,close);
  gtk_window_set_child(w,GTK_WIDGET(box));gtk_window_present(w);
}
static gboolean useful_result(const char *op) {
  return strstr(op,".get")||strstr(op,".snapshots")||strstr(op,".files")||strstr(op,".find")||strstr(op,".diff")||strstr(op,".stats")||strstr(op,".history")||strstr(op,".search")||strstr(op,".recovery")||strstr(op,".forget")||strstr(op,".check")||strstr(op,".test")||!strcmp(op,"migration.list");
}
static void operation_done(GObject *source,GAsyncResult *result,gpointer data) {
  (void)source;Operation *o=data;App *app=o->app;GError *error=NULL;
  JsonNode *response=g_task_propagate_pointer(G_TASK(result),&error);
  JsonNode *payload=NULL;
  if(response&&JSON_NODE_HOLDS_OBJECT(response)){
    JsonObject *root=json_node_get_object(response);
    if(!boolean(root,"ok")){
      const char *message="The operation could not be completed.";
      if(json_object_has_member(root,"error")&&JSON_NODE_HOLDS_OBJECT(json_object_get_member(root,"error")))message=str(json_object_get_object_member(root,"error"),"message");
      g_set_error_literal(&error,G_IO_ERROR,G_IO_ERROR_FAILED,*message?message:"The operation could not be completed.");
    }else if(json_object_has_member(root,"data"))payload=json_object_get_member(root,"data");
  }else if(response)g_set_error_literal(&error,G_IO_ERROR,G_IO_ERROR_INVALID_DATA,"The service returned an invalid operation response.");
  if(!o->background){app->active=NULL;gtk_widget_set_visible(app->job_box,FALSE);}
  gboolean guided=!o->background&&backup_setup_handle_result(app,o->op,payload,error);
  if(guided){if(!error)refresh_all(app);g_clear_error(&error);}
  else if(error){
    if(o->background){
      if(o->collection==0){add_activity(app,error->message);if(!strcmp(app->page,"Dashboard")||!strcmp(app->page,"Vaults")){render_page(app);append_text(app->body,"The system service is unavailable or did not complete this request. Install OctoVault's system package, then use Refresh. See Activity for details.","error");}}
    }else{add_activity(app,error->message);if(!app->priority_lock){error_window(app,o->title,error->message);notify(app,"Operation needs attention",error->message);}}
    g_clear_error(&error);
  }else if(o->background){
    if(app->collections[o->collection])json_node_free(app->collections[o->collection]);
    app->collections[o->collection]=payload?json_node_copy(payload):NULL;render_page(app);
    if(o->collection==0)g_idle_add(drain_unlocks,app);
  }else{
    char *message=g_strdup_printf("%s completed",o->title);add_activity(app,message);notify(app,"OctoVault",message);g_free(message);
    if(payload&&(!strcmp(o->op,"repository.create")||!strcmp(o->op,"repository.password"))){
      const char *id=JSON_NODE_HOLDS_OBJECT(payload)?str(json_node_get_object(payload),"id"):"";
      if(!*id)id=o->record_id;
      if(id&&*id){JsonObject *p=json_object_new();json_object_set_string_member(p,"id",id);start_operation(app,"repository.recovery",p,"Save your recovery information",-1,TRUE);json_object_unref(p);}
      else error_window(app,"Save your recovery information","The repository was created, but recovery information was not returned. Open its Recovery information action before relying on this backup.");
    }
    else if(o->reveal&&payload)result_window(app,"Save your recovery information",payload,TRUE,o->acknowledge);
    else if(!strcmp(o->op,"repository.snapshots")&&payload)snapshots_window(app,o->record_id,payload);
    else if(!strcmp(o->op,"repository.files")&&payload)files_window(app,o->record_id,o->snapshot,payload);
    else if(!strcmp(o->op,"migration.list")&&payload)migrations_window(app,o->record_id,payload);
    else if(useful_result(o->op)&&payload)result_window(app,o->title,payload,FALSE,FALSE);
    refresh_all(app);
  }
  if(response)json_node_free(response);
  operation_free(o);
  if(app->priority_lock&&!app->active){JsonObject*params=g_steal_pointer(&app->priority_lock);start_operation(app,"vault.close",params,"Lock vault",-1,FALSE);json_object_unref(params);}
  g_idle_add(drain_unlocks,app);
}
static void start_operation(App *app,const char *op,JsonObject *params,const char *title,gint collection,gboolean acknowledge) {
  if(collection<0&&app->active){
    if(!strcmp(op,"vault.close")&&!strcmp(app->active->op,"backup.run")){
      if(app->priority_lock)json_object_unref(app->priority_lock);
      app->priority_lock=copy_object(params);g_atomic_int_set(&app->active->cancelled,1);gtk_label_set_text(app->job_label,"Stopping the backup before locking the vault…");return;
    }
    error_window(app,"An operation is already running","Wait for the current operation to finish, or cancel it, before starting another.");return;
  }
  Operation *o=g_new0(Operation,1);o->app=app;o->op=g_strdup(op);o->title=g_strdup(title);o->collection=collection;
  o->background=collection>=0;o->record_id=g_strdup(str(params,"id"));o->snapshot=g_strdup(*str(params,"snapshot")?str(params,"snapshot"):"latest");o->request=serialize_request(op,params);o->acknowledge=acknowledge;
  o->reveal=!strcmp(op,"repository.recovery");g_mutex_init(&o->mutex);
  if(!o->background){app->active=o;gtk_label_set_text(app->job_label,title);gtk_progress_bar_set_fraction(app->progress,0);gtk_widget_set_visible(app->job_box,TRUE);add_activity(app,title);}
  GTask *task=g_task_new(NULL,NULL,operation_done,o);g_task_set_task_data(task,o,NULL);g_task_run_in_thread(task,operation_thread);g_object_unref(task);
}
static void cancel_job(GtkButton *button,gpointer data) {
  (void)button;App *app=data;if(app->active){g_atomic_int_set(&app->active->cancelled,1);gtk_label_set_text(app->job_label,"Cancelling safely…");}
}
static void refresh_all(App *app) {
  if(app->smoke)return;
  for(gint i=0;i<4;i++){char *op=g_strconcat(collection_names[i],".list",NULL);JsonObject *p=json_object_new();start_operation(app,op,p,"Refresh",i,FALSE);json_object_unref(p);g_free(op);}
}
static void refresh_clicked(GtkButton *b,gpointer data){(void)b;refresh_all(data);}

/* Human-readable data display. Backend dictionaries are never shown as JSON. */
static void detail_nodes(GtkBox *box,const char *name,JsonNode *node,int depth) {
  if(depth>5)return;
  if(JSON_NODE_HOLDS_OBJECT(node)){
    JsonObject *object=json_node_get_object(node);GList *members=json_object_get_members(object);
    if(name&&*name){char *h=humanize(name);append_text(box,h,"heading");g_free(h);}
    for(GList *l=members;l;l=l->next){
      const char *key=l->data;
      if(!strcmp(key,"credential_id")||!strcmp(key,"credentials")||!strcmp(key,"schema_version"))continue;
      detail_nodes(box,key,json_object_get_member(object,key),depth+1);
    }g_list_free(members);
  }else if(JSON_NODE_HOLDS_ARRAY(node)){
    JsonArray *a=json_node_get_array(node);if(name&&*name){char *h=humanize(name);append_text(box,h,"heading");g_free(h);}
    if(!json_array_get_length(a))append_text(box,"None", "dim-label");
    for(guint i=0;i<json_array_get_length(a);i++){
      JsonNode *n=json_array_get_element(a,i);detail_nodes(box,JSON_NODE_HOLDS_OBJECT(n)?NULL:"",n,depth+1);
      if(JSON_NODE_HOLDS_OBJECT(n)&&i+1<json_array_get_length(a))gtk_box_append(box,gtk_separator_new(GTK_ORIENTATION_HORIZONTAL));
    }
  }else{
    char *value=node_text(node);char *h=humanize(name);char *text=(name&&*name)?g_strdup_printf("%s: %s",h,value):g_strdup(value);
    GtkWidget *w=label(text,NULL);gtk_label_set_selectable(GTK_LABEL(w),TRUE);gtk_box_append(box,w);g_free(text);g_free(h);g_free(value);
  }
}
typedef struct { App*app; GtkWindow *window; char *text; gboolean acknowledge; gboolean copied, notified; GtkWidget *ack, *view, *copy, *toggle; guint expiry; } Recovery;
static void wipe(char *text){if(text){gsize len=strlen(text);volatile char *p=(volatile char*)text;while(len--)*p++=0;}}
static void recovery_notify(Recovery*r,gboolean saved){if(!r->notified){r->notified=TRUE;backup_setup_recovery_closed(r->app,saved);}}
static void recovery_free(gpointer data){Recovery *r=data;recovery_notify(r,FALSE);if(r->expiry)g_source_remove(r->expiry);wipe(r->text);g_free(r->text);g_free(r);}
static gboolean expire_recovery(gpointer data){
  Recovery*r=data;r->expiry=0;r->acknowledge=FALSE;wipe(r->text);g_clear_pointer(&r->text,g_free);
  gtk_text_buffer_set_text(gtk_text_view_get_buffer(GTK_TEXT_VIEW(r->view)),"This recovery display has expired. Open Recovery information again to reveal the credentials.",-1);
  gtk_widget_set_visible(r->view,TRUE);gtk_widget_set_sensitive(r->copy,FALSE);gtk_widget_set_sensitive(r->toggle,FALSE);
  if(r->ack)gtk_widget_set_sensitive(r->ack,FALSE);
  recovery_notify(r,FALSE);
  return G_SOURCE_REMOVE;
}
typedef struct { GdkClipboard *clipboard; GdkContentProvider *content; } ClipboardTimeout;
static gboolean clear_clipboard(gpointer data){
  ClipboardTimeout *saved=data;
  /* Never discard something the user copied after the recovery record. */
  if(gdk_clipboard_get_content(saved->clipboard)==saved->content)gdk_clipboard_set_text(saved->clipboard,"");
  g_clear_object(&saved->content);g_object_unref(saved->clipboard);g_free(saved);return G_SOURCE_REMOVE;
}
static void copy_recovery(GtkButton *b,gpointer data){
  Recovery *r=data;if(!r->text)return;GdkClipboard *cb=gtk_widget_get_clipboard(GTK_WIDGET(r->window));gdk_clipboard_set_text(cb,r->text);
  r->copied=TRUE;gtk_button_set_label(b,"Copied — save it outside this computer");
  if(r->ack)gtk_widget_set_sensitive(r->ack,TRUE);
  ClipboardTimeout *saved=g_new0(ClipboardTimeout,1);saved->clipboard=g_object_ref(cb);saved->content=gdk_clipboard_get_content(cb);if(saved->content)g_object_ref(saved->content);
  g_timeout_add_seconds(60,clear_clipboard,saved);
}
static void recovery_flatten(GString *s,const char *key,JsonNode *n){
  if(JSON_NODE_HOLDS_OBJECT(n)){JsonObject *o=json_node_get_object(n);GList *keys=json_object_get_members(o);for(GList*l=keys;l;l=l->next)recovery_flatten(s,l->data,json_object_get_member(o,l->data));g_list_free(keys);}
  else{char *value=node_text(n);g_string_append_printf(s,"%s: %s\n",key?key:"Value",value);wipe(value);g_free(value);}
}
static gboolean reveal_close(GtkWindow *w,gpointer data){
  Recovery *r=data;if(r->acknowledge&&!gtk_check_button_get_active(GTK_CHECK_BUTTON(r->ack))){gtk_widget_grab_focus(r->ack);return TRUE;}recovery_notify(r,r->acknowledge&&r->ack&&gtk_check_button_get_active(GTK_CHECK_BUTTON(r->ack)));(void)w;return FALSE;
}
static void reveal_done(GtkButton *b,gpointer data){(void)b;Recovery*r=data;if(!r->acknowledge||gtk_check_button_get_active(GTK_CHECK_BUTTON(r->ack))){recovery_notify(r,r->acknowledge&&r->ack&&gtk_check_button_get_active(GTK_CHECK_BUTTON(r->ack)));gtk_window_destroy(r->window);}}
static void reveal_toggle(GtkToggleButton *button,gpointer data){gtk_widget_set_visible(GTK_WIDGET(data),gtk_toggle_button_get_active(button));}
static void result_window(App *app,const char *title,JsonNode *node,gboolean reveal,gboolean acknowledge){
  GtkWindow *w=dialog_window(app,title,720,620);GtkBox *root=GTK_BOX(gtk_box_new(GTK_ORIENTATION_VERTICAL,14));margin(GTK_WIDGET(root),24);
  append_text(root,title,"title-2");
  GtkWidget *scroll=gtk_scrolled_window_new();gtk_widget_set_vexpand(scroll,TRUE);
  GtkBox *content=GTK_BOX(gtk_box_new(GTK_ORIENTATION_VERTICAL,10));margin(GTK_WIDGET(content),8);
  gtk_scrolled_window_set_child(GTK_SCROLLED_WINDOW(scroll),GTK_WIDGET(content));gtk_box_append(root,scroll);
  if(reveal){
    Recovery *r=g_new0(Recovery,1);r->app=app;r->window=w;r->acknowledge=acknowledge;
    GString *s=g_string_new("OctoVault repository recovery\nKeep this record in a secure password manager outside this computer.\n\n");recovery_flatten(s,NULL,node);
    g_string_append(s,"\nUse the saved repository connection and password to recover your backup on a replacement computer. Restore any required SSH key, verify the server host fingerprint, or configure the S3 access credentials before connecting.\n");
    r->text=g_string_free(s,FALSE);g_object_set_data_full(G_OBJECT(w),"recovery",r,recovery_free);
    append_text(content,"Save this complete recovery record in your password manager. OctoVault stores its credentials encrypted. A machine-bound credential file cannot recover your backup on another computer.",NULL);
    GtkWidget *toggle=gtk_toggle_button_new_with_mnemonic("_Reveal recovery information");r->toggle=toggle;gtk_box_append(content,toggle);
    GtkWidget *text=gtk_text_view_new();gtk_text_view_set_editable(GTK_TEXT_VIEW(text),FALSE);gtk_text_view_set_monospace(GTK_TEXT_VIEW(text),TRUE);gtk_text_view_set_wrap_mode(GTK_TEXT_VIEW(text),GTK_WRAP_WORD_CHAR);
    r->view=text;gtk_text_buffer_set_text(gtk_text_view_get_buffer(GTK_TEXT_VIEW(text)),r->text,-1);gtk_widget_set_visible(text,FALSE);gtk_box_append(content,text);g_signal_connect(toggle,"toggled",G_CALLBACK(reveal_toggle),text);
    GtkWidget *copy=gtk_button_new_with_mnemonic("_Copy complete recovery record");r->copy=copy;gtk_box_append(root,copy);g_signal_connect(copy,"clicked",G_CALLBACK(copy_recovery),r);
    append_text(root,"This display expires after five minutes. Clipboard clearing is attempted after one minute. Clipboard history applications may retain copied text.","dim-label");
    r->expiry=g_timeout_add_seconds(300,expire_recovery,r);
    if(acknowledge){r->ack=gtk_check_button_new_with_mnemonic("I have _saved the complete recovery record outside this computer");gtk_box_append(root,r->ack);}
    GtkWidget *done=gtk_button_new_with_mnemonic("_Done");gtk_widget_set_halign(done,GTK_ALIGN_END);gtk_box_append(root,done);g_signal_connect(done,"clicked",G_CALLBACK(reveal_done),r);g_signal_connect(w,"close-request",G_CALLBACK(reveal_close),r);
  }else{detail_nodes(content,NULL,node,0);GtkWidget *close=gtk_button_new_with_mnemonic("_Close");gtk_widget_set_halign(close,GTK_ALIGN_END);gtk_box_append(root,close);g_signal_connect(close,"clicked",G_CALLBACK(close_window),w);}
  gtk_window_set_child(w,GTK_WIDGET(root));gtk_window_present(w);
}

#define S(k,l,t,o,h,r) {k,l,t,o,h,r}
#define END {NULL,NULL,NULL,NULL,NULL,FALSE}
static const Spec vault_create[]={
 S("name","_Vault name","text",NULL,"For example, Personal. This also names the encrypted vault file.",TRUE),
 S("directory","_Save vault in","folder",NULL,"Choose a folder on your computer or a mounted drive.",TRUE),
 S("size_gb","Size in _gigabytes","number","10","Decimal GB; the actual container is rounded up to a whole MiB.",TRUE),
 S("auth","_How to unlock","choice","key|image|text|gpg",NULL,TRUE),
 S("use_existing_key","I already have a _key","boolean",NULL,"Use an existing vault key or carrier instead of generating a new one.",FALSE),
 S("key_file","_Existing key or carrier","file",NULL,"Choose the encrypted key file, image, or text file that already contains your vault key.",TRUE),
 S("image_source","_Choose an image","file",NULL,"Choose a JPEG or BMP. OctoVault hides a new encrypted key in a private copy; your original image stays unchanged.",TRUE),
 S("recipient","OpenPGP _encryption key","text",NULL,"Choose a software OpenPGP key from your keyring, or detect a compatible YubiKey. You need its private key to unlock the vault.",TRUE),
 S("cipher_file","Text cipher _file (optional)","file",NULL,"Only needed if your existing text carrier uses a custom word list. Otherwise leave this blank.",FALSE),
 S("password","_Passphrase","password",NULL,"Remember this passphrase. OctoVault never saves it.",TRUE),
 S("_confirm_password","_Confirm passphrase","password",NULL,NULL,TRUE),
 S("open_on","_Offer to unlock","choice","login|manual|drive|token",NULL,FALSE),S("drive_uuid","Key drive _UUID","text",NULL,"Used for drive-triggered unlocking.",FALSE),
 S("close_on","_Lock automatically","flags","screen-lock|logout|sleep|shutdown",NULL,FALSE),
 S("force_close","Allow force close of _busy applications","boolean",NULL,"Force closing can discard unsaved application work.",FALSE),END};
static const Spec vault_import[]={
 S("name","_Vault name","text",NULL,NULL,TRUE),S("file","_Existing encrypted vault","file",NULL,"Choose the existing encrypted vault file to register.",TRUE),
 S("auth","_How to unlock","choice","key|image|text|gpg","Select the method used by the existing key or carrier below.",TRUE),
 S("key_file","_Existing key or carrier","file",NULL,"Select its encrypted key file, image, or text carrier. Importing never generates a replacement key.",TRUE),
 S("recipient","OpenPGP _encryption key","text",NULL,"Software OpenPGP keys and compatible YubiKeys are supported.",FALSE),
 S("cipher_file","Text cipher _file (optional)","file",NULL,"Choose the original cipher for a custom text carrier; otherwise leave blank.",FALSE),
 S("open_on","_Unlock automatically","choice","login|manual|drive|token",NULL,FALSE),S("drive_uuid","Key drive _UUID","text",NULL,"Used for drive-triggered unlocking.",FALSE),
 S("close_on","_Lock automatically","flags","screen-lock|logout|sleep|shutdown",NULL,FALSE),
 S("force_close","Allow force close of _busy applications","boolean",NULL,"Force closing can discard unsaved application work.",FALSE),
 S("trust_native_hooks","Trust _scripts stored inside this vault","boolean",NULL,"Allows executable hooks from the vault to run as your account. Leave disabled for untrusted imported vaults.",FALSE),END};
static const Spec vault_settings[]={
 S("name","_Vault name","text",NULL,NULL,TRUE),
 S("auth","_Authentication","choice","key|gpg|image|text","Select the method used by the existing key or carrier below.",TRUE),
 S("key_file","_Key file or image/text carrier","file",NULL,"Select an existing compatible key. Use Replace key to change the vault's encryption key.",TRUE),
 S("recipient","OpenPGP _recipient","text",NULL,NULL,FALSE),S("cipher_file","Text cipher _file","file",NULL,"Leave blank to use OctoVault's included word-list cipher. Existing text keys need their original cipher.",FALSE),
 S("open_on","_Unlock automatically","choice","login|manual|drive|token",NULL,FALSE),
 S("drive_uuid","Key drive _UUID","text",NULL,NULL,FALSE),S("close_on","_Lock automatically","flags","screen-lock|logout|sleep|shutdown",NULL,FALSE),
 S("force_close","Allow force close of _busy applications","boolean",NULL,"Applications holding this vault open may be terminated.",FALSE),
 S("trust_native_hooks","Trust _scripts stored inside this vault","boolean",NULL,"Allows the vault's own executable hooks to run as your account. Enable only for a vault whose scripts you trust.",FALSE),
 S("hooks.open","After _opening script","file",NULL,"Runs as your user. Only choose scripts you trust.",FALSE),
 S("hooks.close","Before _closing script","file",NULL,"Runs while protected files are still accessible.",FALSE),
 S("hooks.after_close","After confirmed _lock script","file",NULL,"Runs only after the vault has been verified closed.",FALSE),END};
static const Spec vault_open[]={S("password","Key _passphrase","password",NULL,"For a password-protected vault key. Software OpenPGP keys and YubiKeys use GnuPG's own passphrase or PIN prompt.",FALSE),END};
static const Spec vault_close[]={S("force","_Force close busy applications","boolean",NULL,"May discard unsaved work. Leave disabled for a graceful lock.",FALSE),END};
static const Spec vault_resize[]={S("size_gb","New size in _gigabytes","number","20","The vault must be closed. Shrinking is not supported.",TRUE),S("password","Key _passphrase","password",NULL,NULL,FALSE),END};
static const Spec vault_passwd[]={S("old_password","_Current passphrase","password",NULL,NULL,TRUE),S("password","_New passphrase","password",NULL,NULL,TRUE),S("_confirm_password","_Confirm new passphrase","password",NULL,NULL,TRUE),END};
static const Spec vault_setkey[]={S("new_key_file","_Replacement key file","file",NULL,NULL,TRUE),S("old_password","Current key _passphrase","password",NULL,NULL,FALSE),S("password","Replacement key p_assphrase","password",NULL,NULL,FALSE),END};
static const Spec vault_export[]={S("format","_Export format","choice","key|image|text|qr",NULL,TRUE),S("output","_Output file","save",NULL,"For an image export, choose an existing JPEG carrier. Keep exported key material secure.",TRUE),S("cipher_file","Text cipher _file","file",NULL,"Leave blank to use OctoVault's included word-list cipher. Keep this word list with your recovery material.",FALSE),S("password","Key _passphrase","password",NULL,NULL,FALSE),END};
static const Spec vault_search[]={S("query","_Search text","text",NULL,NULL,TRUE),END};
static const Spec migration_add[]={S("source","_File or folder to protect","path",NULL,"The original is retained temporarily until the close/reopen comparison succeeds.",TRUE),S("relative","_Location inside vault","text",NULL,"Relative destination, for example Documents or browser/profile.",TRUE),S("password","Key _passphrase to reopen","password",NULL,NULL,FALSE),END};
static const Spec migration_recover[]={S("migration_id","_Migration identifier","text",NULL,"Find this in Migration recovery records.",TRUE),S("action","_Recovery action","choice","resume|rollback",NULL,TRUE),S("password","Key _passphrase","password",NULL,NULL,FALSE),END};
static const Spec destination_fields[]={
 S("name","_Destination name","text",NULL,NULL,TRUE),S("type","_Store backups on","choice","local|sftp|s3|rest",NULL,TRUE),
 S("endpoint","S3 or REST _endpoint","text",NULL,"Use HTTPS for remote destinations.",FALSE),S("region","S3 _region","text",NULL,NULL,FALSE),S("bucket","S3 _bucket","text",NULL,NULL,FALSE),
 S("access_key","S3 access key _ID","password",NULL,NULL,FALSE),S("secret_key","S3 secret access _key","password",NULL,NULL,FALSE),
 S("host","SSH _host","text",NULL,NULL,FALSE),S("port","SSH _port","integer","22",NULL,FALSE),S("user","SSH _username","text",NULL,NULL,FALSE),
 S("host_fingerprint","SSH host _fingerprint","text",NULL,"Verify the SHA256: fingerprint with the server administrator before connecting.",FALSE),
 S("ssh_private_key","SSH _private key","secret-file",NULL,"Paste or load the private key. It is stored as an encrypted service credential.",FALSE),S("ssh_passphrase","SSH key pass_phrase","password",NULL,NULL,FALSE),
 S("path","_Backup folder","destination-path",NULL,"Choose a folder on a local or removable drive.",FALSE),
 S("rest_username","REST user_name","text",NULL,NULL,FALSE),S("rest_password","REST _password","password",NULL,NULL,FALSE),END};
static const Spec repository_fields[]={S("name","Repository _name","text",NULL,NULL,TRUE),S("destination_id","_Destination","reference","1",NULL,TRUE),S("path","Repository _path or prefix","text",NULL,"Location within the selected destination. Use a separate path for independent backup credentials.",FALSE),END};
static const Spec repository_import[]={S("name","Repository _name","text",NULL,NULL,TRUE),S("destination_id","_Destination","reference","1",NULL,TRUE),S("path","Repository _path or prefix","text",NULL,NULL,FALSE),S("password","Repository _password","password",NULL,NULL,TRUE),END};
static const Spec repository_check[]={S("read_data","_Read and verify all stored data","boolean",NULL,"Full verification may download a large amount of data.",FALSE),END};
static const Spec repository_files[]={S("snapshot","_Snapshot","text","latest","A snapshot identifier or latest.",TRUE),S("path","_Path within snapshot","text","/",NULL,FALSE),END};
static const Spec repository_find[]={S("pattern","Filename _pattern","text",NULL,"For example *.pdf.",TRUE),END};
static const Spec repository_diff[]={S("snapshot_a","_Earlier snapshot","text",NULL,NULL,TRUE),S("snapshot_b","_Later snapshot","text","latest",NULL,TRUE),END};
static const Spec repository_restore[]={S("snapshot","_Snapshot","text","latest",NULL,TRUE),S("target","Restore _destination","folder",NULL,"A separate empty folder is recommended.",TRUE),S("include","_Include paths or patterns","lines",NULL,"One per line. Leave blank to restore the complete snapshot.",FALSE),S("overwrite","_Replace existing files","choice","never|if-newer|if-changed|always","Never keeps all existing files. Other choices can replace files at the restore destination.",TRUE),END};
static const Spec repository_forget[]={S("keep_daily","Keep _daily snapshots","integer","7",NULL,FALSE),S("keep_weekly","Keep _weekly snapshots","integer","4",NULL,FALSE),S("keep_monthly","Keep _monthly snapshots","integer","12",NULL,FALSE),S("dry_run","_Preview only","boolean","true","Keep enabled to review the selection before removing snapshots.",FALSE),END};
static const Spec repository_password[]={S("password","_New repository password","password",NULL,"Leave blank to generate a strong random password. Save the new recovery record externally.",FALSE),S("_confirm_password","_Confirm new password","password",NULL,NULL,FALSE),END};
static const Spec repository_copy[]={S("target_id","_Target repository","reference","2",NULL,TRUE),S("snapshot","_Snapshot","text","latest",NULL,TRUE),END};
static const Spec plan_fields[]={
 S("name","Backup plan _name","text",NULL,NULL,TRUE),S("repository_id","_Repository","reference","2",NULL,TRUE),
 S("sources","_Files and folders","paths",NULL,"One absolute path per line. System-owned sources are backed up with approved administrative access.",TRUE),
 S("excludes","_Exclude patterns","lines",NULL,"One pattern per line.",FALSE),S("one_file_system","Stay on each source _filesystem","boolean",NULL,NULL,FALSE),
 S("vault_id","Linked _vault","reference","0",NULL,FALSE),S("vault_mode","Vault backup _mode","choice","none|open-files|closed-container","Open-files requires every source to be inside or mapped from the linked vault. For independent sources reacting to a vault event, choose None. Closed-container requires verified closure.",FALSE),
 S("trigger","_Run backup","choice","manual|calendar|boot|idle|vault-open|vault-close|drive",NULL,TRUE),
 S("calendar","_How often","schedule","daily|hourly|weekly|monthly",NULL,FALSE),
 S("_calendar_expression","Custom calendar _schedule","text",NULL,"Optional: enter a systemd calendar expression, such as Mon..Fri 20:00. Leave blank to use the frequency selected above.",FALSE),
 S("boot_delay_sec","Seconds after _boot","integer","3600",NULL,FALSE),S("idle_sec","Idle _seconds","integer","900",NULL,FALSE),S("drive_uuid","Trigger drive _UUID","text",NULL,NULL,FALSE),
 S("on_battery","Allow running on _battery power","boolean",NULL,NULL,FALSE),S("metered","Allow _metered connections","boolean",NULL,NULL,FALSE),
 S("retention.keep_daily","Keep _daily snapshots","integer","0","All zero keeps every snapshot. Nonzero retention removes older snapshots after successful backups.",FALSE),S("retention.keep_weekly","Keep _weekly snapshots","integer","0",NULL,FALSE),S("retention.keep_monthly","Keep _monthly snapshots","integer","0",NULL,FALSE),END};
static const Spec empty_fields[]={END};
#undef S
#undef END
static const Spec *specifications(const char *op){
 if(!strcmp(op,"vault.create"))return vault_create;
 if(!strcmp(op,"vault.import"))return vault_import;
 if(!strcmp(op,"vault.update"))return vault_settings;
 if(!strcmp(op,"vault.open"))return vault_open;
 if(!strcmp(op,"vault.close"))return vault_close;
 if(!strcmp(op,"vault.resize"))return vault_resize;
 if(!strcmp(op,"vault.passwd"))return vault_passwd;
 if(!strcmp(op,"vault.setkey"))return vault_setkey;
 if(!strcmp(op,"vault.key-export"))return vault_export;
 if(!strcmp(op,"vault.search"))return vault_search;
 if(!strcmp(op,"migration.add"))return migration_add;
 if(!strcmp(op,"migration.recover"))return migration_recover;
 if(!strcmp(op,"destination.save"))return destination_fields;
 if(!strcmp(op,"repository.create"))return repository_fields;
 if(!strcmp(op,"repository.import"))return repository_import;
 if(!strcmp(op,"repository.check"))return repository_check;
 if(!strcmp(op,"repository.files"))return repository_files;
 if(!strcmp(op,"repository.find"))return repository_find;
 if(!strcmp(op,"repository.diff"))return repository_diff;
 if(!strcmp(op,"repository.restore"))return repository_restore;
 if(!strcmp(op,"repository.forget"))return repository_forget;
 if(!strcmp(op,"repository.password"))return repository_password;
 if(!strcmp(op,"repository.copy"))return repository_copy;
 if(!strcmp(op,"backup.save"))return plan_fields;
 return empty_fields;
}
static JsonNode *lookup(JsonObject *record,const char *key){
  const char *dot=strchr(key,'.');
  if(!record)return NULL;
  if(!dot)return json_object_has_member(record,key)?json_object_get_member(record,key):NULL;
  char *parent=g_strndup(key,dot-key);JsonNode *n=json_object_has_member(record,parent)?json_object_get_member(record,parent):NULL;g_free(parent);
  return n&&JSON_NODE_HOLDS_OBJECT(n)?lookup(json_node_get_object(n),dot+1):NULL;
}
static void set_nested(JsonObject *record,const char *key,JsonNode *value){
  const char *dot=strchr(key,'.');
  if(!dot){json_object_set_member(record,key,value);return;}
  char *parent=g_strndup(key,dot-key);
  if(!json_object_has_member(record,parent))json_object_set_object_member(record,parent,json_object_new());
  set_nested(json_object_get_object_member(record,parent),dot+1,value);g_free(parent);
}
static gboolean advanced_field(const char*operation,const char*key);
static const char *selected_value(Form *form,const char *key){
  for(guint i=0;i<form->fields->len;i++){
    Field*f=g_ptr_array_index(form->fields,i);
    if(!strcmp(f->spec->key,key)&&GTK_IS_DROP_DOWN(f->widget)){
      if(form->advanced&&!gtk_check_button_get_active(form->advanced)&&advanced_field(form->operation,key)){
        JsonNode*n=lookup(form->original,key);if(n&&JSON_NODE_HOLDS_VALUE(n)&&json_node_get_value_type(n)==G_TYPE_STRING)return json_node_get_string(n);
        return f->values->len?g_ptr_array_index(f->values,0):"";
      }
      guint n=gtk_drop_down_get_selected(GTK_DROP_DOWN(f->widget));
      return n<f->values->len?g_ptr_array_index(f->values,n):"";
    }
  }
  return "";
}
static Field *find_field(Form *form,const char *key){
  for(guint i=0;i<form->fields->len;i++){Field*f=g_ptr_array_index(form->fields,i);if(!strcmp(f->spec->key,key))return f;}
  return NULL;
}
static gboolean advanced_field(const char*operation,const char*key){
  if(g_str_has_prefix(operation,"vault.")){
    if(!strcmp(key,"open_on")||!strcmp(key,"close_on")||!strcmp(key,"force_close")||!strcmp(key,"trust_native_hooks")||g_str_has_prefix(key,"hooks."))return TRUE;
    if(!strcmp(key,"cipher_file"))return TRUE;
    if(!strcmp(operation,"vault.close")&&!strcmp(key,"force"))return TRUE;
  }
  if(!strcmp(operation,"destination.save"))return !strcmp(key,"port")||!strcmp(key,"region");
  if(!strcmp(operation,"repository.create")||!strcmp(operation,"repository.import"))return !strcmp(key,"path");
  if(!strcmp(operation,"repository.restore"))return !strcmp(key,"include");
  if(!strcmp(operation,"repository.check"))return !strcmp(key,"read_data");
  if(!strcmp(operation,"repository.password"))return !strcmp(key,"password")||!strcmp(key,"_confirm_password");
  if(!strcmp(operation,"backup.save"))return !strcmp(key,"_calendar_expression")||!strcmp(key,"excludes")||!strcmp(key,"one_file_system")||!strcmp(key,"vault_mode")||!strcmp(key,"on_battery")||!strcmp(key,"metered")||g_str_has_prefix(key,"retention.");
  return FALSE;
}
static JsonNode *field_default(const Spec*spec){
  JsonNode*n=json_node_new(JSON_NODE_VALUE);const char*value=spec->options?spec->options:"";
  if(!strcmp(spec->kind,"boolean"))json_node_set_boolean(n,!strcmp(value,"true"));
  else if(!strcmp(spec->kind,"integer"))json_node_set_int(n,g_ascii_strtoll(value,NULL,10));
  else if(!strcmp(spec->kind,"number"))json_node_set_double(n,g_ascii_strtod(value,NULL));
  else if(!strcmp(spec->kind,"flags")||!strcmp(spec->kind,"lines")||!strcmp(spec->kind,"paths")){
    JsonArray*a=json_array_new();if(!strcmp(spec->kind,"flags")){char**parts=g_strsplit(value,"|",-1);for(guint i=0;parts[i];i++)if(!strcmp(parts[i],"shutdown"))json_array_add_string_element(a,parts[i]);g_strfreev(parts);}
    json_node_free(n);n=json_node_new(JSON_NODE_ARRAY);json_node_take_array(n,a);
  }else if(!strcmp(spec->kind,"choice")||!strcmp(spec->kind,"schedule")){char**parts=g_strsplit(value,"|",2);json_node_set_string(n,parts[0]?parts[0]:"");g_strfreev(parts);}
  else json_node_set_string(n,!strcmp(spec->kind,"password")||!strcmp(spec->kind,"reference")?"":value);
  return n;
}
static JsonNode *hidden_advanced_value(Form*form,const Spec*spec){
  JsonNode*original=strcmp(spec->kind,"password")?lookup(form->original,spec->key):NULL;
  return original?json_node_copy(original):field_default(spec);
}
/* These rules also define which fields may be sent to the service. Hidden
 * values from an earlier selection must never influence vault creation. */
static gboolean vault_create_field_visible(const char *key,const char *auth,gboolean existing){
  if(!strcmp(key,"key_file"))return existing;
  if(!strcmp(key,"image_source"))return !existing&&!strcmp(auth,"image");
  if(!strcmp(key,"recipient"))return !existing&&!strcmp(auth,"gpg");
  if(!strcmp(key,"cipher_file"))return existing&&!strcmp(auth,"text");
  if(!strcmp(key,"password"))return strcmp(auth,"gpg")!=0;
  if(!strcmp(key,"_confirm_password"))return !existing&&strcmp(auth,"gpg")!=0;
  return TRUE;
}
static const char *vault_create_guidance(const char *auth,gboolean existing){
  if(existing){
    if(!strcmp(auth,"gpg"))return "Choose your existing OpenPGP-encrypted vault key. GnuPG will ask for your software-key passphrase or security-key PIN when needed; OctoVault does not save it.";
    if(!strcmp(auth,"image"))return "Choose the image that already contains your encrypted vault key, then enter its passphrase. An ordinary image without a hidden key cannot unlock a vault.";
    if(!strcmp(auth,"text"))return "Choose the text file that already contains your encrypted vault key, then enter its passphrase. An ordinary text document cannot unlock a vault.";
    return "Choose your existing encrypted vault key and enter its passphrase. OctoVault remembers the key's location; it never saves the passphrase.";
  }
  if(!strcmp(auth,"image"))return "OctoVault generates the key automatically, protects it with your passphrase, and hides it in a copy of your chosen image. The carrier is saved privately and its location remembered.";
  if(!strcmp(auth,"text"))return "OctoVault generates the key automatically, protects it with your passphrase, and creates a text carrier. The carrier is saved privately and its location remembered.";
  if(!strcmp(auth,"gpg"))return "OctoVault generates a vault key and encrypts it for your selected OpenPGP key. Software OpenPGP keys and compatible YubiKeys both work. GnuPG asks for your passphrase or PIN when needed.";
  return "OctoVault generates and securely stores an encrypted key for you. You only need to enter its passphrase when unlocking. The key's location is remembered; the passphrase is never saved.";
}
static void update_location_preview(GtkEditable *editable,gpointer data){
  (void)editable;Form*f=data;if(!f->location_preview)return;
  Field*name=find_field(f,"name"),*directory=find_field(f,"directory");
  const char*n=gtk_editable_get_text(GTK_EDITABLE(name->widget)),*d=gtk_editable_get_text(GTK_EDITABLE(directory->widget));
  char*filename=g_str_has_suffix(n,".tomb")?g_strdup(n):g_strconcat(n,".tomb",NULL);
  char*path=g_build_filename(d,filename,NULL);char*message=*n&&*d?g_strdup_printf("Vault file: %s",path):g_strdup("Choose a name and folder; OctoVault creates the vault file there.");
  gtk_label_set_text(f->location_preview,message);g_free(message);g_free(path);g_free(filename);
}
static void update_form_visibility(GObject *object,GParamSpec *pspec,gpointer data){
  (void)object;(void)pspec;Form*form=data;
  const char*type=selected_value(form,"type"),*auth=selected_value(form,"auth");
  const char*trigger=selected_value(form,"trigger"),*open=selected_value(form,"open_on");
  const char*mode=selected_value(form,"vault_mode"),*format=selected_value(form,"format");
  Field*existing_field=find_field(form,"use_existing_key");
  gboolean existing=existing_field&&gtk_check_button_get_active(GTK_CHECK_BUTTON(existing_field->widget));
  for(guint i=0;i<form->fields->len;i++){
    Field*f=g_ptr_array_index(form->fields,i);const char*k=f->spec->key;gboolean visible=TRUE;
    if(!strcmp(form->operation,"destination.save")){
      if(!strcmp(k,"endpoint"))visible=!strcmp(type,"s3")||!strcmp(type,"rest");
      else if(!strcmp(k,"region")||!strcmp(k,"bucket")||!strcmp(k,"access_key")||!strcmp(k,"secret_key"))visible=!strcmp(type,"s3");
      else if(!strcmp(k,"host")||!strcmp(k,"port")||!strcmp(k,"user")||!strcmp(k,"host_fingerprint")||g_str_has_prefix(k,"ssh_"))visible=!strcmp(type,"sftp");
      else if(g_str_has_prefix(k,"rest_"))visible=!strcmp(type,"rest");
      if(!strcmp(k,"path")){
        gtk_label_set_text_with_mnemonic(f->name,!strcmp(type,"local")?"_Backup folder":!strcmp(type,"sftp")?"_Server folder":"_Folder prefix (optional)");
        gtk_label_set_text(f->hint,!strcmp(type,"local")?"Choose a folder on a local or mounted removable drive.":!strcmp(type,"sftp")?"Enter the folder on your SSH server where backups will be stored.":"Leave blank to use the selected destination directly, or enter a folder prefix.");
        if(f->picker)gtk_widget_set_visible(f->picker,!strcmp(type,"local"));
      }
    }
    if(*auth){
      if(!strcmp(k,"recipient"))visible=!strcmp(auth,"gpg");
      if(!strcmp(k,"cipher_file"))visible=!strcmp(auth,"text");
      if(!strcmp(k,"password")||!strcmp(k,"_confirm_password"))visible=strcmp(auth,"gpg")!=0;
    }
    if(!strcmp(form->operation,"vault.create"))visible=vault_create_field_visible(k,auth,existing);
    if(*format&&!strcmp(k,"cipher_file"))visible=!strcmp(format,"text");
    if(*open&&!strcmp(k,"drive_uuid"))visible=!strcmp(open,"drive");
    if(!strcmp(form->operation,"backup.save")){
      if(!strcmp(k,"calendar")||!strcmp(k,"_calendar_expression"))visible=!strcmp(trigger,"calendar");
      if(!strcmp(k,"boot_delay_sec"))visible=!strcmp(trigger,"boot");
      if(!strcmp(k,"idle_sec"))visible=!strcmp(trigger,"idle");
      if(!strcmp(k,"drive_uuid"))visible=!strcmp(trigger,"drive");
      if(!strcmp(k,"vault_id"))visible=strcmp(mode,"none")!=0||!strcmp(trigger,"vault-open")||!strcmp(trigger,"vault-close");
      if(!strcmp(k,"sources"))visible=strcmp(mode,"closed-container")!=0;
    }
    f->context_visible=visible;
    if(advanced_field(form->operation,k)&&form->advanced&&!gtk_check_button_get_active(form->advanced))visible=FALSE;
    gtk_widget_set_visible(f->row,visible);
  }
  if(form->guidance)gtk_label_set_text(form->guidance,vault_create_guidance(auth,existing));
}
static void field_free(gpointer data){Field*f=data;if(f->values)g_ptr_array_unref(f->values);g_free(f);}
static void form_free(gpointer data){Form*f=data;if(f->guided_backup)backup_setup_form_closed(f->app,f->operation,f->submitted);if(f->automatic){f->app->automatic_prompt=FALSE;g_idle_add(drain_unlocks,f->app);}g_free(f->operation);json_object_unref(f->base);json_object_unref(f->original);g_ptr_array_unref(f->fields);g_free(f);}
static char *field_text(Field *f){
  if(GTK_IS_TEXT_VIEW(f->widget)){GtkTextBuffer *b=gtk_text_view_get_buffer(GTK_TEXT_VIEW(f->widget));GtkTextIter start,end;gtk_text_buffer_get_bounds(b,&start,&end);return gtk_text_buffer_get_text(b,&start,&end,FALSE);}
  return g_strdup(gtk_editable_get_text(GTK_EDITABLE(f->widget)));
}
#include "file-picker.c"

/* Public-key discovery is deliberately unprivileged and read-only. GnuPG's
 * colon protocol is used rather than parsing translated terminal output. */
typedef struct { char *fingerprint, *identity; } GpgKey;
typedef struct {
  GtkWidget *entry, *row;
  GtkWindow *parent;
  GSubprocess *process;
  GCancellable *cancel;
  guint timeout;
  gboolean detect, timed_out;
  char *card_fingerprint;
} GpgLookup;
static void gpg_key_free(gpointer data){GpgKey*k=data;g_free(k->fingerprint);g_free(k->identity);g_free(k);}
static gboolean valid_fingerprint(const char *value){
  gsize length=strlen(value);gboolean nonzero=FALSE;
  if(length!=40&&length!=64)return FALSE;
  for(gsize i=0;i<length;i++){if(!g_ascii_isxdigit(value[i]))return FALSE;if(value[i]!='0')nonzero=TRUE;}
  return nonzero;
}
static char *card_encryption_fingerprint(const char *output){
  char **lines=g_strsplit(output,"\n",-1),*fingerprint=NULL;
  for(guint i=0;lines[i];i++)if(g_str_has_prefix(lines[i],"fpr:")){
    char **parts=g_strsplit(lines[i],":",-1);
    /* OpenPGP slots are signing, encryption, then authentication. */
    if(g_strv_length(parts)>=4&&valid_fingerprint(parts[2]))fingerprint=g_ascii_strup(parts[2],-1);
    g_strfreev(parts);break;
  }
  g_strfreev(lines);return fingerprint;
}
static GPtrArray *parse_encryption_keys(const char *output){
  GPtrArray *keys=g_ptr_array_new_with_free_func(gpg_key_free);char **lines=g_strsplit(output,"\n",-1);
  char *identity=g_strdup("OpenPGP encryption key");gboolean usable=FALSE,primary_usable=TRUE;GpgKey *pending_identity=NULL;
  gint64 now=g_get_real_time()/G_USEC_PER_SEC;
  for(guint i=0;lines[i];i++){
    char **fields=g_strsplit(lines[i],":",-1);guint length=g_strv_length(fields);
    if(length>11&&(!strcmp(fields[0],"pub")||!strcmp(fields[0],"sub"))){
      gboolean primary=!strcmp(fields[0],"pub");
      gboolean available=(!*fields[1]||!strchr("redi",fields[1][0]))&&!strchr(fields[11],'D');
      gint64 expires=*fields[6]?g_ascii_strtoll(fields[6],NULL,10):0;
      if(expires&&expires<=now)available=FALSE;
      if(primary){primary_usable=available;g_free(identity);identity=g_strdup("OpenPGP encryption key");pending_identity=NULL;}
      usable=available&&primary_usable&&(strchr(fields[11],'e')||strchr(fields[11],'E'));
    }else if(length>9&&!strcmp(fields[0],"fpr")){
      if(usable&&valid_fingerprint(fields[9])){
        GpgKey*k=g_new0(GpgKey,1);k->fingerprint=g_ascii_strup(fields[9],-1);k->identity=g_strdup(identity);g_ptr_array_add(keys,k);pending_identity=k;
      }
      usable=FALSE;
    }else if(length>9&&!strcmp(fields[0],"uid")&&(!*fields[1]||!strchr("red",fields[1][0]))){
      g_free(identity);identity=g_utf8_make_valid(fields[9],-1);
      if(pending_identity){g_free(pending_identity->identity);pending_identity->identity=g_strdup(identity);pending_identity=NULL;}
    }
    g_strfreev(fields);
  }
  g_strfreev(lines);g_free(identity);return keys;
}
static void gpg_lookup_free(GpgLookup *lookup){
  if(lookup->timeout)g_source_remove(lookup->timeout);
  gtk_widget_set_sensitive(lookup->row,TRUE);
  g_clear_object(&lookup->process);g_clear_object(&lookup->cancel);g_object_unref(lookup->entry);g_object_unref(lookup->row);g_object_unref(lookup->parent);g_free(lookup->card_fingerprint);g_free(lookup);
}
static void gpg_message(GpgLookup *lookup,const char *message){
  if(gtk_widget_get_visible(GTK_WIDGET(lookup->parent))){GtkAlertDialog*dialog=gtk_alert_dialog_new("%s",message);gtk_alert_dialog_show(dialog,lookup->parent);g_object_unref(dialog);}
}
static gboolean gpg_timeout(gpointer data){GpgLookup*lookup=data;lookup->timeout=0;lookup->timed_out=TRUE;g_subprocess_force_exit(lookup->process);g_cancellable_cancel(lookup->cancel);return G_SOURCE_REMOVE;}
typedef struct { GtkWidget *entry; GtkWindow *window; char *recipient; } GpgChoice;
static void gpg_choice_free(gpointer data,GClosure*closure){(void)closure;GpgChoice*choice=data;g_object_unref(choice->entry);g_free(choice->recipient);g_free(choice);}
static void gpg_choice_clicked(GtkButton*button,gpointer data){(void)button;GpgChoice*choice=data;gtk_editable_set_text(GTK_EDITABLE(choice->entry),choice->recipient);gtk_window_destroy(choice->window);}
static void gpg_choose_result(GpgLookup *lookup,GPtrArray *keys){
  GtkWindow*w=GTK_WINDOW(gtk_window_new());gtk_window_set_title(w,"Choose an OpenPGP recipient");gtk_window_set_transient_for(w,lookup->parent);gtk_window_set_destroy_with_parent(w,TRUE);gtk_window_set_modal(w,TRUE);gtk_window_set_default_size(w,650,500);
  GtkBox*box=GTK_BOX(gtk_box_new(GTK_ORIENTATION_VERTICAL,12));margin(GTK_WIDGET(box),24);append_text(box,"Choose an encryption key","title-2");append_text(box,"These usable public keys are already in your personal GnuPG keyring. Use Detect security key to match a connected hardware token.","dim-label");
  GtkWidget*scroll=gtk_scrolled_window_new();gtk_widget_set_vexpand(scroll,TRUE);GtkBox*list=GTK_BOX(gtk_box_new(GTK_ORIENTATION_VERTICAL,12));gtk_scrolled_window_set_child(GTK_SCROLLED_WINDOW(scroll),GTK_WIDGET(list));gtk_box_append(box,scroll);
  for(guint i=0;i<keys->len&&i<256;i++){
    GpgKey*key=g_ptr_array_index(keys,i);GtkBox*row=GTK_BOX(gtk_box_new(GTK_ORIENTATION_VERTICAL,6));margin(GTK_WIDGET(row),12);gtk_widget_add_css_class(GTK_WIDGET(row),"card");gtk_box_append(list,GTK_WIDGET(row));append_text(row,key->identity,"heading");GtkWidget*fingerprint=label(key->fingerprint,"monospace");gtk_label_set_selectable(GTK_LABEL(fingerprint),TRUE);gtk_box_append(row,fingerprint);
    GtkWidget*button=gtk_button_new_with_label("Use this key");gtk_widget_set_halign(button,GTK_ALIGN_START);gtk_box_append(row,button);GpgChoice*choice=g_new0(GpgChoice,1);choice->entry=g_object_ref(lookup->entry);choice->window=w;choice->recipient=g_strdup(key->fingerprint);g_signal_connect_data(button,"clicked",G_CALLBACK(gpg_choice_clicked),choice,gpg_choice_free,0);
  }
  if(keys->len>256)append_text(box,"Only the first 256 keys are displayed. You can enter any full fingerprint directly in the recipient field.","dim-label");
  GtkWidget*close=gtk_button_new_with_label("Cancel");gtk_widget_set_halign(close,GTK_ALIGN_END);g_signal_connect(close,"clicked",G_CALLBACK(close_window),w);gtk_box_append(box,close);gtk_window_set_child(w,GTK_WIDGET(box));gtk_window_present(w);
}
static void gpg_lookup_launch(GpgLookup *lookup,gboolean card);
static void gpg_lookup_finished(GObject *source,GAsyncResult *result,gpointer data){
  GpgLookup*lookup=data;char*output=NULL;GError*error=NULL;
  gboolean completed=g_subprocess_communicate_utf8_finish(G_SUBPROCESS(source),result,&output,NULL,&error);
  if(lookup->timeout){g_source_remove(lookup->timeout);lookup->timeout=0;}
  if(!gtk_widget_get_visible(GTK_WIDGET(lookup->parent))){g_free(output);g_clear_error(&error);gpg_lookup_free(lookup);return;}
  if(!completed||!g_subprocess_get_successful(G_SUBPROCESS(source))||!output||strlen(output)>1048576){
    gpg_message(lookup,lookup->timed_out?"The security key or GnuPG keyring did not respond within 12 seconds. Check the connection and try again.":lookup->detect&&!lookup->card_fingerprint?"No usable OpenPGP security key was found. Connect a key with an existing OpenPGP encryption key and check that its OpenPGP application is enabled.":"The public key could not be read. Import the matching public key into your personal GnuPG keyring, then try again. This action does not initialize or reset a security key.");
    g_free(output);g_clear_error(&error);gpg_lookup_free(lookup);return;
  }
  if(lookup->detect&&!lookup->card_fingerprint){
    lookup->card_fingerprint=card_encryption_fingerprint(output);g_free(output);
    if(!lookup->card_fingerprint){gpg_message(lookup,"The connected OpenPGP card has no encryption key in its encryption slot. Set up or restore its OpenPGP encryption key using your security-key management software, then detect it again. OctoVault will not modify or reset the card.");gpg_lookup_free(lookup);return;}
    gpg_lookup_launch(lookup,FALSE);return;
  }
  GPtrArray*keys=parse_encryption_keys(output);g_free(output);
  if(lookup->detect){
    gboolean matched=FALSE;for(guint i=0;i<keys->len;i++){GpgKey*key=g_ptr_array_index(keys,i);if(!strcmp(key->fingerprint,lookup->card_fingerprint)){matched=TRUE;break;}}
    if(matched){char*recipient=g_strconcat(lookup->card_fingerprint,"!",NULL);gtk_editable_set_text(GTK_EDITABLE(lookup->entry),recipient);g_free(recipient);gpg_message(lookup,"Security key detected. Its encryption fingerprint has been selected. Unlocking will honour the key's PIN and touch policy. Keep a separate recovery key.");}
    else gpg_message(lookup,"The security key is connected, but its matching usable public encryption key is missing from your GnuPG keyring. Import that public key into your account, then detect the security key again. No private key needs to be exported from the device.");
  }else if(keys->len)gpg_choose_result(lookup,keys);
  else gpg_message(lookup,"No usable public encryption keys are available in your GnuPG keyring. Import your public key using your OpenPGP key manager, then choose it here. Revoked, expired and disabled keys are excluded.");
  g_ptr_array_unref(keys);gpg_lookup_free(lookup);
}
static void gpg_lookup_launch(GpgLookup *lookup,gboolean card){
  g_clear_object(&lookup->process);g_clear_object(&lookup->cancel);lookup->cancel=g_cancellable_new();GError*error=NULL;
  const char *card_args[]={"/usr/bin/gpg","--no-options","--batch","--no-tty","--with-colons","--card-status",NULL};
  const char *list_args[]={"/usr/bin/gpg","--no-options","--batch","--no-tty","--with-colons","--with-fingerprint","--with-subkey-fingerprint","--list-keys",lookup->card_fingerprint,NULL};
  lookup->process=g_subprocess_newv(card?card_args:list_args,G_SUBPROCESS_FLAGS_STDOUT_PIPE|G_SUBPROCESS_FLAGS_STDERR_SILENCE,&error);
  if(!lookup->process){gpg_message(lookup,"GnuPG could not start. Install the OctoVault package dependencies and try again.");g_clear_error(&error);gpg_lookup_free(lookup);return;}
  lookup->timeout=g_timeout_add_seconds(12,gpg_timeout,lookup);g_subprocess_communicate_utf8_async(lookup->process,NULL,lookup->cancel,gpg_lookup_finished,lookup);
}
static void choose_gpg(GtkButton*button,gpointer data){
  Field*field=data;GpgLookup*lookup=g_new0(GpgLookup,1);lookup->entry=g_object_ref(field->widget);lookup->row=g_object_ref(field->row);lookup->parent=g_object_ref(GTK_WINDOW(gtk_widget_get_root(GTK_WIDGET(button))));lookup->detect=GPOINTER_TO_INT(g_object_get_data(G_OBJECT(button),"detect-token"));gtk_widget_set_sensitive(field->row,FALSE);gpg_lookup_launch(lookup,lookup->detect);
}
typedef struct { GtkWidget *entry; GtkWindow *window; char *uuid; } DriveChoice;
static void drive_choice_free(gpointer data,GClosure*closure){(void)closure;DriveChoice*choice=data;g_object_unref(choice->entry);g_free(choice->uuid);g_free(choice);}
static void drive_choice_clicked(GtkButton*button,gpointer data){(void)button;DriveChoice*choice=data;gtk_editable_set_text(GTK_EDITABLE(choice->entry),choice->uuid);gtk_window_destroy(choice->window);}
static void choose_drive(GtkButton*button,gpointer data){
  Field*field=data;GtkWindow*parent=GTK_WINDOW(gtk_widget_get_root(GTK_WIDGET(button)));
  GtkWindow*window=GTK_WINDOW(gtk_window_new());gtk_window_set_title(window,"Choose a drive");gtk_window_set_transient_for(window,parent);gtk_window_set_destroy_with_parent(window,TRUE);gtk_window_set_modal(window,TRUE);gtk_window_set_default_size(window,620,480);
  GtkBox*box=GTK_BOX(gtk_box_new(GTK_ORIENTATION_VERTICAL,14));margin(GTK_WIDGET(box),24);append_text(box,"Choose a mounted drive","title-2");append_text(box,"OctoVault remembers the filesystem's stable identity, so the drive can be recognized when it mounts again.","dim-label");
  GtkWidget*scroll=gtk_scrolled_window_new();gtk_widget_set_vexpand(scroll,TRUE);gtk_box_append(box,scroll);GtkBox*list=GTK_BOX(gtk_box_new(GTK_ORIENTATION_VERTICAL,12));gtk_scrolled_window_set_child(GTK_SCROLLED_WINDOW(scroll),GTK_WIDGET(list));
  /* GVolumeMonitor supplies the desktop's current local mount inventory. No
   * root helper, network request, mounting or filesystem scanning is done. */
  GVolumeMonitor*monitor=g_volume_monitor_get();GList*mounts=g_volume_monitor_get_mounts(monitor);guint count=0;
  for(GList*item=mounts;item;item=item->next){
    GMount*mount=G_MOUNT(item->data);GFile*root=g_mount_get_root(mount);char*path=g_file_get_path(root);char*uuid=g_mount_get_uuid(mount);
    if(!uuid||!*uuid){GVolume*volume=g_mount_get_volume(mount);g_free(uuid);uuid=volume?g_volume_get_uuid(volume):NULL;g_clear_object(&volume);}
    if(path&&uuid&&*uuid){
      char*name=g_mount_get_name(mount);GtkBox*row=GTK_BOX(gtk_box_new(GTK_ORIENTATION_VERTICAL,6));margin(GTK_WIDGET(row),12);gtk_widget_add_css_class(GTK_WIDGET(row),"card");gtk_box_append(list,GTK_WIDGET(row));append_text(row,name,"heading");append_text(row,path,NULL);append_text(row,uuid,"dim-label");
      GtkWidget*use=gtk_button_new_with_label("Use this drive");gtk_widget_set_halign(use,GTK_ALIGN_START);gtk_box_append(row,use);DriveChoice*choice=g_new0(DriveChoice,1);choice->entry=g_object_ref(field->widget);choice->window=window;choice->uuid=g_strdup(uuid);g_signal_connect_data(use,"clicked",G_CALLBACK(drive_choice_clicked),choice,drive_choice_free,0);g_free(name);count++;
    }
    g_free(path);g_free(uuid);g_object_unref(root);
  }
  g_list_free_full(mounts,g_object_unref);g_object_unref(monitor);
  if(!count)append_text(list,"No mounted local drives with a filesystem UUID are available. Connect and mount your drive in Files, then reopen this chooser. You can also enter a known filesystem UUID directly.",NULL);
  GtkWidget*close=gtk_button_new_with_label("Cancel");gtk_widget_set_halign(close,GTK_ALIGN_END);gtk_box_append(box,close);g_signal_connect(close,"clicked",G_CALLBACK(close_window),window);gtk_window_set_child(window,GTK_WIDGET(box));gtk_window_present(window);
}
static char *choice_label(const char *s){
  if(!strcmp(s,"key"))return g_strdup("Password-protected key file");
  if(!strcmp(s,"gpg"))return g_strdup("OpenPGP key or YubiKey");
  if(!strcmp(s,"image"))return g_strdup("Key hidden in an image");
  if(!strcmp(s,"text"))return g_strdup("Key hidden in text");
  if(!strcmp(s,"s3"))return g_strdup("S3-compatible object storage");
  if(!strcmp(s,"sftp"))return g_strdup("SSH / SFTP server");
  if(!strcmp(s,"rest"))return g_strdup("REST backup server");
  if(!strcmp(s,"local"))return g_strdup("Local or removable drive");
  if(!strcmp(s,"login"))return g_strdup("After desktop login");
  if(!strcmp(s,"boot"))return g_strdup("After computer startup");
  if(!strcmp(s,"calendar"))return g_strdup("Calendar schedule");
  if(!strcmp(s,"daily"))return g_strdup("Every day");
  if(!strcmp(s,"hourly"))return g_strdup("Every hour");
  if(!strcmp(s,"weekly"))return g_strdup("Every week");
  if(!strcmp(s,"monthly"))return g_strdup("Every month");
  if(!strcmp(s,"manual"))return g_strdup("Only when I choose");
  if(!strcmp(s,"idle"))return g_strdup("When the computer is idle");
  if(!strcmp(s,"drive"))return g_strdup("When the selected drive appears");
  if(!strcmp(s,"token"))return g_strdup("When the security key appears");
  if(!strcmp(s,"screen-lock"))return g_strdup("Screen locks");
  if(!strcmp(s,"sleep"))return g_strdup("Suspend or hibernate");
  if(!strcmp(s,"shutdown"))return g_strdup("Computer shuts down");
  if(!strcmp(s,"logout"))return g_strdup("Desktop session ends");
  if(!strcmp(s,"vault-open"))return g_strdup("After the linked vault opens");
  if(!strcmp(s,"vault-close"))return g_strdup("After the linked vault locks");
  if(!strcmp(s,"open-files"))return g_strdup("Files inside an open vault");
  if(!strcmp(s,"closed-container"))return g_strdup("Closed encrypted container");
  return humanize(s);
}
static gboolean string_array_has(JsonNode*n,const char*s){if(!n||!JSON_NODE_HOLDS_ARRAY(n))return FALSE;JsonArray*a=json_node_get_array(n);for(guint i=0;i<json_array_get_length(a);i++){JsonNode*v=json_array_get_element(a,i);if(JSON_NODE_HOLDS_VALUE(v)&&json_node_get_value_type(v)==G_TYPE_STRING&&!strcmp(json_node_get_string(v),s))return TRUE;}return FALSE;}
static void size_changed(GtkSpinButton*spin,gpointer data){
  long double requested=(long double)gtk_spin_button_get_value(spin)*1000000000.0L/1048576.0L;
  guint64 mib=(guint64)requested;if((long double)mib<requested)mib++;
  char*text=g_strdup_printf("Allocated container: %.6f GB (%" G_GUINT64_FORMAT " MiB). Filesystem overhead reduces usable space.",(double)mib*1048576.0/1000000000.0,mib);
  gtk_label_set_text(GTK_LABEL(data),text);g_free(text);
}
static Field *create_field(Form*form,const Spec*spec,JsonObject*record,GtkBox*content){
  Field*f=g_new0(Field,1);f->spec=spec;JsonNode*existing=lookup(record,spec->key);char *initial=existing?node_text(existing):g_strdup(spec->options?spec->options:"");
  GtkBox*row=GTK_BOX(gtk_box_new(GTK_ORIENTATION_VERTICAL,5));f->row=GTK_WIDGET(row);gtk_box_append(content,GTK_WIDGET(row));
  GtkWidget*name=gtk_label_new_with_mnemonic(spec->label);f->name=GTK_LABEL(name);gtk_label_set_xalign(GTK_LABEL(name),0);gtk_widget_add_css_class(name,"heading");gtk_box_append(row,name);
  const char *kind=spec->kind;
  if(!strcmp(kind,"boolean")){f->widget=gtk_check_button_new_with_mnemonic(spec->label);gtk_widget_set_visible(name,FALSE);gtk_check_button_set_active(GTK_CHECK_BUTTON(f->widget),existing?json_node_get_boolean(existing):spec->options&&!strcmp(spec->options,"true"));gtk_box_append(row,f->widget);}
  else if(!strcmp(kind,"flags")){
    f->widget=gtk_box_new(GTK_ORIENTATION_VERTICAL,4);f->values=g_ptr_array_new_with_free_func(g_free);char**options=g_strsplit(spec->options,"|",-1);
    for(guint i=0;options[i];i++){char*t=choice_label(options[i]);GtkWidget*b=gtk_check_button_new_with_label(t);g_free(t);gtk_check_button_set_active(GTK_CHECK_BUTTON(b),existing?string_array_has(existing,options[i]):!strcmp(options[i],"shutdown"));gtk_box_append(GTK_BOX(f->widget),b);g_ptr_array_add(f->values,g_strdup(options[i]));}g_strfreev(options);gtk_box_append(row,f->widget);
  }else if(!strcmp(kind,"choice")||!strcmp(kind,"schedule")||!strcmp(kind,"reference")){
    GtkStringList*model=gtk_string_list_new(NULL);f->values=g_ptr_array_new_with_free_func(g_free);guint selected=0;
    if(!strcmp(kind,"reference")){
      gtk_string_list_append(model,spec->required?"Select…":"None");g_ptr_array_add(f->values,g_strdup(""));
      guint index=(guint)atoi(spec->options);JsonNode*n=form->app->collections[index];
      if(n&&JSON_NODE_HOLDS_ARRAY(n)){JsonArray*a=json_node_get_array(n);for(guint i=0;i<json_array_get_length(a);i++){JsonNode*item=json_array_get_element(a,i);if(!JSON_NODE_HOLDS_OBJECT(item))continue;JsonObject*o=json_node_get_object(item);gtk_string_list_append(model,str(o,"name"));g_ptr_array_add(f->values,g_strdup(str(o,"id")));if(existing&&!strcmp(initial,str(o,"id")))selected=f->values->len-1;}}
    }else{gboolean matched=FALSE;char**options=g_strsplit(spec->options,"|",-1);for(guint i=0;options[i];i++){char*t=choice_label(options[i]);gtk_string_list_append(model,t);g_free(t);g_ptr_array_add(f->values,g_strdup(options[i]));if(existing&&!strcmp(initial,options[i])){selected=i;matched=TRUE;}}g_strfreev(options);if(!strcmp(kind,"schedule")&&existing&&*initial&&!matched){char*t=g_strdup_printf("Custom: %s",initial);gtk_string_list_append(model,t);g_free(t);g_ptr_array_add(f->values,g_strdup(initial));selected=f->values->len-1;}}
    f->widget=gtk_drop_down_new(G_LIST_MODEL(model),NULL);gtk_drop_down_set_selected(GTK_DROP_DOWN(f->widget),selected);gtk_box_append(row,f->widget);
  }else if(!strcmp(kind,"number")||!strcmp(kind,"integer")){
    f->widget=gtk_spin_button_new_with_range(!strcmp(kind,"number")?0.001:0,100000000, !strcmp(kind,"number")?0.1:1);gtk_spin_button_set_digits(GTK_SPIN_BUTTON(f->widget),!strcmp(kind,"number")?3:0);gtk_spin_button_set_value(GTK_SPIN_BUTTON(f->widget),g_ascii_strtod(initial,NULL));gtk_box_append(row,f->widget);
  }else if(!strcmp(kind,"lines")||!strcmp(kind,"paths")||!strcmp(kind,"secret-file")){
    f->widget=gtk_text_view_new();gtk_text_view_set_wrap_mode(GTK_TEXT_VIEW(f->widget),GTK_WRAP_WORD_CHAR);gtk_text_view_set_monospace(GTK_TEXT_VIEW(f->widget),TRUE);gtk_widget_set_size_request(f->widget,-1,90);
    if(existing)gtk_text_buffer_set_text(gtk_text_view_get_buffer(GTK_TEXT_VIEW(f->widget)),initial,-1);
    GtkWidget*scroll=gtk_scrolled_window_new();gtk_scrolled_window_set_min_content_height(GTK_SCROLLED_WINDOW(scroll),90);gtk_scrolled_window_set_max_content_height(GTK_SCROLLED_WINDOW(scroll),160);gtk_scrolled_window_set_child(GTK_SCROLLED_WINDOW(scroll),f->widget);gtk_widget_add_css_class(scroll,"frame");gtk_box_append(row,scroll);
    if(!strcmp(kind,"secret-file")){GtkWidget*b=gtk_button_new_with_label("Load private key…");gtk_box_append(row,b);g_signal_connect(b,"clicked",G_CALLBACK(choose_file),f);}
    if(!strcmp(kind,"paths")){GtkBox*buttons=GTK_BOX(gtk_box_new(GTK_ORIENTATION_HORIZONTAL,8));gtk_box_append(row,GTK_WIDGET(buttons));GtkWidget*b=gtk_button_new_with_label("Add files…");gtk_box_append(buttons,b);g_signal_connect(b,"clicked",G_CALLBACK(choose_file),f);b=gtk_button_new_with_label("Add folders…");g_object_set_data(G_OBJECT(b),"choose-folder",GINT_TO_POINTER(1));gtk_box_append(buttons,b);g_signal_connect(b,"clicked",G_CALLBACK(choose_file),f);}
  }else{
    f->widget=!strcmp(kind,"password")?gtk_password_entry_new():gtk_entry_new();
    if(!strcmp(kind,"password"))gtk_password_entry_set_show_peek_icon(GTK_PASSWORD_ENTRY(f->widget),TRUE);
    else gtk_editable_set_text(GTK_EDITABLE(f->widget),!existing&&!strcmp(spec->key,"directory")?g_get_home_dir():initial);
    GtkBox*line=GTK_BOX(gtk_box_new(GTK_ORIENTATION_HORIZONTAL,8));gtk_widget_set_hexpand(f->widget,TRUE);gtk_box_append(line,f->widget);gtk_box_append(row,GTK_WIDGET(line));
    if(!strcmp(spec->key,"recipient")){
      GtkBox*controls=GTK_BOX(gtk_box_new(GTK_ORIENTATION_HORIZONTAL,8));gtk_box_append(row,GTK_WIDGET(controls));
      GtkWidget*detect=gtk_button_new_with_label("Detect security key");g_object_set_data(G_OBJECT(detect),"detect-token",GINT_TO_POINTER(1));g_signal_connect(detect,"clicked",G_CALLBACK(choose_gpg),f);gtk_box_append(controls,detect);
      GtkWidget*choose=gtk_button_new_with_label("Choose existing key…");g_signal_connect(choose,"clicked",G_CALLBACK(choose_gpg),f);gtk_box_append(controls,choose);
    }
    if(!strcmp(spec->key,"drive_uuid")){GtkWidget*choose=gtk_button_new_with_label("Choose drive…");g_signal_connect(choose,"clicked",G_CALLBACK(choose_drive),f);gtk_box_append(row,choose);}
    if(!strcmp(kind,"destination-path")){GtkWidget*b=gtk_button_new_from_icon_name("folder-open-symbolic");f->picker=b;gtk_widget_set_tooltip_text(b,"Choose a backup folder");gtk_accessible_update_property(GTK_ACCESSIBLE(b),GTK_ACCESSIBLE_PROPERTY_LABEL,"Choose a backup folder",-1);g_object_set_data(G_OBJECT(b),"choose-folder",GINT_TO_POINTER(1));gtk_box_append(line,b);g_signal_connect(b,"clicked",G_CALLBACK(choose_file),f);}
    if(!strcmp(kind,"file")||!strcmp(kind,"folder")||!strcmp(kind,"path")||!strcmp(kind,"save")){const char*description=!strcmp(kind,"folder")?"Choose a folder":"Choose a file";GtkWidget*b=gtk_button_new_from_icon_name(!strcmp(kind,"folder")?"folder-open-symbolic":"document-open-symbolic");gtk_widget_set_tooltip_text(b,description);gtk_accessible_update_property(GTK_ACCESSIBLE(b),GTK_ACCESSIBLE_PROPERTY_LABEL,description,-1);gtk_box_append(line,b);g_signal_connect(b,"clicked",G_CALLBACK(choose_file),f);if(!strcmp(kind,"path")){b=gtk_button_new_from_icon_name("folder-open-symbolic");gtk_widget_set_tooltip_text(b,"Choose a folder");gtk_accessible_update_property(GTK_ACCESSIBLE(b),GTK_ACCESSIBLE_PROPERTY_LABEL,"Choose a folder",-1);g_object_set_data(G_OBJECT(b),"choose-folder",GINT_TO_POINTER(1));gtk_box_append(line,b);g_signal_connect(b,"clicked",G_CALLBACK(choose_file),f);}}
  }
  gtk_label_set_mnemonic_widget(GTK_LABEL(name),f->widget);
  char*accessible=g_strdup(spec->label);for(char*p=accessible;*p;p++)if(*p=='_')memmove(p,p+1,strlen(p));
  gtk_accessible_update_property(GTK_ACCESSIBLE(f->widget),GTK_ACCESSIBLE_PROPERTY_LABEL,accessible,-1);g_free(accessible);
  if(spec->hint){f->hint=GTK_LABEL(label(spec->hint,"dim-label"));gtk_box_append(row,GTK_WIDGET(f->hint));}
  if(!strcmp(spec->key,"size_gb")){GtkWidget*actual=label("","dim-label");gtk_box_append(row,actual);g_signal_connect(f->widget,"value-changed",G_CALLBACK(size_changed),actual);size_changed(GTK_SPIN_BUTTON(f->widget),actual);}
  g_free(initial);g_ptr_array_add(form->fields,f);return f;
}
static const char *vault_creation_error(JsonObject *params){
  const char*name=str(params,"name"),*directory=str(params,"directory"),*auth=str(params,"auth");
  if(!*name)return "Give your vault a name.";
  if(!strcmp(name,".")||!strcmp(name,"..")||strchr(name,'/'))return "Use a vault name without folder separators.";
  for(const char*p=name;*p;p++)if(g_ascii_iscntrl(*p))return "The vault name cannot contain control characters.";
  if(!*directory||!g_path_is_absolute(directory))return "Choose a folder in Save vault in.";
  if(!g_file_test(directory,G_FILE_TEST_IS_DIR))return "The selected folder is unavailable. Choose an existing folder or connect its drive.";
  if(!json_object_has_member(params,"size_gb")||json_object_get_double_member(params,"size_gb")<=0)return "Choose a vault size greater than zero.";
  if(boolean(params,"use_existing_key")){
    if(!*str(params,"key_file"))return "Choose your existing encrypted key or carrier.";
    if(!g_file_test(str(params,"key_file"),G_FILE_TEST_IS_REGULAR))return "The selected key or carrier is unavailable. Choose an existing file.";
  }else{
    if(!strcmp(auth,"image")&&(!*str(params,"image_source")||!g_file_test(str(params,"image_source"),G_FILE_TEST_IS_REGULAR)))return "Choose an existing JPEG or BMP image to carry your new key.";
    if(!strcmp(auth,"gpg")&&!*str(params,"recipient"))return "Choose an OpenPGP encryption key or detect your YubiKey.";
  }
  if(strcmp(auth,"gpg")&&!*str(params,"password"))return "Enter the passphrase that protects your vault key.";
  return NULL;
}
static const char *destination_setup_error(JsonObject*params,JsonObject*original){
  const char*type=str(params,"type");gboolean existing=*str(original,"id")&&!strcmp(type,str(original,"type"));
  if(!strcmp(type,"local")&&!g_path_is_absolute(str(params,"path")))return "Choose a backup folder on your computer or a mounted drive.";
  if((!strcmp(type,"s3")||!strcmp(type,"rest"))&&!*str(params,"endpoint"))return "Enter the HTTPS address supplied by your storage provider.";
  if(!strcmp(type,"s3")){
    if(!*str(params,"bucket"))return "Enter your S3 bucket name.";
    if(!existing&&(!*str(params,"access_key")||!*str(params,"secret_key")))return "Enter both the access key ID and secret access key for your S3 storage.";
  }
  if(!strcmp(type,"sftp")){
    if(!*str(params,"host"))return "Enter your SSH server's hostname or IP address.";
    if(!*str(params,"user"))return "Enter the username used to connect to your SSH server.";
    if(!*str(params,"path"))return "Enter the server folder that will hold your backups.";
    if(!*str(params,"host_fingerprint"))return "Enter the server's verified SHA256 host-key fingerprint. Ask your server administrator for it.";
    if(!existing&&!*str(params,"ssh_private_key"))return "Load or paste the SSH private key used for this server.";
  }
  return NULL;
}
static JsonObject *form_parameters(Form*f,gboolean*accepted){
  JsonObject*params=copy_object(f->base);gboolean valid=TRUE;
  for(guint i=0;i<f->fields->len;i++){
    Field*field=g_ptr_array_index(f->fields,i);const Spec*s=field->spec;JsonNode*n=json_node_new(JSON_NODE_VALUE);
    if(s->key[0]=='_'){json_node_free(n);continue;}
    if(!gtk_widget_get_visible(field->row)){
      json_node_free(n);
      if(field->context_visible&&advanced_field(f->operation,s->key))set_nested(params,s->key,hidden_advanced_value(f,s));
      continue;
    }
    if(!strcmp(s->kind,"boolean"))json_node_set_boolean(n,gtk_check_button_get_active(GTK_CHECK_BUTTON(field->widget)));
    else if(!strcmp(s->kind,"number"))json_node_set_double(n,gtk_spin_button_get_value(GTK_SPIN_BUTTON(field->widget)));
    else if(!strcmp(s->kind,"integer"))json_node_set_int(n,(gint64)gtk_spin_button_get_value(GTK_SPIN_BUTTON(field->widget)));
    else if(!strcmp(s->kind,"flags")){
      JsonArray*a=json_array_new();guint j=0;for(GtkWidget*w=gtk_widget_get_first_child(field->widget);w;w=gtk_widget_get_next_sibling(w),j++)if(gtk_check_button_get_active(GTK_CHECK_BUTTON(w)))json_array_add_string_element(a,g_ptr_array_index(field->values,j));json_node_free(n);n=json_node_new(JSON_NODE_ARRAY);json_node_take_array(n,a);
    }else{
      char*value=NULL;
      if(GTK_IS_DROP_DOWN(field->widget)){guint selected=gtk_drop_down_get_selected(GTK_DROP_DOWN(field->widget));value=g_strdup(selected<field->values->len?g_ptr_array_index(field->values,selected):"");}
      else value=field_text(field);
      if(!*value&&!strcmp(s->key,"mountpoint")){g_free(value);json_node_free(n);continue;}
      if(s->required&&!*value){char*caption=g_strdup(s->label);for(char*p=caption;*p;p++)if(*p=='_')memmove(p,p+1,strlen(p));char*msg=g_strdup_printf("Please complete %s.",caption);gtk_label_set_text(f->error,msg);g_free(msg);g_free(caption);gtk_widget_grab_focus(field->widget);valid=FALSE;wipe(value);g_free(value);json_node_free(n);break;}
      if(!strcmp(s->kind,"lines")||!strcmp(s->kind,"paths")){
        JsonArray*a=json_array_new();char**lines=g_strsplit(value,"\n",-1);for(guint j=0;lines[j];j++){if(*lines[j])json_array_add_string_element(a,lines[j]);}g_strfreev(lines);json_node_free(n);n=json_node_new(JSON_NODE_ARRAY);json_node_take_array(n,a);
      }else json_node_set_string(n,value);
      wipe(value);g_free(value);
    }
    set_nested(params,s->key,n);
  }
  if(valid){
    Field*custom_schedule=find_field(f,"_calendar_expression");
    if(custom_schedule&&gtk_widget_get_visible(custom_schedule->row)){char*value=field_text(custom_schedule);if(*value)json_object_set_string_member(params,"calendar",value);g_free(value);}
    for(guint i=0;i<f->fields->len;i++){
      Field*field=g_ptr_array_index(f->fields,i);
      if(!strcmp(field->spec->key,"_confirm_password")&&gtk_widget_get_visible(field->row)){
        char*confirmation=field_text(field);
        if(strcmp(confirmation,str(params,"password"))){gtk_label_set_text(f->error,"The password confirmation does not match.");gtk_widget_grab_focus(field->widget);valid=FALSE;}
        wipe(confirmation);g_free(confirmation);
      }
    }
    if(!strcmp(f->operation,"backup.save")&&(!strcmp(str(params,"trigger"),"vault-open")||!strcmp(str(params,"trigger"),"vault-close")||(*str(params,"vault_mode")&&strcmp(str(params,"vault_mode"),"none")))&&!*str(params,"vault_id")){
      gtk_label_set_text(f->error,"Select the vault used by this backup's event or source mode.");valid=FALSE;
    }
    if(!strcmp(f->operation,"backup.save")&&!strcmp(str(params,"vault_mode"),"closed-container")){
      const char*id=str(params,"vault_id");JsonArray*sources=json_array_new();JsonNode*collection=f->app->collections[0];
      if(collection&&JSON_NODE_HOLDS_ARRAY(collection)){
        JsonArray*vaults=json_node_get_array(collection);
        for(guint i=0;i<json_array_get_length(vaults);i++){JsonNode*v=json_array_get_element(vaults,i);if(JSON_NODE_HOLDS_OBJECT(v)&&!strcmp(str(json_node_get_object(v),"id"),id))json_array_add_string_element(sources,str(json_node_get_object(v),"file"));}
      }
      json_object_set_array_member(params,"sources",sources);
      if(!*id){gtk_label_set_text(f->error,"Select the vault whose encrypted container should be backed up.");valid=FALSE;}
    }
    if(!strcmp(f->operation,"vault.create")){const char*error=vault_creation_error(params);if(error){gtk_label_set_text(f->error,error);valid=FALSE;}}
    if(!strcmp(f->operation,"destination.save")){const char*error=destination_setup_error(params,f->original);if(error){gtk_label_set_text(f->error,error);valid=FALSE;}}
  }
  *accepted=valid;return params;
}
static void submit_form(GtkButton*button,gpointer data){
  (void)button;Form*f=data;gboolean valid;JsonObject*params=form_parameters(f,&valid);
  if(valid){f->submitted=TRUE;start_operation(f->app,f->operation,params,gtk_window_get_title(f->window),-1,f->acknowledge);gtk_window_destroy(f->window);}
  json_object_unref(params);
}
static void open_form(App*app,const char*operation,const char*title,JsonObject*record){
  if(app->active&&!( !strcmp(operation,"vault.close")&&!strcmp(app->active->op,"backup.run"))){error_window(app,"An operation is already running","Wait for the current operation to complete or cancel it first.");return;}
  Form*f=g_new0(Form,1);f->app=app;f->operation=g_strdup(operation);f->base=json_object_new();f->original=copy_object(record);f->fields=g_ptr_array_new_with_free_func(field_free);f->acknowledge=!strcmp(operation,"repository.create");f->automatic=app->automatic_prompt&&!strcmp(operation,"vault.open");
  if(record&&*str(record,"id"))json_object_set_string_member(f->base,"id",str(record,"id"));
  gboolean creating=!strcmp(operation,"vault.create");
  GtkWindow*w=dialog_window(app,title,650,creating?860:760);f->window=w;g_object_set_data_full(G_OBJECT(w),"form",f,form_free);
  GtkBox*root=GTK_BOX(gtk_box_new(GTK_ORIENTATION_VERTICAL,12));margin(GTK_WIDGET(root),24);append_text(root,title,"title-2");
  if(record&&*str(record,"name"))append_text(root,str(record,"name"),"dim-label");
  const Spec*spec=specifications(operation);gboolean has_advanced=FALSE;
  for(guint i=0;spec[i].key;i++)if(advanced_field(operation,spec[i].key))has_advanced=TRUE;
  if(has_advanced){f->advanced=GTK_CHECK_BUTTON(gtk_check_button_new_with_mnemonic("_Advanced options"));gtk_widget_set_tooltip_text(GTK_WIDGET(f->advanced),"Show optional technical settings. Basic mode uses defaults for new items and keeps saved settings when editing.");gtk_box_append(root,GTK_WIDGET(f->advanced));g_signal_connect(f->advanced,"notify::active",G_CALLBACK(update_form_visibility),f);}
  GtkWidget*scroll=gtk_scrolled_window_new();gtk_widget_set_vexpand(scroll,TRUE);GtkBox*content=GTK_BOX(gtk_box_new(GTK_ORIENTATION_VERTICAL,18));margin(GTK_WIDGET(content),6);gtk_scrolled_window_set_child(GTK_SCROLLED_WINDOW(scroll),GTK_WIDGET(content));gtk_box_append(root,scroll);
  if(strstr(operation,".remove"))append_text(content,"This removes the registration and its managed automation. Your encrypted container or remote backup data will remain intact.",NULL);
  else if(!strcmp(operation,"migration.add"))append_text(content,"OctoVault retains a temporary original, copies into the open vault, creates the mapping and empty original placeholder, then closes and reopens the vault. The temporary original is removed only after the mounted contents match. Close applications using this data before continuing.",NULL);
  else if(!strcmp(operation,"repository.create"))append_text(content,"A strong random repository password will be generated. After creation, save the complete recovery record in your password manager.",NULL);
  else if(!strcmp(operation,"repository.prune"))append_text(content,"Pruning permanently removes data no longer referenced by retained snapshots. Other jobs for this repository must finish first.",NULL);
  else if(!strcmp(operation,"repository.recovery"))append_text(content,"This reveals repository access credentials. Continue only when you can save or inspect them privately.",NULL);
  else if(!strcmp(operation,"destination.save"))append_text(content,"Fill the connection settings for the selected destination type. When editing, empty secret fields keep the existing encrypted credentials.",NULL);
  else if(!strcmp(operation,"vault.open")&&record&&!strcmp(str(record,"auth"),"gpg"))append_text(content,"GnuPG will ask for your software OpenPGP key's passphrase or your security key's PIN when needed. OctoVault remembers the vault key's location and does not save your passphrase or PIN.",NULL);
  else if(specifications(operation)==empty_fields)append_text(content,"Continue to run this operation. Its progress and result will appear in OctoVault.",NULL);
  for(guint i=0;spec[i].key;i++){
    if(!strcmp(operation,"vault.open")&&record&&!strcmp(str(record,"auth"),"gpg")&&!strcmp(spec[i].key,"password"))continue;
    if(creating&&!strcmp(spec[i].key,"open_on")){
      append_text(content,"When unlocked, your vault opens as a folder managed by OctoVault. Use Browse files to open it; no mount location needs to be configured.","dim-label");
    }
    create_field(f,&spec[i],record,content);
    if(creating&&!strcmp(spec[i].key,"directory")){f->location_preview=GTK_LABEL(label("","dim-label"));gtk_box_append(content,GTK_WIDGET(f->location_preview));}
    if(creating&&!strcmp(spec[i].key,"auth")){f->guidance=GTK_LABEL(label("","dim-label"));gtk_box_append(content,GTK_WIDGET(f->guidance));}
  }
  for(guint i=0;i<f->fields->len;i++){Field*field=g_ptr_array_index(f->fields,i);if(GTK_IS_DROP_DOWN(field->widget))g_signal_connect(field->widget,"notify::selected",G_CALLBACK(update_form_visibility),f);if(!strcmp(field->spec->key,"use_existing_key"))g_signal_connect(field->widget,"notify::active",G_CALLBACK(update_form_visibility),f);if(creating&&(!strcmp(field->spec->key,"name")||!strcmp(field->spec->key,"directory")))g_signal_connect(field->widget,"changed",G_CALLBACK(update_location_preview),f);}
  update_form_visibility(NULL,NULL,f);
  if(creating)update_location_preview(NULL,f);
  f->error=GTK_LABEL(label("","error"));gtk_box_append(root,GTK_WIDGET(f->error));
  GtkBox*buttons=GTK_BOX(gtk_box_new(GTK_ORIENTATION_HORIZONTAL,10));gtk_widget_set_halign(GTK_WIDGET(buttons),GTK_ALIGN_END);gtk_box_append(root,GTK_WIDGET(buttons));
  GtkWidget*cancel=gtk_button_new_with_mnemonic("_Cancel");gtk_box_append(buttons,cancel);g_signal_connect(cancel,"clicked",G_CALLBACK(close_window),w);
  GtkWidget*submit=gtk_button_new_with_mnemonic(creating?"_Create vault":"_Continue");gtk_widget_add_css_class(submit,strstr(operation,".remove")||!strcmp(operation,"repository.prune")?"destructive-action":"suggested-action");gtk_box_append(buttons,submit);g_signal_connect(submit,"clicked",G_CALLBACK(submit_form),f);
  gtk_window_set_child(w,GTK_WIDGET(root));gtk_window_present(w);
}

static void action_free(gpointer data,GClosure*closure){(void)closure;Action*a=data;g_free(a->operation);g_free(a->title);if(a->record)json_object_unref(a->record);g_free(a);}
#include "backup-setup.c"
static void vault_folder_opened(GObject*source,GAsyncResult*result,gpointer data){
  App*app=data;GError*error=NULL;
  if(!gtk_file_launcher_launch_finish(GTK_FILE_LAUNCHER(source),result,&error)&&error&&!g_error_matches(error,GTK_DIALOG_ERROR,GTK_DIALOG_ERROR_DISMISSED)&&!g_error_matches(error,GTK_DIALOG_ERROR,GTK_DIALOG_ERROR_CANCELLED))error_window(app,"Could not open the vault folder",error->message);
  g_clear_error(&error);
}
static void browse_vault(App*app,JsonObject*record){
  const char*path=str(record,"mountpoint");
  if(strcmp(str(record,"status"),"open")||!g_path_is_absolute(path)||!g_file_test(path,G_FILE_TEST_IS_DIR)){error_window(app,"Vault folder is unavailable","Unlock the vault and refresh its status, then choose Browse files again.");return;}
  GFile*folder=g_file_new_for_path(path);GtkFileLauncher*launcher=gtk_file_launcher_new(folder);gtk_file_launcher_launch(launcher,app->window,NULL,vault_folder_opened,app);g_object_unref(launcher);g_object_unref(folder);
}
static void action_clicked(GtkButton*button,gpointer data){
  Action*a=data;GtkWidget*ancestor=gtk_widget_get_ancestor(GTK_WIDGET(button),GTK_TYPE_POPOVER);if(ancestor)gtk_popover_popdown(GTK_POPOVER(ancestor));
  if(!strcmp(a->operation,"ui.backup-setup")){open_backup_setup(a->app);return;}
  if(!strcmp(a->operation,"ui.browse-vault")){browse_vault(a->app,a->record);return;}
  open_form(a->app,a->operation,a->title,a->record);
}
static GtkWidget *action_button(App*app,const char*title,const char*operation,JsonObject*record,const char*css){
  GtkWidget*b=gtk_button_new_with_label(title);if(css)gtk_widget_add_css_class(b,css);
  Action*a=g_new0(Action,1);a->app=app;a->operation=g_strdup(operation);a->title=g_strdup(title);a->record=record?copy_object(record):NULL;
  g_signal_connect_data(b,"clicked",G_CALLBACK(action_clicked),a,action_free,0);return b;
}
static void snapshots_window(App*app,const char*repository,JsonNode*node){
  if(!JSON_NODE_HOLDS_ARRAY(node)){result_window(app,"Snapshots",node,FALSE,FALSE);return;}
  GtkWindow*w=dialog_window(app,"Browse snapshots",760,640);
  GtkBox*root=GTK_BOX(gtk_box_new(GTK_ORIENTATION_VERTICAL,16));margin(GTK_WIDGET(root),24);append_text(root,"Browse snapshots","title-2");
  append_text(root,"Choose a snapshot to inspect or restore. Restoring to a separate folder keeps existing files safe.","dim-label");
  GtkWidget*scroll=gtk_scrolled_window_new();gtk_widget_set_vexpand(scroll,TRUE);gtk_box_append(root,scroll);
  GtkBox*list=GTK_BOX(gtk_box_new(GTK_ORIENTATION_VERTICAL,12));gtk_scrolled_window_set_child(GTK_SCROLLED_WINDOW(scroll),GTK_WIDGET(list));
  JsonArray*a=json_node_get_array(node);
  if(!json_array_get_length(a))append_text(list,"No snapshots yet. Run a backup plan to create the first snapshot.",NULL);
  for(guint i=0;i<json_array_get_length(a);i++){
    JsonNode*n=json_array_get_element(a,i);if(!JSON_NODE_HOLDS_OBJECT(n))continue;
    JsonObject*snapshot=json_node_get_object(n);GtkBox*box=GTK_BOX(gtk_box_new(GTK_ORIENTATION_VERTICAL,8));margin(GTK_WIDGET(box),12);gtk_widget_add_css_class(GTK_WIDGET(box),"card");gtk_box_append(list,GTK_WIDGET(box));
    char *heading=g_strdup_printf("%s · %s",str(snapshot,"time"),str(snapshot,"hostname"));append_text(box,heading,"heading");g_free(heading);
    const char*id=str(snapshot,"id");char *short_id=g_strndup(id,12);append_text(box,short_id,"dim-label");g_free(short_id);
    if(json_object_has_member(snapshot,"paths")){char*paths=node_text(json_object_get_member(snapshot,"paths"));append_text(box,paths,NULL);g_free(paths);}
    JsonObject*params=json_object_new();json_object_set_string_member(params,"id",repository);json_object_set_string_member(params,"snapshot",id);
    GtkBox*buttons=GTK_BOX(gtk_box_new(GTK_ORIENTATION_HORIZONTAL,8));gtk_box_append(box,GTK_WIDGET(buttons));gtk_box_append(buttons,action_button(app,"Browse files…","repository.files",params,NULL));gtk_box_append(buttons,action_button(app,"Restore this snapshot…","repository.restore",params,"suggested-action"));json_object_unref(params);
  }
  GtkWidget*close=gtk_button_new_with_mnemonic("_Close");gtk_widget_set_halign(close,GTK_ALIGN_END);gtk_box_append(root,close);g_signal_connect(close,"clicked",G_CALLBACK(close_window),w);gtk_window_set_child(w,GTK_WIDGET(root));gtk_window_present(w);
}
static gboolean file_filter(GtkListBoxRow*row,gpointer data){
  const char*query=gtk_editable_get_text(GTK_EDITABLE(data));const char*path=g_object_get_data(G_OBJECT(row),"path");
  if(!*query)return TRUE;
  char*folded_query=g_utf8_casefold(query,-1),*folded_path=g_utf8_casefold(path?path:"",-1);gboolean match=strstr(folded_path,folded_query)!=NULL;g_free(folded_query);g_free(folded_path);return match;
}
static void filter_changed(GtkSearchEntry*entry,gpointer data){(void)entry;gtk_list_box_invalidate_filter(GTK_LIST_BOX(data));}
static void files_window(App*app,const char*repository,const char*snapshot,JsonNode*node){
  if(!JSON_NODE_HOLDS_ARRAY(node)){result_window(app,"Snapshot files",node,FALSE,FALSE);return;}
  GtkWindow*w=dialog_window(app,"Browse snapshot files",820,680);GtkBox*root=GTK_BOX(gtk_box_new(GTK_ORIENTATION_VERTICAL,14));margin(GTK_WIDGET(root),24);append_text(root,"Snapshot files","title-2");
  append_text(root,"Restore any listed file or folder to a destination you choose.","dim-label");
  GtkWidget*search=gtk_search_entry_new();gtk_widget_set_tooltip_text(search,"Filter paths in this snapshot listing");gtk_accessible_update_property(GTK_ACCESSIBLE(search),GTK_ACCESSIBLE_PROPERTY_LABEL,"Filter snapshot paths",-1);gtk_box_append(root,search);
  GtkWidget*scroll=gtk_scrolled_window_new();gtk_widget_set_vexpand(scroll,TRUE);gtk_box_append(root,scroll);GtkWidget*list=gtk_list_box_new();gtk_list_box_set_selection_mode(GTK_LIST_BOX(list),GTK_SELECTION_NONE);gtk_widget_add_css_class(list,"boxed-list");gtk_scrolled_window_set_child(GTK_SCROLLED_WINDOW(scroll),list);
  gtk_list_box_set_filter_func(GTK_LIST_BOX(list),file_filter,g_object_ref(search),g_object_unref);g_signal_connect_object(search,"search-changed",G_CALLBACK(filter_changed),list,0);
  JsonArray*a=json_node_get_array(node);guint count=0;
  for(guint i=0;i<json_array_get_length(a);i++){
    JsonNode*n=json_array_get_element(a,i);if(!JSON_NODE_HOLDS_OBJECT(n))continue;JsonObject*file=json_node_get_object(n);const char*path=str(file,"path");if(!*path)continue;
    GtkWidget*row=gtk_list_box_row_new();g_object_set_data_full(G_OBJECT(row),"path",g_strdup(path),g_free);GtkBox*body=GTK_BOX(gtk_box_new(GTK_ORIENTATION_HORIZONTAL,10));margin(GTK_WIDGET(body),12);gtk_list_box_row_set_child(GTK_LIST_BOX_ROW(row),GTK_WIDGET(body));gtk_list_box_append(GTK_LIST_BOX(list),row);
    gboolean directory=!strcmp(str(file,"type"),"dir");GtkWidget*icon=gtk_image_new_from_icon_name(directory?"folder-symbolic":"text-x-generic-symbolic");gtk_box_append(body,icon);
    GtkBox*text=GTK_BOX(gtk_box_new(GTK_ORIENTATION_VERTICAL,4));gtk_widget_set_hexpand(GTK_WIDGET(text),TRUE);gtk_box_append(body,GTK_WIDGET(text));append_text(text,path,"heading");
    char*size=json_object_has_member(file,"size")?g_format_size((guint64)json_object_get_int_member(file,"size")):g_strdup(directory?"Folder":"File");append_text(text,size,"dim-label");g_free(size);
    JsonObject*p=json_object_new();json_object_set_string_member(p,"id",repository);json_object_set_string_member(p,"snapshot",snapshot);json_object_set_string_member(p,"path",path);JsonArray*include=json_array_new();json_array_add_string_element(include,path);json_object_set_array_member(p,"include",include);
    if(directory)gtk_box_append(body,action_button(app,"Browse…","repository.files",p,NULL));
    gtk_box_append(body,action_button(app,"Restore…","repository.restore",p,NULL));json_object_unref(p);count++;
  }
  if(!count)append_text(root,"No files were returned for this snapshot path.","dim-label");
  GtkWidget*close=gtk_button_new_with_mnemonic("_Close");gtk_widget_set_halign(close,GTK_ALIGN_END);gtk_box_append(root,close);g_signal_connect(close,"clicked",G_CALLBACK(close_window),w);gtk_window_set_child(w,GTK_WIDGET(root));gtk_window_present(w);
}
static void migrations_window(App*app,const char*vault,JsonNode*node){
  if(!JSON_NODE_HOLDS_ARRAY(node)){result_window(app,"Migration recovery",node,FALSE,FALSE);return;}
  GtkWindow*w=dialog_window(app,"Migration recovery",720,600);GtkBox*root=GTK_BOX(gtk_box_new(GTK_ORIENTATION_VERTICAL,14));margin(GTK_WIDGET(root),24);append_text(root,"Migration recovery","title-2");
  GtkWidget*scroll=gtk_scrolled_window_new();gtk_widget_set_vexpand(scroll,TRUE);gtk_box_append(root,scroll);GtkBox*list=GTK_BOX(gtk_box_new(GTK_ORIENTATION_VERTICAL,12));gtk_scrolled_window_set_child(GTK_SCROLLED_WINDOW(scroll),GTK_WIDGET(list));
  JsonArray*a=json_node_get_array(node);if(!json_array_get_length(a))append_text(list,"No migrations have been recorded for this vault.","dim-label");
  for(guint i=0;i<json_array_get_length(a);i++){
    JsonNode*n=json_array_get_element(a,i);if(!JSON_NODE_HOLDS_OBJECT(n))continue;JsonObject*migration=json_node_get_object(n);
    GtkBox*box=GTK_BOX(gtk_box_new(GTK_ORIENTATION_VERTICAL,8));margin(GTK_WIDGET(box),12);gtk_widget_add_css_class(GTK_WIDGET(box),"card");gtk_box_append(list,GTK_WIDGET(box));
    append_text(box,str(migration,"source"),"heading");char*stage=humanize(str(migration,"stage"));append_text(box,stage,"dim-label");g_free(stage);
    const char*state=str(migration,"stage");
    if(strcmp(state,"complete")&&strcmp(state,"rolled_back")){
      if(*str(migration,"staging")){char*staging=g_strdup_printf("Retained original: %s",str(migration,"staging"));append_text(box,staging,NULL);g_free(staging);}
      JsonObject*p=json_object_new();json_object_set_string_member(p,"id",vault);json_object_set_string_member(p,"migration_id",str(migration,"id"));json_object_set_string_member(p,"action","resume");gtk_box_append(box,action_button(app,"Recover this migration…","migration.recover",p,"suggested-action"));json_object_unref(p);
    }
  }
  GtkWidget*close=gtk_button_new_with_mnemonic("_Close");gtk_widget_set_halign(close,GTK_ALIGN_END);gtk_box_append(root,close);g_signal_connect(close,"clicked",G_CALLBACK(close_window),w);gtk_window_set_child(w,GTK_WIDGET(root));gtk_window_present(w);
}
static void add_menu_action(GtkBox*menu,App*app,const char*title,const char*operation,JsonObject*record){gtk_box_append(menu,action_button(app,title,operation,record,"flat"));}
static void show_record(App*app,JsonObject*record,gint collection){
  GtkBox*card=GTK_BOX(gtk_box_new(GTK_ORIENTATION_VERTICAL,10));gtk_widget_add_css_class(GTK_WIDGET(card),"card");
  GtkBox*inside=GTK_BOX(gtk_box_new(GTK_ORIENTATION_VERTICAL,10));margin(GTK_WIDGET(inside),16);gtk_box_append(card,GTK_WIDGET(inside));gtk_box_append(app->body,GTK_WIDGET(card));
  GtkBox*heading=GTK_BOX(gtk_box_new(GTK_ORIENTATION_HORIZONTAL,10));gtk_box_append(inside,GTK_WIDGET(heading));
  GtkBox*titles=GTK_BOX(gtk_box_new(GTK_ORIENTATION_VERTICAL,4));gtk_widget_set_hexpand(GTK_WIDGET(titles),TRUE);gtk_box_append(heading,GTK_WIDGET(titles));
  append_text(titles,*str(record,"name")?str(record,"name"):"Unnamed", "heading");
  char*summary=NULL;
  if(collection==0){
    const char*status=str(record,"status");if(!*status)status=str(record,"state");
    if(!*status)status=boolean(record,"open")?"Open":"Locked";
    char*human=humanize(status);summary=g_strdup_printf("%s · %s",human,str(record,"file"));g_free(human);
  }else if(collection==1){char*type=choice_label(str(record,"type"));summary=g_strdup_printf("%s · %s",type,*str(record,"host")?str(record,"host"):*str(record,"endpoint")?str(record,"endpoint"):str(record,"path"));g_free(type);}
  else if(collection==2)summary=g_strdup(str(record,"repository"));
  else{char*trigger=choice_label(str(record,"trigger"));summary=g_strdup_printf("%s%s%s",trigger,*str(record,"calendar")?" · ":"",str(record,"calendar"));g_free(trigger);}
  append_text(titles,summary,"dim-label");g_free(summary);
  if(collection==0){
    if(*str(record,"last_opened_at")){char*last=g_strdup_printf("Last opened %s by %s",str(record,"last_opened_at"),str(record,"last_opened_by"));append_text(inside,last,"dim-label");g_free(last);}
    if(json_object_has_member(record,"usage")&&JSON_NODE_HOLDS_OBJECT(json_object_get_member(record,"usage"))){
      JsonObject*usage=json_object_get_object_member(record,"usage");
      if(json_object_has_member(usage,"available")&&json_object_has_member(usage,"total")){
        char*free_size=g_format_size((guint64)json_object_get_int_member(usage,"available"));char*total_size=g_format_size((guint64)json_object_get_int_member(usage,"total"));char*space=g_strdup_printf("%s available of %s",free_size,total_size);append_text(inside,space,NULL);g_free(space);g_free(free_size);g_free(total_size);
      }
    }
  }else if(collection==2){
    if(json_object_has_member(record,"last_check")&&JSON_NODE_HOLDS_OBJECT(json_object_get_member(record,"last_check"))){
      JsonObject*check=json_object_get_object_member(record,"last_check");char*state=g_strdup_printf("Last %s check: %s · %s",boolean(check,"read_data")?"full data":"repository",boolean(check,"successful")?"Passed":"Failed",str(check,"at"));append_text(inside,state,boolean(check,"successful")?"dim-label":"error");g_free(state);
    }else append_text(inside,"Repository has not yet been checked by OctoVault.","dim-label");
  }else if(collection==3&&json_object_has_member(record,"last_run")&&JSON_NODE_HOLDS_OBJECT(json_object_get_member(record,"last_run"))){
    JsonObject*last=json_object_get_object_member(record,"last_run");char*state=g_strdup_printf("Last run: %s · %s",str(last,"status"),str(last,"finished_at"));append_text(inside,state,"dim-label");g_free(state);
  }
  GtkWidget*more=gtk_menu_button_new();gtk_menu_button_set_icon_name(GTK_MENU_BUTTON(more),"view-more-symbolic");gtk_widget_set_tooltip_text(more,"More actions");gtk_widget_set_valign(more,GTK_ALIGN_START);gtk_box_append(heading,more);
  GtkWidget*popover=gtk_popover_new();GtkBox*menu=GTK_BOX(gtk_box_new(GTK_ORIENTATION_VERTICAL,2));margin(GTK_WIDGET(menu),6);
  GtkWidget*menu_scroll=gtk_scrolled_window_new();gtk_scrolled_window_set_max_content_height(GTK_SCROLLED_WINDOW(menu_scroll),420);gtk_scrolled_window_set_propagate_natural_height(GTK_SCROLLED_WINDOW(menu_scroll),TRUE);gtk_scrolled_window_set_child(GTK_SCROLLED_WINDOW(menu_scroll),GTK_WIDGET(menu));gtk_popover_set_child(GTK_POPOVER(popover),menu_scroll);gtk_menu_button_set_popover(GTK_MENU_BUTTON(more),popover);
  GtkBox*buttons=GTK_BOX(gtk_box_new(GTK_ORIENTATION_HORIZONTAL,8));gtk_box_append(inside,GTK_WIDGET(buttons));
  if(collection==0){
    gboolean opened=!strcmp(str(record,"status"),"open");
    if(opened)gtk_box_append(buttons,action_button(app,"Browse files","ui.browse-vault",record,"suggested-action"));
    else gtk_box_append(buttons,action_button(app,"Unlock","vault.open",record,"suggested-action"));
    gtk_box_append(buttons,action_button(app,"Lock","vault.close",record,NULL));gtk_box_append(buttons,action_button(app,"Protect files…","migration.add",record,NULL));
    add_menu_action(menu,app,"Details","vault.get",record);add_menu_action(menu,app,"Automation & scripts…","vault.update",record);
    add_menu_action(menu,app,"Change passphrase…","vault.passwd",record);add_menu_action(menu,app,"Replace key…","vault.setkey",record);add_menu_action(menu,app,"Export key…","vault.key-export",record);add_menu_action(menu,app,"Increase capacity…","vault.resize",record);
    add_menu_action(menu,app,"Migration recovery records","migration.list",record);add_menu_action(menu,app,"Recover interrupted migration…","migration.recover",record);add_menu_action(menu,app,"Build search index","vault.index",record);add_menu_action(menu,app,"Search protected files…","vault.search",record);add_menu_action(menu,app,"Remove registration…","vault.remove",record);
  }else if(collection==1){
    gtk_box_append(buttons,action_button(app,"Test connection","destination.test",record,"suggested-action"));gtk_box_append(buttons,action_button(app,"Edit…","destination.save",record,NULL));
    add_menu_action(menu,app,"Connection details","destination.get",record);add_menu_action(menu,app,"Remove destination…","destination.remove",record);
  }else if(collection==2){
    gtk_box_append(buttons,action_button(app,"Snapshots","repository.snapshots",record,"suggested-action"));gtk_box_append(buttons,action_button(app,"Restore…","repository.restore",record,NULL));gtk_box_append(buttons,action_button(app,"Check…","repository.check",record,NULL));
    add_menu_action(menu,app,"Browse snapshot files…","repository.files",record);add_menu_action(menu,app,"Find a file…","repository.find",record);add_menu_action(menu,app,"Compare snapshots…","repository.diff",record);add_menu_action(menu,app,"Storage statistics","repository.stats",record);
    add_menu_action(menu,app,"Recovery information…","repository.recovery",record);add_menu_action(menu,app,"Change repository password…","repository.password",record);add_menu_action(menu,app,"Retention / remove snapshots…","repository.forget",record);add_menu_action(menu,app,"Prune unused data…","repository.prune",record);add_menu_action(menu,app,"Copy a snapshot…","repository.copy",record);add_menu_action(menu,app,"Remove registration…","repository.remove",record);
  }else{
    gtk_box_append(buttons,action_button(app,"Back up now","backup.run",record,"suggested-action"));gtk_box_append(buttons,action_button(app,"Edit plan…","backup.save",record,NULL));
    add_menu_action(menu,app,"Backup history","backup.history",record);add_menu_action(menu,app,"Remove plan…","backup.remove",record);
  }
}
static guint collection_count(App*app,guint i){JsonNode*n=app->collections[i];return n&&JSON_NODE_HOLDS_ARRAY(n)?json_array_get_length(json_node_get_array(n)):0;}
static void collection_cards(App*app,gint i,const char*empty){
  JsonNode*n=app->collections[i];if(!collection_count(app,i)){append_text(app->body,empty,"dim-label");return;}
  JsonArray*a=json_node_get_array(n);for(guint j=0;j<json_array_get_length(a);j++){JsonNode*item=json_array_get_element(a,j);if(JSON_NODE_HOLDS_OBJECT(item))show_record(app,json_node_get_object(item),i);}
}
static void theme_changed(GtkDropDown*drop,GParamSpec*pspec,gpointer data){(void)pspec;App*app=data;guint i=gtk_drop_down_get_selected(drop);app->preferred_theme=i;adw_style_manager_set_color_scheme(adw_style_manager_get_default(),i==1?ADW_COLOR_SCHEME_FORCE_LIGHT:i==2?ADW_COLOR_SCHEME_FORCE_DARK:ADW_COLOR_SCHEME_DEFAULT);save_preferences(app);}
static void notifications_changed(GtkCheckButton*button,gpointer data){App*app=data;app->show_notifications=gtk_check_button_get_active(button);save_preferences(app);}
#if ADW_CHECK_VERSION(1, 5, 0)
#define OV_ABOUT_API(name) adw_about_dialog_##name
#define OV_ABOUT(obj) ADW_ABOUT_DIALOG(obj)
#else
#define OV_ABOUT_API(name) adw_about_window_##name
#define OV_ABOUT(obj) ADW_ABOUT_WINDOW(obj)
#endif
static void about_clicked(GtkButton*button,gpointer data){
  (void)button;App*app=data;const char*developers[]={"Vast Development Method",NULL};
#if ADW_CHECK_VERSION(1, 5, 0)
  AdwDialog*w=adw_about_dialog_new();
#else
  GtkWidget*w=adw_about_window_new();
#endif
  OV_ABOUT_API(set_application_name)(OV_ABOUT(w),"OctoVault");OV_ABOUT_API(set_application_icon)(OV_ABOUT(w),"io.vdm.OctoVault");
  OV_ABOUT_API(set_developer_name)(OV_ABOUT(w),"Vast Development Method");OV_ABOUT_API(set_developers)(OV_ABOUT(w),developers);OV_ABOUT_API(set_version)(OV_ABOUT(w),OCTOVAULT_VERSION);OV_ABOUT_API(set_website)(OV_ABOUT(w),"https://www.vdm.io");OV_ABOUT_API(set_issue_url)(OV_ABOUT(w),"https://github.com/octoleo/octovault/issues");OV_ABOUT_API(set_copyright)(OV_ABOUT(w),"© 2026 Vast Development Method");OV_ABOUT_API(set_license_type)(OV_ABOUT(w),GTK_LICENSE_APACHE_2_0);OV_ABOUT_API(set_comments)(OV_ABOUT(w),"Encrypted vaults and independent backups. Part of the OctoLeo Suite.");
  const char*tomb[]={"Tomb developers — https://dyne.org/tomb/",NULL};const char*restic[]={"Restic contributors — https://restic.net/",NULL};const char*desktop[]={"GNOME, GTK and libadwaita contributors", "systemd, GnuPG, cryptsetup and Linux contributors",NULL};
  OV_ABOUT_API(add_credit_section)(OV_ABOUT(w),"Vault technology",tomb);OV_ABOUT_API(add_credit_section)(OV_ABOUT(w),"Backup technology",restic);OV_ABOUT_API(add_credit_section)(OV_ABOUT(w),"Desktop and system integration",desktop);
  OV_ABOUT_API(add_legal_section)(OV_ABOUT(w),"Tomb","Tomb contributors",GTK_LICENSE_GPL_3_0,NULL);OV_ABOUT_API(add_legal_section)(OV_ABOUT(w),"Restic","Restic contributors",GTK_LICENSE_CUSTOM,"BSD 2-Clause License. See https://github.com/restic/restic/blob/master/LICENSE for the full license and copyright notices.");
#if ADW_CHECK_VERSION(1, 5, 0)
  adw_dialog_present(w,GTK_WIDGET(app->window));
#else
  gtk_window_set_transient_for(GTK_WINDOW(w),app->window);gtk_window_present(GTK_WINDOW(w));
#endif
}
#undef OV_ABOUT_API
#undef OV_ABOUT
static void render_page(App*app){
  if(!app->body)return;
  GtkWidget*child;while((child=gtk_widget_get_first_child(GTK_WIDGET(app->body))))gtk_box_remove(app->body,child);
  gtk_label_set_text(app->title,app->page);
  GtkBox*toolbar=GTK_BOX(gtk_box_new(GTK_ORIENTATION_HORIZONTAL,8));gtk_box_append(app->body,GTK_WIDGET(toolbar));
  if(!strcmp(app->page,"Dashboard")){
    append_text(app->body,"Your protected data, at a glance","title-1");
    char*summary=g_strdup_printf("%u vaults · %u backup plans · %u repositories · %u destinations",collection_count(app,0),collection_count(app,3),collection_count(app,2),collection_count(app,1));append_text(app->body,summary,"title-3");g_free(summary);
    gtk_box_append(toolbar,action_button(app,"Create vault…","vault.create",NULL,"suggested-action"));gtk_box_append(toolbar,action_button(app,"Create backup…","ui.backup-setup",NULL,NULL));
    append_text(app->body,"Vaults","title-2");collection_cards(app,0,"Create or import a vault to protect folders and files.");
    append_text(app->body,"Backup plans","title-2");collection_cards(app,3,"Choose Create backup to connect storage, save recovery information, and select your files.");
  }else if(!strcmp(app->page,"Vaults")){
    gtk_box_append(toolbar,action_button(app,"Create vault…","vault.create",NULL,"suggested-action"));gtk_box_append(toolbar,action_button(app,"Import existing vault…","vault.import",NULL,NULL));
    append_text(app->body,"Protect files in encrypted containers. When a vault locks, its mapped locations reveal their independent underlying contents.","dim-label");collection_cards(app,0,"No vaults registered.");
  }else if(!strcmp(app->page,"Backups")){
    gtk_box_append(toolbar,action_button(app,"Create backup…","ui.backup-setup",NULL,"suggested-action"));gtk_box_append(toolbar,action_button(app,"Connect existing backup…","repository.import",NULL,NULL));
    append_text(app->body,"Plans","title-2");collection_cards(app,3,"Choose Create backup for guided setup.");append_text(app->body,"Backup storage & recovery","title-2");collection_cards(app,2,"Backup storage is set up when you create your first backup.");
  }else if(!strcmp(app->page,"Destinations")){
    gtk_box_append(toolbar,action_button(app,"Add destination…","destination.save",NULL,"suggested-action"));append_text(app->body,"Connect a local drive, S3 storage, SSH server, or REST backup server. Secrets are stored as encrypted service credentials.","dim-label");collection_cards(app,1,"No destinations configured.");
  }else if(!strcmp(app->page,"Activity")){
    append_text(app->body,"This session","title-2");if(!app->activity->len)append_text(app->body,"No operations yet.","dim-label");for(guint i=0;i<app->activity->len;i++)append_text(app->body,g_ptr_array_index(app->activity,i),NULL);
    append_text(app->body,"Each backup plan also provides its persistent Backup history in its actions menu.","dim-label");
  }else{
    append_text(app->body,"Appearance","title-2");const char*themes[]={"Follow system","Light","Dark",NULL};GtkWidget*drop=gtk_drop_down_new_from_strings(themes);AdwColorScheme scheme=adw_style_manager_get_color_scheme(adw_style_manager_get_default());gtk_drop_down_set_selected(GTK_DROP_DOWN(drop),scheme==ADW_COLOR_SCHEME_FORCE_LIGHT?1:scheme==ADW_COLOR_SCHEME_FORCE_DARK?2:0);g_signal_connect(drop,"notify::selected",G_CALLBACK(theme_changed),app);gtk_box_append(app->body,drop);
    GtkWidget*notify_button=gtk_check_button_new_with_label("Show operation notifications");gtk_check_button_set_active(GTK_CHECK_BUTTON(notify_button),app->show_notifications);g_signal_connect(notify_button,"toggled",G_CALLBACK(notifications_changed),app);gtk_box_append(app->body,notify_button);
    append_text(app->body,"Automation","title-2");append_text(app->body,"Unlock and lock events belong to each vault. Backup timing, power and network preferences belong to each backup plan. Services continue working after this window closes.",NULL);gtk_box_append(app->body,action_button(app,"Synchronize schedules","schedule.sync",NULL,NULL));
    append_text(app->body,"Credential protection","title-2");append_text(app->body,"Backup credentials are encrypted by systemd. Hardware binding uses TPM2 when available. Save repository recovery information in a separate password manager so backups remain recoverable after losing this computer.",NULL);
    GtkWidget*about=gtk_button_new_with_label("About OctoVault");gtk_widget_set_halign(about,GTK_ALIGN_START);g_signal_connect(about,"clicked",G_CALLBACK(about_clicked),app);gtk_box_append(app->body,about);
  }
}
static void navigation_changed(GtkToggleButton*button,gpointer data){App*app=data;if(!gtk_toggle_button_get_active(button))return;g_free(app->page);app->page=g_strdup(gtk_button_get_label(GTK_BUTTON(button)));render_page(app);}
static void activate(GApplication*application,gpointer data){
  App*app=data;
  if(app->window){gtk_window_present(app->window);return;}
  if(!app->smoke&&g_file_test("/usr/bin/octovault-session",G_FILE_TEST_IS_REGULAR)&&g_file_test("/usr/bin/octovault-session",G_FILE_TEST_IS_EXECUTABLE)){
    char*arguments[]={"/usr/bin/octovault-session",NULL};
    /* The observer owns a unique session-bus name, so an existing autostart
     * process causes this launch to exit without creating a duplicate. */
    (void)g_spawn_async(NULL,arguments,NULL,G_SPAWN_STDOUT_TO_DEV_NULL|G_SPAWN_STDERR_TO_DEV_NULL,NULL,NULL,NULL,NULL);
  }
  adw_style_manager_set_color_scheme(adw_style_manager_get_default(),app->preferred_theme==1?ADW_COLOR_SCHEME_FORCE_LIGHT:app->preferred_theme==2?ADW_COLOR_SCHEME_FORCE_DARK:ADW_COLOR_SCHEME_DEFAULT);
  app->window=GTK_WINDOW(adw_application_window_new(GTK_APPLICATION(application)));gtk_window_set_title(app->window,"OctoVault");gtk_window_set_default_size(app->window,1100,780);
  GtkBox*root=GTK_BOX(gtk_box_new(GTK_ORIENTATION_VERTICAL,0));adw_application_window_set_content(ADW_APPLICATION_WINDOW(app->window),GTK_WIDGET(root));
  GtkWidget*header=adw_header_bar_new();GtkWidget*window_title=adw_window_title_new("OctoVault","OctoLeo Suite");adw_header_bar_set_title_widget(ADW_HEADER_BAR(header),window_title);gtk_box_append(root,header);
  app->refresh=gtk_button_new_from_icon_name("view-refresh-symbolic");gtk_widget_set_tooltip_text(app->refresh,"Refresh vaults and backups");g_signal_connect(app->refresh,"clicked",G_CALLBACK(refresh_clicked),app);adw_header_bar_pack_end(ADW_HEADER_BAR(header),app->refresh);
  GtkWidget*about=gtk_button_new_from_icon_name("help-about-symbolic");gtk_widget_set_tooltip_text(about,"About OctoVault");g_signal_connect(about,"clicked",G_CALLBACK(about_clicked),app);adw_header_bar_pack_end(ADW_HEADER_BAR(header),about);
  GtkBox*layout=GTK_BOX(gtk_box_new(GTK_ORIENTATION_HORIZONTAL,0));gtk_widget_set_vexpand(GTK_WIDGET(layout),TRUE);gtk_box_append(root,GTK_WIDGET(layout));
  GtkBox*sidebar=GTK_BOX(gtk_box_new(GTK_ORIENTATION_VERTICAL,6));margin(GTK_WIDGET(sidebar),12);gtk_widget_set_size_request(GTK_WIDGET(sidebar),172,-1);gtk_box_append(layout,GTK_WIDGET(sidebar));
  GtkWidget*icon=gtk_image_new_from_icon_name("io.vdm.OctoVault");gtk_image_set_pixel_size(GTK_IMAGE(icon),72);gtk_widget_set_margin_top(icon,12);gtk_widget_set_margin_bottom(icon,20);gtk_box_append(sidebar,icon);
  const char*pages[]={"Dashboard","Vaults","Backups","Destinations","Activity","Settings"};
  for(guint i=0;i<6;i++){GtkWidget*b=gtk_toggle_button_new_with_label(pages[i]);app->navigation[i]=GTK_TOGGLE_BUTTON(b);if(i)gtk_toggle_button_set_group(GTK_TOGGLE_BUTTON(b),app->navigation[0]);gtk_widget_add_css_class(b,"flat");gtk_widget_set_size_request(b,-1,42);g_signal_connect(b,"toggled",G_CALLBACK(navigation_changed),app);gtk_box_append(sidebar,b);}
  gtk_box_append(layout,gtk_separator_new(GTK_ORIENTATION_VERTICAL));
  GtkBox*main=GTK_BOX(gtk_box_new(GTK_ORIENTATION_VERTICAL,12));gtk_widget_set_hexpand(GTK_WIDGET(main),TRUE);margin(GTK_WIDGET(main),24);gtk_box_append(layout,GTK_WIDGET(main));
  app->title=GTK_LABEL(label("Dashboard","title-1"));gtk_box_append(main,GTK_WIDGET(app->title));
  GtkWidget*scroll=gtk_scrolled_window_new();gtk_widget_set_vexpand(scroll,TRUE);gtk_scrolled_window_set_policy(GTK_SCROLLED_WINDOW(scroll),GTK_POLICY_NEVER,GTK_POLICY_AUTOMATIC);gtk_box_append(main,scroll);
  app->body=GTK_BOX(gtk_box_new(GTK_ORIENTATION_VERTICAL,18));gtk_widget_set_margin_end(GTK_WIDGET(app->body),8);gtk_scrolled_window_set_child(GTK_SCROLLED_WINDOW(scroll),GTK_WIDGET(app->body));
  app->job_box=gtk_box_new(GTK_ORIENTATION_VERTICAL,8);margin(app->job_box,16);gtk_box_append(root,app->job_box);gtk_widget_set_visible(app->job_box,FALSE);
  GtkBox*job_row=GTK_BOX(gtk_box_new(GTK_ORIENTATION_HORIZONTAL,12));gtk_box_append(GTK_BOX(app->job_box),GTK_WIDGET(job_row));app->job_label=GTK_LABEL(label("","heading"));gtk_widget_set_hexpand(GTK_WIDGET(app->job_label),TRUE);gtk_box_append(job_row,GTK_WIDGET(app->job_label));app->cancel=gtk_button_new_with_label("Cancel operation");gtk_box_append(job_row,app->cancel);g_signal_connect(app->cancel,"clicked",G_CALLBACK(cancel_job),app);
  app->progress=GTK_PROGRESS_BAR(gtk_progress_bar_new());gtk_box_append(GTK_BOX(app->job_box),GTK_WIDGET(app->progress));
  gtk_toggle_button_set_active(app->navigation[0],TRUE);gtk_window_present(app->window);refresh_all(app);
}
static gboolean smoke_finished(gpointer data){
  App*app=data;
  if(app->screenshot){
    GtkWidget*widget=GTK_WIDGET(app->screenshot_window?app->screenshot_window:app->window);int width=gtk_widget_get_width(widget),height=gtk_widget_get_height(widget);
    GdkPaintable*paintable=gtk_widget_paintable_new(widget);GtkSnapshot*snapshot=gtk_snapshot_new();gdk_paintable_snapshot(paintable,GDK_SNAPSHOT(snapshot),width,height);
    GskRenderNode*node=gtk_snapshot_free_to_node(snapshot);
    if(node){GskRenderer*renderer=gtk_native_get_renderer(GTK_NATIVE(widget));graphene_rect_t bounds=GRAPHENE_RECT_INIT(0,0,width,height);GdkTexture*texture=gsk_renderer_render_texture(renderer,node,&bounds);g_assert_true(gdk_texture_save_to_png(texture,app->screenshot));g_object_unref(texture);gsk_render_node_unref(node);}else g_error("The native screenshot has no rendered contents");g_object_unref(paintable);
  }
  g_application_quit(G_APPLICATION(app->application));return G_SOURCE_REMOVE;
}
static gboolean unlock_registered(App*app,const char*id){
  JsonNode*n=app->collections[0];if(!n||!JSON_NODE_HOLDS_ARRAY(n))return FALSE;
  JsonArray*a=json_node_get_array(n);
  for(guint i=0;i<json_array_get_length(a);i++){
    JsonNode*v=json_array_get_element(a,i);if(!JSON_NODE_HOLDS_OBJECT(v))continue;
    JsonObject*record=json_node_get_object(v);if(strcmp(str(record,"id"),id))continue;
    if(!strcmp(str(record,"auth"),"gpg")){JsonObject*p=json_object_new();json_object_set_string_member(p,"id",id);start_operation(app,"vault.open",p,"Unlock vault",-1,FALSE);json_object_unref(p);}
    else {app->automatic_prompt=TRUE;open_form(app,"vault.open","Unlock vault",record);}
    return TRUE;
  }
  return FALSE;
}
static gboolean drain_unlocks(gpointer data){
  App*app=data;
  if(app->active||app->automatic_prompt||!app->collections[0]||g_queue_is_empty(app->pending_unlocks))return G_SOURCE_REMOVE;
  char*id=g_queue_pop_head(app->pending_unlocks);
  if(!unlock_registered(app,id)){error_window(app,"Vault is unavailable","The automatically requested vault is no longer registered. Refresh the vault list and check its settings.");g_idle_add(drain_unlocks,app);}
  g_free(id);return G_SOURCE_REMOVE;
}
static void smoke_vault_creation(Form*f){
  GError*error=NULL;char*sample_path=NULL;int fd=g_file_open_tmp("octovault-ui-XXXXXX",&sample_path,&error);g_assert_no_error(error);g_assert_cmpint(fd,>=,0);g_assert_true(g_close(fd,&error));g_assert_no_error(error);
  gtk_editable_set_text(GTK_EDITABLE(find_field(f,"name")->widget),"Personal");
  gtk_editable_set_text(GTK_EDITABLE(find_field(f,"directory")->widget),g_get_tmp_dir());
  gtk_editable_set_text(GTK_EDITABLE(find_field(f,"key_file")->widget),sample_path);
  gtk_editable_set_text(GTK_EDITABLE(find_field(f,"image_source")->widget),sample_path);
  gtk_editable_set_text(GTK_EDITABLE(find_field(f,"recipient")->widget),"1111111111111111111111111111111111111111!");
  gtk_editable_set_text(GTK_EDITABLE(find_field(f,"password")->widget),"smoke-test-only");
  gtk_editable_set_text(GTK_EDITABLE(find_field(f,"_confirm_password")->widget),"smoke-test-only");
  Field*auth=find_field(f,"auth"),*existing=find_field(f,"use_existing_key");
  for(guint i=0;i<auth->values->len;i++)for(guint reuse=0;reuse<2;reuse++){
    gtk_drop_down_set_selected(GTK_DROP_DOWN(auth->widget),i);gtk_check_button_set_active(GTK_CHECK_BUTTON(existing->widget),reuse);
    const char*method=g_ptr_array_index(auth->values,i);gboolean accepted=FALSE;JsonObject*params=form_parameters(f,&accepted);g_assert_true(accepted);
    g_assert_cmpstr(str(params,"auth"),==,method);g_assert_cmpint(boolean(params,"use_existing_key"),==,(gboolean)reuse);
    g_assert_cmpint(json_object_has_member(params,"key_file"),==,(gboolean)reuse);
    g_assert_cmpint(json_object_has_member(params,"image_source"),==,!reuse&&!strcmp(method,"image"));
    g_assert_cmpint(json_object_has_member(params,"recipient"),==,!reuse&&!strcmp(method,"gpg"));
    g_assert_cmpint(json_object_has_member(params,"password"),==,strcmp(method,"gpg")!=0);
    g_assert_false(json_object_has_member(params,"file"));g_assert_false(json_object_has_member(params,"mountpoint"));g_assert_false(json_object_has_member(params,"_confirm_password"));
    json_object_unref(params);
  }
  gtk_drop_down_set_selected(GTK_DROP_DOWN(auth->widget),0);gtk_check_button_set_active(GTK_CHECK_BUTTON(existing->widget),FALSE);
  gtk_editable_set_text(GTK_EDITABLE(find_field(f,"_confirm_password")->widget),"does-not-match");gboolean accepted=TRUE;JsonObject*params=form_parameters(f,&accepted);g_assert_false(accepted);json_object_unref(params);
  gtk_editable_set_text(GTK_EDITABLE(find_field(f,"_confirm_password")->widget),"smoke-test-only");
  gtk_check_button_set_active(f->advanced,TRUE);gtk_drop_down_set_selected(GTK_DROP_DOWN(find_field(f,"open_on")->widget),1);gtk_check_button_set_active(GTK_CHECK_BUTTON(find_field(f,"force_close")->widget),TRUE);gtk_check_button_set_active(f->advanced,FALSE);
  params=form_parameters(f,&accepted);g_assert_true(accepted);g_assert_cmpstr(str(params,"open_on"),==,"login");g_assert_false(boolean(params,"force_close"));g_assert_true(string_array_has(json_object_get_member(params,"close_on"),"shutdown"));json_object_unref(params);
  g_assert_cmpint(g_unlink(sample_path),==,0);g_free(sample_path);
}
static void smoke_advanced_defaults(App*app){
  for(guint editing=0;editing<2;editing++){
    JsonObject*record=json_object_new();json_object_set_string_member(record,"name","Smoke-test destination");json_object_set_string_member(record,"type","sftp");json_object_set_string_member(record,"host","example.test");json_object_set_string_member(record,"user","backup");json_object_set_string_member(record,"path","/backup");json_object_set_string_member(record,"host_fingerprint","SHA256:smoke-test");
    if(editing){json_object_set_string_member(record,"id","test-existing");json_object_set_int_member(record,"port",2222);}
    open_form(app,"destination.save","Destination smoke test",record);json_object_unref(record);
    GListModel*windows=gtk_window_get_toplevels();GtkWindow*window=g_list_model_get_item(windows,g_list_model_get_n_items(windows)-1);Form*f=g_object_get_data(G_OBJECT(window),"form");
    g_assert_false(gtk_check_button_get_active(f->advanced));g_assert_false(gtk_widget_get_visible(find_field(f,"port")->row));g_assert_true(gtk_widget_get_visible(find_field(f,"host_fingerprint")->row));
    gtk_text_buffer_set_text(gtk_text_view_get_buffer(GTK_TEXT_VIEW(find_field(f,"ssh_private_key")->widget)),"smoke-test-private-key",-1);
    gtk_editable_set_text(GTK_EDITABLE(find_field(f,"access_key")->widget),"must-not-be-sent");gtk_editable_set_text(GTK_EDITABLE(find_field(f,"secret_key")->widget),"must-not-be-sent");
    gtk_check_button_set_active(f->advanced,TRUE);gtk_spin_button_set_value(GTK_SPIN_BUTTON(find_field(f,"port")->widget),3333);gtk_check_button_set_active(f->advanced,FALSE);
    gboolean accepted=FALSE;JsonObject*params=form_parameters(f,&accepted);g_assert_true(accepted);g_assert_cmpint(json_object_get_int_member(params,"port"),==,editing?2222:22);g_assert_false(json_object_has_member(params,"access_key"));g_assert_false(json_object_has_member(params,"secret_key"));g_assert_false(json_object_has_member(params,"region"));json_object_unref(params);
    gtk_window_destroy(window);g_object_unref(window);
  }
}
static int command_line(GApplication*application,GApplicationCommandLine*command,gpointer data){
  App*app=data;GVariantDict*options=g_application_command_line_get_options_dict(command);
  if(g_variant_dict_contains(options,"smoke-test"))app->smoke=TRUE;
  const char*screenshot=NULL;if(g_variant_dict_lookup(options,"screenshot","&s",&screenshot)){app->screenshot=g_strdup(screenshot);app->smoke=TRUE;}
  if(g_variant_dict_lookup(options,"screenshot-create","&s",&screenshot)){g_free(app->screenshot);app->screenshot=g_strdup(screenshot);app->smoke=TRUE;app->screenshot_create=TRUE;}
  if(g_variant_dict_lookup(options,"screenshot-backup","&s",&screenshot)){g_free(app->screenshot);app->screenshot=g_strdup(screenshot);app->smoke=TRUE;app->screenshot_backup=TRUE;}
  if(g_variant_dict_lookup(options,"screenshot-backup-files","&s",&screenshot)){g_free(app->screenshot);app->screenshot=g_strdup(screenshot);app->smoke=TRUE;app->screenshot_backup_files=TRUE;}
  if(g_variant_dict_lookup(options,"screenshot-destination","&s",&screenshot)){g_free(app->screenshot);app->screenshot=g_strdup(screenshot);app->smoke=TRUE;app->screenshot_destination=TRUE;}
  app->screenshot_advanced=g_variant_dict_contains(options,"screenshot-advanced");
  g_application_activate(application);
  const char*unlock=NULL;if(g_variant_dict_lookup(options,"unlock","&s",&unlock)){
    if(!g_queue_find_custom(app->pending_unlocks,unlock,(GCompareFunc)g_strcmp0))g_queue_push_tail(app->pending_unlocks,g_strdup(unlock));
    g_idle_add(drain_unlocks,app);
  }
  if(app->smoke){
    for(guint i=0;i<6;i++)gtk_toggle_button_set_active(app->navigation[i],TRUE);
    const char *ops[]={"vault.create","vault.import","vault.update","vault.open","vault.close","vault.resize","vault.passwd","vault.setkey","vault.key-export","vault.search","migration.add","migration.recover","destination.save","repository.create","repository.import","repository.check","repository.files","repository.find","repository.diff","repository.restore","repository.forget","repository.password","repository.copy","backup.save"};
    for(guint i=0;i<G_N_ELEMENTS(ops);i++){open_form(app,ops[i],ops[i],NULL);GListModel*windows=gtk_window_get_toplevels();guint count=g_list_model_get_n_items(windows);if(count>1){GtkWindow*w=g_list_model_get_item(windows,count-1);if(w!=app->window){if(!strcmp(ops[i],"vault.create"))smoke_vault_creation(g_object_get_data(G_OBJECT(w),"form"));gtk_window_destroy(w);}g_object_unref(w);}}
    smoke_advanced_defaults(app);backup_setup_smoke(app);
    gtk_toggle_button_set_active(app->navigation[0],TRUE);
    if(app->screenshot_create){open_form(app,"vault.create","Create vault",NULL);GListModel*windows=gtk_window_get_toplevels();app->screenshot_window=g_list_model_get_item(windows,g_list_model_get_n_items(windows)-1);Form*f=g_object_get_data(G_OBJECT(app->screenshot_window),"form");gtk_editable_set_text(GTK_EDITABLE(find_field(f,"name")->widget),"Personal");}
    if(app->screenshot_backup){open_backup_setup(app);app->screenshot_window=app->backup_setup->window;}
    if(app->screenshot_backup_files){
      backup_setup_cache(app,2,"screenshot-repository","Documents backup storage");JsonObject*record=json_object_new();json_object_set_string_member(record,"name","My documents");json_object_set_string_member(record,"repository_id","screenshot-repository");json_object_set_string_member(record,"trigger","calendar");json_object_set_string_member(record,"calendar","daily");
      open_form(app,"backup.save","Choose files and a schedule",record);json_object_unref(record);GListModel*windows=gtk_window_get_toplevels();app->screenshot_window=g_list_model_get_item(windows,g_list_model_get_n_items(windows)-1);
    }
    if(app->screenshot_destination){JsonObject*record=json_object_new();json_object_set_string_member(record,"name","Backup server");json_object_set_string_member(record,"type","sftp");open_form(app,"destination.save","Connect a backup location",record);json_object_unref(record);GListModel*windows=gtk_window_get_toplevels();app->screenshot_window=g_list_model_get_item(windows,g_list_model_get_n_items(windows)-1);}
    if(app->screenshot_window&&app->screenshot_advanced){Form*f=g_object_get_data(G_OBJECT(app->screenshot_window),"form");if(f&&f->advanced)gtk_check_button_set_active(f->advanced,TRUE);}
    g_timeout_add(300,smoke_finished,app);
  }
  return 0;
}
int main(int argc,char**argv){
  const struct rlimit core_limit={0,0};(void)setrlimit(RLIMIT_CORE,&core_limit);(void)prctl(PR_SET_DUMPABLE,0,0,0,0);
  App*app=g_new0(App,1);app->page=g_strdup("Dashboard");app->activity=g_ptr_array_new_with_free_func(g_free);app->pending_unlocks=g_queue_new();app->show_notifications=TRUE;
  load_preferences(app);
  app->application=adw_application_new("io.vdm.OctoVault",G_APPLICATION_HANDLES_COMMAND_LINE);
  g_application_add_main_option(G_APPLICATION(app->application),"smoke-test",0,G_OPTION_FLAG_NONE,G_OPTION_ARG_NONE,"Construct all pages and dialogs, then exit",NULL);
  g_application_add_main_option(G_APPLICATION(app->application),"unlock",0,G_OPTION_FLAG_NONE,G_OPTION_ARG_STRING,"Offer to unlock a registered vault","ID");
  g_application_add_main_option(G_APPLICATION(app->application),"screenshot",0,G_OPTION_FLAG_NONE,G_OPTION_ARG_STRING,"Save a smoke-test screenshot","FILE");
  g_application_add_main_option(G_APPLICATION(app->application),"screenshot-create",0,G_OPTION_FLAG_NONE,G_OPTION_ARG_STRING,"Save the guided vault creation form after native UI checks","FILE");
  g_application_add_main_option(G_APPLICATION(app->application),"screenshot-backup",0,G_OPTION_FLAG_NONE,G_OPTION_ARG_STRING,"Save the guided backup setup after native UI checks","FILE");
  g_application_add_main_option(G_APPLICATION(app->application),"screenshot-backup-files",0,G_OPTION_FLAG_NONE,G_OPTION_ARG_STRING,"Save the backup source and schedule form after native UI checks","FILE");
  g_application_add_main_option(G_APPLICATION(app->application),"screenshot-destination",0,G_OPTION_FLAG_NONE,G_OPTION_ARG_STRING,"Save the server connection form after native UI checks","FILE");
  g_application_add_main_option(G_APPLICATION(app->application),"screenshot-advanced",0,G_OPTION_FLAG_NONE,G_OPTION_ARG_NONE,"Reveal advanced settings in the captured form",NULL);
  g_signal_connect(app->application,"activate",G_CALLBACK(activate),app);g_signal_connect(app->application,"command-line",G_CALLBACK(command_line),app);
  int status=g_application_run(G_APPLICATION(app->application),argc,argv);g_object_unref(app->application);
  /* Process exit also terminates background polling threads; the service owns jobs. */
  return status;
}
