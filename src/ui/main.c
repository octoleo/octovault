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

#define BUS_NAME "io.vdm.OctoVault1"
#define BUS_PATH "/io/vdm/OctoVault1"
#define BUS_IFACE "io.vdm.OctoVault1"
#ifndef OCTOVAULT_VERSION
#define OCTOVAULT_VERSION "1.0.0"
#endif

typedef struct App App;
typedef struct Operation Operation;
typedef struct Form Form;
typedef struct { const char *key, *label, *kind, *options, *hint; gboolean required; } Spec;
typedef struct { const Spec *spec; GtkWidget *widget, *row; GPtrArray *values; } Field;
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
  GQueue *pending_unlocks;
  gboolean automatic_prompt;
  Operation *active;
  gboolean smoke;
  gboolean show_notifications;
  guint preferred_theme;
};
struct Operation {
  App *app;
  char *op, *request, *id, *title, *record_id;
  GMutex mutex;
  gint cancelled;
  gint collection;
  gboolean background, reveal, acknowledge;
};
struct Form {
  App *app;
  GtkWindow *window;
  GtkLabel *error;
  char *operation;
  JsonObject *base;
  GPtrArray *fields;
  gboolean acknowledge;
  gboolean automatic;
};

typedef struct { App *app; char *operation, *title; JsonObject *record; } Action;
static const char *collection_names[] = { "vault", "destination", "repository", "backup" };
static void render_page(App *app);
static void refresh_all(App *app);
static void open_form(App *app, const char *operation, const char *title, JsonObject *record);
static void start_operation(App *app, const char *op, JsonObject *params, const char *title, gint collection, gboolean acknowledge);
static void result_window(App *app, const char *title, JsonNode *node, gboolean reveal, gboolean acknowledge);
static void snapshots_window(App *app, const char *repository, JsonNode *node);
static gboolean unlock_registered(App *app, const char *id);
static gboolean drain_unlocks(gpointer data);

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
    if(g_key_file_save_to_file(settings,path,NULL))g_chmod(path,0600);g_key_file_unref(settings);
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
  g_free(o->op);g_free(o->request);g_free(o->id);g_free(o->title);g_free(o->record_id);g_mutex_clear(&o->mutex);g_free(o);
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
        G_DBUS_CALL_FLAGS_NONE,120000,NULL,error);
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
  if(error){
    if(o->background){
      if(o->collection==0){add_activity(app,error->message);if(!strcmp(app->page,"Dashboard")||!strcmp(app->page,"Vaults")){render_page(app);append_text(app->body,"The system service is unavailable or did not complete this request. Install OctoVault's system package, then use Refresh. See Activity for details.","error");}}
    }else{add_activity(app,error->message);error_window(app,o->title,error->message);notify(app,"Operation needs attention",error->message);}
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
    else if(useful_result(o->op)&&payload)result_window(app,o->title,payload,FALSE,FALSE);
    refresh_all(app);
  }
  if(response)json_node_free(response);
  operation_free(o);
  g_idle_add(drain_unlocks,app);
}
static void start_operation(App *app,const char *op,JsonObject *params,const char *title,gint collection,gboolean acknowledge) {
  if(collection<0&&app->active){error_window(app,"An operation is already running","Wait for the current operation to finish, or cancel it, before starting another.");return;}
  Operation *o=g_new0(Operation,1);o->app=app;o->op=g_strdup(op);o->title=g_strdup(title);o->collection=collection;
  o->background=collection>=0;o->record_id=g_strdup(str(params,"id"));o->request=serialize_request(op,params);o->acknowledge=acknowledge;
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
typedef struct { GtkWindow *window; char *text; gboolean acknowledge; gboolean copied; GtkWidget *ack; } Recovery;
static void wipe(char *text){if(text){gsize len=strlen(text);volatile char *p=(volatile char*)text;while(len--)*p++=0;}}
static void recovery_free(gpointer data){Recovery *r=data;wipe(r->text);g_free(r->text);g_free(r);}
typedef struct { GdkClipboard *clipboard; GdkContentProvider *content; } ClipboardTimeout;
static gboolean clear_clipboard(gpointer data){
  ClipboardTimeout *saved=data;
  /* Never discard something the user copied after the recovery record. */
  if(gdk_clipboard_get_content(saved->clipboard)==saved->content)gdk_clipboard_set_text(saved->clipboard,"");
  g_clear_object(&saved->content);g_object_unref(saved->clipboard);g_free(saved);return G_SOURCE_REMOVE;
}
static void copy_recovery(GtkButton *b,gpointer data){
  Recovery *r=data;GdkClipboard *cb=gtk_widget_get_clipboard(GTK_WIDGET(r->window));gdk_clipboard_set_text(cb,r->text);
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
  Recovery *r=data;if(r->acknowledge&&!gtk_check_button_get_active(GTK_CHECK_BUTTON(r->ack))){gtk_widget_grab_focus(r->ack);return TRUE;}(void)w;return FALSE;
}
static void reveal_done(GtkButton *b,gpointer data){(void)b;Recovery*r=data;if(!r->acknowledge||gtk_check_button_get_active(GTK_CHECK_BUTTON(r->ack)))gtk_window_destroy(r->window);}
static void reveal_toggle(GtkToggleButton *button,gpointer data){gtk_widget_set_visible(GTK_WIDGET(data),gtk_toggle_button_get_active(button));}
static void result_window(App *app,const char *title,JsonNode *node,gboolean reveal,gboolean acknowledge){
  GtkWindow *w=dialog_window(app,title,720,620);GtkBox *root=GTK_BOX(gtk_box_new(GTK_ORIENTATION_VERTICAL,14));margin(GTK_WIDGET(root),24);
  append_text(root,title,"title-2");
  GtkWidget *scroll=gtk_scrolled_window_new();gtk_widget_set_vexpand(scroll,TRUE);
  GtkBox *content=GTK_BOX(gtk_box_new(GTK_ORIENTATION_VERTICAL,10));margin(GTK_WIDGET(content),8);
  gtk_scrolled_window_set_child(GTK_SCROLLED_WINDOW(scroll),GTK_WIDGET(content));gtk_box_append(root,scroll);
  if(reveal){
    Recovery *r=g_new0(Recovery,1);r->window=w;r->acknowledge=acknowledge;
    GString *s=g_string_new("OctoVault repository recovery\nKeep this record in a secure password manager outside this computer.\n\n");recovery_flatten(s,NULL,node);
    g_string_append(s,"\nUse the repository address and repository password with Restic on a replacement computer. Restore any required SSH key, verify the server host fingerprint, or configure the S3 access credentials before connecting.\n");
    r->text=g_string_free(s,FALSE);g_object_set_data_full(G_OBJECT(w),"recovery",r,recovery_free);
    append_text(content,"Save this complete recovery record in your password manager. OctoVault stores its credentials encrypted. A machine-bound credential file cannot recover your backup on another computer.",NULL);
    GtkWidget *toggle=gtk_toggle_button_new_with_mnemonic("_Reveal recovery information");gtk_box_append(content,toggle);
    GtkWidget *text=gtk_text_view_new();gtk_text_view_set_editable(GTK_TEXT_VIEW(text),FALSE);gtk_text_view_set_monospace(GTK_TEXT_VIEW(text),TRUE);gtk_text_view_set_wrap_mode(GTK_TEXT_VIEW(text),GTK_WRAP_WORD_CHAR);
    gtk_text_buffer_set_text(gtk_text_view_get_buffer(GTK_TEXT_VIEW(text)),r->text,-1);gtk_widget_set_visible(text,FALSE);gtk_box_append(content,text);g_signal_connect(toggle,"toggled",G_CALLBACK(reveal_toggle),text);
    GtkWidget *copy=gtk_button_new_with_mnemonic("_Copy complete recovery record");gtk_box_append(root,copy);g_signal_connect(copy,"clicked",G_CALLBACK(copy_recovery),r);
    append_text(root,"Clipboard clearing is attempted after one minute. Clipboard history applications may retain copied text.","dim-label");
    if(acknowledge){r->ack=gtk_check_button_new_with_mnemonic("I have _saved the complete recovery record outside this computer");gtk_box_append(root,r->ack);}
    GtkWidget *done=gtk_button_new_with_mnemonic("_Done");gtk_widget_set_halign(done,GTK_ALIGN_END);gtk_box_append(root,done);g_signal_connect(done,"clicked",G_CALLBACK(reveal_done),r);g_signal_connect(w,"close-request",G_CALLBACK(reveal_close),r);
  }else{detail_nodes(content,NULL,node,0);GtkWidget *close=gtk_button_new_with_mnemonic("_Close");gtk_widget_set_halign(close,GTK_ALIGN_END);gtk_box_append(root,close);g_signal_connect(close,"clicked",G_CALLBACK(close_window),w);}
  gtk_window_set_child(w,GTK_WIDGET(root));gtk_window_present(w);
}

#define S(k,l,t,o,h,r) {k,l,t,o,h,r}
#define END {NULL,NULL,NULL,NULL,NULL,FALSE}
static const Spec vault_fields[]={
 S("name","_Vault name","text",NULL,NULL,TRUE),S("file","Vault _container","save",NULL,"Choose the encrypted container's location and filename.",TRUE),
 S("size_gb","Size in _gigabytes","number","10","Decimal GB; the actual container is rounded up to a whole MiB.",TRUE),
 S("auth","_Authentication","choice","key|gpg|image|text","Hardware authentication uses an OpenPGP encryption key on a compatible security key.",TRUE),
 S("key_file","_Key file or image/text carrier","save",NULL,"Store the key separately from the encrypted container when possible. For an image carrier, select an existing JPEG.",TRUE),
 S("password","Key _passphrase","password",NULL,"Required for a password-protected key. It is sent only to the authorized service and never saved.",FALSE),
 S("_confirm_password","_Confirm key passphrase","password",NULL,NULL,FALSE),
 S("recipient","OpenPGP _recipient","text",NULL,"Full fingerprint of an existing encryption-capable OpenPGP recipient.",FALSE),
 S("cipher_file","Text cipher _file","file",NULL,"Required when using a cloaked text key.",FALSE),
 S("mountpoint","_Mount location","folder",NULL,"An empty, dedicated directory. Leave blank for the managed default.",FALSE),
 S("open_on","_Unlock automatically","choice","login|manual|drive|token",NULL,FALSE),S("drive_uuid","Key drive _UUID","text",NULL,"Used for drive-triggered unlocking.",FALSE),
 S("close_on","_Lock automatically","flags","screen-lock|logout|sleep|shutdown",NULL,FALSE),
 S("force_close","Allow force close of _busy applications","boolean",NULL,"Force closing can discard unsaved application work.",FALSE),END};
static const Spec vault_settings[]={
 S("name","_Vault name","text",NULL,NULL,TRUE),
 S("auth","_Authentication","choice","key|gpg|image|text","Select the method used by the existing key or carrier below.",TRUE),
 S("key_file","_Key file or image/text carrier","file",NULL,"Select an existing compatible key. Use Replace key to change the vault's encryption key.",TRUE),
 S("recipient","OpenPGP _recipient","text",NULL,NULL,FALSE),S("cipher_file","Text cipher _file","file",NULL,NULL,FALSE),
 S("open_on","_Unlock automatically","choice","login|manual|drive|token",NULL,FALSE),
 S("drive_uuid","Key drive _UUID","text",NULL,NULL,FALSE),S("close_on","_Lock automatically","flags","screen-lock|logout|sleep|shutdown",NULL,FALSE),
 S("force_close","Allow force close of _busy applications","boolean",NULL,"Applications holding this vault open may be terminated.",FALSE),
 S("hooks.open","After _opening script","file",NULL,"Runs as your user. Only choose scripts you trust.",FALSE),
 S("hooks.close","Before _closing script","file",NULL,"Runs while protected files are still accessible.",FALSE),
 S("hooks.after_close","After confirmed _lock script","file",NULL,"Runs only after the vault has been verified closed.",FALSE),END};
static const Spec vault_open[]={S("password","Key _passphrase","password",NULL,"Leave blank for supported hardware authentication.",FALSE),END};
static const Spec vault_close[]={S("force","_Force close busy applications","boolean",NULL,"May discard unsaved work. Leave disabled for a graceful lock.",FALSE),END};
static const Spec vault_resize[]={S("size_gb","New size in _gigabytes","number","20","The vault must be closed. Shrinking is not supported.",TRUE),S("password","Key _passphrase","password",NULL,NULL,FALSE),END};
static const Spec vault_passwd[]={S("old_password","_Current passphrase","password",NULL,NULL,TRUE),S("password","_New passphrase","password",NULL,NULL,TRUE),S("_confirm_password","_Confirm new passphrase","password",NULL,NULL,TRUE),END};
static const Spec vault_setkey[]={S("new_key_file","_Replacement key file","file",NULL,NULL,TRUE),S("old_password","Current key _passphrase","password",NULL,NULL,FALSE),S("password","Replacement key p_assphrase","password",NULL,NULL,FALSE),END};
static const Spec vault_export[]={S("format","_Export format","choice","key|image|text|qr",NULL,TRUE),S("output","_Output file","save",NULL,"For an image export, choose an existing JPEG carrier. Keep exported key material secure.",TRUE),S("cipher_file","Text cipher _file","file",NULL,"Required for a text export.",FALSE),S("password","Key _passphrase","password",NULL,NULL,FALSE),END};
static const Spec vault_search[]={S("query","_Search text","text",NULL,NULL,TRUE),END};
static const Spec migration_add[]={S("source","_File or folder to protect","path",NULL,"The original is retained temporarily until the close/reopen comparison succeeds.",TRUE),S("relative","_Location inside vault","text",NULL,"Relative destination, for example Documents or browser/profile.",TRUE),S("password","Key _passphrase to reopen","password",NULL,NULL,FALSE),END};
static const Spec migration_recover[]={S("migration_id","_Migration identifier","text",NULL,"Find this in Migration recovery records.",TRUE),S("action","_Recovery action","choice","resume|rollback",NULL,TRUE),S("password","Key _passphrase","password",NULL,NULL,FALSE),END};
static const Spec destination_fields[]={
 S("name","_Destination name","text",NULL,NULL,TRUE),S("type","Destination _type","choice","s3|sftp|local|rest",NULL,TRUE),
 S("endpoint","S3 or REST _endpoint","text",NULL,"Use HTTPS for remote destinations.",FALSE),S("region","S3 _region","text",NULL,NULL,FALSE),S("bucket","S3 _bucket","text",NULL,NULL,FALSE),
 S("access_key","S3 access key _ID","password",NULL,NULL,FALSE),S("secret_key","S3 secret access _key","password",NULL,NULL,FALSE),
 S("host","SSH _host","text",NULL,NULL,FALSE),S("port","SSH _port","integer","22",NULL,FALSE),S("user","SSH _username","text",NULL,NULL,FALSE),
 S("host_fingerprint","SSH host _fingerprint","text",NULL,"Verify the SHA256: fingerprint with the server administrator before connecting.",FALSE),
 S("ssh_private_key","SSH _private key","secret-file",NULL,"Paste or load the private key. It is stored as an encrypted service credential.",FALSE),S("ssh_passphrase","SSH key pass_phrase","password",NULL,NULL,FALSE),
 S("path","Base _path","text",NULL,"Local folder, SSH server directory, or destination prefix.",FALSE),
 S("rest_username","REST user_name","text",NULL,NULL,FALSE),S("rest_password","REST _password","password",NULL,NULL,FALSE),END};
static const Spec repository_fields[]={S("name","Repository _name","text",NULL,NULL,TRUE),S("destination_id","_Destination","reference","1",NULL,TRUE),S("path","Repository _path or prefix","text",NULL,"Location within the selected destination. Use a separate path for independent backup credentials.",FALSE),END};
static const Spec repository_import[]={S("name","Repository _name","text",NULL,NULL,TRUE),S("destination_id","_Destination","reference","1",NULL,TRUE),S("path","Repository _path or prefix","text",NULL,NULL,FALSE),S("password","Repository _password","password",NULL,NULL,TRUE),END};
static const Spec repository_check[]={S("read_data","_Read and verify all stored data","boolean",NULL,"Full verification may download a large amount of data.",FALSE),END};
static const Spec repository_files[]={S("snapshot","_Snapshot","text","latest","A snapshot identifier or latest.",TRUE),S("path","_Path within snapshot","text","/",NULL,FALSE),END};
static const Spec repository_find[]={S("pattern","Filename _pattern","text",NULL,"For example *.pdf.",TRUE),END};
static const Spec repository_diff[]={S("snapshot_a","_Earlier snapshot","text",NULL,NULL,TRUE),S("snapshot_b","_Later snapshot","text","latest",NULL,TRUE),END};
static const Spec repository_restore[]={S("snapshot","_Snapshot","text","latest",NULL,TRUE),S("target","Restore _destination","folder",NULL,"A separate empty folder is recommended.",TRUE),S("include","_Include paths or patterns","lines",NULL,"One per line. Leave blank to restore the complete snapshot.",FALSE),S("overwrite","_Allow replacing existing files","boolean",NULL,"Existing data at the restore destination may be overwritten.",FALSE),END};
static const Spec repository_forget[]={S("keep_daily","Keep _daily snapshots","integer","7",NULL,FALSE),S("keep_weekly","Keep _weekly snapshots","integer","4",NULL,FALSE),S("keep_monthly","Keep _monthly snapshots","integer","12",NULL,FALSE),S("dry_run","_Preview only","boolean","true","Keep enabled to review the selection before removing snapshots.",FALSE),END};
static const Spec repository_password[]={S("password","_New repository password","password",NULL,"Save the new password externally. The service updates its encrypted credential.",TRUE),S("_confirm_password","_Confirm new password","password",NULL,NULL,TRUE),END};
static const Spec repository_copy[]={S("target_id","_Target repository","reference","2",NULL,TRUE),S("snapshot","_Snapshot","text","latest",NULL,TRUE),END};
static const Spec plan_fields[]={
 S("name","Backup plan _name","text",NULL,NULL,TRUE),S("repository_id","_Repository","reference","2",NULL,TRUE),
 S("sources","_Files and folders","paths",NULL,"One absolute path per line. System-owned sources are backed up with approved administrative access.",TRUE),
 S("excludes","_Exclude patterns","lines",NULL,"One pattern per line.",FALSE),S("one_file_system","Stay on each source _filesystem","boolean",NULL,NULL,FALSE),
 S("vault_id","Linked _vault","reference","0",NULL,FALSE),S("vault_mode","Vault backup _mode","choice","none|open-files|closed-container","Open-files requires the vault to be mounted; closed-container requires verified closure.",FALSE),
 S("trigger","_Run backup","choice","manual|calendar|boot|idle|vault-open|vault-close|drive",NULL,TRUE),
 S("calendar","Calendar _schedule","text","daily","systemd calendar expression, for example daily or Mon..Fri 20:00.",FALSE),
 S("boot_delay_sec","Seconds after _boot","integer","3600",NULL,FALSE),S("idle_sec","Idle _seconds","integer","900",NULL,FALSE),S("drive_uuid","Trigger drive _UUID","text",NULL,NULL,FALSE),
 S("on_battery","Allow running on _battery power","boolean",NULL,NULL,FALSE),S("metered","Allow _metered connections","boolean",NULL,NULL,FALSE),
 S("retention.keep_daily","Keep _daily snapshots","integer","7",NULL,FALSE),S("retention.keep_weekly","Keep _weekly snapshots","integer","4",NULL,FALSE),S("retention.keep_monthly","Keep _monthly snapshots","integer","12",NULL,FALSE),END};
static const Spec empty_fields[]={END};
#undef S
#undef END
static const Spec *specifications(const char *op){
 if(!strcmp(op,"vault.create")||!strcmp(op,"vault.import"))return vault_fields;
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
static const char *selected_value(Form *form,const char *key){
  for(guint i=0;i<form->fields->len;i++){
    Field*f=g_ptr_array_index(form->fields,i);
    if(!strcmp(f->spec->key,key)&&GTK_IS_DROP_DOWN(f->widget)){
      guint n=gtk_drop_down_get_selected(GTK_DROP_DOWN(f->widget));
      return n<f->values->len?g_ptr_array_index(f->values,n):"";
    }
  }
  return "";
}
static void update_form_visibility(GObject *object,GParamSpec *pspec,gpointer data){
  (void)object;(void)pspec;Form*form=data;
  const char*type=selected_value(form,"type"),*auth=selected_value(form,"auth");
  const char*trigger=selected_value(form,"trigger"),*open=selected_value(form,"open_on");
  const char*mode=selected_value(form,"vault_mode"),*format=selected_value(form,"format");
  for(guint i=0;i<form->fields->len;i++){
    Field*f=g_ptr_array_index(form->fields,i);const char*k=f->spec->key;gboolean visible=TRUE;
    if(!strcmp(form->operation,"destination.save")){
      if(!strcmp(k,"endpoint"))visible=!strcmp(type,"s3")||!strcmp(type,"rest");
      else if(!strcmp(k,"region")||!strcmp(k,"bucket")||!strcmp(k,"access_key")||!strcmp(k,"secret_key"))visible=!strcmp(type,"s3");
      else if(!strcmp(k,"host")||!strcmp(k,"port")||!strcmp(k,"user")||!strcmp(k,"host_fingerprint")||g_str_has_prefix(k,"ssh_"))visible=!strcmp(type,"sftp");
      else if(g_str_has_prefix(k,"rest_"))visible=!strcmp(type,"rest");
    }
    if(*auth){
      if(!strcmp(k,"recipient"))visible=!strcmp(auth,"gpg");
      if(!strcmp(k,"cipher_file"))visible=!strcmp(auth,"text");
      if(!strcmp(k,"password")||!strcmp(k,"_confirm_password"))visible=strcmp(auth,"gpg")!=0;
    }
    if(*format&&!strcmp(k,"cipher_file"))visible=!strcmp(format,"text");
    if(*open&&!strcmp(k,"drive_uuid"))visible=!strcmp(open,"drive");
    if(!strcmp(form->operation,"backup.save")){
      if(!strcmp(k,"calendar"))visible=!strcmp(trigger,"calendar");
      if(!strcmp(k,"boot_delay_sec"))visible=!strcmp(trigger,"boot");
      if(!strcmp(k,"idle_sec"))visible=!strcmp(trigger,"idle");
      if(!strcmp(k,"drive_uuid"))visible=!strcmp(trigger,"drive");
      if(!strcmp(k,"vault_id"))visible=strcmp(mode,"none")!=0;
      if(!strcmp(k,"sources"))visible=strcmp(mode,"closed-container")!=0;
    }
    gtk_widget_set_visible(f->row,visible);
  }
}
static void field_free(gpointer data){Field*f=data;if(f->values)g_ptr_array_unref(f->values);g_free(f);}
static void form_free(gpointer data){Form*f=data;if(f->automatic){f->app->automatic_prompt=FALSE;g_idle_add(drain_unlocks,f->app);}g_free(f->operation);json_object_unref(f->base);g_ptr_array_unref(f->fields);g_free(f);}
static char *field_text(Field *f){
  if(GTK_IS_TEXT_VIEW(f->widget)){GtkTextBuffer *b=gtk_text_view_get_buffer(GTK_TEXT_VIEW(f->widget));GtkTextIter start,end;gtk_text_buffer_get_bounds(b,&start,&end);return gtk_text_buffer_get_text(b,&start,&end,FALSE);}
  return g_strdup(gtk_editable_get_text(GTK_EDITABLE(f->widget)));
}
typedef struct { GtkWidget *widget; GtkWindow *parent; gboolean secret; int mode; } Picker;
static void file_chosen(GObject *source,GAsyncResult *result,gpointer data){
  Picker*p=data;
  GError *select_error=NULL;
  GtkFileDialog *dialog=GTK_FILE_DIALOG(source);
  GFile *file=p->mode==2?gtk_file_dialog_select_folder_finish(dialog,result,&select_error):p->mode==1?gtk_file_dialog_save_finish(dialog,result,&select_error):gtk_file_dialog_open_finish(dialog,result,&select_error);
  if(file){char *path=g_file_get_path(file);
    if(path){
      if(p->secret){char *contents=NULL;gsize size=0;GError*error=NULL;if(g_file_get_contents(path,&contents,&size,&error)&&size<=262144){gtk_text_buffer_set_text(gtk_text_view_get_buffer(GTK_TEXT_VIEW(p->widget)),contents,(int)size);}else{GtkAlertDialog *message=gtk_alert_dialog_new("%s",error?error->message:"The selected key is too large.");gtk_alert_dialog_show(message,p->parent);g_object_unref(message);}g_clear_error(&error);wipe(contents);g_free(contents);}
      else if(GTK_IS_TEXT_VIEW(p->widget)){GtkTextBuffer *b=gtk_text_view_get_buffer(GTK_TEXT_VIEW(p->widget));GtkTextIter end;gtk_text_buffer_get_end_iter(b,&end);if(gtk_text_buffer_get_char_count(b))gtk_text_buffer_insert(b,&end,"\n",1);gtk_text_buffer_insert(b,&end,path,-1);}
      else gtk_editable_set_text(GTK_EDITABLE(p->widget),path);
    }g_free(path);g_object_unref(file);
  }
  g_clear_error(&select_error);g_object_unref(p->widget);g_object_unref(p->parent);g_free(p);
}
static void choose_file(GtkButton *button,gpointer data){
  Field*f=data;const char *kind=f->spec->kind;
  GtkWindow *parent=GTK_WINDOW(gtk_widget_get_root(GTK_WIDGET(button)));
  gboolean folder=!strcmp(kind,"folder")||GPOINTER_TO_INT(g_object_get_data(G_OBJECT(button),"choose-folder"));
  GtkFileDialog *dialog=gtk_file_dialog_new();gtk_file_dialog_set_title(dialog,folder?"Choose a folder":"Choose a file");
  Picker*p=g_new0(Picker,1);p->widget=g_object_ref(f->widget);p->parent=g_object_ref(parent);p->secret=!strcmp(kind,"secret-file");p->mode=folder?2:!strcmp(kind,"save")?1:0;
  if(p->mode==2)gtk_file_dialog_select_folder(dialog,parent,NULL,file_chosen,p);
  else if(p->mode==1)gtk_file_dialog_save(dialog,parent,NULL,file_chosen,p);
  else gtk_file_dialog_open(dialog,parent,NULL,file_chosen,p);
  g_object_unref(dialog);
}
static char *choice_label(const char *s){
  if(!strcmp(s,"key"))return g_strdup("Password-protected key file");
  if(!strcmp(s,"gpg"))return g_strdup("OpenPGP / YubiKey");
  if(!strcmp(s,"image"))return g_strdup("Key hidden in a JPEG image");
  if(!strcmp(s,"text"))return g_strdup("Key hidden in text");
  if(!strcmp(s,"s3"))return g_strdup("S3-compatible object storage");
  if(!strcmp(s,"sftp"))return g_strdup("SSH / SFTP server");
  if(!strcmp(s,"rest"))return g_strdup("REST backup server");
  if(!strcmp(s,"local"))return g_strdup("Local or removable drive");
  if(!strcmp(s,"login"))return g_strdup("After desktop login");
  if(!strcmp(s,"boot"))return g_strdup("After computer startup");
  if(!strcmp(s,"calendar"))return g_strdup("Calendar schedule");
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
  GtkWidget*name=gtk_label_new_with_mnemonic(spec->label);gtk_label_set_xalign(GTK_LABEL(name),0);gtk_widget_add_css_class(name,"heading");gtk_box_append(row,name);
  const char *kind=spec->kind;
  if(!strcmp(kind,"boolean")){f->widget=gtk_check_button_new();gtk_check_button_set_active(GTK_CHECK_BUTTON(f->widget),existing?json_node_get_boolean(existing):spec->options&&!strcmp(spec->options,"true"));gtk_box_append(row,f->widget);}
  else if(!strcmp(kind,"flags")){
    f->widget=gtk_box_new(GTK_ORIENTATION_VERTICAL,4);f->values=g_ptr_array_new_with_free_func(g_free);char**options=g_strsplit(spec->options,"|",-1);
    for(guint i=0;options[i];i++){char*t=choice_label(options[i]);GtkWidget*b=gtk_check_button_new_with_label(t);g_free(t);gtk_check_button_set_active(GTK_CHECK_BUTTON(b),existing?string_array_has(existing,options[i]):!strcmp(options[i],"shutdown"));gtk_box_append(GTK_BOX(f->widget),b);g_ptr_array_add(f->values,g_strdup(options[i]));}g_strfreev(options);gtk_box_append(row,f->widget);
  }else if(!strcmp(kind,"choice")||!strcmp(kind,"reference")){
    GtkStringList*model=gtk_string_list_new(NULL);f->values=g_ptr_array_new_with_free_func(g_free);guint selected=0;
    if(!strcmp(kind,"reference")){
      gtk_string_list_append(model,spec->required?"Select…":"None");g_ptr_array_add(f->values,g_strdup(""));
      guint index=(guint)atoi(spec->options);JsonNode*n=form->app->collections[index];
      if(n&&JSON_NODE_HOLDS_ARRAY(n)){JsonArray*a=json_node_get_array(n);for(guint i=0;i<json_array_get_length(a);i++){JsonNode*item=json_array_get_element(a,i);if(!JSON_NODE_HOLDS_OBJECT(item))continue;JsonObject*o=json_node_get_object(item);gtk_string_list_append(model,str(o,"name"));g_ptr_array_add(f->values,g_strdup(str(o,"id")));if(existing&&!strcmp(initial,str(o,"id")))selected=f->values->len-1;}}
    }else{char**options=g_strsplit(spec->options,"|",-1);for(guint i=0;options[i];i++){char*t=choice_label(options[i]);gtk_string_list_append(model,t);g_free(t);g_ptr_array_add(f->values,g_strdup(options[i]));if(existing&&!strcmp(initial,options[i]))selected=i;}g_strfreev(options);}
    f->widget=gtk_drop_down_new(G_LIST_MODEL(model),NULL);gtk_drop_down_set_selected(GTK_DROP_DOWN(f->widget),selected);gtk_box_append(row,f->widget);
  }else if(!strcmp(kind,"number")||!strcmp(kind,"integer")){
    f->widget=gtk_spin_button_new_with_range(!strcmp(kind,"number")?0.001:0,100000000, !strcmp(kind,"number")?0.1:1);gtk_spin_button_set_digits(GTK_SPIN_BUTTON(f->widget),!strcmp(kind,"number")?3:0);gtk_spin_button_set_value(GTK_SPIN_BUTTON(f->widget),g_ascii_strtod(initial,NULL));gtk_box_append(row,f->widget);
  }else if(!strcmp(kind,"lines")||!strcmp(kind,"paths")||!strcmp(kind,"secret-file")){
    f->widget=gtk_text_view_new();gtk_text_view_set_wrap_mode(GTK_TEXT_VIEW(f->widget),GTK_WRAP_WORD_CHAR);gtk_text_view_set_monospace(GTK_TEXT_VIEW(f->widget),TRUE);gtk_widget_set_size_request(f->widget,-1,90);
    if(existing)gtk_text_buffer_set_text(gtk_text_view_get_buffer(GTK_TEXT_VIEW(f->widget)),initial,-1);
    GtkWidget*scroll=gtk_scrolled_window_new();gtk_scrolled_window_set_min_content_height(GTK_SCROLLED_WINDOW(scroll),90);gtk_scrolled_window_set_max_content_height(GTK_SCROLLED_WINDOW(scroll),160);gtk_scrolled_window_set_child(GTK_SCROLLED_WINDOW(scroll),f->widget);gtk_widget_add_css_class(scroll,"frame");gtk_box_append(row,scroll);
    if(!strcmp(kind,"secret-file")){GtkWidget*b=gtk_button_new_with_label("Load private key…");gtk_box_append(row,b);g_signal_connect(b,"clicked",G_CALLBACK(choose_file),f);}
    if(!strcmp(kind,"paths")){GtkBox*buttons=GTK_BOX(gtk_box_new(GTK_ORIENTATION_HORIZONTAL,8));gtk_box_append(row,GTK_WIDGET(buttons));GtkWidget*b=gtk_button_new_with_label("Add file…");gtk_box_append(buttons,b);g_signal_connect(b,"clicked",G_CALLBACK(choose_file),f);b=gtk_button_new_with_label("Add folder…");g_object_set_data(G_OBJECT(b),"choose-folder",GINT_TO_POINTER(1));gtk_box_append(buttons,b);g_signal_connect(b,"clicked",G_CALLBACK(choose_file),f);}
  }else{
    f->widget=!strcmp(kind,"password")?gtk_password_entry_new():gtk_entry_new();
    if(!strcmp(kind,"password"))gtk_password_entry_set_show_peek_icon(GTK_PASSWORD_ENTRY(f->widget),TRUE);
    else gtk_editable_set_text(GTK_EDITABLE(f->widget),initial);
    GtkBox*line=GTK_BOX(gtk_box_new(GTK_ORIENTATION_HORIZONTAL,8));gtk_widget_set_hexpand(f->widget,TRUE);gtk_box_append(line,f->widget);gtk_box_append(row,GTK_WIDGET(line));
    if(!strcmp(kind,"file")||!strcmp(kind,"folder")||!strcmp(kind,"path")||!strcmp(kind,"save")){GtkWidget*b=gtk_button_new_from_icon_name("document-open-symbolic");gtk_widget_set_tooltip_text(b,"Choose a file or folder");gtk_box_append(line,b);g_signal_connect(b,"clicked",G_CALLBACK(choose_file),f);if(!strcmp(kind,"path")){b=gtk_button_new_from_icon_name("folder-open-symbolic");gtk_widget_set_tooltip_text(b,"Choose a folder");g_object_set_data(G_OBJECT(b),"choose-folder",GINT_TO_POINTER(1));gtk_box_append(line,b);g_signal_connect(b,"clicked",G_CALLBACK(choose_file),f);}}
  }
  gtk_label_set_mnemonic_widget(GTK_LABEL(name),f->widget);
  char*accessible=g_strdup(spec->label);for(char*p=accessible;*p;p++)if(*p=='_')memmove(p,p+1,strlen(p));
  gtk_accessible_update_property(GTK_ACCESSIBLE(f->widget),GTK_ACCESSIBLE_PROPERTY_LABEL,accessible,-1);g_free(accessible);
  if(spec->hint)append_text(row,spec->hint,"dim-label");
  if(!strcmp(spec->key,"size_gb")){GtkWidget*actual=label("","dim-label");gtk_box_append(row,actual);g_signal_connect(f->widget,"value-changed",G_CALLBACK(size_changed),actual);size_changed(GTK_SPIN_BUTTON(f->widget),actual);}
  g_free(initial);g_ptr_array_add(form->fields,f);return f;
}
static void submit_form(GtkButton*button,gpointer data){
  (void)button;Form*f=data;JsonObject*params=copy_object(f->base);gboolean valid=TRUE;
  for(guint i=0;i<f->fields->len;i++){
    Field*field=g_ptr_array_index(f->fields,i);const Spec*s=field->spec;JsonNode*n=json_node_new(JSON_NODE_VALUE);
    if(s->key[0]=='_'){json_node_free(n);continue;}
    if(!gtk_widget_get_visible(field->row)){json_node_free(n);continue;}
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
      if(s->required&&!*value){char*msg=g_strdup_printf("Please complete %s.",s->label);gtk_label_set_text(f->error,msg);g_free(msg);gtk_widget_grab_focus(field->widget);valid=FALSE;wipe(value);g_free(value);json_node_free(n);break;}
      if(!strcmp(s->kind,"lines")||!strcmp(s->kind,"paths")){
        JsonArray*a=json_array_new();char**lines=g_strsplit(value,"\n",-1);for(guint j=0;lines[j];j++){g_strstrip(lines[j]);if(*lines[j])json_array_add_string_element(a,lines[j]);}g_strfreev(lines);json_node_free(n);n=json_node_new(JSON_NODE_ARRAY);json_node_take_array(n,a);
      }else json_node_set_string(n,value);
      wipe(value);g_free(value);
    }
    set_nested(params,s->key,n);
  }
  if(valid){
    for(guint i=0;i<f->fields->len;i++){
      Field*field=g_ptr_array_index(f->fields,i);
      if(!strcmp(field->spec->key,"_confirm_password")&&gtk_widget_get_visible(field->row)){
        char*confirmation=field_text(field);
        if(strcmp(confirmation,str(params,"password"))){gtk_label_set_text(f->error,"The password confirmation does not match.");gtk_widget_grab_focus(field->widget);valid=FALSE;}
        wipe(confirmation);g_free(confirmation);
      }
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
    if(!strcmp(f->operation,"vault.create")){double gb=json_object_get_double_member(params,"size_gb");if(gb<=0){gtk_label_set_text(f->error,"Choose a vault size greater than zero.");valid=FALSE;}}
    if(valid){start_operation(f->app,f->operation,params,gtk_window_get_title(f->window),-1,f->acknowledge);gtk_window_destroy(f->window);}
  }
  json_object_unref(params);
}
static void open_form(App*app,const char*operation,const char*title,JsonObject*record){
  if(app->active){error_window(app,"An operation is already running","Wait for the current operation to complete or cancel it first.");return;}
  Form*f=g_new0(Form,1);f->app=app;f->operation=g_strdup(operation);f->base=json_object_new();f->fields=g_ptr_array_new_with_free_func(field_free);f->acknowledge=!strcmp(operation,"repository.create");f->automatic=app->automatic_prompt&&!strcmp(operation,"vault.open");
  if(record&&*str(record,"id"))json_object_set_string_member(f->base,"id",str(record,"id"));
  GtkWindow*w=dialog_window(app,title,650,760);f->window=w;g_object_set_data_full(G_OBJECT(w),"form",f,form_free);
  GtkBox*root=GTK_BOX(gtk_box_new(GTK_ORIENTATION_VERTICAL,12));margin(GTK_WIDGET(root),24);append_text(root,title,"title-2");
  if(record&&*str(record,"name"))append_text(root,str(record,"name"),"dim-label");
  GtkWidget*scroll=gtk_scrolled_window_new();gtk_widget_set_vexpand(scroll,TRUE);GtkBox*content=GTK_BOX(gtk_box_new(GTK_ORIENTATION_VERTICAL,18));margin(GTK_WIDGET(content),6);gtk_scrolled_window_set_child(GTK_SCROLLED_WINDOW(scroll),GTK_WIDGET(content));gtk_box_append(root,scroll);
  if(strstr(operation,".remove"))append_text(content,"This removes the registration and its managed automation. Your encrypted container or remote backup data will remain intact.",NULL);
  else if(!strcmp(operation,"migration.add"))append_text(content,"OctoVault retains a temporary original, copies into the open vault, creates the mapping and empty original placeholder, then closes and reopens the vault. The temporary original is removed only after the mounted contents match. Close applications using this data before continuing.",NULL);
  else if(!strcmp(operation,"repository.create"))append_text(content,"A strong random repository password will be generated. After creation, save the complete recovery record in your password manager.",NULL);
  else if(!strcmp(operation,"repository.prune"))append_text(content,"Pruning permanently removes data no longer referenced by retained snapshots. Other jobs for this repository must finish first.",NULL);
  else if(!strcmp(operation,"repository.recovery"))append_text(content,"This reveals repository access credentials. Continue only when you can save or inspect them privately.",NULL);
  else if(!strcmp(operation,"destination.save"))append_text(content,"Fill the connection settings for the selected destination type. When editing, empty secret fields keep the existing encrypted credentials.",NULL);
  else if(specifications(operation)==empty_fields)append_text(content,"Continue to run this operation. Its progress and result will appear in OctoVault.",NULL);
  const Spec*spec=specifications(operation);
  for(guint i=0;spec[i].key;i++){
    if(!strcmp(operation,"vault.import")&&!strcmp(spec[i].key,"size_gb"))continue;
    if(!strcmp(operation,"vault.import")&&(!strcmp(spec[i].key,"password")||!strcmp(spec[i].key,"_confirm_password")))continue;
    create_field(f,&spec[i],record,content);
  }
  for(guint i=0;i<f->fields->len;i++){Field*field=g_ptr_array_index(f->fields,i);if(GTK_IS_DROP_DOWN(field->widget))g_signal_connect(field->widget,"notify::selected",G_CALLBACK(update_form_visibility),f);}
  update_form_visibility(NULL,NULL,f);
  f->error=GTK_LABEL(label("","error"));gtk_box_append(root,GTK_WIDGET(f->error));
  GtkBox*buttons=GTK_BOX(gtk_box_new(GTK_ORIENTATION_HORIZONTAL,10));gtk_widget_set_halign(GTK_WIDGET(buttons),GTK_ALIGN_END);gtk_box_append(root,GTK_WIDGET(buttons));
  GtkWidget*cancel=gtk_button_new_with_mnemonic("_Cancel");gtk_box_append(buttons,cancel);g_signal_connect(cancel,"clicked",G_CALLBACK(close_window),w);
  GtkWidget*submit=gtk_button_new_with_mnemonic("_Continue");gtk_widget_add_css_class(submit,strstr(operation,".remove")||!strcmp(operation,"repository.prune")?"destructive-action":"suggested-action");gtk_box_append(buttons,submit);g_signal_connect(submit,"clicked",G_CALLBACK(submit_form),f);
  gtk_window_set_child(w,GTK_WIDGET(root));gtk_window_present(w);
}

static void action_free(gpointer data,GClosure*closure){(void)closure;Action*a=data;g_free(a->operation);g_free(a->title);if(a->record)json_object_unref(a->record);g_free(a);}
static void action_clicked(GtkButton*button,gpointer data){
  Action*a=data;GtkWidget*ancestor=gtk_widget_get_ancestor(GTK_WIDGET(button),GTK_TYPE_POPOVER);if(ancestor)gtk_popover_popdown(GTK_POPOVER(ancestor));
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
      JsonObject*check=json_object_get_object_member(record,"last_check");char*state=g_strdup_printf("Last %s check: %s",boolean(check,"read_data")?"full data":"repository",str(check,"at"));append_text(inside,state,"dim-label");g_free(state);
    }else append_text(inside,"Repository has not yet been checked by OctoVault.","dim-label");
  }else if(collection==3&&json_object_has_member(record,"last_run")&&JSON_NODE_HOLDS_OBJECT(json_object_get_member(record,"last_run"))){
    JsonObject*last=json_object_get_object_member(record,"last_run");char*state=g_strdup_printf("Last run: %s · %s",str(last,"status"),str(last,"finished_at"));append_text(inside,state,"dim-label");g_free(state);
  }
  GtkWidget*more=gtk_menu_button_new();gtk_menu_button_set_icon_name(GTK_MENU_BUTTON(more),"view-more-symbolic");gtk_widget_set_tooltip_text(more,"More actions");gtk_widget_set_valign(more,GTK_ALIGN_START);gtk_box_append(heading,more);
  GtkWidget*popover=gtk_popover_new();GtkBox*menu=GTK_BOX(gtk_box_new(GTK_ORIENTATION_VERTICAL,2));margin(GTK_WIDGET(menu),6);
  GtkWidget*menu_scroll=gtk_scrolled_window_new();gtk_scrolled_window_set_max_content_height(GTK_SCROLLED_WINDOW(menu_scroll),420);gtk_scrolled_window_set_propagate_natural_height(GTK_SCROLLED_WINDOW(menu_scroll),TRUE);gtk_scrolled_window_set_child(GTK_SCROLLED_WINDOW(menu_scroll),GTK_WIDGET(menu));gtk_popover_set_child(GTK_POPOVER(popover),menu_scroll);gtk_menu_button_set_popover(GTK_MENU_BUTTON(more),popover);
  GtkBox*buttons=GTK_BOX(gtk_box_new(GTK_ORIENTATION_HORIZONTAL,8));gtk_box_append(inside,GTK_WIDGET(buttons));
  if(collection==0){
    gtk_box_append(buttons,action_button(app,"Unlock","vault.open",record,"suggested-action"));gtk_box_append(buttons,action_button(app,"Lock","vault.close",record,NULL));gtk_box_append(buttons,action_button(app,"Protect files…","migration.add",record,NULL));
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
static void about_clicked(GtkButton*button,gpointer data){
  (void)button;App*app=data;const char*developers[]={"Vast Development Method",NULL};
  GtkWidget*w=adw_about_window_new();adw_about_window_set_application_name(ADW_ABOUT_WINDOW(w),"OctoVault");adw_about_window_set_application_icon(ADW_ABOUT_WINDOW(w),"io.vdm.OctoVault");
  adw_about_window_set_developer_name(ADW_ABOUT_WINDOW(w),"Vast Development Method");adw_about_window_set_developers(ADW_ABOUT_WINDOW(w),developers);adw_about_window_set_version(ADW_ABOUT_WINDOW(w),OCTOVAULT_VERSION);adw_about_window_set_website(ADW_ABOUT_WINDOW(w),"https://www.vdm.io");adw_about_window_set_issue_url(ADW_ABOUT_WINDOW(w),"https://github.com/octoleo/octovault/issues");adw_about_window_set_copyright(ADW_ABOUT_WINDOW(w),"© 2026 Vast Development Method");adw_about_window_set_license_type(ADW_ABOUT_WINDOW(w),GTK_LICENSE_APACHE_2_0);adw_about_window_set_comments(ADW_ABOUT_WINDOW(w),"Encrypted vaults and independent backups. Part of the OctoLeo Suite.");
  const char*tomb[]={"Tomb developers — https://dyne.org/tomb/",NULL};const char*restic[]={"Restic contributors — https://restic.net/",NULL};const char*desktop[]={"GNOME, GTK and libadwaita contributors", "systemd, GnuPG, cryptsetup and Linux contributors",NULL};
  adw_about_window_add_credit_section(ADW_ABOUT_WINDOW(w),"Vault technology",tomb);adw_about_window_add_credit_section(ADW_ABOUT_WINDOW(w),"Backup technology",restic);adw_about_window_add_credit_section(ADW_ABOUT_WINDOW(w),"Desktop and system integration",desktop);
  adw_about_window_add_legal_section(ADW_ABOUT_WINDOW(w),"Tomb","Tomb contributors",GTK_LICENSE_GPL_3_0,NULL);adw_about_window_add_legal_section(ADW_ABOUT_WINDOW(w),"Restic","Restic contributors",GTK_LICENSE_CUSTOM,"BSD 2-Clause License. See https://github.com/restic/restic/blob/master/LICENSE for the full license and copyright notices.");
  gtk_window_set_transient_for(GTK_WINDOW(w),app->window);gtk_window_present(GTK_WINDOW(w));
}
static void render_page(App*app){
  if(!app->body)return;
  GtkWidget*child;while((child=gtk_widget_get_first_child(GTK_WIDGET(app->body))))gtk_box_remove(app->body,child);
  gtk_label_set_text(app->title,app->page);
  GtkBox*toolbar=GTK_BOX(gtk_box_new(GTK_ORIENTATION_HORIZONTAL,8));gtk_box_append(app->body,GTK_WIDGET(toolbar));
  if(!strcmp(app->page,"Dashboard")){
    append_text(app->body,"Your protected data, at a glance","title-1");
    char*summary=g_strdup_printf("%u vaults · %u backup plans · %u repositories · %u destinations",collection_count(app,0),collection_count(app,3),collection_count(app,2),collection_count(app,1));append_text(app->body,summary,"title-3");g_free(summary);
    gtk_box_append(toolbar,action_button(app,"Create vault…","vault.create",NULL,"suggested-action"));gtk_box_append(toolbar,action_button(app,"Create backup plan…","backup.save",NULL,NULL));
    append_text(app->body,"Vaults","title-2");collection_cards(app,0,"Create or import a vault to protect folders and files.");
    append_text(app->body,"Backup plans","title-2");collection_cards(app,3,"Add a destination and repository, then create your first independent backup plan.");
  }else if(!strcmp(app->page,"Vaults")){
    gtk_box_append(toolbar,action_button(app,"Create vault…","vault.create",NULL,"suggested-action"));gtk_box_append(toolbar,action_button(app,"Import existing vault…","vault.import",NULL,NULL));
    append_text(app->body,"Protect files in encrypted containers. When a vault locks, its mapped locations reveal their independent underlying contents.","dim-label");collection_cards(app,0,"No vaults registered.");
  }else if(!strcmp(app->page,"Backups")){
    gtk_box_append(toolbar,action_button(app,"Create plan…","backup.save",NULL,"suggested-action"));gtk_box_append(toolbar,action_button(app,"Create repository…","repository.create",NULL,NULL));gtk_box_append(toolbar,action_button(app,"Connect existing repository…","repository.import",NULL,NULL));
    append_text(app->body,"Plans","title-2");collection_cards(app,3,"No backup plans configured.");append_text(app->body,"Repositories & recovery","title-2");collection_cards(app,2,"Add a destination, then create or connect a repository.");
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
    GtkWidget*widget=GTK_WIDGET(app->window);int width=gtk_widget_get_width(widget),height=gtk_widget_get_height(widget);
    GdkPaintable*paintable=gtk_widget_paintable_new(widget);GtkSnapshot*snapshot=gtk_snapshot_new();gdk_paintable_snapshot(paintable,GDK_SNAPSHOT(snapshot),width,height);
    GskRenderNode*node=gtk_snapshot_free_to_node(snapshot);
    if(node){GskRenderer*renderer=gtk_native_get_renderer(GTK_NATIVE(app->window));graphene_rect_t bounds=GRAPHENE_RECT_INIT(0,0,width,height);GdkTexture*texture=gsk_renderer_render_texture(renderer,node,&bounds);gdk_texture_save_to_png(texture,app->screenshot);g_object_unref(texture);gsk_render_node_unref(node);}g_object_unref(paintable);
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
static int command_line(GApplication*application,GApplicationCommandLine*command,gpointer data){
  App*app=data;GVariantDict*options=g_application_command_line_get_options_dict(command);
  if(g_variant_dict_contains(options,"smoke-test"))app->smoke=TRUE;
  const char*screenshot=NULL;if(g_variant_dict_lookup(options,"screenshot","&s",&screenshot)){app->screenshot=g_strdup(screenshot);app->smoke=TRUE;}
  g_application_activate(application);
  const char*unlock=NULL;if(g_variant_dict_lookup(options,"unlock","&s",&unlock)){
    if(!g_queue_find_custom(app->pending_unlocks,unlock,(GCompareFunc)g_strcmp0))g_queue_push_tail(app->pending_unlocks,g_strdup(unlock));
    g_idle_add(drain_unlocks,app);
  }
  if(app->smoke){
    for(guint i=0;i<6;i++)gtk_toggle_button_set_active(app->navigation[i],TRUE);
    const char *ops[]={"vault.create","vault.import","vault.update","vault.open","vault.close","vault.resize","vault.passwd","vault.setkey","vault.key-export","vault.search","migration.add","migration.recover","destination.save","repository.create","repository.import","repository.check","repository.files","repository.find","repository.diff","repository.restore","repository.forget","repository.password","repository.copy","backup.save"};
    for(guint i=0;i<G_N_ELEMENTS(ops);i++){open_form(app,ops[i],ops[i],NULL);GListModel*windows=gtk_window_get_toplevels();guint count=g_list_model_get_n_items(windows);if(count>1){GtkWindow*w=g_list_model_get_item(windows,count-1);if(w!=app->window)gtk_window_destroy(w);g_object_unref(w);}}
    gtk_toggle_button_set_active(app->navigation[0],TRUE);g_timeout_add(300,smoke_finished,app);
  }
  return 0;
}
int main(int argc,char**argv){
  App*app=g_new0(App,1);app->page=g_strdup("Dashboard");app->activity=g_ptr_array_new_with_free_func(g_free);app->pending_unlocks=g_queue_new();app->show_notifications=TRUE;
  load_preferences(app);
  app->application=adw_application_new("io.vdm.OctoVault",G_APPLICATION_HANDLES_COMMAND_LINE);
  g_application_add_main_option(G_APPLICATION(app->application),"smoke-test",0,G_OPTION_FLAG_NONE,G_OPTION_ARG_NONE,"Construct all pages and dialogs, then exit",NULL);
  g_application_add_main_option(G_APPLICATION(app->application),"unlock",0,G_OPTION_FLAG_NONE,G_OPTION_ARG_STRING,"Offer to unlock a registered vault","ID");
  g_application_add_main_option(G_APPLICATION(app->application),"screenshot",0,G_OPTION_FLAG_NONE,G_OPTION_ARG_STRING,"Save a smoke-test screenshot","FILE");
  g_signal_connect(app->application,"activate",G_CALLBACK(activate),app);g_signal_connect(app->application,"command-line",G_CALLBACK(command_line),app);
  int status=g_application_run(G_APPLICATION(app->application),argc,argv);g_object_unref(app->application);
  /* Process exit also terminates background polling threads; the service owns jobs. */
  return status;
}
