/* Desktop unlock sequence and unprivileged FIDO2 interaction. */
static gboolean has_fido(JsonObject *record){
  JsonNode *node=record&&json_object_has_member(record,"fido2")?json_object_get_member(record,"fido2"):NULL;
  return node&&JSON_NODE_HOLDS_OBJECT(node);
}
static gboolean same_vault_key(JsonObject *a,JsonObject *b){
  return *str(a,"key_file")&&!strcmp(str(a,"key_file"),str(b,"key_file"))&&!strcmp(str(a,"auth"),str(b,"auth"))&&
    !strcmp(str(a,"recipient"),str(b,"recipient"))&&boolean(a,"require_token")==boolean(b,"require_token");
}
static void clear_shared_unlock(App *app){
  wipe(app->shared_password);g_clear_pointer(&app->shared_password,g_free);g_clear_pointer(&app->shared_key,g_free);g_clear_pointer(&app->shared_vaults,g_hash_table_unref);
}
static void remember_shared_unlock(Form *form,JsonObject *params){
  Field *choice=find_field(form,"_unlock_shared");
  Field *remaining=find_field(form,"_unlock_remaining");
  gboolean matching=choice&&gtk_widget_get_visible(choice->row)&&gtk_check_button_get_active(GTK_CHECK_BUTTON(choice->widget));
  gboolean all=remaining&&gtk_widget_get_visible(remaining->row)&&gtk_check_button_get_active(GTK_CHECK_BUTTON(remaining->widget));
  if((!matching&&!all)||!*str(params,"password"))return;
  App *app=form->app;clear_shared_unlock(app);app->shared_password=g_strdup(str(params,"password"));app->shared_key=g_strdup(str(form->original,"key_file"));app->shared_vaults=g_hash_table_new_full(g_str_hash,g_str_equal,g_free,NULL);
  JsonNode *collection=app->collections[0];if(!collection||!JSON_NODE_HOLDS_ARRAY(collection))return;
  JsonArray *vaults=json_node_get_array(collection);
  for(guint i=0;i<json_array_get_length(vaults);i++){
    JsonNode *node=json_array_get_element(vaults,i);if(!JSON_NODE_HOLDS_OBJECT(node))continue;
    JsonObject *record=json_node_get_object(node);const char *id=str(record,"id");
    if(strcmp(id,str(form->original,"id"))&&strcmp(str(record,"status"),"open")&&!openpgp_auth(str(record,"auth"))&&((matching&&same_vault_key(form->original,record))||(all&&g_queue_find_custom(app->pending_unlocks,id,(GCompareFunc)g_strcmp0)))){
      g_hash_table_add(app->shared_vaults,g_strdup(id));if(!g_queue_find_custom(app->pending_unlocks,id,(GCompareFunc)g_strcmp0))g_queue_push_tail(app->pending_unlocks,g_strdup(id));
    }
  }
}
static void run_form_operation(Form *form,JsonObject *params,const char *operation){
  form->submitted=TRUE;gtk_label_set_text(form->error,"");
  if(!strcmp(operation,"vault.open"))remember_shared_unlock(form,params);
  start_operation(form->app,operation,params,!strcmp(operation,"vault.update")&&!strcmp(form->operation,"ui.fido-enroll")?"Register FIDO2 security key":gtk_window_get_title(form->window),-1,form->acknowledge);
  if(form->app->active&&!strcmp(form->app->active->op,operation)){
    form->app->active->setup_window=g_object_ref(form->window);clear_form_secrets(form);gtk_widget_set_visible(GTK_WIDGET(form->window),FALSE);
  }else gtk_window_destroy(form->window);
}
static const char *fido_error_message(const char *code){
  if(!strcmp(code,"pin_invalid"))return "The security key PIN is incorrect. Check it before trying again; repeated failures can block the key.";
  if(!strcmp(code,"pin_blocked"))return "The security key PIN is blocked. Use your vault recovery passphrase. Do not reset the key to try to recover its vault credential.";
  if(!strcmp(code,"pin_not_set"))return "Set a FIDO2 PIN using your security key manager, then register the key here.";
  if(!strcmp(code,"wrong_key"))return "This is not the registered security key. Connect the original key or use your recovery passphrase.";
  if(!strcmp(code,"multiple_devices"))return "More than one FIDO2 key is connected. Leave only the key you want to use connected, then retry.";
  if(!strcmp(code,"unsupported_device"))return "This security key does not support FIDO2 hmac-secret. Use a compatible key or your recovery passphrase.";
  if(!strcmp(code,"device_missing"))return "Connect your FIDO2 security key, then try again.";
  if(!strcmp(code,"cancelled"))return "The security key operation was cancelled or timed out. Your vault is unchanged.";
  if(!strcmp(code,"invalid_enrollment"))return "The saved security key registration could not be read or verified. Use your recovery passphrase.";
  return "The FIDO2 operation did not finish. Check the key, PIN and touch prompt, then try again. Your vault and recovery passphrase are unchanged.";
}
typedef struct {Form *form;GtkWindow *window;JsonObject *params;gboolean enrolling;guint timeout,generation;char *input;} FidoCall;
static gboolean fido_timeout(gpointer data){
  FidoCall *call=data;call->timeout=0;if(call->form->fido_process)g_subprocess_force_exit(call->form->fido_process);return G_SOURCE_REMOVE;
}
static void fido_finished(GObject *source,GAsyncResult *result,gpointer data){
  FidoCall *call=data;Form *form=call->form;char *output=NULL,*errors=NULL;GError *error=NULL;
  gboolean ok=g_subprocess_communicate_utf8_finish(G_SUBPROCESS(source),result,&output,&errors,&error)&&g_subprocess_get_successful(G_SUBPROCESS(source));
  if(call->timeout)g_source_remove(call->timeout);
  g_clear_object(&form->fido_process);wipe(call->input);g_free(call->input);
  if(!form->dismissed&&call->generation==form->app->access_generation&&access_can(form->app,call->enrolling?"vault.update":"vault.open")){
    gtk_widget_set_sensitive(form->submit,TRUE);JsonNode *response=output?parse_json(output,NULL):NULL;
    if(response&&JSON_NODE_HOLDS_OBJECT(response)){
      JsonObject *object=json_node_get_object(response);
      if(!ok||*str(object,"error"))gtk_label_set_text(form->error,fido_error_message(str(object,"error")));
      else if(call->enrolling&&json_object_has_member(object,"enrollment")&&JSON_NODE_HOLDS_OBJECT(json_object_get_member(object,"enrollment"))){
        json_object_set_member(call->params,"fido2",json_node_copy(json_object_get_member(object,"enrollment")));run_form_operation(form,call->params,"vault.update");
      }else if(!call->enrolling&&*str(object,"password")){
        json_object_set_string_member(call->params,"password",str(object,"password"));run_form_operation(form,call->params,"vault.open");
      }else gtk_label_set_text(form->error,"The security key returned an invalid result. Use your recovery passphrase or try again.");
      if(json_object_has_member(object,"password"))wipe((char *)str(object,"password"));
    }else gtk_label_set_text(form->error,"The FIDO2 operation did not finish. Check the key, PIN and touch prompt, then try again. Your vault and recovery passphrase are unchanged.");
    if(response)json_node_free(response);
  }else if(!form->dismissed){gtk_widget_set_sensitive(form->submit,TRUE);gtk_label_set_text(form->error,"Authorization ended during the security key operation. Authorize again, then retry.");}
  wipe(output);g_free(output);wipe(errors);g_free(errors);g_clear_error(&error);
  if(json_object_has_member(call->params,"password"))wipe((char *)str(call->params,"password"));
  json_object_unref(call->params);g_object_unref(call->window);g_free(call);
}
static void fido_submit(Form *form,JsonObject *params,gboolean enrolling){
  if(form->fido_process)return;
  Field *pin=find_field(form,"_fido_pin");const char *value=pin?gtk_editable_get_text(GTK_EDITABLE(pin->widget)):"";
  if(!*value){gtk_label_set_text(form->error,"Enter your security key's FIDO2 PIN.");if(pin)gtk_widget_grab_focus(pin->widget);return;}
  JsonObject *request=json_object_new();json_object_set_string_member(request,"pin",value);
  if(enrolling){json_object_set_string_member(request,"password",str(params,"password"));json_object_set_string_member(request,"id",str(form->original,"id"));}
  else json_object_set_member(request,"enrollment",json_node_copy(json_object_get_member(form->original,"fido2")));
  JsonNode *node=json_node_new(JSON_NODE_OBJECT);json_node_take_object(node,request);JsonGenerator *generator=json_generator_new();json_generator_set_root(generator,node);char *input=json_generator_to_data(generator,NULL);g_object_unref(generator);
  wipe((char *)str(request,"pin"));if(enrolling)wipe((char *)str(request,"password"));json_node_free(node);
  GError *error=NULL;form->fido_process=g_subprocess_new(G_SUBPROCESS_FLAGS_STDIN_PIPE|G_SUBPROCESS_FLAGS_STDOUT_PIPE|G_SUBPROCESS_FLAGS_STDERR_PIPE,&error,"/usr/libexec/octovault/fido2",enrolling?"enroll":"unlock",NULL);
  if(!form->fido_process){gtk_label_set_text(form->error,"FIDO2 support is unavailable. Install the complete OctoVault package or use your recovery passphrase.");g_clear_error(&error);wipe(input);g_free(input);return;}
  FidoCall *call=g_new0(FidoCall,1);call->form=form;call->window=g_object_ref(form->window);call->params=json_object_new();json_object_set_string_member(call->params,"id",str(params,"id"));if(enrolling)json_object_set_string_member(call->params,"password",str(params,"password"));call->enrolling=enrolling;call->input=input;call->generation=form->app->access_generation;
  clear_form_secrets(form);gtk_widget_set_sensitive(form->submit,FALSE);gtk_label_set_text(form->error,"Touch your security key when it flashes…");
  call->timeout=g_timeout_add_seconds(120,fido_timeout,call);g_subprocess_communicate_utf8_async(form->fido_process,input,NULL,fido_finished,call);
}
static void cancel_remaining_unlocks(GtkButton *button,gpointer data){
  Form *form=data;g_queue_clear_full(form->app->pending_unlocks,g_free);clear_shared_unlock(form->app);close_window(button,form->window);
}
static gboolean form_close_requested(GtkWindow *window,gpointer data){
  (void)window;Form *form=data;form->dismissed=TRUE;if(form->fido_process)g_subprocess_force_exit(form->fido_process);return FALSE;
}
static void shared_key_selected(GObject *object,GParamSpec *pspec,gpointer data){
  (void)object;(void)pspec;Form *form=data;const char *id=selected_value(form,"_shared_key");JsonNode *collection=form->app->collections[0];if(!*id||!collection||!JSON_NODE_HOLDS_ARRAY(collection))return;
  JsonArray *vaults=json_node_get_array(collection);
  for(guint i=0;i<json_array_get_length(vaults);i++){
    JsonNode *node=json_array_get_element(vaults,i);if(!JSON_NODE_HOLDS_OBJECT(node))continue;JsonObject *record=json_node_get_object(node);if(strcmp(str(record,"id"),id))continue;
    const char *method=boolean(record,"require_token")?"token":str(record,"auth");Field *auth=find_field(form,"auth");
    for(guint j=0;j<auth->values->len;j++)if(!strcmp(g_ptr_array_index(auth->values,j),method))gtk_drop_down_set_selected(GTK_DROP_DOWN(auth->widget),j);
    gtk_check_button_set_active(GTK_CHECK_BUTTON(find_field(form,"use_existing_key")->widget),TRUE);
    const char *keys[]={"key_file","recipient","cipher_file"};for(guint j=0;j<G_N_ELEMENTS(keys);j++){Field *field=find_field(form,keys[j]);if(field)gtk_editable_set_text(GTK_EDITABLE(field->widget),str(record,keys[j]));}
    update_form_visibility(NULL,NULL,form);break;
  }
}
