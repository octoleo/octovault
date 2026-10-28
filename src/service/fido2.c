/* FIDO2 hmac-secret passphrase wrapping. SPDX-License-Identifier: Apache-2.0 */
#define _GNU_SOURCE
#include <fido.h>
#include <fido/err.h>
#include <json-glib/json-glib.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/rand.h>
#include <sys/prctl.h>
#include <sys/resource.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#define RP "io.vdm.octovault"
#define DOMAIN "OctoVault FIDO2 passphrase v1"
#define INPUT_LIMIT 32768
#define PASSWORD_LIMIT 4096

typedef struct {
    unsigned char *credential; size_t credential_len;
    unsigned char salt[32], nonce[12], tag[16], ciphertext[PASSWORD_LIMIT];
    size_t ciphertext_len; char *vault_id;
} Enrollment;
static const char *failure="The FIDO2 operation could not complete.", *failure_code="fido2_failed";
static void wipe(void *p,size_t n){if(p)OPENSSL_cleanse(p,n);}
static void wipe_string(char *p){if(p){wipe(p,strlen(p));g_free(p);}}
static const char *string_member(JsonObject *o,const char *name){JsonNode *n=json_object_get_member(o,name);return n&&JSON_NODE_HOLDS_VALUE(n)&&json_node_get_value_type(n)==G_TYPE_STRING?json_node_get_string(n):NULL;}
static void wipe_member(JsonObject *o,const char *name){const char *s=string_member(o,name);if(s)wipe((void *)s,strlen(s));}
static void output(JsonObject *o){JsonNode *n=json_node_new(JSON_NODE_OBJECT);json_node_take_object(n,o);JsonGenerator *g=json_generator_new();json_generator_set_root(g,n);char *s=json_generator_to_data(g,NULL);puts(s);fflush(stdout);wipe_string(s);wipe_member(o,"password");g_object_unref(g);json_node_free(n);}
static gboolean fail(const char *code,const char *message){failure_code=code;failure=message;return FALSE;}
static gboolean valid_id(const char *id){return id&&*id&&strlen(id)<=64&&strspn(id,"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-")==strlen(id);}
static gboolean decode(JsonObject *o,const char *name,unsigned char **bytes,size_t *length,size_t min,size_t max){
    const char *s=string_member(o,name);if(!s||strlen(s)>max*2+8)return FALSE;
    gsize n=0;guchar *p=g_base64_decode(s,&n);char *canonical=g_base64_encode(p,n);
    gboolean ok=n>=min&&n<=max&&!strcmp(canonical,s);g_free(canonical);if(!ok){g_free(p);return FALSE;}*bytes=p;*length=n;return TRUE;
}
static gboolean decode_fixed(JsonObject *o,const char *name,unsigned char *out,size_t length){unsigned char *p=NULL;size_t n=0;if(!decode(o,name,&p,&n,length,length))return FALSE;memcpy(out,p,n);g_free(p);return TRUE;}
static gboolean parse_enrollment(JsonObject *o,Enrollment *e){
    JsonNode *v=json_object_get_member(o,"version");const char *id=string_member(o,"vault_id");
    if(!v||!JSON_NODE_HOLDS_VALUE(v)||json_node_get_value_type(v)!=G_TYPE_INT64||json_node_get_int(v)!=1||!valid_id(id))return FALSE;
    e->vault_id=g_strdup(id);unsigned char *p=NULL;size_t n=0;
    if(!decode(o,"credential",&e->credential,&e->credential_len,1,1024)||!decode_fixed(o,"salt",e->salt,32)||!decode_fixed(o,"nonce",e->nonce,12)||!decode_fixed(o,"tag",e->tag,16)||!decode(o,"ciphertext",&p,&n,1,PASSWORD_LIMIT))return FALSE;
    memcpy(e->ciphertext,p,n);e->ciphertext_len=n;wipe(p,n);g_free(p);return TRUE;
}
static void add_bytes(JsonObject *o,const char *name,const void *bytes,size_t n){char *s=g_base64_encode(bytes,n);json_object_set_string_member(o,name,s);g_free(s);}
static JsonObject *serialize(const Enrollment *e){
    JsonObject *o=json_object_new();json_object_set_int_member(o,"version",1);json_object_set_string_member(o,"vault_id",e->vault_id);
    add_bytes(o,"credential",e->credential,e->credential_len);add_bytes(o,"salt",e->salt,32);add_bytes(o,"nonce",e->nonce,12);add_bytes(o,"tag",e->tag,16);add_bytes(o,"ciphertext",e->ciphertext,e->ciphertext_len);return o;
}
static gboolean fido_error(int rc){switch(rc){
case FIDO_ERR_PIN_INVALID:return fail("pin_invalid","The security key PIN is incorrect. Try again carefully; repeated failures can block the key.");
case FIDO_ERR_PIN_BLOCKED:case FIDO_ERR_PIN_AUTH_BLOCKED:return fail("pin_blocked","The security key PIN is blocked. Use your recovery passphrase.");
case FIDO_ERR_PIN_NOT_SET:return fail("pin_not_set","Set a FIDO2 PIN on your security key before adding it to OctoVault.");
case FIDO_ERR_ACTION_TIMEOUT:case FIDO_ERR_USER_ACTION_TIMEOUT:case FIDO_ERR_KEEPALIVE_CANCEL:return fail("cancelled","The security key operation was cancelled or timed out. Retry or use your recovery passphrase.");
case FIDO_ERR_NO_CREDENTIALS:return fail("wrong_key","This security key does not contain this vault credential. Connect the registered key or use your recovery passphrase.");
default:return fail("fido2_failed","The security key could not complete the operation. Check its connection or use your recovery passphrase.");}}
static fido_dev_t *open_device(void){
fido_dev_info_t *list=fido_dev_info_new(16);size_t count=0;fido_dev_t *selected=NULL;guint compatible=0;
if(!list||fido_dev_info_manifest(list,16,&count)!=FIDO_OK){fail("device_missing","No FIDO2 security key could be found. Connect your key and try again.");goto done;}
for(size_t i=0;i<count;i++){
const fido_dev_info_t *info=fido_dev_info_ptr(list,i);fido_dev_t *d=fido_dev_new();fido_cbor_info_t *ci=fido_cbor_info_new();
if(!d||!ci){fido_dev_free(&d);fido_cbor_info_free(&ci);continue;}fido_dev_set_timeout(d,5000);gboolean supported=FALSE;
if(fido_dev_open(d,fido_dev_info_path(info))==FIDO_OK&&fido_dev_get_cbor_info(d,ci)==FIDO_OK){char **ext=fido_cbor_info_extensions_ptr(ci);for(size_t j=0;j<fido_cbor_info_extensions_len(ci);j++)if(!strcmp(ext[j],"hmac-secret"))supported=TRUE;}
fido_cbor_info_free(&ci);if(supported){compatible++;if(!selected){selected=d;continue;}}fido_dev_close(d);fido_dev_free(&d);
}
if(compatible>1){fido_dev_close(selected);fido_dev_free(&selected);fail("multiple_devices","Connect only the security key you want to use, then try again.");}
else if(!selected)fail("unsupported_device","No connected key supports FIDO2 hmac-secret. OpenPGP-only and U2F-only keys cannot use this option.");
else if(!fido_dev_has_pin(selected)){fido_dev_close(selected);fido_dev_free(&selected);fail("pin_not_set","Set a FIDO2 PIN on your security key before adding it to OctoVault.");}
done:if(list)fido_dev_info_free(&list,16);if(selected)fido_dev_set_timeout(selected,45000);return selected;
}
static gboolean create_credential(fido_dev_t *d,const char *pin,Enrollment *e){
fido_cred_t *c=fido_cred_new();unsigned char challenge[32],user[32];int rc=FIDO_ERR_INTERNAL;gboolean ok=FALSE;
if(!c||RAND_bytes(challenge,32)!=1||RAND_bytes(user,32)!=1)goto done;
if(fido_cred_set_type(c,COSE_ES256)!=FIDO_OK||fido_cred_set_clientdata_hash(c,challenge,32)!=FIDO_OK||fido_cred_set_rp(c,RP,"OctoVault")!=FIDO_OK||fido_cred_set_user(c,user,32,"octovault","OctoVault",NULL)!=FIDO_OK||fido_cred_set_extensions(c,FIDO_EXT_HMAC_SECRET)!=FIDO_OK||fido_cred_set_rk(c,FIDO_OPT_FALSE)!=FIDO_OK||fido_cred_set_uv(c,FIDO_OPT_TRUE)!=FIDO_OK)goto done;
rc=fido_dev_make_cred(d,c,pin);if(rc!=FIDO_OK)goto done;e->credential_len=fido_cred_id_len(c);if(!e->credential_len||e->credential_len>1024)goto done;e->credential=g_memdup2(fido_cred_id_ptr(c),e->credential_len);ok=TRUE;
done:wipe(challenge,32);wipe(user,32);fido_cred_free(&c);if(!ok)fido_error(rc);return ok;
}
static gboolean derive(fido_dev_t *d,const char *pin,const Enrollment *e,unsigned char key[32]){
fido_assert_t *a=fido_assert_new();unsigned char challenge[32];int rc=FIDO_ERR_INTERNAL;gboolean ok=FALSE;EVP_PKEY_CTX *ctx=NULL;size_t n=32;
if(!a||RAND_bytes(challenge,32)!=1)goto done;
if(fido_assert_set_rp(a,RP)!=FIDO_OK||fido_assert_set_clientdata_hash(a,challenge,32)!=FIDO_OK||fido_assert_allow_cred(a,e->credential,e->credential_len)!=FIDO_OK||fido_assert_set_extensions(a,FIDO_EXT_HMAC_SECRET)!=FIDO_OK||fido_assert_set_hmac_salt(a,e->salt,32)!=FIDO_OK||fido_assert_set_up(a,FIDO_OPT_TRUE)!=FIDO_OK||fido_assert_set_uv(a,FIDO_OPT_TRUE)!=FIDO_OK)goto done;
rc=fido_dev_get_assert(d,a,pin);if(rc!=FIDO_OK)goto done;
if(fido_assert_count(a)!=1||(fido_assert_flags(a,0)&0x05)!=0x05||fido_assert_hmac_secret_len(a,0)!=32)goto done;
ctx=EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF,NULL);
if(!ctx||EVP_PKEY_derive_init(ctx)<=0||EVP_PKEY_CTX_set_hkdf_md(ctx,EVP_sha256())<=0||EVP_PKEY_CTX_set1_hkdf_salt(ctx,e->salt,32)<=0||EVP_PKEY_CTX_set1_hkdf_key(ctx,fido_assert_hmac_secret_ptr(a,0),32)<=0||EVP_PKEY_CTX_add1_hkdf_info(ctx,(const unsigned char *)DOMAIN,strlen(DOMAIN))<=0||EVP_PKEY_derive(ctx,key,&n)<=0||n!=32)goto done;
ok=TRUE;
done:EVP_PKEY_CTX_free(ctx);wipe(challenge,32);fido_assert_free(&a);if(!ok)fido_error(rc);return ok;
}
static gboolean crypt_password(Enrollment *e,const unsigned char key[32],unsigned char *password,size_t *length,gboolean encrypt){
EVP_CIPHER_CTX *c=EVP_CIPHER_CTX_new();int n=0,total=0;gboolean ok=FALSE;char *aad=g_strconcat(DOMAIN,":",e->vault_id,NULL);
if(!c||EVP_CipherInit_ex(c,EVP_aes_256_gcm(),NULL,NULL,NULL,encrypt)!=1||EVP_CIPHER_CTX_ctrl(c,EVP_CTRL_GCM_SET_IVLEN,12,NULL)!=1||EVP_CipherInit_ex(c,NULL,NULL,key,e->nonce,encrypt)!=1||EVP_CipherUpdate(c,NULL,&n,(const unsigned char *)aad,strlen(aad))!=1)goto done;
if(encrypt){
if(*length<1||*length>PASSWORD_LIMIT||EVP_CipherUpdate(c,e->ciphertext,&n,password,*length)!=1)goto done;
total=n;
if(EVP_CipherFinal_ex(c,e->ciphertext+total,&n)!=1||EVP_CIPHER_CTX_ctrl(c,EVP_CTRL_GCM_GET_TAG,16,e->tag)!=1)goto done;
e->ciphertext_len=total+n;
}else{
if(EVP_CipherUpdate(c,password,&n,e->ciphertext,e->ciphertext_len)!=1)goto done;
total=n;
if(EVP_CIPHER_CTX_ctrl(c,EVP_CTRL_GCM_SET_TAG,16,e->tag)!=1||EVP_CipherFinal_ex(c,password+total,&n)!=1)goto done;
*length=total+n;password[*length]=0;
if(!*length||memchr(password,0,*length)||!g_utf8_validate((const char *)password,*length,NULL))goto done;
}ok=TRUE;
done:if(!ok&&!encrypt)wipe(password,PASSWORD_LIMIT+1);g_free(aad);EVP_CIPHER_CTX_free(c);return ok;
}
#ifndef OCTOVAULT_FIDO_TEST
int main(int argc,char **argv){
struct rlimit limit={0,0};setrlimit(RLIMIT_CORE,&limit);if(prctl(PR_SET_DUMPABLE,0)!=0)return 1;
if(argc!=2||(strcmp(argv[1],"enroll")&&strcmp(argv[1],"unlock")))return 2;
gboolean enroll=!strcmp(argv[1],"enroll"),ok=FALSE;char input[INPUT_LIMIT+1];size_t used=fread(input,1,INPUT_LIMIT+1,stdin);
JsonParser *parser=json_parser_new();JsonObject *request=NULL,*result=NULL;fido_dev_t *device=NULL;
Enrollment e={0};unsigned char key[32]={0},password[PASSWORD_LIMIT+1]={0};size_t password_len=0;char *pin=NULL;
if(used>INPUT_LIMIT||!json_parser_load_from_data(parser,input,used,NULL)||!JSON_NODE_HOLDS_OBJECT(json_parser_get_root(parser))){fail("invalid_request","The FIDO2 request is invalid.");goto done;}
request=json_node_get_object(json_parser_get_root(parser));const char *p=string_member(request,"pin");
if(!p||!*p||strlen(p)>63){fail("pin_required","Enter the FIDO2 PIN for your security key.");goto done;}pin=g_strdup(p);
if(enroll){
const char *value=string_member(request,"password"),*id=string_member(request,"id");
if(!valid_id(id)||!value||!*value||strlen(value)>PASSWORD_LIMIT||strchr(value,'\n')||strchr(value,'\r')){fail("invalid_request","Provide the vault identity and recovery passphrase.");goto done;}
e.vault_id=g_strdup(id);password_len=strlen(value);memcpy(password,value,password_len);
if(RAND_bytes(e.salt,32)!=1||RAND_bytes(e.nonce,12)!=1)goto done;
}else{
JsonNode *n=json_object_get_member(request,"enrollment");
if(!n||!JSON_NODE_HOLDS_OBJECT(n)||!parse_enrollment(json_node_get_object(n),&e)){fail("invalid_enrollment","The saved FIDO2 enrollment is invalid. Use your recovery passphrase.");goto done;}
}
wipe_member(request,"pin");wipe_member(request,"password");json_object_remove_member(request,"pin");json_object_remove_member(request,"password");wipe(input,sizeof(input));fido_init(0);device=open_device();if(!device)goto done;
if(enroll&&!create_credential(device,pin,&e))goto done;
if(!derive(device,pin,&e,key))goto done;
if(!crypt_password(&e,key,password,&password_len,enroll)){fail("invalid_enrollment","The security key could not decrypt this enrollment. Use your recovery passphrase.");goto done;}
result=json_object_new();if(enroll)json_object_set_object_member(result,"enrollment",serialize(&e));else json_object_set_string_member(result,"password",(const char *)password);ok=TRUE;
done:
wipe(input,sizeof(input));wipe(password,sizeof(password));wipe(key,sizeof(key));wipe_string(pin);
if(device){fido_dev_close(device);fido_dev_free(&device);}g_free(e.credential);g_free(e.vault_id);wipe(&e,sizeof(e));
if(!ok){result=json_object_new();json_object_set_string_member(result,"error",failure_code);json_object_set_string_member(result,"message",failure);}output(result);if(request){wipe_member(request,"pin");wipe_member(request,"password");}g_object_unref(parser);return ok?0:1;
}
#endif
