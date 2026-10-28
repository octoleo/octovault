/* SPDX-License-Identifier: Apache-2.0
 * Real libfido2 objects and OpenSSL, with hardware exchanges replaced.
 */
#include <fido.h>
#include <glib.h>
static int token_create(fido_dev_t *, fido_cred_t *, const char *);
static int token_assert(fido_dev_t *, fido_assert_t *, const char *);
#define fido_dev_make_cred token_create
#define fido_dev_get_assert token_assert
#define OCTOVAULT_FIDO_TEST
#include "../../src/service/fido2.c"
static int token_result=FIDO_OK;
static guint exchanges;
static unsigned char flags=5, secret[32]={7};
static int token_create(fido_dev_t *d,fido_cred_t *c,const char *pin){
    (void)d;exchanges++;g_assert_cmpstr(pin,==,"123456");g_assert_cmpstr(fido_cred_rp_id(c),==,RP);
    if(token_result!=FIDO_OK)return token_result;
    const unsigned char id[]={1,2,3,4};return fido_cred_set_id(c,id,sizeof(id));
}
static int token_assert(fido_dev_t *d,fido_assert_t *a,const char *pin){
    (void)d;exchanges++;g_assert_cmpstr(pin,==,"123456");g_assert_cmpstr(fido_assert_rp_id(a),==,RP);
    if(token_result!=FIDO_OK)return token_result;
    unsigned char data[37]={0};data[32]=flags;
    g_assert_cmpint(fido_assert_set_count(a,1),==,FIDO_OK);
    g_assert_cmpint(fido_assert_set_authdata_raw(a,0,data,sizeof(data)),==,FIDO_OK);
    return fido_assert_set_hmac_secret(a,0,secret,sizeof(secret));
}
static void release(Enrollment *e){g_free(e->credential);g_free(e->vault_id);wipe(e,sizeof(*e));}
static void fixture(Enrollment *e,unsigned char key[32]){
    e->vault_id=g_strdup("documents");memset(e->salt,3,32);memset(e->nonce,4,12);
    token_result=FIDO_OK;flags=5;exchanges=0;
    g_assert_true(create_credential(NULL,"123456",e));g_assert_true(derive(NULL,"123456",e,key));g_assert_cmpuint(exchanges,==,2);
}
static void round_trip(void){
    Enrollment e={0},decoded={0};unsigned char key[32],other[32],text[PASSWORD_LIMIT+1]="recovery password";size_t n=strlen((char *)text);
    fixture(&e,key);g_assert_true(crypt_password(&e,key,text,&n,TRUE));JsonObject *json=serialize(&e);
    g_assert_true(parse_enrollment(json,&decoded));json_object_unref(json);g_assert_true(derive(NULL,"123456",&decoded,other));g_assert_cmpmem(key,32,other,32);
    memset(text,0,sizeof(text));g_assert_true(crypt_password(&decoded,other,text,&n,FALSE));g_assert_cmpstr((char *)text,==,"recovery password");
    release(&e);release(&decoded);wipe(key,32);wipe(other,32);wipe(text,sizeof(text));
}
static void tampering(void){
    Enrollment e={0};unsigned char key[32],text[PASSWORD_LIMIT+1]="recovery password";size_t n=strlen((char *)text);fixture(&e,key);g_assert_true(crypt_password(&e,key,text,&n,TRUE));
    for(guint i=0;i<5;i++){
        unsigned char *changed=i==0?e.tag:i==1?e.ciphertext:i==2?e.nonce:i==3?key:(unsigned char *)e.vault_id;
        changed[0]^=1;memset(text,0xa5,sizeof(text));g_assert_false(crypt_password(&e,key,text,&n,FALSE));
        for(guint j=0;j<sizeof(text);j++){g_assert_cmpuint(text[j],==,0);}
        changed[0]^=1;
    }
    unsigned char original[32];memcpy(original,key,32);e.salt[0]^=1;g_assert_true(derive(NULL,"123456",&e,key));g_assert_cmpint(memcmp(original,key,32),!=,0);
    g_assert_false(crypt_password(&e,key,text,&n,FALSE));release(&e);wipe(key,32);wipe(original,32);
}
static void pin_presence(void){
    Enrollment e={0};unsigned char key[32];fixture(&e,key);token_result=FIDO_ERR_PIN_INVALID;exchanges=0;
    g_assert_false(derive(NULL,"123456",&e,key));g_assert_cmpstr(failure_code,==,"pin_invalid");g_assert_cmpuint(exchanges,==,1);
    token_result=FIDO_OK;flags=1;g_assert_false(derive(NULL,"123456",&e,key));flags=4;g_assert_false(derive(NULL,"123456",&e,key));
    token_result=FIDO_ERR_KEEPALIVE_CANCEL;g_assert_false(derive(NULL,"123456",&e,key));g_assert_cmpstr(failure_code,==,"cancelled");release(&e);wipe(key,32);
}
static void malformed(void){
    Enrollment e={0},bad={0};unsigned char key[32],text[PASSWORD_LIMIT+1]="password";size_t n=8;fixture(&e,key);g_assert_true(crypt_password(&e,key,text,&n,TRUE));
    JsonObject *json=serialize(&e);json_object_set_string_member(json,"credential","!!AA==");g_assert_false(parse_enrollment(json,&bad));release(&bad);
    json_object_set_string_member(json,"vault_id","../documents");g_assert_false(parse_enrollment(json,&bad));release(&bad);json_object_unref(json);release(&e);wipe(key,32);wipe(text,sizeof(text));
}
int main(int argc,char **argv){
    g_test_init(&argc,&argv,NULL);fido_init(0);(void)open_device;(void)output;(void)wipe_string;
    g_test_add_func("/fido2/round-trip",round_trip);g_test_add_func("/fido2/tampering",tampering);g_test_add_func("/fido2/pin-presence-cancel",pin_presence);g_test_add_func("/fido2/malformed",malformed);return g_test_run();
}
