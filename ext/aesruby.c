#ifdef _WIN32
__declspec(dllexport) void Init_aesruby(void);
#endif

#include <stdlib.h>

#include "aes.h"
#include "aesruby.h"
#include "ruby.h"

#ifndef RSTRING_PTR
#define RSTRING_PTR(s) (RSTRING(s)->ptr)
#endif
#ifndef RSTRING_LEN
#define RSTRING_LEN(s) (RSTRING(s)->len)
#endif

#define AES_PADDED_LEN(s) (RSTRING_LEN(s) + (AES_BLOCK_SIZE - RSTRING_LEN(s) % AES_BLOCK_SIZE));

static VALUE AES;
static VALUE AES_EncStr;

static VALUE aesruby_encstr_get_srclen(VALUE self) {
  return rb_ivar_get(self, rb_intern("@srclen"));
}

static VALUE aesruby_encstr_set_srclen(VALUE self, VALUE srclen) {
  return rb_ivar_set(self, rb_intern("@srclen"), srclen);
}

static void aesruby_chack_encstr(VALUE str) {
  if (!rb_obj_is_instance_of(str, AES_EncStr)) {
    rb_raise(rb_eTypeError, "wrong argument type %s (expected AES::EncryptedString)", rb_class2name(CLASS_OF(str)));
  }
}

static void aesruby_chack_key(VALUE key) {
  long keylen;

  Check_Type(key, T_STRING);
  keylen = RSTRING_LEN(key);

  if (keylen < 1) {
    rb_raise(rb_eArgError, "key is too short");
  } else if (keylen > 32) {
    rb_raise(rb_eArgError, "key is too long (over 256 bits)");
  }
}

static VALUE aesruby_encrypt0(VALUE self, VALUE key, VALUE src,
                              AES_RETURN (*encrypt_function)(const unsigned char *, unsigned char *, int, const aes_encrypt_ctx *cx)) {
  VALUE encrypted;
  aes_encrypt_ctx cx;
  char *pkey, *ibuf, *obuf;
  long keylen, len;

  Check_Type(src, T_STRING);
  aesruby_chack_key(key);
  memset(&cx, 0, sizeof(cx));
  keylen = AES_PADDED_LEN(key);
  pkey = ALLOC_N(char, keylen);
  memset(pkey, 0, sizeof(char) * keylen);
  memcpy(pkey, RSTRING_PTR(key), RSTRING_LEN(key));

  if (aes_encrypt_key(pkey, keylen, &cx) != EXIT_SUCCESS) {
    xfree(pkey);
    return Qnil;
  }

  len = AES_PADDED_LEN(src);
  ibuf = ALLOC_N(char, len);
  memset(ibuf, 0, sizeof(char) * len);
  memcpy(ibuf, RSTRING_PTR(src), RSTRING_LEN(src));
  obuf = ALLOC_N(char, len);
  memset(obuf, 0, sizeof(char) * len);

  if (encrypt_function(ibuf, obuf, len, &cx) != EXIT_SUCCESS) {
    xfree(obuf);
    xfree(ibuf);
    xfree(pkey);
    return Qnil;
  }

  encrypted = rb_funcall(AES_EncStr, rb_intern("new"), 0);
  rb_funcall(encrypted, rb_intern("replace"), 1, rb_str_new(obuf, len));
  xfree(obuf);
  xfree(ibuf);
  xfree(pkey);
  aesruby_encstr_set_srclen(encrypted, LONG2FIX(RSTRING_LEN(src)));

  return encrypted;
}

static VALUE aesruby_decrypt0(VALUE self, VALUE key, VALUE encrypted,
                              AES_RETURN (*decrypt_function)(const unsigned char *, unsigned char *, int, const aes_decrypt_ctx *)) {
  VALUE decrypted;
  aes_decrypt_ctx cx;
  char *pkey, *obuf;
  long keylen, srclen;

  aesruby_chack_encstr(encrypted);
  aesruby_chack_key(key);
  memset(&cx, 0, sizeof(cx));
  keylen = AES_PADDED_LEN(key);
  pkey = ALLOC_N(char, keylen);
  memset(pkey, 0, sizeof(char) * keylen);
  memcpy(pkey, RSTRING_PTR(key), RSTRING_LEN(key));

  if (aes_decrypt_key(pkey, keylen, &cx) != EXIT_SUCCESS) {
    xfree(pkey);
    return Qnil;
  }

  obuf = ALLOC_N(char, RSTRING_LEN(encrypted));
  memset(obuf, 0, sizeof(char) * RSTRING_LEN(encrypted));

  if (decrypt_function(RSTRING_PTR(encrypted), obuf, RSTRING_LEN(encrypted), &cx) != EXIT_SUCCESS) {
    xfree(obuf);
    xfree(pkey);
    return Qnil;
  }

  srclen = FIX2LONG(aesruby_encstr_get_srclen(encrypted));
  decrypted = rb_str_new(obuf, srclen);
  xfree(obuf);
  xfree(pkey);

  return decrypted;
}

static VALUE aesruby_ecb_encrypt(VALUE self, VALUE key, VALUE src) {
  return aesruby_encrypt0(self, key, src, aes_ecb_encrypt);
}

static VALUE aesruby_ecb_decrypt(VALUE self, VALUE key, VALUE encrypted) {
  return aesruby_decrypt0(self, key, encrypted, aes_ecb_decrypt);
}

static AES_RETURN aes_cbc_encrypt0(const unsigned char *ibuf, unsigned char *obuf, int len, const aes_encrypt_ctx cx[1]) {
  unsigned char iv[AES_BLOCK_SIZE];
  return aes_cbc_encrypt(ibuf, obuf, len, iv, cx);
}

static AES_RETURN aes_cbc_decrypt0(const unsigned char *ibuf, unsigned char *obuf, int len, const aes_decrypt_ctx cx[1]) {
  unsigned char iv[AES_BLOCK_SIZE];
  return aes_cbc_decrypt(ibuf, obuf, len, iv, cx);
}

static VALUE aesruby_cbc_encrypt(VALUE self, VALUE key, VALUE src) {
  return aesruby_encrypt0(self, key, src, aes_cbc_encrypt0);
}

static VALUE aesruby_cbc_decrypt(VALUE self, VALUE key, VALUE encrypted) {
  return aesruby_decrypt0(self, key, encrypted, aes_cbc_decrypt0);
}

void Init_aesruby() {
  AES = rb_define_module("AES");
  rb_define_const(AES, "VERSION", rb_str_new2(VERSION));
  rb_define_module_function(AES, "ecb_encrypt", aesruby_ecb_encrypt, 2);
  rb_define_module_function(AES, "ecb_decrypt", aesruby_ecb_decrypt, 2);
  rb_define_module_function(AES, "cbc_encrypt", aesruby_cbc_encrypt, 2);
  rb_define_module_function(AES, "cbc_decrypt", aesruby_cbc_decrypt, 2);

  AES_EncStr = rb_define_class_under(AES, "EncryptedString", rb_cString);
  rb_define_method(AES_EncStr, "srclen", aesruby_encstr_get_srclen, 0);
  rb_define_method(AES_EncStr, "srclen=", aesruby_encstr_set_srclen, 1);

  aes_init();
}
