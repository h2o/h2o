/*
** digest.c - Digest and subclasses
**
** See Copyright Notice in mruby.h
*/

#include "mruby.h"

#define USE_DIGEST_PICOHASH

#if !defined(USE_DIGEST_PICOHASH)
#elif defined(__APPLE__)
#define USE_DIGEST_OSX_COMMONCRYPTO
#else
#define USE_DIGEST_OPENSSL
#endif

#if defined(USE_DIGEST_PICOHASH)
#include "picohash.h"
#elif defined(USE_DIGEST_OPENSSL)
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/sha.h>
#elif defined(USE_DIGEST_OSX_COMMONCRYPTO)
#include <CommonCrypto/CommonDigest.h>
#include <CommonCrypto/CommonHMAC.h>
#else
#error "define USE_DIGEST_PICOHASH or USE_DIGEST_OPENSSL or USE_DIGEST_OSX_COMMONCRYPTO"
#endif
#include <limits.h>
#include <stdio.h>
#include <string.h>
#include "mruby/array.h"
#include "mruby/class.h"
#include "mruby/data.h"
#include "mruby/string.h"
#include "mruby/variable.h"

#define TYPESYM "__type__"


/*
 * library-independent layer API
 */
enum {
	MD_TYPE_MD5,
	MD_TYPE_RMD160,
	MD_TYPE_SHA1,
	MD_TYPE_SHA256,
	MD_TYPE_SHA384,
	MD_TYPE_SHA512,
};

struct mrb_md;
struct mrb_hmac;

static void lib_init(void);
static int lib_md_block_length(const struct mrb_md *);
static mrb_value lib_md_digest(mrb_state *, const struct mrb_md *);
static mrb_value lib_md_digest_bang(mrb_state *, struct mrb_md *);
static int lib_md_digest_length(const struct mrb_md *);
static void lib_md_free(mrb_state *, void *);
static void lib_md_init(mrb_state *, struct mrb_md *, int);
static void lib_md_init_copy(mrb_state *, struct mrb_md *, struct mrb_md *);
static void lib_md_reset(mrb_state *, struct mrb_md *);
static void lib_md_update(mrb_state *, struct mrb_md *, unsigned char *, mrb_int);

static mrb_value lib_hmac_digest(mrb_state *, const struct mrb_hmac *);
static int lib_hmac_block_length(const struct mrb_hmac *);
static int lib_hmac_digest_length(const struct mrb_hmac *);
static void lib_hmac_free(mrb_state *, void *);
static void lib_hmac_init(mrb_state *, struct mrb_hmac *, int, const unsigned char *, mrb_int);
static void lib_hmac_update(mrb_state *, struct mrb_hmac *, unsigned char *, mrb_int);


#if defined(USE_DIGEST_PICOHASH)

#define HAVE_MD5
#define HAVE_SHA1

struct mrb_md {
  picohash_ctx_t ctx;
};

struct mrb_hmac {
  picohash_ctx_t ctx;
};

static void
lib_md_free(mrb_state *mrb, void *ptr)
{
  struct mrb_md *md = ptr;
  if (md != NULL)
    mrb_free(mrb, md);
}

static void
lib_hmac_free(mrb_state *mrb, void *ptr)
{
  struct mrb_hmac *hmac = ptr;
  if (hmac != NULL)
    mrb_free(mrb, hmac);
}

static struct mrb_data_type mrb_md_type = { "MD", lib_md_free };
static struct mrb_data_type mrb_hmac_type = { "HMAC", lib_hmac_free };

static void
lib_init(void)
{
}

static int
lib_md_block_length(const struct mrb_md *md)
{
  return (int)md->ctx.block_length;
}

static mrb_value
lib_md_digest(mrb_state *mrb, const struct mrb_md *md)
{
  picohash_ctx_t ctx;
  unsigned char mdstr[PICOHASH_MAX_DIGEST_LENGTH];

  ctx = md->ctx;
  picohash_final(&ctx, mdstr);
  return mrb_str_new(mrb, (char *)mdstr, ctx.digest_length);
}

static mrb_value
lib_md_digest_bang(mrb_state *mrb, struct mrb_md *md)
{
  unsigned char mdstr[PICOHASH_MAX_DIGEST_LENGTH];

  picohash_final(&md->ctx, mdstr);
  picohash_reset(&md->ctx);
  return mrb_str_new(mrb, (char *)mdstr, md->ctx.digest_length);
}

static int
lib_md_digest_length(const struct mrb_md *md)
{
  return md->ctx.digest_length;
}

static void (*md_type_md(int type))(picohash_ctx_t *)
{
  switch (type) {
  case MD_TYPE_MD5:	return picohash_init_md5;
  case MD_TYPE_SHA1:	return picohash_init_sha1;
  default:		return NULL;
  }
}

static void
lib_md_init(mrb_state *mrb, struct mrb_md *md, int type)
{
  void (*ctor)(picohash_ctx_t *) = md_type_md(type);
  if (ctor == NULL)
    mrb_raise(mrb, E_NOTIMP_ERROR, "not supported");
  ctor(&md->ctx);
}

static void
lib_md_init_copy(mrb_state *mrb, struct mrb_md *mdnew, struct mrb_md *mdold)
{
  mdnew->ctx = mdold->ctx;
  picohash_reset(&mdnew->ctx);
}

static void
lib_md_reset(mrb_state *mrb, struct mrb_md *md)
{
  picohash_reset(&md->ctx);
}

static void
lib_md_update(mrb_state *mrb, struct mrb_md *md, unsigned char *str, mrb_int len)
{
#if MRB_INT_MAX > SIZE_MAX
  if (len > SIZE_MAX)
    mrb_raise(mrb, E_ARGUMENT_ERROR, "too long string (not supported yet)");
#endif
  picohash_update(&md->ctx, str, len);
}

static mrb_value
lib_hmac_digest(mrb_state *mrb, const struct mrb_hmac *hmac)
{
  picohash_ctx_t ctx;
  unsigned char mdstr[PICOHASH_MAX_DIGEST_LENGTH];

  ctx = hmac->ctx;
  picohash_final(&ctx, mdstr);
  return mrb_str_new(mrb, (char *)mdstr, ctx.digest_length);
}

static int
lib_hmac_block_length(const struct mrb_hmac *hmac)
{
  return hmac->ctx.block_length;
}

static int
lib_hmac_digest_length(const struct mrb_hmac *hmac)
{
  return hmac->ctx.digest_length;
}

static void
lib_hmac_init(mrb_state *mrb, struct mrb_hmac *hmac, int type, const unsigned char *key, mrb_int keylen)
{
  void (*ctor)(picohash_ctx_t *) = md_type_md(type);

#if MRB_INT_MAX > SIZE_MAX
  if (keylen > SIZE_MAX)
      mrb_raise(mrb, E_ARGUMENT_ERROR, "too long key");
#endif
  if (ctor == NULL)
    mrb_raise(mrb, E_NOTIMP_ERROR, "not supported");
  picohash_init_hmac(&hmac->ctx, ctor, key, keylen);
}

static void
lib_hmac_update(mrb_state *mrb, struct mrb_hmac *hmac, unsigned char *data, mrb_int len)
{
#if MRB_INT_MAX > SIZE_MAX
  if (len > SIZE_MAX) {
      mrb_raise(mrb, E_ARGUMENT_ERROR, "too long string (not supported yet)");
  }
#endif
  picohash_update(&hmac->ctx, data, len);
}

#elif defined(USE_DIGEST_OPENSSL)
/*
 * OpenSSL Implementation
 */

#define HAVE_MD5

#ifndef OPENSSL_NO_RIPEMD
#define HAVE_RMD160
#endif

#define HAVE_SHA1
#ifdef SHA256_DIGEST_LENGTH
#define HAVE_SHA256
#endif
#ifdef SHA512_DIGEST_LENGTH
#define HAVE_SHA384
#define HAVE_SHA512
#endif

struct mrb_md {
  EVP_MD_CTX *ctx;
};

struct mrb_hmac {
  HMAC_CTX ctx;
  const EVP_MD *md;
};

static void
lib_md_free(mrb_state *mrb, void *ptr)
{
  struct mrb_md *md = ptr;

  if (md != NULL) {
    if (md->ctx != NULL) {
      EVP_MD_CTX_destroy(md->ctx);
    }
    mrb_free(mrb, md);
  }
}

static void
lib_hmac_free(mrb_state *mrb, void *ptr)
{
  struct mrb_hmac *hmac = ptr;

  if (hmac != NULL) {
    HMAC_CTX_cleanup(&hmac->ctx);
    mrb_free(mrb, hmac);
  }
}

static struct mrb_data_type mrb_md_type = { "MD", lib_md_free };
static struct mrb_data_type mrb_hmac_type = { "HMAC", lib_hmac_free };

static void
lib_init(void)
{
  OpenSSL_add_all_digests();
}

static int
lib_md_block_length(const struct mrb_md *md)
{
  return EVP_MD_CTX_block_size(md->ctx);
}

static mrb_value
lib_md_digest(mrb_state *mrb, const struct mrb_md *md)
{
  EVP_MD_CTX ctx;
  unsigned int mdlen;
  unsigned char mdstr[EVP_MAX_MD_SIZE];

  EVP_MD_CTX_copy(&ctx, md->ctx);
  EVP_DigestFinal(&ctx, mdstr, &mdlen);
  return mrb_str_new(mrb, (char *)mdstr, mdlen);
}

static mrb_value
lib_md_digest_bang(mrb_state *mrb, struct mrb_md *md)
{
  unsigned int mdlen;
  unsigned char mdstr[EVP_MAX_MD_SIZE];

  EVP_DigestFinal_ex(md->ctx, mdstr, &mdlen);
  EVP_DigestInit_ex(md->ctx, EVP_MD_CTX_md(md->ctx), NULL);
  return mrb_str_new(mrb, (char *)mdstr, mdlen);
}

static int
lib_md_digest_length(const struct mrb_md *md)
{
  return EVP_MD_CTX_size(md->ctx);
}

const EVP_MD *
md_type_md(int type)
{
  switch (type) {
  case MD_TYPE_MD5:	return EVP_md5();
#ifdef HAVE_RMD160
  case MD_TYPE_RMD160:	return EVP_ripemd160();
#endif
  case MD_TYPE_SHA1:	return EVP_sha1();
#ifdef HAVE_SHA256
  case MD_TYPE_SHA256:	return EVP_sha256();
#endif
#ifdef HAVE_SHA512
  case MD_TYPE_SHA384:	return EVP_sha384();
  case MD_TYPE_SHA512:	return EVP_sha512();
#endif
  default:		return NULL;
  }
}

static void
lib_md_init(mrb_state *mrb, struct mrb_md *md, int type)
{
  const EVP_MD *evpmd;

  md->ctx = NULL;
  evpmd = md_type_md(type);
  if (!evpmd) {
    mrb_raise(mrb, E_NOTIMP_ERROR, "not supported");
  }
  md->ctx = EVP_MD_CTX_create();
  EVP_DigestInit_ex(md->ctx, evpmd, NULL);
}

static void
lib_md_init_copy(mrb_state *mrb, struct mrb_md *mdnew, struct mrb_md *mdold)
{
  mdnew->ctx = EVP_MD_CTX_create();
  EVP_DigestInit_ex(mdnew->ctx, EVP_MD_CTX_md(mdold->ctx), NULL);
}

static void
lib_md_reset(mrb_state *mrb, struct mrb_md *md)
{
  //EVP_MD_CTX_init(&md->ctx);
  EVP_DigestInit_ex(md->ctx, EVP_MD_CTX_md(md->ctx), NULL);
}

static void
lib_md_update(mrb_state *mrb, struct mrb_md *md, unsigned char *str, mrb_int len)
{
#if MRB_INT_MAX > SIZE_MAX
  if (len > SIZE_MAX) {
    mrb_raise(mrb, E_ARGUMENT_ERROR, "too long string (not supported yet)");
  }
#endif
  EVP_DigestUpdate(md->ctx, str, len);
}

static mrb_value
lib_hmac_digest(mrb_state *mrb, const struct mrb_hmac *hmac)
{
  HMAC_CTX ctx;
  unsigned int mdlen;
  unsigned char mdstr[EVP_MAX_MD_SIZE];

  memcpy(&ctx, &hmac->ctx, sizeof(ctx));
  HMAC_Final(&ctx, mdstr, &mdlen);
  return mrb_str_new(mrb, (char *)mdstr, mdlen);
}

static int
lib_hmac_block_length(const struct mrb_hmac *hmac)
{
  return EVP_MD_block_size(hmac->md);
}

static int
lib_hmac_digest_length(const struct mrb_hmac *hmac)
{
  return EVP_MD_size(hmac->md);
}

static void
lib_hmac_init(mrb_state *mrb, struct mrb_hmac *hmac, int type, const unsigned char *key, mrb_int keylen)
{
#if MRB_INT_MAX > INT_MAX
  if (keylen > INT_MAX) {
      mrb_raise(mrb, E_ARGUMENT_ERROR, "too long key");
  }
#endif
  hmac->md = md_type_md(type);
  HMAC_CTX_init(&hmac->ctx);
  HMAC_Init_ex(&hmac->ctx, key, keylen, hmac->md, NULL);
}

static void
lib_hmac_update(mrb_state *mrb, struct mrb_hmac *hmac, unsigned char *data, mrb_int len)
{
#if MRB_INT_MAX > INT_MAX
  if (len > INT_MAX) {
      mrb_raise(mrb, E_ARGUMENT_ERROR, "too long string (not supported yet)");
  }
#endif
  HMAC_Update(&hmac->ctx, data, len);
}

#elif defined(USE_DIGEST_OSX_COMMONCRYPTO)
/*
 * Mac OS X CommonCrypto Implementation
 */

#define HAVE_MD5
/* #define HAVE_RMD160 */
#define HAVE_SHA1
#define HAVE_SHA256
#define HAVE_SHA384
#define HAVE_SHA512

struct mrb_md {
  int type;
  void *ctx;
  int ctx_size;
};

struct mrb_hmac {
  int type;
  CCHmacContext ctx;
};

static int
md_ctx_size(int type)
{
  switch (type) {
  case MD_TYPE_MD5:	return sizeof(CC_MD5_CTX);
  case MD_TYPE_SHA1:	return sizeof(CC_SHA1_CTX);
  case MD_TYPE_SHA256:	return sizeof(CC_SHA256_CTX);
  case MD_TYPE_SHA384:	return sizeof(CC_SHA512_CTX);	/* ! */
  case MD_TYPE_SHA512:	return sizeof(CC_SHA512_CTX);
  default:		return 0;
  }
}

static void
lib_md_free(mrb_state *mrb, void *ptr)
{
  struct mrb_md *md = ptr;

  memset(md->ctx, 0, md_ctx_size(md->type));
  mrb_free(mrb, md->ctx);
  mrb_free(mrb, md);
}

static void
lib_hmac_free(mrb_state *mrb, void *ptr)
{
  struct mrb_hmac *hmac = ptr;

  memset(&hmac->ctx, 0, sizeof(hmac->ctx));
  mrb_free(mrb, hmac);
}

static struct mrb_data_type mrb_md_type = { "MD", lib_md_free };
static struct mrb_data_type mrb_hmac_type = { "HMAC", lib_hmac_free };

#define MAX_DIGEST_LENGTH	CC_SHA512_DIGEST_LENGTH

union ctx_union {
  CC_MD5_CTX md5;
  CC_SHA1_CTX sha1;
  CC_SHA256_CTX sha256;
  /* we don't have CC_SHA384_CTX! */
  CC_SHA512_CTX sha512;
};

static void
lib_init(void)
{
}

static int
md_block_length(int type)
{
  switch (type) {
  case MD_TYPE_MD5:	return CC_MD5_BLOCK_BYTES;
  case MD_TYPE_SHA1:	return CC_SHA1_BLOCK_BYTES;
  case MD_TYPE_SHA256:	return CC_SHA256_BLOCK_BYTES;
  case MD_TYPE_SHA384:	return CC_SHA384_BLOCK_BYTES;
  case MD_TYPE_SHA512:	return CC_SHA512_BLOCK_BYTES;
  default:		return 0;
  }
}

static int
lib_md_block_length(const struct mrb_md *md)
{
  return md_block_length(md->type);
}

static void
md_init(int type, void *ctxp)
{
  switch (type) {
  case MD_TYPE_MD5:	CC_MD5_Init(ctxp);    break;
  case MD_TYPE_SHA1:	CC_SHA1_Init(ctxp);   break;
  case MD_TYPE_SHA256:	CC_SHA256_Init(ctxp); break;
  case MD_TYPE_SHA384:	CC_SHA384_Init(ctxp); break;
  case MD_TYPE_SHA512:	CC_SHA512_Init(ctxp); break;
  default:				      break;
  }
}

static void
md_final(int type, unsigned char *str, void *ctx)
{
  switch (type) {
  case MD_TYPE_MD5:	CC_MD5_Final(str, ctx);		break;
  case MD_TYPE_SHA1:	CC_SHA1_Final(str, ctx);	break;
  case MD_TYPE_SHA256:	CC_SHA256_Final(str, ctx);	break;
  case MD_TYPE_SHA384:	CC_SHA384_Final(str, ctx);	break;
  case MD_TYPE_SHA512:	CC_SHA512_Final(str, ctx);	break;
  default:						break;
  }
}

static int
md_digest_length(int type)
{
  switch (type) {
  case MD_TYPE_MD5:	return 16;
  case MD_TYPE_SHA1:	return 20;
  case MD_TYPE_SHA256:	return 32;
  case MD_TYPE_SHA384:	return 48;
  case MD_TYPE_SHA512:	return 64;
  default:		return 0;
  }
}

static mrb_value
lib_md_digest(mrb_state *mrb, const struct mrb_md *md)
{
  union ctx_union ctx;
  unsigned char mdstr[MAX_DIGEST_LENGTH];

  memcpy(&ctx, md->ctx, md_ctx_size(md->type));
  md_final(md->type, mdstr, &ctx);
  return mrb_str_new(mrb, (char *)mdstr, md_digest_length(md->type));
}

static mrb_value
lib_md_digest_bang(mrb_state *mrb, struct mrb_md *md)
{
  unsigned char mdstr[MAX_DIGEST_LENGTH];

  md_final(md->type, mdstr, md->ctx);
  md_init(md->type, md->ctx);
  return mrb_str_new(mrb, (char *)mdstr, md_digest_length(md->type));
}

static int
lib_md_digest_length(const struct mrb_md *md)
{
  return md_digest_length(md->type);
}

static void
lib_md_init(mrb_state *mrb, struct mrb_md *md, int type)
{
  int ctxsize;

  ctxsize = md_ctx_size(type);
  if (ctxsize == 0) {
    mrb_raise(mrb, E_NOTIMP_ERROR, "not supported");
  }
  md->type = type;
  md->ctx = NULL;
  md->ctx = mrb_malloc(mrb, ctxsize);
  md_init(type, md->ctx);
}

static void
lib_md_init_copy(mrb_state *mrb, struct mrb_md *mdnew, struct mrb_md *mdold)
{
  lib_md_init(mrb, mdnew, mdold->type);
}

static void
lib_md_reset(mrb_state *mrb, struct mrb_md *md)
{
  md_init(md->type, md->ctx);
}

static void
lib_md_update(mrb_state *mrb, struct mrb_md *md, unsigned char *data, mrb_int len)
{
  if (sizeof(len) > sizeof(CC_LONG)) {
    if (len != (CC_LONG)len) {
      mrb_raise(mrb, E_ARGUMENT_ERROR, "too long string (not supported yet)");
    }
  }
  switch (md->type) {
  case MD_TYPE_MD5:	CC_MD5_Update(md->ctx, data, len);	break;
  case MD_TYPE_SHA1:	CC_SHA1_Update(md->ctx, data, len);	break;
  case MD_TYPE_SHA256:	CC_SHA256_Update(md->ctx, data, len);	break;
  case MD_TYPE_SHA384:	CC_SHA384_Update(md->ctx, data, len);	break;
  case MD_TYPE_SHA512:	CC_SHA512_Update(md->ctx, data, len);	break;
  default: break;
  }
}

static int
lib_hmac_block_length(const struct mrb_hmac *hmac)
{
  return md_block_length(hmac->type);
}

static mrb_value
lib_hmac_digest(mrb_state *mrb, const struct mrb_hmac *hmac)
{
  CCHmacContext ctx;
  unsigned char str[MAX_DIGEST_LENGTH];

  memcpy(&ctx, &hmac->ctx, sizeof(ctx));
  CCHmacFinal(&ctx, str);
  return mrb_str_new(mrb, (const char *)str, md_digest_length(hmac->type));
}

static int
lib_hmac_digest_length(const struct mrb_hmac *hmac)
{
  return md_digest_length(hmac->type);
}

static void
lib_hmac_init(mrb_state *mrb, struct mrb_hmac *hmac, int type, const unsigned char *key, mrb_int keylen)
{
  CCHmacAlgorithm algorithm;

#if MRB_INT_MAX > SIZE_MAX
  if (len > SIZE_MAX) {
    mrb_raise(mrb, E_ARGUMENT_ERROR, "too long key");
  }
#endif
  switch (type) {
  case MD_TYPE_MD5:    algorithm = kCCHmacAlgMD5;    break;
  case MD_TYPE_SHA1:   algorithm = kCCHmacAlgSHA1;   break;
  case MD_TYPE_SHA256: algorithm = kCCHmacAlgSHA256; break;
  case MD_TYPE_SHA384: algorithm = kCCHmacAlgSHA384; break;
  case MD_TYPE_SHA512: algorithm = kCCHmacAlgSHA512; break;
  default:
    mrb_raisef(mrb, E_RUNTIME_ERROR, "mruby-digest: internal error: unexpected HMAC type: %S", mrb_fixnum_value(type));
    algorithm = 0;
    break;
  }
  hmac->type = type;
  CCHmacInit(&hmac->ctx, algorithm, key, keylen);
}

static void
lib_hmac_update(mrb_state *mrb, struct mrb_hmac *hmac, unsigned char *data, mrb_int len)
{
#if MRB_INT_MAX > SIZE_MAX
  if (len > SIZE_MAX) {
    mrb_raise(mrb, E_ARGUMENT_ERROR, "too long string");
  }
#endif
  CCHmacUpdate(&hmac->ctx, data, len);
}

#endif

static void
basecheck(mrb_state *mrb, mrb_value self, struct mrb_md **mdp)
{
  struct RClass *c;
  struct mrb_md *md;
  mrb_value t;

  c = mrb_obj_class(mrb, self);
  t = mrb_const_get(mrb, mrb_obj_value(c), mrb_intern_lit(mrb, TYPESYM));
  if (mrb_nil_p(t)) {
    mrb_raise(mrb, E_NOTIMP_ERROR, "Digest::Base is an abstract class");
  }
  md = (struct mrb_md *)DATA_PTR(self);
  if (!md) {
    mrb_raise(mrb, E_RUNTIME_ERROR, "no md found (BUG?)");
  }
  if (mdp) *mdp = md;
}

static mrb_value
mrb_digest_block_length(mrb_state *mrb, mrb_value self)
{
  struct mrb_md *md;

  basecheck(mrb, self, &md);
  return mrb_fixnum_value(lib_md_block_length(md));
}

static mrb_value
mrb_digest_digest(mrb_state *mrb, mrb_value self)
{
  struct mrb_md *md;

  md = (struct mrb_md *)DATA_PTR(self);
  if (!md) return mrb_nil_value();
  return lib_md_digest(mrb, md);
}

static mrb_value
mrb_digest_digest_bang(mrb_state *mrb, mrb_value self)
{
  struct mrb_md *md;

  md = (struct mrb_md *)DATA_PTR(self);
  if (!md) return mrb_nil_value();
  return lib_md_digest_bang(mrb, md);
}

static mrb_value
mrb_digest_digest_length(mrb_state *mrb, mrb_value self)
{
  struct mrb_md *md;

  basecheck(mrb, self, &md);
  return mrb_fixnum_value(lib_md_digest_length(md));
}

static mrb_value
digest2hexdigest(mrb_state *mrb, mrb_value b)
{
  mrb_value h;
  int i, len;
  char *bp, buf[3];

  bp = RSTRING_PTR(b);
  len = RSTRING_LEN(b);
  h = mrb_str_buf_new(mrb, len * 2);
  for (i = 0; i < len; i++) {
    snprintf(buf, sizeof(buf), "%02x", (unsigned char )bp[i]);
    mrb_str_buf_cat(mrb, h, buf, 2);
  }
  return h;
}

static mrb_value
mrb_digest_hexdigest(mrb_state *mrb, mrb_value self)
{
  return digest2hexdigest(mrb, mrb_digest_digest(mrb, self));
}

static mrb_value
mrb_digest_init(mrb_state *mrb, mrb_value self)
{
  struct RClass *c;
  struct mrb_md *md;
  mrb_value t;

  md = (struct mrb_md *)DATA_PTR(self);
  if (md) {
    lib_md_free(mrb, md);
  }
  DATA_TYPE(self) = &mrb_md_type;
  DATA_PTR(self) = NULL;

  c = mrb_obj_class(mrb, self);
  if (!mrb_const_defined(mrb, mrb_obj_value(c), mrb_intern_lit(mrb, TYPESYM))) {
    mrb_raise(mrb, E_NOTIMP_ERROR, "Digest::Base is an abstract class");
  }
  t = mrb_const_get(mrb, mrb_obj_value(c), mrb_intern_lit(mrb, TYPESYM));
#if 0
  if (lib_md_supported(t)) {
    mrb_raise(mrb, E_NOTIMP_ERROR, "unknown algorithm");
  }
#endif

  md = (struct mrb_md *)mrb_malloc(mrb, sizeof(*md));
  DATA_PTR(self) = md;
  lib_md_init(mrb, md, mrb_fixnum(t));
  return self;
}

static mrb_value
mrb_digest_init_copy(mrb_state *mrb, mrb_value copy)
{
  struct mrb_md *m1, *m2;
  mrb_value src;

  mrb_get_args(mrb, "o", &src);
  if (mrb_obj_equal(mrb, copy, src)) return copy;
  if (!mrb_obj_is_instance_of(mrb, src, mrb_obj_class(mrb, copy))) {
    mrb_raise(mrb, E_TYPE_ERROR, "wrong argument class");
  }
  if (!DATA_PTR(copy)) {
    DATA_PTR(copy) = mrb_malloc(mrb, sizeof(struct mrb_md));
    DATA_TYPE(copy) = &mrb_md_type;
  }
  m1 = DATA_PTR(src);
  m2 = DATA_PTR(copy);
  lib_md_init_copy(mrb, m2, m1);
  return copy;
}

static mrb_value
mrb_digest_reset(mrb_state *mrb, mrb_value self)
{
  struct mrb_md *md;

  md = (struct mrb_md *)DATA_PTR(self);
  if (!md) return mrb_nil_value();
  lib_md_reset(mrb, md);
  return self;
}

static mrb_value
mrb_digest_update(mrb_state *mrb, mrb_value self)
{
  struct mrb_md *md;
  mrb_int len;
  char *str;

  md = (struct mrb_md *)DATA_PTR(self);
  if (!md) return mrb_nil_value();
  mrb_get_args(mrb, "s", &str, &len);
  lib_md_update(mrb, md, (unsigned char *)str, len);
  return self;
}

static mrb_value
mrb_hmac_block_length(mrb_state *mrb, mrb_value self)
{
  struct mrb_hmac *hmac;

  hmac = (struct mrb_hmac *)DATA_PTR(self);
  if (!hmac) return mrb_nil_value();
  return mrb_fixnum_value(lib_hmac_block_length(hmac));
}

static mrb_value
mrb_hmac_digest(mrb_state *mrb, mrb_value self)
{
  struct mrb_hmac *hmac;

  hmac = (struct mrb_hmac *)DATA_PTR(self);
  if (!hmac) return mrb_nil_value();
  return lib_hmac_digest(mrb, hmac);
}

static mrb_value
mrb_hmac_digest_length(mrb_state *mrb, mrb_value self)
{
  struct mrb_hmac *hmac;

  hmac = (struct mrb_hmac *)DATA_PTR(self);
  if (!hmac) return mrb_nil_value();
  return mrb_fixnum_value(lib_hmac_digest_length(hmac));
}

static mrb_value
mrb_hmac_hexdigest(mrb_state *mrb, mrb_value self)
{
  return digest2hexdigest(mrb, mrb_hmac_digest(mrb, self));
}

static mrb_value
mrb_hmac_init(mrb_state *mrb, mrb_value self)
{
  struct mrb_hmac *hmac;
  mrb_value digest, t;
  mrb_int keylen;
  char *key;

  hmac = (struct mrb_hmac *)DATA_PTR(self);
  if (hmac) {
    lib_hmac_free(mrb, hmac);
  }
  DATA_TYPE(self) = &mrb_hmac_type;
  DATA_PTR(self) = NULL;

  mrb_get_args(mrb, "so", &key, &keylen, &digest);
  t = mrb_const_get(mrb, digest, mrb_intern_lit(mrb, TYPESYM));
  if (mrb_nil_p(t)) {
    mrb_raise(mrb, E_RUNTIME_ERROR, "not a digester");
  }

  hmac = (struct mrb_hmac *)mrb_malloc(mrb, sizeof(*hmac));
  DATA_PTR(self) = hmac;
  lib_hmac_init(mrb, hmac, mrb_fixnum(t), (unsigned char *)key, keylen);
  return self;
}

static mrb_value
mrb_hmac_init_copy(mrb_state *mrb, mrb_value copy)
{
  mrb_raise(mrb, E_RUNTIME_ERROR, "cannot duplicate HMAC");
  return copy;
}

static mrb_value
mrb_hmac_update(mrb_state *mrb, mrb_value self)
{
  struct mrb_hmac *hmac;
  mrb_int len;
  char *str;

  hmac = (struct mrb_hmac *)DATA_PTR(self);
  if (!hmac) return mrb_nil_value();
  mrb_get_args(mrb, "s", &str, &len);
  lib_hmac_update(mrb, hmac, (unsigned char *)str, len);
  return self;
}


void
mrb_mruby_digest_gem_init(mrb_state *mrb)
{
  struct RClass *b, *d, *h;

  lib_init();

  d = mrb_define_module(mrb, "Digest");

  b = mrb_define_class_under(mrb, d, "Base", mrb->object_class);
  mrb_define_method(mrb, b, "block_length",    mrb_digest_block_length,  MRB_ARGS_NONE());
  mrb_define_method(mrb, b, "digest",          mrb_digest_digest,        MRB_ARGS_NONE());
  mrb_define_method(mrb, b, "digest!",         mrb_digest_digest_bang,   MRB_ARGS_NONE()); /* XXX: can be defined in mrblib... */
  mrb_define_method(mrb, b, "digest_length",   mrb_digest_digest_length, MRB_ARGS_NONE());
  //mrb_define_method(mrb, b, "file",            mrb_digest_file,          MRB_ARGS_REQ(1));
  mrb_define_method(mrb, b, "hexdigest",       mrb_digest_hexdigest,     MRB_ARGS_NONE());
  //mrb_define_method(mrb, b, "hexdigest!",      mrb_digest_hexdigest_bang, MRB_ARGS_NONE()); /* XXX: can be defined in mrblib... */
  mrb_define_method(mrb, b, "initialize",      mrb_digest_init,          MRB_ARGS_NONE());
  mrb_define_method(mrb, b, "initialize_copy", mrb_digest_init_copy,     MRB_ARGS_REQ(1));
  mrb_define_method(mrb, b, "reset",           mrb_digest_reset,         MRB_ARGS_NONE());
  mrb_define_method(mrb, b, "update",          mrb_digest_update,        MRB_ARGS_REQ(1));

#define DEFCLASS(n)						\
do {								\
  struct RClass *a = mrb_define_class_under(mrb, d, #n, b);	\
  MRB_SET_INSTANCE_TT(a, MRB_TT_DATA);				\
  mrb_define_const(mrb, a, TYPESYM, mrb_fixnum_value(MD_TYPE_##n));	\
} while (0)

#ifdef HAVE_MD5
  DEFCLASS(MD5);
#endif
#ifdef HAVE_RMD160
  DEFCLASS(RMD160);
#endif
#ifdef HAVE_SHA1
  DEFCLASS(SHA1);
#endif
#ifdef HAVE_SHA256
  DEFCLASS(SHA256);
#endif
#ifdef HAVE_SHA384
  DEFCLASS(SHA384);
#endif
#ifdef HAVE_SHA512
  DEFCLASS(SHA512);
#endif

  h = mrb_define_class_under(mrb, d, "HMAC", mrb->object_class);
  MRB_SET_INSTANCE_TT(h, MRB_TT_DATA);
  mrb_define_method(mrb, h, "block_length",    mrb_hmac_block_length,  MRB_ARGS_NONE());
  mrb_define_method(mrb, h, "digest",          mrb_hmac_digest,        MRB_ARGS_NONE());
  mrb_define_method(mrb, h, "digest_length",   mrb_hmac_digest_length, MRB_ARGS_NONE());
  mrb_define_method(mrb, h, "hexdigest",       mrb_hmac_hexdigest,     MRB_ARGS_NONE());
  mrb_define_method(mrb, h, "initialize",      mrb_hmac_init,          MRB_ARGS_REQ(2));
  mrb_define_method(mrb, h, "initialize_copy", mrb_hmac_init_copy,     MRB_ARGS_REQ(1));
  mrb_define_method(mrb, h, "update",          mrb_hmac_update,        MRB_ARGS_REQ(1));
}

void
mrb_mruby_digest_gem_final(mrb_state *mrb)
{
}
