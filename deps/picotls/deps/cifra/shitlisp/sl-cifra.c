#include "handy.h"
#include "dstr.h"
#include "shitlisp.h"
#include "aes.h"
#include "sha2.h"
#include "hmac.h"
#include "pbkdf2.h"

#include <assert.h>

static sl_value * aes_block_fn(sl_value *self, sl_value *args, sl_symboltab *tab,
                               void (*blockfn)(const cf_aes_context *ctx,
                                               const uint8_t *in,
                                               uint8_t *out))
{
  sl_iter it = sl_iter_start(args);
  sl_value *key = sl_iter_convert(&it, sl_preprocess_eval, sl_assert_bytes, tab);
  sl_value *block = sl_iter_convert(&it, sl_preprocess_eval, sl_assert_bytes, tab);

  sl_value *ret = NULL;

  if (!key || !block ||
      (key->u.bytes.len != 16 && key->u.bytes.len != 24 && key->u.bytes.len != 32) ||
      block->u.bytes.len != AES_BLOCKSZ)
  {
    ret = sl_get_nil();
    goto x_err;
  }

  cf_aes_context ctx;
  cf_aes_init(&ctx, key->u.bytes.buf, key->u.bytes.len);
  uint8_t blockout[AES_BLOCKSZ];
  blockfn(&ctx, block->u.bytes.buf, blockout);
  ret = sl_new_bytes(blockout, AES_BLOCKSZ);
  cf_aes_finish(&ctx);

x_err:
  sl_decref(key);
  sl_decref(block);
  return ret;
}

static sl_value * aes_block_encrypt(sl_value *self, sl_value *args, sl_symboltab *tab)
{
  return aes_block_fn(self, args, tab, cf_aes_encrypt);
}

static sl_value * aes_block_decrypt(sl_value *self, sl_value *args, sl_symboltab *tab)
{
  return aes_block_fn(self, args, tab, cf_aes_decrypt);
}

/* Hashing */
static sl_value * hash_fn(sl_value *self, sl_value *args, sl_symboltab *tab, const cf_chash *h)
{
  sl_iter it = sl_iter_start(args);
  sl_value *msg = sl_iter_convert(&it, sl_preprocess_eval, sl_assert_bytes, tab);

  if (!msg)
    return sl_get_nil();

  cf_chash_ctx ctx;
  assert(h->ctxsz <= CF_CHASH_MAXCTX);
  h->init(&ctx);
  h->update(&ctx, msg->u.bytes.buf, msg->u.bytes.len);
  sl_decref(msg);

  uint8_t result[CF_MAXHASH];
  assert(h->hashsz <= CF_MAXHASH);
  h->digest(&ctx, result);

  return sl_new_bytes(result, h->hashsz);
}

static sl_value * sha224(sl_value *self, sl_value *args, sl_symboltab *tab)
{
  return hash_fn(self, args, tab, &cf_sha224);
}

static sl_value * sha256(sl_value *self, sl_value *args, sl_symboltab *tab)
{
  return hash_fn(self, args, tab, &cf_sha256);
}

static sl_value * sha384(sl_value *self, sl_value *args, sl_symboltab *tab)
{
  return hash_fn(self, args, tab, &cf_sha384);
}

static sl_value * sha512(sl_value *self, sl_value *args, sl_symboltab *tab)
{
  return hash_fn(self, args, tab, &cf_sha512);
}

/* HMAC */
static sl_value * hmac_fn(sl_value *self, sl_value *args, sl_symboltab *tab, const cf_chash *h)
{
  sl_iter it = sl_iter_start(args);
  sl_value *key = sl_iter_convert(&it, sl_preprocess_eval, sl_assert_bytes, tab);
  sl_value *msg = sl_iter_convert(&it, sl_preprocess_eval, sl_assert_bytes, tab);

  if (!key || !msg)
  {
    sl_decref(key);
    sl_decref(msg);
    return sl_get_nil();
  }

  uint8_t result[CF_MAXHASH];
  cf_hmac(key->u.bytes.buf, key->u.bytes.len,
          msg->u.bytes.buf, msg->u.bytes.len,
          result,
          h);

  sl_decref(key);
  sl_decref(msg);
  return sl_new_bytes(result, h->hashsz);
}

static sl_value * hmac_sha224(sl_value *self, sl_value *args, sl_symboltab *tab)
{ return hmac_fn(self, args, tab, &cf_sha224); }

static sl_value * hmac_sha256(sl_value *self, sl_value *args, sl_symboltab *tab)
{ return hmac_fn(self, args, tab, &cf_sha256); }

static sl_value * hmac_sha384(sl_value *self, sl_value *args, sl_symboltab *tab)
{ return hmac_fn(self, args, tab, &cf_sha384); }

static sl_value * hmac_sha512(sl_value *self, sl_value *args, sl_symboltab *tab)
{ return hmac_fn(self, args, tab, &cf_sha512); }


/* PBKDF2 */
static sl_value * do_pbkdf2(const cf_chash *h, sl_value *pw, sl_value *salt,
                            uint32_t iterations, uint32_t outlen)
{
  dstr out;
  dstr_init(&out);
  if (dstr_expand(&out, outlen))
    return NULL;

  cf_pbkdf2_hmac(pw->u.bytes.buf, pw->u.bytes.len,
                 salt->u.bytes.buf, salt->u.bytes.len,
                 iterations,
                 (uint8_t *) out.start, outlen,
                 h);

  sl_value *ret = sl_new_bytes((uint8_t *) out.start, outlen);
  dstr_free(&out);
  return ret;
}

static sl_value * pbkdf2_fn(sl_value *self, sl_value *args, sl_symboltab *tab, const cf_chash *h)
{
  sl_iter it = sl_iter_start(args);
  sl_value *pw = sl_iter_convert(&it, sl_preprocess_eval, sl_assert_bytes, tab);
  sl_value *salt = sl_iter_convert(&it, sl_preprocess_eval, sl_assert_bytes, tab);
  sl_value *iterations = sl_iter_convert(&it, sl_preprocess_eval, sl_assert_integer, tab);
  sl_value *outlen = sl_iter_convert(&it, sl_preprocess_eval, sl_assert_integer, tab);

  sl_value *ret;

  if (!pw || !salt || !iterations || !outlen)
    ret = sl_get_nil();
  else
  {
    assert(bignum_len_words(&iterations->u.integer.bn) == 1);
    assert(bignum_len_words(&outlen->u.integer.bn) == 1);
    ret = do_pbkdf2(h, pw, salt,
                    iterations->u.integer.bn.v[0],
                    outlen->u.integer.bn.v[0]);
  }
  
  sl_decref(pw);
  sl_decref(salt);
  sl_decref(iterations);
  sl_decref(outlen);
  return ret;
}

static sl_value * pbkdf2_sha224(sl_value *self, sl_value *args, sl_symboltab *tab)
{
  return pbkdf2_fn(self, args, tab, &cf_sha224);
}

static sl_value * pbkdf2_sha256(sl_value *self, sl_value *args, sl_symboltab *tab)
{
  return pbkdf2_fn(self, args, tab, &cf_sha256);
}

int SL_MODULE_ENTRY(sl_symboltab *tab)
{
  ER(sl_symboltab_add_name_native(tab, "aes-encrypt", aes_block_encrypt));
  ER(sl_symboltab_add_name_native(tab, "aes-decrypt", aes_block_decrypt));
  ER(sl_symboltab_add_name_native(tab, "sha224", sha224));
  ER(sl_symboltab_add_name_native(tab, "sha256", sha256));
  ER(sl_symboltab_add_name_native(tab, "sha384", sha384));
  ER(sl_symboltab_add_name_native(tab, "sha512", sha512));
  ER(sl_symboltab_add_name_native(tab, "hmac-sha224", hmac_sha224));
  ER(sl_symboltab_add_name_native(tab, "hmac-sha256", hmac_sha256));
  ER(sl_symboltab_add_name_native(tab, "hmac-sha384", hmac_sha384));
  ER(sl_symboltab_add_name_native(tab, "hmac-sha512", hmac_sha512));
  ER(sl_symboltab_add_name_native(tab, "pbkdf2-sha224", pbkdf2_sha224));
  ER(sl_symboltab_add_name_native(tab, "pbkdf2-sha256", pbkdf2_sha256));
  return 0;
}
