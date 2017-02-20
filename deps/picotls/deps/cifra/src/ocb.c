/*
 * cifra - embedded cryptography library
 * Written in 2016 by Joseph Birr-Pixton <jpixton@gmail.com>
 *
 * To the extent possible under law, the author(s) have dedicated all
 * copyright and related and neighboring rights to this software to the
 * public domain worldwide. This software is distributed without any
 * warranty.
 *
 * You should have received a copy of the CC0 Public Domain Dedication
 * along with this software. If not, see
 * <http://creativecommons.org/publicdomain/zero/1.0/>.
 */

#include "handy.h"
#include "prp.h"
#include "modes.h"
#include "blockwise.h"
#include "bitops.h"
#include "gf128.h"
#include "tassert.h"

#include <string.h>

/* How many L_n values to compute at schedule time. */
#define MAX_L 4

/* We and RFC7253 assume 128-bit blocks. */
#define BLOCK 16

typedef struct
{
  const cf_prp *prp;
  void *prpctx;                 /* Our PRP */
  uint8_t *out;                 /* Output pointer for block processing */
  cf_gf128 L_star;              /* Zero block ciphertext */
  cf_gf128 L_dollar;            /* L_$ is double of L_* */
  cf_gf128 L[MAX_L];            /* L[0] is double of L_$, L[1] is double of L[0], etc. */
  cf_gf128 offset;              /* Offset_i */
  cf_gf128 checksum;            /* Checksum_i */
  uint32_t i;                   /* Block index, 1-based */
} ocb;

typedef struct
{
  ocb *o;                       /* OCB context (contains PRP, etc.) */
  cf_gf128 sum;                 /* Current Sum_i */
  cf_gf128 offset;              /* Current Offset_i */
  uint32_t i;                   /* Block index, 1-based */
} ocb_hash;

static void ocb_init(ocb *o, const cf_prp *prp, void *prpctx,
                     const uint8_t *nonce, size_t nnonce,
                     size_t ntag)
{
  o->prp = prp;
  o->prpctx = prpctx;

  assert(o->prp->blocksz == BLOCK);

  /* L_* = ENCIPHER(K, zeros(128)) */
  uint8_t L_star_bytes[BLOCK] = { 0 };
  prp->encrypt(prpctx, L_star_bytes, L_star_bytes);
  cf_gf128_frombytes_be(L_star_bytes, o->L_star);

  /* L_$ = double(L_*) */
  cf_gf128_double(o->L_star, o->L_dollar);

  /* L_0 = double(L_$) etc. */
  cf_gf128_double(o->L_dollar, o->L[0]);

  for (int i = 1; i < MAX_L; i++)
    cf_gf128_double(o->L[i - 1], o->L[i]);

  /* Compute nonce-dependent and per-encryption vars */
  assert(nnonce > 0 && nnonce < BLOCK);
  uint8_t full_nonce[BLOCK] = { 0 };
  full_nonce[0] = ((ntag * 8) & 0x7f) << 1;
  full_nonce[BLOCK - 1 - nnonce] |= 0x01;
  memcpy(full_nonce + BLOCK - nnonce, nonce, nnonce);
  uint8_t bottom = full_nonce[BLOCK - 1] & 0x3f;

  /* Make Ktop */
  full_nonce[BLOCK - 1] &= 0xc0;
  uint8_t Ktop[BLOCK + 8];
  prp->encrypt(prpctx, full_nonce, Ktop);

  /* Stretch Ktop */
  for (int i = 0; i < 8; i++)
    Ktop[i + BLOCK] = Ktop[i] ^ Ktop[i + 1];

  /* Outputs */
  uint8_t offset[BLOCK];
  copy_bytes_unaligned(offset, Ktop, BLOCK, bottom);
  cf_gf128_frombytes_be(offset, o->offset);
  memset(o->checksum, 0, sizeof o->checksum);
}

static void ocb_start_cipher(ocb *o, uint8_t *output)
{
  o->i = 1;
  o->out = output;
}

static void ocb_add_Ln(ocb *o, uint32_t n, cf_gf128 out)
{
  /* Do we have a precomputed L term? */
  if (n < MAX_L)
  {
    cf_gf128_add(o->L[n], out, out);
    return;
  }

  /* Compute more terms of L. */
  cf_gf128 accum;
  memcpy(accum, o->L[MAX_L - 1], sizeof accum);

  for (uint32_t i = MAX_L - 1; i < n; i++)
  {
    cf_gf128 next;
    cf_gf128_double(accum, next);
    memcpy(accum, next, sizeof accum);
  }

  cf_gf128_add(accum, out, out);
}

static void ocb_hash_init(ocb_hash *h)
{
  memset(h->offset, 0, sizeof h->offset);
  memset(h->sum, 0, sizeof h->sum);
  h->i = 1;
}

static void ocb_hash_sum(ocb *o, const uint8_t *block,
                         cf_gf128 sum, const cf_gf128 offset)
{
  uint8_t offset_bytes[BLOCK];
  cf_gf128_tobytes_be(offset, offset_bytes);

  uint8_t block_tmp[BLOCK];
  xor_bb(block_tmp, block, offset_bytes, sizeof block_tmp);
  o->prp->encrypt(o->prpctx, block_tmp, block_tmp);

  cf_gf128 tmp;
  cf_gf128_frombytes_be(block_tmp, tmp);
  cf_gf128_add(sum, tmp, sum);
}

static void ocb_hash_block(void *vctx, const uint8_t *block)
{
  ocb_hash *h = vctx;

  /* Offset_i = Offset_{i - 1} xor L{ntz(i)} */
  ocb_add_Ln(h->o, count_trailing_zeroes(h->i), h->offset);

  /* Sum_i = Sum_{i - 1} xor ENCIPHER(K, A_i xor Offset_i) */
  ocb_hash_sum(h->o, block, h->sum, h->offset);

  h->i++;
}

static void ocb_process_header(ocb *o, const uint8_t *header, size_t nheader,
                               uint8_t out[BLOCK])
{
  ocb_hash ctx = { o };
  ocb_hash_init(&ctx);

  uint8_t partial[BLOCK];
  size_t npartial = 0;

  cf_blockwise_accumulate(partial, &npartial,
                          o->prp->blocksz,
                          header, nheader,
                          ocb_hash_block,
                          &ctx);

  if (npartial)
  {
    /* Offset_* = Offset_m xor L_* */
    cf_gf128_add(ctx.offset, o->L_star, ctx.offset);

    /* CipherInput = (A_* || 1 || zeros(127 - bitlen(A_*))) xor Offset_* */
    memset(partial + npartial, 0, sizeof(partial) - npartial);
    partial[npartial] = 0x80;

    /* Sum = Sum_m xor ENCIPHER(K, CipherInput) */
    ocb_hash_sum(ctx.o, partial, ctx.sum, ctx.offset);
  }

  cf_gf128_tobytes_be(ctx.sum, out);
  mem_clean(&ctx, sizeof ctx);
}

static void ocb_encrypt_block(void *vctx, const uint8_t *block)
{
  ocb *o = vctx;

  /* Offset_i = Offset_{i - 1} xor L{ntz(i)} */
  ocb_add_Ln(o, count_trailing_zeroes(o->i), o->offset);

  /* C_i = Offset_i xor ENCIPHER(K, P_i xor Offset_i) */
  uint8_t offset_bytes[BLOCK];
  cf_gf128_tobytes_be(o->offset, offset_bytes);

  uint8_t block_tmp[BLOCK];
  xor_bb(block_tmp, block, offset_bytes, sizeof block_tmp);
  o->prp->encrypt(o->prpctx, block_tmp, block_tmp);
  xor_bb(o->out, block_tmp, offset_bytes, sizeof block_tmp);
  o->out += sizeof block_tmp;

  /* Checksum_i = Checksum_{i - 1} xor P_i */
  cf_gf128 P;
  cf_gf128_frombytes_be(block, P);
  cf_gf128_add(o->checksum, P, o->checksum);

  o->i++;
}

void cf_ocb_encrypt(const cf_prp *prp, void *prpctx,
                    const uint8_t *plain, size_t nplain,
                    const uint8_t *header, size_t nheader,
                    const uint8_t *nonce, size_t nnonce,
                    uint8_t *cipher, /* the same size as nplain */
                    uint8_t *tag, size_t ntag)
{
  ocb o;
  ocb_init(&o, prp, prpctx, nonce, nnonce, ntag);

  /* Process blocks.  The blockwise machinery takes care of
   * splitting the input into 128-bit blocks, and calling
   * a function on each one. */
  uint8_t partial[BLOCK];
  size_t npartial = 0;

  ocb_start_cipher(&o, cipher);
  cf_blockwise_accumulate(partial, &npartial,
                          prp->blocksz,
                          plain, nplain,
                          ocb_encrypt_block,
                          &o);

  /* Move along plain and cipher. */
  plain += (o.out - cipher);
  cipher = o.out;

  /* If we have remaining data to pad and process,
   * it's in partial. */
  if (npartial)
  {
    /* Offset_* = Offset_m xor L_* */
    cf_gf128_add(o.offset, o.L_star, o.offset);

    /* Pad = ENCIPHER(K, Offset_*) */
    uint8_t pad[BLOCK];
    cf_gf128_tobytes_be(o.offset, pad);
    o.prp->encrypt(o.prpctx, pad, pad);

    /* C_* = P_* xor Pad[1..bitlen(P_*)] */
    xor_bb(cipher, partial, pad, npartial);
    mem_clean(pad, sizeof pad);

    /* Checksum_* = Checksum_m xor (P_* || 1 || zeros(127 - bitlen(P_*))) */
    memset(partial + npartial, 0, sizeof(partial) - npartial);
    partial[npartial] = 0x80;

    cf_gf128 last_block;
    cf_gf128_frombytes_be(partial, last_block);
    cf_gf128_add(o.checksum, last_block, o.checksum);
    mem_clean(last_block, sizeof last_block);
  }

  /* Compute: Tag = ENCIPHER(K, Checksum_m xor Offset_m xor L_$) xor HASH(K, A) */
  cf_gf128 full_tag;
  for (size_t i = 0; i < 4; i++)
    full_tag[i] = o.checksum[i] ^ o.offset[i] ^ o.L_dollar[i];

  /* Convert tag to bytes for encryption */
  uint8_t tag_bytes[BLOCK];
  cf_gf128_tobytes_be(full_tag, tag_bytes);

  /* ENCIPHER(...) */
  o.prp->encrypt(o.prpctx, tag_bytes, tag_bytes);

  /* Compute HASH(K, A). */
  uint8_t hash_a[BLOCK];
  ocb_process_header(&o, header, nheader, hash_a);

  /* ... xor HASH(K, A) */
  xor_bb(tag_bytes, tag_bytes, hash_a, sizeof tag_bytes);

  /* Copy out tag to caller. */
  memcpy(tag, tag_bytes, ntag);

  mem_clean(&o, sizeof o);
}

static void ocb_decrypt_block(void *vctx, const uint8_t *block)
{
  ocb *o = vctx;

  /* Offset_i = Offset_{i - 1} xor L{ntz(i)} */
  ocb_add_Ln(o, count_trailing_zeroes(o->i), o->offset);

  /* P_i = Offset_i xor DECIPHER(K, C_i xor Offset_i) */
  uint8_t offset_bytes[BLOCK];
  cf_gf128_tobytes_be(o->offset, offset_bytes);

  uint8_t block_tmp[BLOCK];
  xor_bb(block_tmp, block, offset_bytes, sizeof block_tmp);
  o->prp->decrypt(o->prpctx, block_tmp, block_tmp);
  xor_bb(o->out, block_tmp, offset_bytes, sizeof block_tmp);

  /* Checksum_i = Checksum_{i - 1} xor P_i */
  cf_gf128 P;
  cf_gf128_frombytes_be(o->out, P);
  o->out += sizeof block_tmp;
  cf_gf128_add(o->checksum, P, o->checksum);

  o->i++;
}

int cf_ocb_decrypt(const cf_prp *prp, void *prpctx,
                   const uint8_t *cipher, size_t ncipher,
                   const uint8_t *header, size_t nheader,
                   const uint8_t *nonce, size_t nnonce,
                   const uint8_t *tag, size_t ntag,
                   uint8_t *plain)
{
  ocb o;
  ocb_init(&o, prp, prpctx, nonce, nnonce, ntag);

  /* Do blockwise decryption */
  uint8_t partial[BLOCK];
  size_t npartial = 0;

  ocb_start_cipher(&o, plain);
  cf_blockwise_accumulate(partial, &npartial,
                          prp->blocksz,
                          cipher, ncipher,
                          ocb_decrypt_block,
                          &o);

  if (npartial)
  {
    /* Offset_* = Offset_m xor L_* */
    cf_gf128_add(o.offset, o.L_star, o.offset);

    /* Pad = ENCIPHER(K, Offset_*) */
    uint8_t pad[BLOCK];
    cf_gf128_tobytes_be(o.offset, pad);
    o.prp->encrypt(o.prpctx, pad, pad);

    /* P_* = C_* xor Pad[1..bitlen(C_*)] */
    xor_bb(partial, partial, pad, npartial);
    mem_clean(pad, sizeof pad);

    memcpy(o.out, partial, npartial);

    /* Checksum_* = Checksum_m xor (P_* || 1 || zeros(127 - bitlen(P_*))) */
    memset(partial + npartial, 0, sizeof(partial) - npartial);
    partial[npartial] = 0x80;

    cf_gf128 last_block;
    cf_gf128_frombytes_be(partial, last_block);
    cf_gf128_add(o.checksum, last_block, o.checksum);
    mem_clean(last_block, sizeof last_block);
  }

  /* Compute: Tag = ENCIPHER(K, Checksum_m xor Offset_m xor L_$) xor HASH(K, A) */
  cf_gf128 full_tag;
  for (size_t i = 0; i < 4; i++)
    full_tag[i] = o.checksum[i] ^ o.offset[i] ^ o.L_dollar[i];

  /* Convert tag to bytes for encryption */
  uint8_t tag_bytes[BLOCK];
  cf_gf128_tobytes_be(full_tag, tag_bytes);

  /* ENCIPHER(...) */
  o.prp->encrypt(o.prpctx, tag_bytes, tag_bytes);

  /* Compute HASH(K, A). */
  uint8_t hash_a[BLOCK];
  ocb_process_header(&o, header, nheader, hash_a);

  /* ... xor HASH(K, A) */
  xor_bb(tag_bytes, tag_bytes, hash_a, sizeof tag_bytes);

  /* Check against caller's tag. */
  int err;

  if (mem_eq(tag, tag_bytes, ntag))
  {
    err = 0;
  } else {
    err = 1;
    mem_clean(plain, ncipher);
  }

  mem_clean(&o, sizeof o);
  mem_clean(tag_bytes, sizeof tag_bytes);
  mem_clean(full_tag, sizeof full_tag);
  return err;
}
