/*
 * cifra - embedded cryptography library
 * Written in 2014 by Joseph Birr-Pixton <jpixton@gmail.com>
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


#include "norx.h"
#include "bitops.h"
#include "handy.h"
#include "blockwise.h"
#include "tassert.h"

#include <string.h>

typedef struct
{
  uint32_t s[16];
} norx32_ctx;

/* Domain separation constants */
#define DOMAIN_HEADER   0x01
#define DOMAIN_PAYLOAD  0x02
#define DOMAIN_TRAILER  0x04
#define DOMAIN_TAG      0x08

#define WORD_BYTES 4
#define WORD_BITS 32
#define ROUNDS 4
#define DEGREE 1
#define TAG_BITS 128
#define RATE_BYTES 48
#define RATE_WORDS 12

static void permute(norx32_ctx *ctx)
{
#ifdef CORTEX_M0
  /* Register usage: A-D r2, r3, r4, r5.
   * Temps: r6 */

#define in(xx) "%[" #xx "]"

  /* Load numbered slots of S into r2-r5 */
#define LOAD(u, v, w, x)           \
  "  ldr r2, [%[S], " in(u) "]\n"  \
  "  ldr r3, [%[S], " in(v) "]\n"  \
  "  ldr r4, [%[S], " in(w) "]\n"  \
  "  ldr r5, [%[S], " in(x) "]\n"

  /* Store r2-r5 into numbered slots of S */
#define STORE(u, v, w, x)          \
  "  str r2, [%[S], " in(u) "]\n"  \
  "  str r3, [%[S], " in(v) "]\n"  \
  "  str r4, [%[S], " in(w) "]\n"  \
  "  str r5, [%[S], " in(x) "]\n"

  /* This is H() plus the xor and rotate in one step of G.
   * rx is the register containing x (read/write)
   * ry is the register containing y (read)
   * rw is the register containing d (read/write)
   * rot is the rotation constant r_n */
#define P(rx, ry, rw, rot)      \
  "  mov r6, " #rx "\n"         \
  "  and " #rx ", " #ry "\n"    \
  "  lsl " #rx ", #1\n"         \
  "  eor " #rx ", r6\n"         \
  "  eor " #rx ", " #ry "\n"    \
  "  mov r6, #" #rot "\n"       \
  "  eor " #rw ", " #rx "\n"    \
  "  ror " #rw ", r6\n"

  /* The function G.  s is the state array, a-d are indices
   * into it. */
#define G(s, a, b, c, d)      \
  __asm__ (                   \
            LOAD(A, B, C, D)  \
            P(r2, r3, r5, 8)  \
            P(r4, r5, r3, 11) \
            P(r2, r3, r5, 16) \
            P(r4, r5, r3, 31) \
            STORE(A, B, C, D) \
          :                   \
          : [S] "r" (s),      \
            [A] "i" (a << 2), \
            [B] "i" (b << 2), \
            [C] "i" (c << 2), \
            [D] "i" (d << 2)  \
          : "memory", "cc", "r2", "r3", "r4", "r5", "r6");
#else

  /* This is one quarter of G; the function H plus xor/rotate. */
#define P(u, v, w, rr) \
  (u) = ((u) ^ (v)) ^ (((u) & (v)) << 1); \
  (w) = rotr32((u) ^ (w), rr);

#define G(s, a, b, c, d) \
  P(s[a], s[b], s[d], 8) \
  P(s[c], s[d], s[b], 11) \
  P(s[a], s[b], s[d], 16) \
  P(s[c], s[d], s[b], 31)
#endif

  for (int i = 0; i < ROUNDS; i++)
  {
    /* columns */
    G(ctx->s, 0, 4, 8, 12);
    G(ctx->s, 1, 5, 9, 13);
    G(ctx->s, 2, 6, 10, 14);
    G(ctx->s, 3, 7, 11, 15);

    /* diagonals */
    G(ctx->s, 0, 5, 10, 15);
    G(ctx->s, 1, 6, 11, 12);
    G(ctx->s, 2, 7, 8, 13);
    G(ctx->s, 3, 4, 9, 14);
  }

#undef G
#undef P
}

static void init(norx32_ctx *ctx,
                 const uint8_t key[16],
                 const uint8_t nonce[8])
{
  /* 1. Basic setup */
  ctx->s[0] = read32_le(nonce + 0);
  ctx->s[1] = read32_le(nonce + 4);
  ctx->s[2] = 0xb707322f;
  ctx->s[3] = 0xa0c7c90d;

  ctx->s[4] = read32_le(key + 0);
  ctx->s[5] = read32_le(key + 4);
  ctx->s[6] = read32_le(key + 8);
  ctx->s[7] = read32_le(key + 12);

  ctx->s[8] = 0xa3d8d930;
  ctx->s[9] = 0x3fa8b72c;
  ctx->s[10] = 0xed84eb49;
  ctx->s[11] = 0xedca4787;

  ctx->s[12] = 0x335463eb;
  ctx->s[13] = 0xf994220b;
  ctx->s[14] = 0xbe0bf5c9;
  ctx->s[15] = 0xd7c49104;

  /* 2. Parameter integration
   * w = 32
   * l = 4
   * p = 1
   * t = 128
   */
  ctx->s[12] ^= WORD_BITS;
  ctx->s[13] ^= ROUNDS;
  ctx->s[14] ^= DEGREE;
  ctx->s[15] ^= TAG_BITS;

  permute(ctx);
}

/* Input domain separation constant for next step, and final permutation of
 * preceeding step. */
static void switch_domain(norx32_ctx *ctx, uint32_t constant)
{
  ctx->s[15] ^= constant;
  permute(ctx);
}

typedef struct
{
  norx32_ctx *ctx;
  uint32_t type;
} blockctx;

static void input_block_final(void *vctx, const uint8_t *data)
{
  blockctx *bctx = vctx;
  norx32_ctx *ctx = bctx->ctx;

  /* just xor-in data. */
  for (int i = 0; i < RATE_WORDS; i++)
  {
    ctx->s[i] ^= read32_le(data);
    data += WORD_BYTES;
  }
}

static void input_block(void *vctx, const uint8_t *data)
{
  /* Process block, then prepare for the next one. */
  blockctx *bctx = vctx;
  input_block_final(vctx, data);
  switch_domain(bctx->ctx, bctx->type);
}

static void input(norx32_ctx *ctx, uint32_t type,
                  const uint8_t *buf, size_t nbuf)
{
  uint8_t partial[RATE_BYTES];
  size_t npartial = 0;
  blockctx bctx = { ctx, type };

  /* Process input. */
  cf_blockwise_accumulate(partial, &npartial, sizeof partial,
                          buf, nbuf,
                          input_block,
                          &bctx);

  /* Now pad partial. This contains the trailing portion of buf. */
  memset(partial + npartial, 0, sizeof(partial) - npartial);
  partial[npartial] = 0x01;
  partial[sizeof(partial) - 1] ^= 0x80;

  input_block_final(&bctx, partial);
}

static void do_header(norx32_ctx *ctx, const uint8_t *buf, size_t nbuf)
{
  if (nbuf)
  {
    switch_domain(ctx, DOMAIN_HEADER);
    input(ctx, DOMAIN_HEADER, buf, nbuf);
  }
}

static void do_trailer(norx32_ctx *ctx, const uint8_t *buf, size_t nbuf)
{
  if (nbuf)
  {
    switch_domain(ctx, DOMAIN_TRAILER);
    input(ctx, DOMAIN_TRAILER, buf, nbuf);
  }
}

static void body_block_encrypt(norx32_ctx *ctx,
                               const uint8_t plain[RATE_BYTES],
                               uint8_t cipher[RATE_BYTES])
{
  for (int i = 0; i < RATE_WORDS; i++)
  {
    ctx->s[i] ^= read32_le(plain);
    write32_le(ctx->s[i], cipher);
    plain += WORD_BYTES;
    cipher += WORD_BYTES;
  }
}

static void encrypt_body(norx32_ctx *ctx,
                         const uint8_t *plain, uint8_t *cipher, size_t nbytes)
{
  if (nbytes == 0)
    return;

  /* Process full blocks: easy */
  while (nbytes >= RATE_BYTES)
  {
    switch_domain(ctx, DOMAIN_PAYLOAD);
    body_block_encrypt(ctx, plain, cipher);
    plain += RATE_BYTES;
    cipher += RATE_BYTES;
    nbytes -= RATE_BYTES;
  }

  /* Final padded block. */
  uint8_t partial[RATE_BYTES];
  memset(partial, 0, sizeof partial);
  memcpy(partial, plain, nbytes);
  partial[nbytes] ^= 0x01;
  partial[sizeof(partial) - 1] ^= 0x80;

  switch_domain(ctx, DOMAIN_PAYLOAD);
  body_block_encrypt(ctx, partial, partial);

  memcpy(cipher, partial, nbytes);
}

static void body_block_decrypt(norx32_ctx *ctx,
                               const uint8_t cipher[RATE_BYTES],
                               uint8_t plain[RATE_BYTES],
                               size_t start, size_t end)
{
  for (size_t i = start; i < end; i++)
  {
    uint32_t ct = read32_le(cipher);
    write32_le(ctx->s[i] ^ ct, plain);
    ctx->s[i] = ct;
    plain += WORD_BYTES;
    cipher += WORD_BYTES;
  }
}

static void undo_padding(norx32_ctx *ctx, size_t bytes)
{
  assert(bytes < RATE_BYTES);
  ctx->s[bytes / WORD_BYTES] ^= 0x01 << ((bytes % WORD_BYTES) * 8);
  ctx->s[RATE_WORDS - 1] ^= 0x80000000;
}

static void decrypt_body(norx32_ctx *ctx,
                         const uint8_t *cipher, uint8_t *plain, size_t nbytes)
{
  if (nbytes == 0)
    return;

  /* Process full blocks. */
  while (nbytes >= RATE_BYTES)
  {
    switch_domain(ctx, DOMAIN_PAYLOAD);
    body_block_decrypt(ctx, cipher, plain, 0, RATE_WORDS);
    plain += RATE_BYTES;
    cipher += RATE_BYTES;
    nbytes -= RATE_BYTES;
  }

  /* Then partial blocks. */
  size_t offset = 0;
  switch_domain(ctx, DOMAIN_PAYLOAD);

  undo_padding(ctx, nbytes);

  /* In units of whole words. */
  while (nbytes >= WORD_BYTES)
  {
    body_block_decrypt(ctx, cipher, plain, offset, offset + 1);
    plain += WORD_BYTES;
    cipher += WORD_BYTES;
    nbytes -= WORD_BYTES;
    offset += 1;
  }

  /* And then, finally, bytewise. */
  uint8_t tmp[WORD_BYTES];
  write32_le(ctx->s[offset], tmp);

  for (size_t i = 0; i < nbytes; i++)
  {
    uint8_t c = cipher[i];
    plain[i] = tmp[i] ^ c;
    tmp[i] = c;
  }

  ctx->s[offset] = read32_le(tmp);
}

static void get_tag(norx32_ctx *ctx, uint8_t tag[16])
{
  switch_domain(ctx, DOMAIN_TAG);
  permute(ctx);
  write32_le(ctx->s[0], tag + 0);
  write32_le(ctx->s[1], tag + 4);
  write32_le(ctx->s[2], tag + 8);
  write32_le(ctx->s[3], tag + 12);
}

void cf_norx32_encrypt(const uint8_t key[16],
                       const uint8_t nonce[8],
                       const uint8_t *header, size_t nheader,
                       const uint8_t *plaintext, size_t nbytes,
                       const uint8_t *trailer, size_t ntrailer,
                       uint8_t *ciphertext,
                       uint8_t tag[16])
{
  norx32_ctx ctx;

  init(&ctx, key, nonce);
  do_header(&ctx, header, nheader);
  encrypt_body(&ctx, plaintext, ciphertext, nbytes);
  do_trailer(&ctx, trailer, ntrailer);
  get_tag(&ctx, tag);

  mem_clean(&ctx, sizeof ctx);
}

int cf_norx32_decrypt(const uint8_t key[16],
                      const uint8_t nonce[8],
                      const uint8_t *header, size_t nheader,
                      const uint8_t *ciphertext, size_t nbytes,
                      const uint8_t *trailer, size_t ntrailer,
                      const uint8_t tag[16],
                      uint8_t *plaintext)
{
  norx32_ctx ctx;
  uint8_t ourtag[16];

  init(&ctx, key, nonce);
  do_header(&ctx, header, nheader);
  decrypt_body(&ctx, ciphertext, plaintext, nbytes);
  do_trailer(&ctx, trailer, ntrailer);
  get_tag(&ctx, ourtag);

  int err = 0;

  if (!mem_eq(ourtag, tag, sizeof ourtag))
  {
    err = 1;
    mem_clean(plaintext, nbytes);
    mem_clean(ourtag, sizeof ourtag);
  }

  mem_clean(&ctx, sizeof ctx);
  return err;
}
