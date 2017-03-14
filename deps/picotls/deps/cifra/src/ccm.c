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

#include "handy.h"
#include "prp.h"
#include "modes.h"
#include "tassert.h"

#include <string.h>

#define CCM_ADATA_PRESENT 0x40

static void write_be(uint8_t *out, size_t value, size_t bytes)
{
  while (bytes)
  {
    out[bytes - 1] = value & 0xff;
    value >>= 8;
    bytes--;
  }

  assert(value == 0); /* or we couldn't encode the value. */
}

static void zero_pad(cf_cbcmac_stream *cm)
{
  cf_cbcmac_stream_finish_block_zero(cm);
}

/* nb. block is general workspace. */
static void add_aad(cf_cbcmac_stream *cm, uint8_t block[CF_MAXBLOCK],
                    const uint8_t *header, size_t nheader)
{
  assert(nheader <= 0xffffffff); /* we don't support 64 bit lengths. */

  /* Add length using stupidly complicated rules. */
  if (nheader < 0xff00)
  {
    write_be(block, nheader, 2);
    cf_cbcmac_stream_update(cm, block, 2);
  } else {
    write_be(block, 0xfffe, 2);
    write_be(block + 2, nheader, 4);
    cf_cbcmac_stream_update(cm, block, 6);
  }

  cf_cbcmac_stream_update(cm, header, nheader);
  zero_pad(cm);
}

static void add_block0(cf_cbcmac_stream *cm,
                       uint8_t block[CF_MAXBLOCK], size_t nblock,
                       const uint8_t *nonce, size_t nnonce,
                       size_t L, size_t nplain,
                       size_t nheader, size_t ntag)
{
  /* Construct first block B_0. */
  block[0] = ((nheader == 0) ? 0x00 : CCM_ADATA_PRESENT) |
             ((ntag - 2) / 2) << 3 |
             (L - 1);
  memcpy(block + 1, nonce, nnonce);
  write_be(block + 1 + nnonce, nplain, L);

  cf_cbcmac_stream_update(cm, block, nblock);
}

static void build_ctr_nonce(uint8_t ctr_nonce[CF_MAXBLOCK],
                            size_t L,
                            const uint8_t *nonce, size_t nnonce)
{
  ctr_nonce[0] = (L - 1);
  memcpy(ctr_nonce + 1, nonce, nnonce);
  memset(ctr_nonce + 1 + nnonce, 0, L);
}

void cf_ccm_encrypt(const cf_prp *prp, void *prpctx,
                    const uint8_t *plain, size_t nplain, size_t L,
                    const uint8_t *header, size_t nheader,
                    const uint8_t *nonce, size_t nnonce,
                    uint8_t *cipher,
                    uint8_t *tag, size_t ntag)
{
  uint8_t block[CF_MAXBLOCK];

  assert(ntag >= 4 && ntag <= 16 && ntag % 2 == 0);
  assert(L >= 2 && L <= 8);
  assert(nnonce == prp->blocksz - L - 1);

  cf_cbcmac_stream cm;
  cf_cbcmac_stream_init(&cm, prp, prpctx);

  /* Add first block. */
  add_block0(&cm, block, prp->blocksz,
             nonce, nnonce,
             L, nplain, nheader, ntag);

  /* Add AAD with length prefix, if present. */
  if (nheader)
    add_aad(&cm, block, header, nheader);

  /* Add message. */
  cf_cbcmac_stream_update(&cm, plain, nplain);
  zero_pad(&cm);

  /* Finish tag. */
  cf_cbcmac_stream_nopad_final(&cm, block);

  /* Start encryption. */
  /* Construct A_0 */
  uint8_t ctr_nonce[CF_MAXBLOCK];
  build_ctr_nonce(ctr_nonce, L, nonce, nnonce);

  cf_ctr ctr;
  cf_ctr_init(&ctr, prp, prpctx, ctr_nonce);
  cf_ctr_custom_counter(&ctr, prp->blocksz - L, L);

  /* Encrypt tag first. */
  cf_ctr_cipher(&ctr, block, block, prp->blocksz);
  memcpy(tag, block, ntag);

  /* Then encrypt message. */
  cf_ctr_cipher(&ctr, plain, cipher, nplain);
}

int cf_ccm_decrypt(const cf_prp *prp, void *prpctx,
                   const uint8_t *cipher, size_t ncipher, size_t L,
                   const uint8_t *header, size_t nheader,
                   const uint8_t *nonce, size_t nnonce,
                   const uint8_t *tag, size_t ntag,
                   uint8_t *plain)
{
  uint8_t block[CF_MAXBLOCK];
  
  assert(ntag >= 4 && ntag <= 16 && ntag % 2 == 0);
  assert(L >= 2 && L <= 8);
  assert(nnonce == prp->blocksz - L - 1);

  uint8_t ctr_nonce[CF_MAXBLOCK];
  build_ctr_nonce(ctr_nonce, L, nonce, nnonce);

  cf_ctr ctr;
  cf_ctr_init(&ctr, prp, prpctx, ctr_nonce);
  cf_ctr_custom_counter(&ctr, prp->blocksz - L, L);

  /* Decrypt tag. */
  uint8_t plain_tag[CF_MAXBLOCK];
  cf_ctr_cipher(&ctr, tag, plain_tag, ntag);
  cf_ctr_discard_block(&ctr);

  /* Decrypt message. */
  cf_ctr_cipher(&ctr, cipher, plain, ncipher);

  cf_cbcmac_stream cm;
  cf_cbcmac_stream_init(&cm, prp, prpctx);
  
  /* Add first block. */
  add_block0(&cm, block, prp->blocksz,
             nonce, nnonce,
             L, ncipher, nheader, ntag);

  if (nheader)
    add_aad(&cm, block, header, nheader);
  
  cf_cbcmac_stream_update(&cm, plain, ncipher);
  zero_pad(&cm);

  /* Finish tag. */
  cf_cbcmac_stream_nopad_final(&cm, block);

  int err = 0;

  if (!mem_eq(block, plain_tag, ntag))
  {
    err = 1;
    mem_clean(plain, ncipher);
  }

  mem_clean(block, sizeof block);
  mem_clean(plain_tag, sizeof plain_tag);
  return err;
}

