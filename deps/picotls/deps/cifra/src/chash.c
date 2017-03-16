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

#include "chash.h"
#include "handy.h"
#include "tassert.h"

void cf_hash(const cf_chash *h, const void *m, size_t nm, uint8_t *out)
{
  cf_chash_ctx ctx;
  assert(h);
  h->init(&ctx);
  h->update(&ctx, m, nm);
  h->digest(&ctx, out);
  mem_clean(&ctx, sizeof ctx);
}

