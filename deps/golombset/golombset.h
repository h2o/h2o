/*
 * Copyright (c) 2015 Kazuho Oku
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to
 * deal in the Software without restriction, including without limitation the
 * rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
 * sell copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
 * IN THE SOFTWARE.
 */
#ifndef GOLOMBSET_H
#define GOLOMBSET_H

#include <inttypes.h>

struct st_golombset_encode_t {
    unsigned char *dst;
    unsigned char *dst_max;
    unsigned dst_shift;
};

struct st_golombset_decode_t {
    const unsigned char *src;
    const unsigned char *src_max;
    unsigned src_shift;
};

static int golombset_encode_bit(struct st_golombset_encode_t *ctx, int bit)
{
    if (ctx->dst_shift == 0) {
        if (++ctx->dst == ctx->dst_max)
            return -1;
        *ctx->dst = 0;
        ctx->dst_shift = 8;
    }
    --ctx->dst_shift;
    if (bit)
        *ctx->dst |= 1 << ctx->dst_shift;
    return 0;
}

static int golombset_encode_bits(struct st_golombset_encode_t *ctx, unsigned bits, uint64_t value)
{
    if (bits != 0) {
        do {
            --bits;
            if (golombset_encode_bit(ctx, (value >> bits) & 1) != 0)
                return -1;
        } while (bits != 0);
    }
    return 0;
}

static int golombset_decode_bit(struct st_golombset_decode_t *ctx)
{
    if (ctx->src_shift == 0) {
        if (++ctx->src == ctx->src_max)
            return -1;
        ctx->src_shift = 8;
    }
    return (*ctx->src >> --ctx->src_shift) & 1;
}

static int golombset_decode_bits(struct st_golombset_decode_t *ctx, unsigned bits, uint64_t *value)
{
    int bit;

    *value = 0;
    for (; bits != 0; --bits) {
        if ((bit = golombset_decode_bit(ctx)) == -1)
            return -1;
        *value = (*value * 2) + bit;
    }

    return 0;
}

static int golombset_encode_value(struct st_golombset_encode_t *ctx, unsigned fixed_bits, uint64_t value)
{
    /* emit quontient */
    uint64_t unary_bits = value >> fixed_bits;
    for (; unary_bits != 0; --unary_bits)
        if (golombset_encode_bit(ctx, 0) != 0)
            return -1;
    if (golombset_encode_bit(ctx, 1) != 0)
        return -1;
    /* emit remainder */
    return golombset_encode_bits(ctx, fixed_bits, value);
}

static int golombset_decode_value(struct st_golombset_decode_t *ctx, unsigned fixed_bits, uint64_t *value)
{
    uint64_t q;
    int bit;

    /* decode quontient */
    for (q = 0; ; ++q) {
        if ((bit = golombset_decode_bit(ctx)) == -1)
            return -1;
        if (bit)
            break;
    }
    /* decode remainder */
    if (golombset_decode_bits(ctx, fixed_bits, value) == -1)
        return -1;
    /* merge q and r */
    *value += q << fixed_bits;

    return 0;
}

static int golombset_encode(unsigned fixed_bits, uint64_t *keys, size_t num_keys, void *buf, size_t *bufsize)
{
    struct st_golombset_encode_t ctx = {(unsigned char *)buf - 1, (unsigned char *)buf + *bufsize};
    size_t i;
    uint64_t next_min = 0;

    for (i = 0; i != num_keys; ++i) {
        if (golombset_encode_value(&ctx, fixed_bits, keys[i] - next_min) != 0)
            return -1;
        next_min = keys[i] + 1;
    }

    *bufsize = ctx.dst + 1 - (unsigned char *)buf;

    return 0;
}

static int golombset_decode(unsigned fixed_bits, const void *buf, size_t bufsize, uint64_t *keys, size_t *num_keys)
{
    struct st_golombset_decode_t ctx = {buf, (unsigned char *)buf + bufsize, 8};
    size_t index = 0;
    uint64_t next_min = 0;

    while (1) {
        uint64_t value;
        if (golombset_decode_value(&ctx, fixed_bits, &value) != 0)
            break;
        if (index == *num_keys) {
            /* not enough space */
            return -1;
        }
        value += next_min;
        keys[index++] = value;
        next_min = value + 1;
    }
    *num_keys = index;
    return 0;
}

#endif
