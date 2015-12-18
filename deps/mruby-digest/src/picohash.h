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
 *
 *
 * The MD5 implementation is based on the reference implementation found in RFC
 * 1321, provided under the following license:
 *
 * Copyright (C) 1991-2, RSA Data Security, Inc. Created 1991. All
 * rights reserved.
 *
 * License to copy and use this software is granted provided that it
 * is identified as the "RSA Data Security, Inc. MD5 Message-Digest
 * Algorithm" in all material mentioning or referencing this software
 * or this function.
 *
 * License is also granted to make and use derivative works provided
 * that such works are identified as "derived from the RSA Data
 * Security, Inc. MD5 Message-Digest Algorithm" in all material
 * mentioning or referencing the derived work.
 *
 * RSA Data Security, Inc. makes no representations concerning either
 * the merchantability of this software or the suitability of this
 * software for any particular purpose. It is provided "as is"
 * without express or implied warranty of any kind.
 *
 * These notices must be retained in any copies of any part of this
 * documentation and/or software.
 *
 *
 * The SHA1 implementation is based on the reference implementation found in RFC
 * 6234, provided under the following license:
 *
 * Copyright (c) 2011 IETF Trust and the persons identified as
 * authors of the code.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or
 * without modification, are permitted provided that the following
 * conditions are met:
 *
 * - Redistributions of source code must retain the above
 *   copyright notice, this list of conditions and
 *   the following disclaimer.
 *
 * - Redistributions in binary form must reproduce the above
 *   copyright notice, this list of conditions and the following
 *   disclaimer in the documentation and/or other materials provided
 *   with the distribution.
 *
 * - Neither the name of Internet Society, IETF or IETF Trust, nor
 *   the names of specific contributors, may be used to endorse or
 *   promote products derived from this software without specific
 *   prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND
 * CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES,
 * INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED.  IN NO EVENT SHALL THE COPYRIGHT OWNER OR
 * CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
 * OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE,
 * EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/

#ifndef _picohash_h_
#define _picohash_h_

#include <assert.h>
#include <inttypes.h>
#include <string.h>

#define PICOHASH_MD5_BLOCK_LENGTH 64
#define PICOHASH_MD5_DIGEST_LENGTH 16

typedef struct {
    uint32_t state[4];
    uint32_t count[2];
    unsigned char buffer[64];
} _picohash_md5_ctx_t;

static void _picohash_md5_init(_picohash_md5_ctx_t *ctx);
static void _picohash_md5_update(_picohash_md5_ctx_t *ctx, const void *input, size_t len);
static void _picohash_md5_final(_picohash_md5_ctx_t *ctx, void *digest);

#define PICOHASH_SHA1_BLOCK_LENGTH 64
#define PICOHASH_SHA1_DIGEST_LENGTH 20

typedef struct {
    uint32_t Intermediate_Hash[PICOHASH_SHA1_DIGEST_LENGTH / 4];
    uint32_t Length_Low;
    uint32_t Length_High;
    int_least16_t Message_Block_Index;
    uint8_t Message_Block[64];
} _picohash_sha1_ctx_t;

static void _picohash_sha1_init(_picohash_sha1_ctx_t *ctx);
static void _picohash_sha1_update(_picohash_sha1_ctx_t *ctx, const void *input, size_t len);
static void _picohash_sha1_final(_picohash_sha1_ctx_t *ctx, void *digest);

#define PICOHASH_MAX_BLOCK_LENGTH 64
#define PICOHASH_MAX_DIGEST_LENGTH 20

typedef struct {
    union {
        _picohash_md5_ctx_t _md5;
        _picohash_sha1_ctx_t _sha1;
    };
    size_t block_length;
    size_t digest_length;
    void (*_reset)(void *ctx);
    void (*_update)(void *ctx, const void *input, size_t len);
    void (*_final)(void *ctx, void *digest);
    struct {
        unsigned char key[PICOHASH_MAX_BLOCK_LENGTH];
        void (*hash_reset)(void *ctx);
        void (*hash_final)(void *ctx, void *digest);
    } _hmac;
} picohash_ctx_t;

static void picohash_init_md5(picohash_ctx_t *ctx);
static void picohash_init_sha1(picohash_ctx_t *ctx);
static void picohash_update(picohash_ctx_t *ctx, const void *input, size_t len);
static void picohash_final(picohash_ctx_t *ctx, void *digest);
static void picohash_reset(picohash_ctx_t *ctx);

static void picohash_init_hmac(picohash_ctx_t *ctx, void (*initf)(picohash_ctx_t *), const void *key, size_t key_len);

/* following are private definitions */

/* Encodes input (uint32_t) into output (unsigned char). Assumes len is
  a multiple of 4.
 */
static inline void _picohash_md5_encode(unsigned char *output, const uint32_t *input, unsigned int len)
{
    unsigned int i, j;

    for (i = 0, j = 0; j < len; i++, j += 4) {
        output[j] = (unsigned char)(input[i] & 0xff);
        output[j + 1] = (unsigned char)((input[i] >> 8) & 0xff);
        output[j + 2] = (unsigned char)((input[i] >> 16) & 0xff);
        output[j + 3] = (unsigned char)((input[i] >> 24) & 0xff);
    }
}

/* Decodes input (unsigned char) into output (uint32_t). Assumes len is
  a multiple of 4.
 */
static inline void _picohash_md5_decode(uint32_t *output, const unsigned char *input, unsigned int len)
{
    unsigned int i, j;

    for (i = 0, j = 0; j < len; i++, j += 4)
        output[i] = ((uint32_t)input[j]) | (((uint32_t)input[j + 1]) << 8) | (((uint32_t)input[j + 2]) << 16) |
                    (((uint32_t)input[j + 3]) << 24);
}

/* MD5 basic transformation. Transforms state based on block.
 */
static inline void _picohash_md5_transform(uint32_t state[4], const unsigned char block[64])
{
#define _PICOHASH_MD5_S11 7
#define _PICOHASH_MD5_S12 12
#define _PICOHASH_MD5_S13 17
#define _PICOHASH_MD5_S14 22
#define _PICOHASH_MD5_S21 5
#define _PICOHASH_MD5_S22 9
#define _PICOHASH_MD5_S23 14
#define _PICOHASH_MD5_S24 20
#define _PICOHASH_MD5_S31 4
#define _PICOHASH_MD5_S32 11
#define _PICOHASH_MD5_S33 16
#define _PICOHASH_MD5_S34 23
#define _PICOHASH_MD5_S41 6
#define _PICOHASH_MD5_S42 10
#define _PICOHASH_MD5_S43 15
#define _PICOHASH_MD5_S44 21

/* F, G, H and I are basic MD5 functions.
 */
#define _PICOHASH_MD5_F(x, y, z) (((x) & (y)) | ((~x) & (z)))
#define _PICOHASH_MD5_G(x, y, z) (((x) & (z)) | ((y) & (~z)))
#define _PICOHASH_MD5_H(x, y, z) ((x) ^ (y) ^ (z))
#define _PICOHASH_MD5_I(x, y, z) ((y) ^ ((x) | (~z)))

/* ROTATE_LEFT rotates x left n bits.
 */
#define _PICOHASH_MD5_ROTATE_LEFT(x, n) (((x) << (n)) | ((x) >> (32 - (n))))

/* FF, GG, HH, and II transformations for rounds 1, 2, 3, and 4.
Rotation is separate from addition to prevent recomputation.
 */
#define _PICOHASH_MD5_FF(a, b, c, d, x, s, ac)                                                                                     \
    {                                                                                                                              \
        (a) += _PICOHASH_MD5_F((b), (c), (d)) + (x) + (uint32_t)(ac);                                                              \
        (a) = _PICOHASH_MD5_ROTATE_LEFT((a), (s));                                                                                 \
        (a) += (b);                                                                                                                \
    }
#define _PICOHASH_MD5_GG(a, b, c, d, x, s, ac)                                                                                     \
    {                                                                                                                              \
        (a) += _PICOHASH_MD5_G((b), (c), (d)) + (x) + (uint32_t)(ac);                                                              \
        (a) = _PICOHASH_MD5_ROTATE_LEFT((a), (s));                                                                                 \
        (a) += (b);                                                                                                                \
    }
#define _PICOHASH_MD5_HH(a, b, c, d, x, s, ac)                                                                                     \
    {                                                                                                                              \
        (a) += _PICOHASH_MD5_H((b), (c), (d)) + (x) + (uint32_t)(ac);                                                              \
        (a) = _PICOHASH_MD5_ROTATE_LEFT((a), (s));                                                                                 \
        (a) += (b);                                                                                                                \
    }
#define _PICOHASH_MD5_II(a, b, c, d, x, s, ac)                                                                                     \
    {                                                                                                                              \
        (a) += _PICOHASH_MD5_I((b), (c), (d)) + (x) + (uint32_t)(ac);                                                              \
        (a) = _PICOHASH_MD5_ROTATE_LEFT((a), (s));                                                                                 \
        (a) += (b);                                                                                                                \
    }

    uint32_t a = state[0], b = state[1], c = state[2], d = state[3], x[16];

    _picohash_md5_decode(x, block, 64);

    /* Round 1 */
    _PICOHASH_MD5_FF(a, b, c, d, x[0], _PICOHASH_MD5_S11, 0xd76aa478);  /* 1 */
    _PICOHASH_MD5_FF(d, a, b, c, x[1], _PICOHASH_MD5_S12, 0xe8c7b756);  /* 2 */
    _PICOHASH_MD5_FF(c, d, a, b, x[2], _PICOHASH_MD5_S13, 0x242070db);  /* 3 */
    _PICOHASH_MD5_FF(b, c, d, a, x[3], _PICOHASH_MD5_S14, 0xc1bdceee);  /* 4 */
    _PICOHASH_MD5_FF(a, b, c, d, x[4], _PICOHASH_MD5_S11, 0xf57c0faf);  /* 5 */
    _PICOHASH_MD5_FF(d, a, b, c, x[5], _PICOHASH_MD5_S12, 0x4787c62a);  /* 6 */
    _PICOHASH_MD5_FF(c, d, a, b, x[6], _PICOHASH_MD5_S13, 0xa8304613);  /* 7 */
    _PICOHASH_MD5_FF(b, c, d, a, x[7], _PICOHASH_MD5_S14, 0xfd469501);  /* 8 */
    _PICOHASH_MD5_FF(a, b, c, d, x[8], _PICOHASH_MD5_S11, 0x698098d8);  /* 9 */
    _PICOHASH_MD5_FF(d, a, b, c, x[9], _PICOHASH_MD5_S12, 0x8b44f7af);  /* 10 */
    _PICOHASH_MD5_FF(c, d, a, b, x[10], _PICOHASH_MD5_S13, 0xffff5bb1); /* 11 */
    _PICOHASH_MD5_FF(b, c, d, a, x[11], _PICOHASH_MD5_S14, 0x895cd7be); /* 12 */
    _PICOHASH_MD5_FF(a, b, c, d, x[12], _PICOHASH_MD5_S11, 0x6b901122); /* 13 */
    _PICOHASH_MD5_FF(d, a, b, c, x[13], _PICOHASH_MD5_S12, 0xfd987193); /* 14 */
    _PICOHASH_MD5_FF(c, d, a, b, x[14], _PICOHASH_MD5_S13, 0xa679438e); /* 15 */
    _PICOHASH_MD5_FF(b, c, d, a, x[15], _PICOHASH_MD5_S14, 0x49b40821); /* 16 */

    /* Round 2 */
    _PICOHASH_MD5_GG(a, b, c, d, x[1], _PICOHASH_MD5_S21, 0xf61e2562);  /* 17 */
    _PICOHASH_MD5_GG(d, a, b, c, x[6], _PICOHASH_MD5_S22, 0xc040b340);  /* 18 */
    _PICOHASH_MD5_GG(c, d, a, b, x[11], _PICOHASH_MD5_S23, 0x265e5a51); /* 19 */
    _PICOHASH_MD5_GG(b, c, d, a, x[0], _PICOHASH_MD5_S24, 0xe9b6c7aa);  /* 20 */
    _PICOHASH_MD5_GG(a, b, c, d, x[5], _PICOHASH_MD5_S21, 0xd62f105d);  /* 21 */
    _PICOHASH_MD5_GG(d, a, b, c, x[10], _PICOHASH_MD5_S22, 0x2441453);  /* 22 */
    _PICOHASH_MD5_GG(c, d, a, b, x[15], _PICOHASH_MD5_S23, 0xd8a1e681); /* 23 */
    _PICOHASH_MD5_GG(b, c, d, a, x[4], _PICOHASH_MD5_S24, 0xe7d3fbc8);  /* 24 */
    _PICOHASH_MD5_GG(a, b, c, d, x[9], _PICOHASH_MD5_S21, 0x21e1cde6);  /* 25 */
    _PICOHASH_MD5_GG(d, a, b, c, x[14], _PICOHASH_MD5_S22, 0xc33707d6); /* 26 */
    _PICOHASH_MD5_GG(c, d, a, b, x[3], _PICOHASH_MD5_S23, 0xf4d50d87);  /* 27 */
    _PICOHASH_MD5_GG(b, c, d, a, x[8], _PICOHASH_MD5_S24, 0x455a14ed);  /* 28 */
    _PICOHASH_MD5_GG(a, b, c, d, x[13], _PICOHASH_MD5_S21, 0xa9e3e905); /* 29 */
    _PICOHASH_MD5_GG(d, a, b, c, x[2], _PICOHASH_MD5_S22, 0xfcefa3f8);  /* 30 */
    _PICOHASH_MD5_GG(c, d, a, b, x[7], _PICOHASH_MD5_S23, 0x676f02d9);  /* 31 */
    _PICOHASH_MD5_GG(b, c, d, a, x[12], _PICOHASH_MD5_S24, 0x8d2a4c8a); /* 32 */

    /* Round 3 */
    _PICOHASH_MD5_HH(a, b, c, d, x[5], _PICOHASH_MD5_S31, 0xfffa3942);  /* 33 */
    _PICOHASH_MD5_HH(d, a, b, c, x[8], _PICOHASH_MD5_S32, 0x8771f681);  /* 34 */
    _PICOHASH_MD5_HH(c, d, a, b, x[11], _PICOHASH_MD5_S33, 0x6d9d6122); /* 35 */
    _PICOHASH_MD5_HH(b, c, d, a, x[14], _PICOHASH_MD5_S34, 0xfde5380c); /* 36 */
    _PICOHASH_MD5_HH(a, b, c, d, x[1], _PICOHASH_MD5_S31, 0xa4beea44);  /* 37 */
    _PICOHASH_MD5_HH(d, a, b, c, x[4], _PICOHASH_MD5_S32, 0x4bdecfa9);  /* 38 */
    _PICOHASH_MD5_HH(c, d, a, b, x[7], _PICOHASH_MD5_S33, 0xf6bb4b60);  /* 39 */
    _PICOHASH_MD5_HH(b, c, d, a, x[10], _PICOHASH_MD5_S34, 0xbebfbc70); /* 40 */
    _PICOHASH_MD5_HH(a, b, c, d, x[13], _PICOHASH_MD5_S31, 0x289b7ec6); /* 41 */
    _PICOHASH_MD5_HH(d, a, b, c, x[0], _PICOHASH_MD5_S32, 0xeaa127fa);  /* 42 */
    _PICOHASH_MD5_HH(c, d, a, b, x[3], _PICOHASH_MD5_S33, 0xd4ef3085);  /* 43 */
    _PICOHASH_MD5_HH(b, c, d, a, x[6], _PICOHASH_MD5_S34, 0x4881d05);   /* 44 */
    _PICOHASH_MD5_HH(a, b, c, d, x[9], _PICOHASH_MD5_S31, 0xd9d4d039);  /* 45 */
    _PICOHASH_MD5_HH(d, a, b, c, x[12], _PICOHASH_MD5_S32, 0xe6db99e5); /* 46 */
    _PICOHASH_MD5_HH(c, d, a, b, x[15], _PICOHASH_MD5_S33, 0x1fa27cf8); /* 47 */
    _PICOHASH_MD5_HH(b, c, d, a, x[2], _PICOHASH_MD5_S34, 0xc4ac5665);  /* 48 */

    /* Round 4 */
    _PICOHASH_MD5_II(a, b, c, d, x[0], _PICOHASH_MD5_S41, 0xf4292244);  /* 49 */
    _PICOHASH_MD5_II(d, a, b, c, x[7], _PICOHASH_MD5_S42, 0x432aff97);  /* 50 */
    _PICOHASH_MD5_II(c, d, a, b, x[14], _PICOHASH_MD5_S43, 0xab9423a7); /* 51 */
    _PICOHASH_MD5_II(b, c, d, a, x[5], _PICOHASH_MD5_S44, 0xfc93a039);  /* 52 */
    _PICOHASH_MD5_II(a, b, c, d, x[12], _PICOHASH_MD5_S41, 0x655b59c3); /* 53 */
    _PICOHASH_MD5_II(d, a, b, c, x[3], _PICOHASH_MD5_S42, 0x8f0ccc92);  /* 54 */
    _PICOHASH_MD5_II(c, d, a, b, x[10], _PICOHASH_MD5_S43, 0xffeff47d); /* 55 */
    _PICOHASH_MD5_II(b, c, d, a, x[1], _PICOHASH_MD5_S44, 0x85845dd1);  /* 56 */
    _PICOHASH_MD5_II(a, b, c, d, x[8], _PICOHASH_MD5_S41, 0x6fa87e4f);  /* 57 */
    _PICOHASH_MD5_II(d, a, b, c, x[15], _PICOHASH_MD5_S42, 0xfe2ce6e0); /* 58 */
    _PICOHASH_MD5_II(c, d, a, b, x[6], _PICOHASH_MD5_S43, 0xa3014314);  /* 59 */
    _PICOHASH_MD5_II(b, c, d, a, x[13], _PICOHASH_MD5_S44, 0x4e0811a1); /* 60 */
    _PICOHASH_MD5_II(a, b, c, d, x[4], _PICOHASH_MD5_S41, 0xf7537e82);  /* 61 */
    _PICOHASH_MD5_II(d, a, b, c, x[11], _PICOHASH_MD5_S42, 0xbd3af235); /* 62 */
    _PICOHASH_MD5_II(c, d, a, b, x[2], _PICOHASH_MD5_S43, 0x2ad7d2bb);  /* 63 */
    _PICOHASH_MD5_II(b, c, d, a, x[9], _PICOHASH_MD5_S44, 0xeb86d391);  /* 64 */

    state[0] += a;
    state[1] += b;
    state[2] += c;
    state[3] += d;

    /* Zeroize sensitive information. */
    memset(x, 0, sizeof(x));

#undef _PICOHASH_MD5_S11
#undef _PICOHASH_MD5_S12
#undef _PICOHASH_MD5_S13
#undef _PICOHASH_MD5_S14
#undef _PICOHASH_MD5_S21
#undef _PICOHASH_MD5_S22
#undef _PICOHASH_MD5_S23
#undef _PICOHASH_MD5_S24
#undef _PICOHASH_MD5_S31
#undef _PICOHASH_MD5_S32
#undef _PICOHASH_MD5_S33
#undef _PICOHASH_MD5_S34
#undef _PICOHASH_MD5_S41
#undef _PICOHASH_MD5_S42
#undef _PICOHASH_MD5_S43
#undef _PICOHASH_MD5_S44
#undef _PICOHASH_MD5_F
#undef _PICOHASH_MD5_G
#undef _PICOHASH_MD5_H
#undef _PICOHASH_MD5_I
#undef _PICOHASH_MD5_ROTATE_LEFT
#undef _PICOHASH_MD5_FF
#undef _PICOHASH_MD5_GG
#undef _PICOHASH_MD5_HH
#undef _PICOHASH_MD5_II
}

/* MD5 initialization. Begins an MD5 operation, writing a new context.
 */
inline void _picohash_md5_init(_picohash_md5_ctx_t *context)
{
    context->count[0] = context->count[1] = 0;
    /* Load magic initialization constants. */
    context->state[0] = 0x67452301;
    context->state[1] = 0xefcdab89;
    context->state[2] = 0x98badcfe;
    context->state[3] = 0x10325476;
}

/* MD5 block update operation. Continues an MD5 message-digest
  operation, processing another message block, and updating the
  context.
 */
inline void _picohash_md5_update(_picohash_md5_ctx_t *context, const void *_input, size_t inputLen)
{
    const unsigned char *input = _input;
    size_t i, index, partLen;

    /* Compute number of bytes mod 64 */
    index = (unsigned int)((context->count[0] >> 3) & 0x3F);

    /* Update number of bits */
    if ((context->count[0] += ((uint32_t)inputLen << 3)) < ((uint32_t)inputLen << 3))
        context->count[1]++;
    context->count[1] += ((uint32_t)inputLen >> 29);

    partLen = 64 - index;

    /* Transform as many times as possible. */
    if (inputLen >= partLen) {
        memcpy(&context->buffer[index], input, partLen);
        _picohash_md5_transform(context->state, context->buffer);

        for (i = partLen; i + 63 < inputLen; i += 64)
            _picohash_md5_transform(context->state, &input[i]);

        index = 0;
    } else
        i = 0;

    /* Buffer remaining input */
    memcpy(&context->buffer[index], &input[i], inputLen - i);
}

/* MD5 finalization. Ends an MD5 message-digest operation, writing the
  the message digest and zeroizing the context.
 */
inline void _picohash_md5_final(_picohash_md5_ctx_t *context, void *_digest)
{
    static const unsigned char PADDING[64] = {0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                                              0,    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                                              0,    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
    unsigned char bits[8], *digest = _digest;
    unsigned int index, padLen;

    /* Save number of bits */
    _picohash_md5_encode(bits, context->count, 8);

    /* Pad out to 56 mod 64. */
    index = (unsigned int)((context->count[0] >> 3) & 0x3f);
    padLen = (index < 56) ? (56 - index) : (120 - index);
    _picohash_md5_update(context, PADDING, padLen);

    /* Append length (before padding) */
    _picohash_md5_update(context, bits, 8);

    /* Store state in digest */
    _picohash_md5_encode(digest, context->state, 16);

    /* Zeroize sensitive information. */
    memset(context, 0, sizeof(*context));
}

static inline void _picohash_sha1_process_message_block(_picohash_sha1_ctx_t *context)
{
#define _PICOHASH_SHA1_Ch(x, y, z) (((x) & ((y) ^ (z))) ^ (z))
#define _PICOHASH_SHA1_Maj(x, y, z) (((x) & ((y) | (z))) | ((y) & (z)))
#define _PICOHASH_SHA1_Parity(x, y, z) ((x) ^ (y) ^ (z))
#define _PICOHASH_SHA1_ROTL(bits, word) (((word) << (bits)) | ((word) >> (32 - (bits))))

    /* Constants defined in FIPS 180-3, section 4.2.1 */
    const uint32_t K[4] = {0x5A827999, 0x6ED9EBA1, 0x8F1BBCDC, 0xCA62C1D6};
    int t;                  /* Loop counter */
    uint32_t temp;          /* Temporary word value */
    uint32_t W[80];         /* Word sequence */
    uint32_t A, B, C, D, E; /* Word buffers */

    /*
     * Initialize the first 16 words in the array W
     */
    for (t = 0; t < 16; t++) {
        W[t] = ((uint32_t)context->Message_Block[t * 4]) << 24;
        W[t] |= ((uint32_t)context->Message_Block[t * 4 + 1]) << 16;
        W[t] |= ((uint32_t)context->Message_Block[t * 4 + 2]) << 8;
        W[t] |= ((uint32_t)context->Message_Block[t * 4 + 3]);
    }

    for (t = 16; t < 80; t++)
        W[t] = _PICOHASH_SHA1_ROTL(1, W[t - 3] ^ W[t - 8] ^ W[t - 14] ^ W[t - 16]);

    A = context->Intermediate_Hash[0];
    B = context->Intermediate_Hash[1];
    C = context->Intermediate_Hash[2];
    D = context->Intermediate_Hash[3];
    E = context->Intermediate_Hash[4];

    for (t = 0; t < 20; t++) {
        temp = _PICOHASH_SHA1_ROTL(5, A) + _PICOHASH_SHA1_Ch(B, C, D) + E + W[t] + K[0];
        E = D;
        D = C;
        C = _PICOHASH_SHA1_ROTL(30, B);
        B = A;
        A = temp;
    }

    for (t = 20; t < 40; t++) {
        temp = _PICOHASH_SHA1_ROTL(5, A) + _PICOHASH_SHA1_Parity(B, C, D) + E + W[t] + K[1];
        E = D;
        D = C;
        C = _PICOHASH_SHA1_ROTL(30, B);
        B = A;
        A = temp;
    }

    for (t = 40; t < 60; t++) {
        temp = _PICOHASH_SHA1_ROTL(5, A) + _PICOHASH_SHA1_Maj(B, C, D) + E + W[t] + K[2];
        E = D;
        D = C;
        C = _PICOHASH_SHA1_ROTL(30, B);
        B = A;
        A = temp;
    }

    for (t = 60; t < 80; t++) {
        temp = _PICOHASH_SHA1_ROTL(5, A) + _PICOHASH_SHA1_Parity(B, C, D) + E + W[t] + K[3];
        E = D;
        D = C;
        C = _PICOHASH_SHA1_ROTL(30, B);
        B = A;
        A = temp;
    }

    context->Intermediate_Hash[0] += A;
    context->Intermediate_Hash[1] += B;
    context->Intermediate_Hash[2] += C;
    context->Intermediate_Hash[3] += D;
    context->Intermediate_Hash[4] += E;
    context->Message_Block_Index = 0;

#undef _PICOHASH_SHA1_Ch
#undef _PICOHASH_SHA1_Maj
#undef _PICOHASH_SHA1_Parity
#undef _PICOHASH_SHA1_ROTL
}

static inline void _picohash_sha1_pad_message(_picohash_sha1_ctx_t *context, uint8_t Pad_Byte)
{
    /*
     * Check to see if the current message block is too small to hold
     * the initial padding bits and length.  If so, we will pad the
     * block, process it, and then continue padding into a second
     * block.
     */
    if (context->Message_Block_Index >= (PICOHASH_SHA1_BLOCK_LENGTH - 8)) {
        context->Message_Block[context->Message_Block_Index++] = Pad_Byte;
        while (context->Message_Block_Index < PICOHASH_SHA1_BLOCK_LENGTH)
            context->Message_Block[context->Message_Block_Index++] = 0;

        _picohash_sha1_process_message_block(context);
    } else
        context->Message_Block[context->Message_Block_Index++] = Pad_Byte;

    while (context->Message_Block_Index < (PICOHASH_SHA1_BLOCK_LENGTH - 8))
        context->Message_Block[context->Message_Block_Index++] = 0;

    /*
     * Store the message length as the last 8 octets
     */
    context->Message_Block[56] = (uint8_t)(context->Length_High >> 24);
    context->Message_Block[57] = (uint8_t)(context->Length_High >> 16);
    context->Message_Block[58] = (uint8_t)(context->Length_High >> 8);
    context->Message_Block[59] = (uint8_t)(context->Length_High);
    context->Message_Block[60] = (uint8_t)(context->Length_Low >> 24);
    context->Message_Block[61] = (uint8_t)(context->Length_Low >> 16);
    context->Message_Block[62] = (uint8_t)(context->Length_Low >> 8);
    context->Message_Block[63] = (uint8_t)(context->Length_Low);

    _picohash_sha1_process_message_block(context);
}

static inline void _picohash_sha1_finalize(_picohash_sha1_ctx_t *context, uint8_t Pad_Byte)
{
    int i;
    _picohash_sha1_pad_message(context, Pad_Byte);
    /* message may be sensitive, clear it out */
    for (i = 0; i < PICOHASH_SHA1_BLOCK_LENGTH; ++i)
        context->Message_Block[i] = 0;
    context->Length_High = 0; /* and clear length */
    context->Length_Low = 0;
}

inline void _picohash_sha1_init(_picohash_sha1_ctx_t *context)
{
    context->Length_High = context->Length_Low = 0;
    context->Message_Block_Index = 0;

    /* Initial Hash Values: FIPS 180-3 section 5.3.1 */
    context->Intermediate_Hash[0] = 0x67452301;
    context->Intermediate_Hash[1] = 0xEFCDAB89;
    context->Intermediate_Hash[2] = 0x98BADCFE;
    context->Intermediate_Hash[3] = 0x10325476;
    context->Intermediate_Hash[4] = 0xC3D2E1F0;
}

inline void _picohash_sha1_update(_picohash_sha1_ctx_t *context, const void *_message_array, size_t length)
{
    const uint8_t *message_array = _message_array;
    uint32_t addTemp;

    while (length--) {
        context->Message_Block[context->Message_Block_Index++] = *message_array;
        addTemp = context->Length_Low;
        if ((context->Length_Low += 8) < addTemp)
            ++context->Length_High;
        if (context->Message_Block_Index == PICOHASH_SHA1_BLOCK_LENGTH)
            _picohash_sha1_process_message_block(context);

        message_array++;
    }
}

inline void _picohash_sha1_final(_picohash_sha1_ctx_t *context, void *_Message_Digest)
{
    unsigned char *Message_Digest = _Message_Digest;
    int i;

    _picohash_sha1_finalize(context, 0x80);

    for (i = 0; i < PICOHASH_SHA1_DIGEST_LENGTH; ++i)
        Message_Digest[i] = (uint8_t)(context->Intermediate_Hash[i >> 2] >> (8 * (3 - (i & 0x03))));
}

inline void picohash_init_md5(picohash_ctx_t *ctx)
{
    ctx->block_length = PICOHASH_MD5_BLOCK_LENGTH;
    ctx->digest_length = PICOHASH_MD5_DIGEST_LENGTH;
    ctx->_reset = (void *)_picohash_md5_init;
    ctx->_update = (void *)_picohash_md5_update;
    ctx->_final = (void *)_picohash_md5_final;

    _picohash_md5_init(&ctx->_md5);
}

inline void picohash_init_sha1(picohash_ctx_t *ctx)
{
    ctx->block_length = PICOHASH_SHA1_BLOCK_LENGTH;
    ctx->digest_length = PICOHASH_SHA1_DIGEST_LENGTH;
    ctx->_reset = (void *)_picohash_sha1_init;
    ctx->_update = (void *)_picohash_sha1_update;
    ctx->_final = (void *)_picohash_sha1_final;
    _picohash_sha1_init(&ctx->_sha1);
}

inline void picohash_update(picohash_ctx_t *ctx, const void *input, size_t len)
{
    ctx->_update(ctx, input, len);
}

inline void picohash_final(picohash_ctx_t *ctx, void *digest)
{
    ctx->_final(ctx, digest);
}

inline void picohash_reset(picohash_ctx_t *ctx)
{
    ctx->_reset(ctx);
}

static inline void _picohash_hmac_apply_key(picohash_ctx_t *ctx, unsigned char delta)
{
    size_t i;
    for (i = 0; i != ctx->block_length; ++i)
        ctx->_hmac.key[i] ^= delta;
    picohash_update(ctx, ctx->_hmac.key, ctx->block_length);
    for (i = 0; i != ctx->block_length; ++i)
        ctx->_hmac.key[i] ^= delta;
}

static void _picohash_hmac_final(picohash_ctx_t *ctx, void *digest)
{
    unsigned char inner_digest[PICOHASH_MAX_DIGEST_LENGTH];

    ctx->_hmac.hash_final(ctx, inner_digest);

    ctx->_hmac.hash_reset(ctx);
    _picohash_hmac_apply_key(ctx, 0x5c);
    picohash_update(ctx, inner_digest, ctx->digest_length);
    memset(inner_digest, 0, ctx->digest_length);

    ctx->_hmac.hash_final(ctx, digest);
}

static inline void _picohash_hmac_reset(picohash_ctx_t *ctx)
{
    ctx->_hmac.hash_reset(ctx);
    _picohash_hmac_apply_key(ctx, 0x36);
}

inline void picohash_init_hmac(picohash_ctx_t *ctx, void (*initf)(picohash_ctx_t *), const void *key, size_t key_len)
{
    initf(ctx);

    memset(ctx->_hmac.key, 0, ctx->block_length);
    if (key_len > ctx->block_length) {
        /* hash the key if it is too long */
        picohash_update(ctx, key, key_len);
        picohash_final(ctx, ctx->_hmac.key);
        ctx->_hmac.hash_reset(ctx);
    } else {
        memcpy(ctx->_hmac.key, key, key_len);
    }

    /* replace reset and final function */
    ctx->_hmac.hash_reset = ctx->_reset;
    ctx->_hmac.hash_final = ctx->_final;
    ctx->_reset = (void *)_picohash_hmac_reset;
    ctx->_final = (void *)_picohash_hmac_final;

    /* start calculating the inner hash */
    _picohash_hmac_apply_key(ctx, 0x36);
}

#endif
