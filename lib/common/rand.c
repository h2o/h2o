/*
 * Copyright (c) 2021 Goro Fuji, Fastly, Inc.
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

#include <openssl/rand.h>
#include <inttypes.h>
#include "h2o/rand.h"
#include "h2o/string_.h"
#include "picotls/openssl.h"

static void format_uuid_rfc4122(char *dst, uint8_t *octets, uint8_t version)
{
    // Variant:
    // > Set the two most significant bits (bits 6 and 7) of the
    // > clock_seq_hi_and_reserved to zero and one, respectively.
    octets[8] = (octets[8] & 0x3f) | 0x80;
    // Version:
    // > Set the four most significant bits (bits 12 through 15) of the
    // > time_hi_and_version field to the 4-bit version number from
    // > Section 4.1.3.
    octets[6] = (octets[6] & 0x0f) | (version << 4);

    // String Representation:
    // > UUID  = time-low "-" time-mid "-"
    // >         time-high-and-version "-"
    // >         clock-seq-and-reserved
    // >         clock-seq-low "-" node
    // See also "4.1.2. Layout and Byte Order" for the layout
    size_t pos = 0;

#define UUID_ENC_PART(first, last)                                                                                                 \
    do {                                                                                                                           \
        h2o_hex_encode(&dst[pos], &octets[first], last - first + 1);                                                               \
        pos += (last - first + 1) * 2;                                                                                             \
    } while (0)

    UUID_ENC_PART(0, 3); /* time_low */
    dst[pos++] = '-';
    UUID_ENC_PART(4, 5); /* time_mid */
    dst[pos++] = '-';
    UUID_ENC_PART(6, 7); /* time_hi_and_version */
    dst[pos++] = '-';
    UUID_ENC_PART(8, 8); /* clock_seq_hi_and_reserved */
    UUID_ENC_PART(9, 9); /* clock_seq_low */
    dst[pos++] = '-';
    UUID_ENC_PART(10, 15); /* node */

#undef UUID_ENC_PART

    /* '\0' is set by h2o_hex_encode() */
}

void h2o_generate_uuidv4(char *dst)
{
    // RFC-4122 "A Universally Unique IDentifier (UUID) URN Namespace"
    // 4.4. Algorithms for Creating a UUID from Truly Random or Pseudo-Random Numbers

    uint8_t octets[16];
    ptls_openssl_random_bytes((void *)&octets, sizeof(octets));
    format_uuid_rfc4122(dst, octets, 4);
}
