/*
   SipHash reference C implementation
   Copyright (c) 2012-2016 Jean-Philippe Aumasson
   <jeanphilippe.aumasson@gmail.com>
   Copyright (c) 2012 Daniel J. Bernstein <djb@cr.yp.to>
   To the extent possible under law, the author(s) have dedicated all copyright
   and related and neighboring rights to this software to the public domain
   worldwide. This software is distributed without any warranty.
   You should have received a copy of the CC0 Public Domain Dedication along
   with
   this software. If not, see
   <http://creativecommons.org/publicdomain/zero/1.0/>.
 */

#include "vectors.h"
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#define PRINTHASH(n)                                                           \
    printf("    { ");                                                          \
    for (int j = 0; j < n; ++j) {                                              \
        printf("0x%02x, ", out[j]);                                            \
    }                                                                          \
    printf("},\n");

int siphash(const uint8_t *in, const size_t inlen, const uint8_t *k,
            uint8_t *out, const size_t outlen);
int halfsiphash(const uint8_t *in, const size_t inlen, const uint8_t *k,
                uint8_t *out, const size_t outlen);

const char *functions[4] = {
    "const uint8_t vectors_sip64[64][8] =",
    "const uint8_t vectors_sip128[64][16] =",
    "const uint8_t vectors_hsip32[64][4] =",
    "const uint8_t vectors_hsip64[64][8] =",
};

const char *labels[4] = {
    "SipHash 64-bit tag:", "SipHash 128-bit tag:", "HalfSipHash 32-bit tag:",
    "HalfSipHash 64-bit tag:",
};

size_t lengths[4] = {8, 16, 4, 8};

int main() {
    uint8_t in[64], out[16], k[16];
    int i;
    int fails = 0;

    for (i = 0; i < 16; ++i)
        k[i] = i;

    for (int version = 0; version < 4; ++version) {
#ifdef GETVECTORS
        printf("%s\n{\n", functions[version]);
#else
        printf("%s\n", labels[version]);
#endif

        for (i = 0; i < 64; ++i) {
            in[i] = i;
            int len = lengths[version];
            if (version < 2)
                siphash(in, i, k, out, len);
            else
                halfsiphash(in, i, k, out, len);
#ifdef GETVECTORS
            PRINTHASH(len);
#else
            const uint8_t *v = NULL;
            switch (version) {
            case 0:
                v = (uint8_t *)vectors_sip64;
                break;
            case 1:
                v = (uint8_t *)vectors_sip128;
                break;
            case 2:
                v = (uint8_t *)vectors_hsip32;
                break;
            case 3:
                v = (uint8_t *)vectors_hsip64;
                break;
            default:
                break;
            }

            if (memcmp(out, v + (i * len), len)) {
                printf("fail for %d bytes\n", i);
                fails++;
            }
#endif
        }

#ifdef GETVECTORS
        printf("};\n");
#else
        if (!fails)
            printf("OK\n");
#endif
        fails = 0;
    }

    return 0;
}
