/* Copyright 2020, Kenneth MacKay. Licensed under the BSD 2-clause license. */

#include "uECC.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct {
  const char* private_key;
  const char* public_key;
  const char* k;
  const char* hash;
  const char* r;
  const char* s;
} Test;

Test secp256k1_tests[] = {
    {
        "ebb2c082fd7727890a28ac82f6bdf97bad8de9f5d7c9028692de1a255cad3e0f",
        "779dd197a5df977ed2cf6cb31d82d43328b790dc6b3b7d4437a427bd5847dfcde94b724a555b6d017bb7607c3e3281daf5b1699d6ef4124975c9237b917d426f",
        "49a0d7b786ec9cde0d0721d72804befd06571c974b191efb42ecf322ba9ddd9a",
        "4b688df40bcedbe641ddb16ff0a1842d9c67ea1c3bf63f3e0471baa664531d1a",
        "241097efbf8b63bf145c8961dbdf10c310efbb3b2676bbc0f8b08505c9e2f795",
        "021006b7838609339e8b415a7f9acb1b661828131aef1ecbc7955dfb01f3ca0e"
    },
};

extern int uECC_sign_with_k(const uint8_t *private_key,
                            const uint8_t *message_hash,
                            unsigned hash_size,
                            const uint8_t *k,
                            uint8_t *signature,
                            uECC_Curve curve);


void vli_print(uint8_t *vli, unsigned int size) {
    for(unsigned i=0; i<size; ++i) {
        printf("%02X ", (unsigned)vli[i]);
    }
    printf("\n");
}

void strtobytes(const char* str, uint8_t* bytes, int count) {
  for (int c = 0; c < count; ++c) {
    if (sscanf(str, "%2hhx", &bytes[c]) != 1) {
      printf("Failed to read string to bytes");
      exit(1);
    }
    str += 2;
  }
}

int run(Test* tests, int num_tests, uECC_Curve curve) {
    uint8_t private[32] = {0};
    uint8_t public[64] = {0};
    uint8_t k[32] = {0};
    uint8_t hash[32] = {0};
    uint8_t r[32] = {0};
    uint8_t s[32] = {0};

    uint8_t signature[64] = {0};

    int result;
    int i;
    int private_key_size;
    int public_key_size;
    int all_success = 1;

    private_key_size = uECC_curve_private_key_size(curve);
    public_key_size = uECC_curve_public_key_size(curve);

    for (i = 0; i < num_tests; ++i) {
        strtobytes(tests[i].private_key, private, private_key_size);
        strtobytes(tests[i].public_key, public, public_key_size);
        strtobytes(tests[i].k, k, private_key_size);
        strtobytes(tests[i].hash, hash, private_key_size);
        strtobytes(tests[i].r, r, private_key_size);
        strtobytes(tests[i].s, s, private_key_size);

        result = uECC_sign_with_k(private, hash, private_key_size, k, signature, curve);
        if (!result) {
            all_success = 0;
            printf("  Sign failed for test %d\n", i);
        }
        if (result) {
            if (memcmp(signature, r, private_key_size) != 0) {
                all_success = 0;
                printf("  Got incorrect r for test %d\n", i);
                printf("    Expected: ");
                vli_print(r, private_key_size);
                printf("    Calculated: ");
                vli_print(signature, private_key_size);
            }
            if (memcmp(signature + private_key_size, s, private_key_size) != 0) {
                all_success = 0;
                printf("  Got incorrect s for test %d\n", i);
                printf("    Expected: ");
                vli_print(s, private_key_size);
                printf("    Calculated: ");
                vli_print(signature + private_key_size, private_key_size);
            }

            result = uECC_verify(public, hash, private_key_size, signature, curve);
            if (!result) {
                printf("  Verify failed for test %d\n", i);
            }
        }
    }

    return all_success;
}

#define RUN_TESTS(curve) \
    printf(#curve ":\n"); \
    if (run(curve##_tests, sizeof(curve##_tests) / sizeof(curve##_tests[0]), uECC_##curve()) ) { \
        printf("  All passed\n"); \
    } else { \
        printf("  Failed\n"); \
    }

int main() {
#if uECC_SUPPORTS_secp256k1
    RUN_TESTS(secp256k1)
#endif

    return 0;
}
