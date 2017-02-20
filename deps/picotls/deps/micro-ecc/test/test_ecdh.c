/* Copyright 2014, Kenneth MacKay. Licensed under the BSD 2-clause license. */

#include "uECC.h"

#include <stdio.h>
#include <string.h>

void vli_print(uint8_t *vli, unsigned int size) {
    for(unsigned i=0; i<size; ++i) {
        printf("%02X ", (unsigned)vli[i]);
    }
}

int main() {
    int i, c;
    uint8_t private1[32] = {0};
    uint8_t private2[32] = {0};
    uint8_t public1[64] = {0};
    uint8_t public2[64] = {0};
    uint8_t secret1[32] = {0};
    uint8_t secret2[32] = {0};
    
    const struct uECC_Curve_t * curves[5];
    int num_curves = 0;
#if uECC_SUPPORTS_secp160r1
    curves[num_curves++] = uECC_secp160r1();
#endif
#if uECC_SUPPORTS_secp192r1
    curves[num_curves++] = uECC_secp192r1();
#endif
#if uECC_SUPPORTS_secp224r1
    curves[num_curves++] = uECC_secp224r1();
#endif
#if uECC_SUPPORTS_secp256r1
    curves[num_curves++] = uECC_secp256r1();
#endif
#if uECC_SUPPORTS_secp256k1
    curves[num_curves++] = uECC_secp256k1();
#endif
    
    printf("Testing 256 random private key pairs\n");

    for (c = 0; c < num_curves; ++c) {
        for (i = 0; i < 256; ++i) {
            printf(".");
            fflush(stdout);

            if (!uECC_make_key(public1, private1, curves[c]) ||
                !uECC_make_key(public2, private2, curves[c])) {
                printf("uECC_make_key() failed\n");
                return 1;
            }

            if (!uECC_shared_secret(public2, private1, secret1, curves[c])) {
                printf("shared_secret() failed (1)\n");
                return 1;
            }

            if (!uECC_shared_secret(public1, private2, secret2, curves[c])) {
                printf("shared_secret() failed (2)\n");
                return 1;
            }
        
            if (memcmp(secret1, secret2, sizeof(secret1)) != 0) {
                printf("Shared secrets are not identical!\n");
                printf("Private key 1 = ");
                vli_print(private1, 32);
                printf("\n");
                printf("Private key 2 = ");
                vli_print(private2, 32);
                printf("\n");
                printf("Public key 1 = ");
                vli_print(public1, 64);
                printf("\n");
                printf("Public key 2 = ");
                vli_print(public2, 64);
                printf("\n");
                printf("Shared secret 1 = ");
                vli_print(secret1, 32);
                printf("\n");
                printf("Shared secret 2 = ");
                vli_print(secret2, 32);
                printf("\n");
            }
        }
        printf("\n");
    }
    
    return 0;
}
