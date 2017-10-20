/* Copyright 2014, Kenneth MacKay. Licensed under the BSD 2-clause license. */

#include "uECC.h"

#include <stdio.h>
#include <string.h>

void vli_print(char *str, uint8_t *vli, unsigned int size) {
    printf("%s ", str);
    for(unsigned i=0; i<size; ++i) {
        printf("%02X ", (unsigned)vli[i]);
    }
    printf("\n");
}

int main() {
    int i;
    int success;
    uint8_t private[32];
    uint8_t public[64];
    uint8_t public_computed[64];
    
    int c;
    
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
            
            memset(public, 0, sizeof(public));
            memset(public_computed, 0, sizeof(public_computed));
            
            if (!uECC_make_key(public, private, curves[c])) {
                printf("uECC_make_key() failed\n");
                continue;
            }

            if (!uECC_compute_public_key(private, public_computed, curves[c])) {
                printf("uECC_compute_public_key() failed\n");
            }

            if (memcmp(public, public_computed, sizeof(public)) != 0) {
                printf("Computed and provided public keys are not identical!\n");
                vli_print("Computed public key = ", public_computed, sizeof(public_computed));
                vli_print("Provided public key = ", public, sizeof(public));
                vli_print("Private key = ", private, sizeof(private));
            }
        }
        
        printf("\n");
        printf("Testing private key = 0\n");

        memset(private, 0, sizeof(private));
        success = uECC_compute_public_key(private, public_computed, curves[c]);
        if (success) {
            printf("uECC_compute_public_key() should have failed\n");
        }
        printf("\n");
    }
    
    return 0;
}
