#ifndef __siphash_h__
#define __siphash_h__
#endif

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <ctype.h>

int siphash(const uint8_t *in, const size_t inlen, const uint8_t *k,
            uint8_t *out, const size_t outlen);
#ifdef __cplusplus
}
#endif
