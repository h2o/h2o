/*
 * Copyright (c) 2016-2019 DeNA Co., Ltd., Kazuho Oku, Christian Huitema
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
#ifndef _XOPEN_SOURCE
#define _XOPEN_SOURCE 700 /* required for glibc to use getaddrinfo, etc. */
#endif
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#ifdef _WINDOWS
#include "wincompat.h"
#else
#include <unistd.h>
#endif
#include "drbg.h"
#include "picotls.h"
#include "picotls/minicrypto.h"
#include <stdio.h>
#ifdef _WINDOWS
#ifdef _WINDOWS_XP
 /* The modern BCrypt API is only available on Windows Vista and later versions.
  * If compiling on Windows XP, we need to use the olded "wincrypt" API */
#include <wincrypt.h>

static void read_entropy(uint8_t *entropy, size_t size)
{
    HCRYPTPROV hCryptProv = 0;
    BOOL ret = FALSE;

    if (CryptAcquireContext(&hCryptProv, NULL, NULL, PROV_RSA_FULL, 0)) {
        ret = CryptGenRandom(hCryptProv, (DWORD)size, entropy);
        (void)CryptReleaseContext(hCryptProv, 0);
    }

    if (ret == FALSE) {
        perror("ptls_minicrypto_random_bytes: could not use CryptGenRandom");
        abort();
    }
}
#else
 /* The old "Wincrypt" API requires access to default security containers.
  * This can cause access control errors on some systems. We prefer
  * to use the modern BCrypt API when available */
#include <bcrypt.h>

 static void read_entropy(uint8_t *entropy, size_t size)
 {
    NTSTATUS nts = 0;
    BCRYPT_ALG_HANDLE hAlgorithm = 0;

    nts = BCryptOpenAlgorithmProvider(&hAlgorithm, BCRYPT_RNG_ALGORITHM, NULL, 0);

    if (BCRYPT_SUCCESS(nts)) {
        nts = BCryptGenRandom(hAlgorithm, (PUCHAR)entropy, (ULONG)size, 0);

        (void)BCryptCloseAlgorithmProvider(hAlgorithm, 0);
    }

    if (!BCRYPT_SUCCESS(nts)) {
        perror("ptls_minicrypto_random_bytes: could not open BCrypt RNG Algorithm");
        abort();
    }
}
#endif
#else
static void read_entropy(uint8_t *entropy, size_t size)
{
    int fd;

    if ((fd = open("/dev/urandom", O_RDONLY | O_CLOEXEC)) == -1) {
        if ((fd = open("/dev/random", O_RDONLY | O_CLOEXEC)) == -1) {
            perror("ptls_minicrypto_random_bytes: could not open neither /dev/random or /dev/urandom");
            abort();
        }
    }

    while (size != 0) {
        ssize_t rret;
        while ((rret = read(fd, entropy, size)) == -1 && errno == EINTR)
            ;
        if (rret < 0) {
            perror("ptls_minicrypto_random_bytes");
            abort();
        }
        entropy += rret;
        size -= rret;
    }

    close(fd);
}
#endif

void ptls_minicrypto_random_bytes(void *buf, size_t len)
{
    static PTLS_THREADLOCAL cf_hash_drbg_sha256 ctx;

    if (cf_hash_drbg_sha256_needs_reseed(&ctx)) {
        uint8_t entropy[256];
        read_entropy(entropy, sizeof(entropy));
        cf_hash_drbg_sha256_init(&ctx, entropy, sizeof(entropy) / 2, entropy + sizeof(entropy) / 2, sizeof(entropy) / 2, "ptls", 4);
    }
    cf_hash_drbg_sha256_gen(&ctx, buf, len);
}
