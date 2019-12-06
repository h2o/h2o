/*
 * Copyright (c) 2016 DeNA Co., Ltd., Kazuho Oku
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

#ifdef _WINDOWS
#include "wincompat.h"
#else
#include <arpa/inet.h>
#include <sys/time.h>
#include <sys/utsname.h>
#include <time.h>
#endif
#include <assert.h>
#include <string.h>
#include <stdio.h>
#include "picotls.h"
#include "picotls/ffx.h"
#include "picotls/minicrypto.h"
#include "picotls/openssl.h"
#include <openssl/opensslv.h>

#ifdef _WINDOWS
#include <bcrypt.h>
#include "picotls/ptlsbcrypt.h"
#ifdef _DEBUG
#define BENCH_MODE "check"
#else
#define BENCH_MODE "release"
#endif
#include "../lib/ptlsbcrypt.c"
#else
#ifdef PTLS_DEBUG
#define BENCH_MODE "debug"
#else
#define BENCH_MODE "release"
#endif
#endif

/* Time in microseconds */
static uint64_t bench_time()
{
    struct timeval tv;
#ifdef CLOCK_PROCESS_CPUTIME_ID
    struct timespec cpu;
    if (clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &cpu) == 0){
        uint64_t nanos = (uint64_t) cpu.tv_nsec;
        uint64_t micros = nanos/1000;
        micros += (1000000ull)*((uint64_t)cpu.tv_sec);
        return micros;
    }
#endif
    gettimeofday(&tv, NULL);
    return (uint64_t)tv.tv_sec * 1000000 + tv.tv_usec;
}

/* Single measurement.
 */

#define BENCH_BATCH 1000

static int bench_run_one(ptls_aead_context_t *e, ptls_aead_context_t *d, size_t n, size_t l, uint64_t *t_enc, uint64_t *t_dec,
                     uint64_t *s)
{
    int ret = 0;
    uint8_t *v_in = NULL;
    uint8_t *v_enc[BENCH_BATCH];
    uint8_t *v_dec = NULL;
    uint64_t h[4];

    *t_enc = 0;
    *t_dec = 0;
    *s = 0;

    memset(v_enc, 0, sizeof(v_enc));
    memset(h, 0, sizeof(h));
    v_in = (uint8_t *)malloc(l);
    v_dec = (uint8_t *)malloc(l);
    if (v_in == NULL || v_dec == NULL) {
        ret = PTLS_ERROR_NO_MEMORY;
    }

    for (size_t i = 0; ret == 0 && i < BENCH_BATCH; i++) {
        v_enc[i] = (uint8_t *)malloc(l + PTLS_MAX_DIGEST_SIZE);
        if (v_enc[i] == 0) {
            ret = PTLS_ERROR_NO_MEMORY;
        }
    }

    if (ret == 0) {
        memset(v_in, 0, l);

        for (size_t k = 0; k < n;) {
            size_t e_len;
            size_t d_len;
            size_t i_max = ((n - k) > BENCH_BATCH) ? BENCH_BATCH : n - k;
            uint64_t old_h = h[0];
            uint64_t t_start = bench_time();
            uint64_t t_medium;
            uint64_t t_end;

            for (size_t i = 0; i < i_max; i++) {
                h[0]++;

                ptls_aead_encrypt_init(e, h[0], h, sizeof(h));
                e_len = ptls_aead_encrypt_update(e, v_enc[i], v_in, l);
                e_len += ptls_aead_encrypt_final(e, v_enc[i] + e_len);

                *s += (v_enc[i])[l];
            }

            t_medium = bench_time();

            h[0] = old_h;

            for (size_t i = 0; i < i_max; i++) {
                h[0]++;

                d_len = ptls_aead_decrypt(d, v_dec, v_enc[i], e_len, h[0], h, sizeof(h));
                if (d_len != l) {
                    ret = PTLS_ALERT_DECRYPT_ERROR;
                    break;
                }
                *s += v_dec[0];
            }

            t_end = bench_time();

            *t_enc += t_medium - t_start;
            *t_dec += t_end - t_medium;

            k += i_max;
        }
    }

    if (v_in != NULL) {
        free(v_in);
    }

    for (size_t i = 0; i < BENCH_BATCH; i++) {
        if (v_enc[i] != NULL) {
            free(v_enc[i]);
        }
    }

    if (v_dec != NULL) {
        free(v_dec);
    }

    return ret;
}

static double bench_mbps(uint64_t t, size_t l, size_t n)
{
    double x = (double)l;

    x *= (double)n;
    x *= 8;
    x /= (double)t;
    return x;
}

/* Measure one specific aead implementation
 */
static int bench_run_aead(char  * OS, char * HW, int basic_ref, uint64_t s0, const char *provider, const char *algo_name, ptls_aead_algorithm_t *aead, ptls_hash_algorithm_t *hash, size_t n, size_t l, uint64_t *s)
{
    int ret = 0;

    uint8_t secret[PTLS_MAX_SECRET_SIZE];
    ptls_aead_context_t *e;
    ptls_aead_context_t *d;
    uint64_t t_e = 0;
    uint64_t t_d = 0;
    char p_version[128];

    /* Document library version as it may have impact on performance */
    p_version[0] = 0;

    if (strcmp(provider, "openssl") == 0) {
        /*
         * OPENSSL_VERSION_NUMBER is a combination of the major, minor and patch version 
         * into a single integer 0xMNNFFPP0L, where M is major, NN is minor, PP is patch
         */
        uint32_t combined = OPENSSL_VERSION_NUMBER;
        int M = combined >> 28;
        int NN = (combined >> 20) & 0xFF;
        int FF = (combined >> 12) & 0xFF;
        int PP = (combined >> 4) & 0xFF;
        char letter = 'a' - 1 + PP;

#ifdef _WINDOWS
        (void)sprintf_s(p_version, sizeof(p_version), "%d.%d.%d%c", M, NN, FF, letter);
#else
        (void)sprintf(p_version, "%d.%d.%d%c", M, NN, FF, letter);
#endif
    }

    *s += s0;

    memset(secret, 'z', sizeof(secret));
    e = ptls_aead_new(aead, hash, 1, secret, NULL);
    d = ptls_aead_new(aead, hash, 0, secret, NULL);

    if (e == NULL || d == NULL) {
        ret = PTLS_ERROR_NO_MEMORY;
    } else {
        ret = bench_run_one(e, d, n, l, &t_e, &t_d, s);
        if (ret == 0) {
            printf("%s, %s, %d, %s, %d, %s, %s, %s, %d, %d, %d, %d, %.2f, %.2f\n", OS, HW, (int)(8 * sizeof(size_t)), BENCH_MODE, basic_ref,
                   provider, p_version, algo_name, (int)n, (int)l, (int)t_e, (int)t_d, bench_mbps(t_e, l, n),
                   bench_mbps(t_d, l, n));
        }
    }

    if (e) {
        ptls_aead_free(e);
    }

    if (d) {
        ptls_aead_free(d);
    }

    return ret;
}

typedef struct st_ptls_bench_entry_t {
    const char *provider;
    const char *algo_name;
    ptls_aead_algorithm_t *aead;
    ptls_hash_algorithm_t *hash;
    int enabled_by_defaut;
} ptls_bench_entry_t;

static ptls_bench_entry_t aead_list[] = {
    /* Minicrypto AES disabled by defaut because of atrocious perf */
    {"minicrypto", "aes128gcm", &ptls_minicrypto_aes128gcm, &ptls_minicrypto_sha256, 0},
    {"minicrypto", "aes256gcm", &ptls_minicrypto_aes256gcm, &ptls_minicrypto_sha384, 0},
    {"minicrypto", "chacha20poly1305", &ptls_minicrypto_chacha20poly1305, &ptls_minicrypto_sha256, 1},
#ifdef _WINDOWS
    {"ptlsbcrypt", "aes128gcm", &ptls_bcrypt_aes128gcm, &ptls_bcrypt_sha256, 1},
    {"ptlsbcrypt", "aes256gcm", &ptls_bcrypt_aes256gcm, &ptls_bcrypt_sha384, 1},
#endif
#if PTLS_OPENSSL_HAVE_CHACHA20_POLY1305
    {"openssl", "chacha20poly1305", &ptls_openssl_chacha20poly1305, &ptls_minicrypto_sha256, 1},
#endif
    {"openssl", "aes128gcm", &ptls_openssl_aes128gcm, &ptls_minicrypto_sha256, 1},
    {"openssl", "aes256gcm", &ptls_openssl_aes256gcm, &ptls_minicrypto_sha384, 1}};

static size_t nb_aead_list = sizeof(aead_list) / sizeof(ptls_bench_entry_t);

static int bench_basic(uint64_t *x)
{
    uint64_t t_start = bench_time();
    uint32_t a = (uint32_t)((*x)&0xFFFFFFFF);
    uint32_t b = (uint32_t)((*x)>>32);

    /* Evaluate the current CPU. The benchmark is designed to 
     * emulate typical encryption operations, hopefully so it
     * will not be compiled out by the optimizer. */
    for (unsigned int i = 0; i < 10000000; i++) {
        uint32_t v = (a >> 3)|(a << 29);
        v += a;
        v ^= b;
        b = a;
        a = v;
    }
    *x = (((uint64_t) b)<<32)|a;

    return (int)(bench_time() - t_start);
}

int main(int argc, char **argv)
{
    int ret = 0;
    int force_all_tests = 0;
    uint64_t x = 0xdeadbeef;
    uint64_t s = 0;
    int basic_ref = bench_basic(&x);
    char OS[128];
    char HW[128];
#ifndef _WINDOWS
    struct utsname uts;
#endif

#ifdef _WINDOWS
    (void) strcpy_s(OS, sizeof(OS), "windows");
    (void)strcpy_s(HW, sizeof(HW), "x86_64");
#else
    OS[0] = 0;
    HW[0] = 0;
    if (uname(&uts) == 0) {
        if (strlen(uts.sysname) + 1 < sizeof(OS)){
            strcpy(OS, uts.sysname);
        }
        if (strlen(uts.machine) + 1 < sizeof(HW)){
            strcpy(HW, uts.machine);
        }
    }
#endif

    if (argc == 2 && strcmp(argv[1], "-f") == 0) {
        force_all_tests = 1;
    } else if (argc > 1) {
        fprintf(stderr, "Usage: %s [-f]\n   Use option \"-f\" to force execution of the slower tests.\n", argv[0]);
        exit (-1);
    }

    printf("OS, HW, bits, mode, 10M ops, provider, version, algorithm, N, L, encrypt us, decrypt us, encrypt mbps, decrypt mbps,\n");
 
    for (size_t i = 0; ret == 0 && i < nb_aead_list; i++) {
        if (aead_list[i].enabled_by_defaut || force_all_tests) {
            ret = bench_run_aead(OS, HW, basic_ref, x, aead_list[i].provider, aead_list[i].algo_name, aead_list[i].aead,
                                 aead_list[i].hash, 1000, 1500, &s);
        }
    }

    /* Gratuitous test, designed to ensure that the initial computation
     * of the basic reference benchmark is not optimized away. */
    if (s == 0){
       printf("Unexpected value of test sum s = %llx\n", (unsigned long long)s);
    } 

    return ret;
}
