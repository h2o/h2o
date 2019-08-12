/*
 * Copyright (c) 2018 Fastly
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
#ifndef picotls_certificate_compression_h
#define picotls_certificate_compression_h

#ifdef __cplusplus
extern "C" {
#endif

#include "picotls.h"

#define PTLS_CERTIFICATE_COMPRESSION_ALGORITHM_GZIP 1
#define PTLS_CERTIFICATE_COMPRESSION_ALGORITHM_BROTLI 2

typedef struct st_ptls_emit_compressed_certificate_t {
    ptls_emit_certificate_t super;
    uint16_t algo;
    struct st_ptls_compressed_certificate_entry_t {
        uint32_t uncompressed_length;
        ptls_iovec_t bytes;
    } with_ocsp_status, without_ocsp_status;
} ptls_emit_compressed_certificate_t;

extern ptls_decompress_certificate_t ptls_decompress_certificate;

/**
 * initializes a certificate emitter that precompresses a certificate chain (and ocsp status)
 */
int ptls_init_compressed_certificate(ptls_emit_compressed_certificate_t *ecc, ptls_iovec_t *certificates, size_t num_certificates,
                                     ptls_iovec_t ocsp_status);
/**
 *
 */
void ptls_dispose_compressed_certificate(ptls_emit_compressed_certificate_t *ecc);

#ifdef __cplusplus
}
#endif

#endif
