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
#include <assert.h>
#include <stdlib.h>
#include "brotli/decode.h"
#include "brotli/encode.h"
#include "picotls/certificate_compression.h"

static inline int decompress_certificate(ptls_decompress_certificate_t *self, ptls_t *tls, uint16_t algorithm, ptls_iovec_t output,
                                         ptls_iovec_t input)
{
    if (algorithm != PTLS_CERTIFICATE_COMPRESSION_ALGORITHM_BROTLI)
        goto Fail;

    size_t decoded_size = output.len;
    if (BrotliDecoderDecompress(input.len, input.base, &decoded_size, output.base) != BROTLI_DECODER_RESULT_SUCCESS)
        goto Fail;

    if (decoded_size != output.len)
        goto Fail;

    return 0;
Fail:
    return PTLS_ALERT_BAD_CERTIFICATE;
}

static const uint16_t algorithms[] = {PTLS_CERTIFICATE_COMPRESSION_ALGORITHM_BROTLI, UINT16_MAX};

ptls_decompress_certificate_t ptls_decompress_certificate = {algorithms, decompress_certificate};

static int emit_compressed_certificate(ptls_emit_certificate_t *_self, ptls_t *tls, ptls_message_emitter_t *emitter,
                                       ptls_key_schedule_t *key_sched, ptls_iovec_t context, int push_status_request,
                                       const uint16_t *compress_algos, size_t num_compress_algos)
{
    ptls_emit_compressed_certificate_t *self = (void *)_self;
    struct st_ptls_compressed_certificate_entry_t *entry;
    int ret;

    assert(context.len == 0 || !"precompressed mode can only be used for server certificates");

    for (size_t i = 0; i != num_compress_algos; ++i) {
        if (compress_algos[i] == PTLS_CERTIFICATE_COMPRESSION_ALGORITHM_BROTLI)
            goto FoundBrotli;
    }
    /* brotli not found, delegate to the core */
    ret = PTLS_ERROR_DELEGATE;
    goto Exit;

FoundBrotli:
    entry = &self->without_ocsp_status;
    if (push_status_request && self->with_ocsp_status.uncompressed_length != 0)
        entry = &self->with_ocsp_status;

    ptls_push_message(emitter, key_sched, PTLS_HANDSHAKE_TYPE_COMPRESSED_CERTIFICATE, {
        ptls_buffer_push16(emitter->buf, PTLS_CERTIFICATE_COMPRESSION_ALGORITHM_BROTLI);
        ptls_buffer_push24(emitter->buf, entry->uncompressed_length);
        ptls_buffer_push_block(emitter->buf, 3, { ptls_buffer_pushv(emitter->buf, entry->bytes.base, entry->bytes.len); });
    });

    ret = 0;

Exit:
    return ret;
}

static int build_compressed(struct st_ptls_compressed_certificate_entry_t *entry, ptls_iovec_t *certificates,
                            size_t num_certificates, ptls_iovec_t ocsp_status)
{
    ptls_buffer_t uncompressed;
    int ret;

    ptls_buffer_init(&uncompressed, "", 0);

    /* build uncompressed */
    if ((ret = ptls_build_certificate_message(&uncompressed, ptls_iovec_init(NULL, 0), certificates, num_certificates,
                                              ocsp_status)) != 0)
        goto Exit;
    entry->uncompressed_length = (uint32_t)uncompressed.off;

    /* compress */
    entry->bytes.len = uncompressed.off - 1;
    if ((entry->bytes.base = malloc(entry->bytes.len)) == NULL) {
        ret = PTLS_ERROR_NO_MEMORY;
        goto Exit;
    }
    if (BrotliEncoderCompress(BROTLI_MAX_QUALITY, BROTLI_DEFAULT_WINDOW, BROTLI_MODE_GENERIC, uncompressed.off, uncompressed.base,
                              &entry->bytes.len, entry->bytes.base) != BROTLI_TRUE) {
        ret = PTLS_ERROR_COMPRESSION_FAILURE;
        goto Exit;
    }

    ret = 0;

Exit:
    if (ret != 0) {
        free(entry->bytes.base);
        *entry = (struct st_ptls_compressed_certificate_entry_t){0};
    }
    ptls_buffer_dispose(&uncompressed);
    return ret;
}

int ptls_init_compressed_certificate(ptls_emit_compressed_certificate_t *self, ptls_iovec_t *certificates, size_t num_certificates,
                                     ptls_iovec_t ocsp_status)
{
    int ret;

    *self = (ptls_emit_compressed_certificate_t){{emit_compressed_certificate}, PTLS_CERTIFICATE_COMPRESSION_ALGORITHM_BROTLI};

    /* build entries */
    if ((ret = build_compressed(&self->without_ocsp_status, certificates, num_certificates, ptls_iovec_init(NULL, 0))) != 0)
        goto Exit;
    if (ocsp_status.len != 0) {
        if ((ret = build_compressed(&self->with_ocsp_status, certificates, num_certificates, ocsp_status)) != 0)
            goto Exit;
    }

    ret = 0;

Exit:
    if (ret != 0)
        ptls_dispose_compressed_certificate(self);
    return ret;
}

void ptls_dispose_compressed_certificate(ptls_emit_compressed_certificate_t *self)
{
    free(self->with_ocsp_status.bytes.base);
    free(self->without_ocsp_status.bytes.base);
}
