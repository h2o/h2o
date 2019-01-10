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
                                       ptls_key_schedule_t *key_sched, ptls_iovec_t context)
{
    ptls_emit_compressed_certificate_t *self = (void *)_self;
    int ret;

    assert(context.len == 0 || !"precompressed mode can only be used for server certificates");

    ptls_push_message(emitter, key_sched, PTLS_HANDSHAKE_TYPE_COMPRESSED_CERTIFICATE, {
        ptls_buffer_push16(emitter->buf, self->algo);
        ptls_buffer_push24(emitter->buf, self->uncompressed_length);
        ptls_buffer_push_block(emitter->buf, 3, { ptls_buffer_pushv(emitter->buf, self->buf.base, self->buf.len); });
    });

    ret = 0;

Exit:
    return ret;
}

int ptls_init_compressed_certificate(ptls_emit_compressed_certificate_t *self, uint16_t algo, ptls_iovec_t *certificates,
                                     size_t num_certificates, ptls_iovec_t ocsp_status)
{
    ptls_buffer_t uncompressed;
    int ret;

    *self = (ptls_emit_compressed_certificate_t){{emit_compressed_certificate}, algo};

    ptls_buffer_init(&uncompressed, "", 0);

    /* build uncompressed */
    if ((ret = ptls_build_certificate_message(&uncompressed, ptls_iovec_init(NULL, 0), certificates, num_certificates,
                                              ocsp_status)) != 0)
        goto Exit;
    self->uncompressed_length = (uint32_t)uncompressed.off;

    /* compress */
    self->buf.len = uncompressed.off - 1;
    if ((self->buf.base = malloc(self->buf.len)) == NULL) {
        ret = PTLS_ERROR_NO_MEMORY;
        goto Exit;
    }
    if (BrotliEncoderCompress(BROTLI_MAX_QUALITY, BROTLI_DEFAULT_WINDOW, BROTLI_MODE_GENERIC, uncompressed.off, uncompressed.base,
                              &self->buf.len, self->buf.base) != BROTLI_TRUE) {
        ret = PTLS_ERROR_COMPRESSION_FAILURE;
        goto Exit;
    }

    ret = 0;

Exit:
    if (ret != 0)
        free(self->buf.base);
    ptls_buffer_dispose(&uncompressed);
    return ret;
}
