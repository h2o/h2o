/*
* Copyright (c) 2017 Christian Huitema <huitema@huitema.net>
*
* Permission to use, copy, modify, and distribute this software for any
* purpose with or without fee is hereby granted, provided that the above
* copyright notice and this permission notice appear in all copies.
*
* THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
* WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
* MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
* ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
* WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
* ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
* OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
*/

#ifndef PTLS_ASN1_H
#define PTLS_ASN1_H

// #include "picotls/minicrypto.h"

/*
* The ASN.1 functions take a "log context" parameter of type ptls_minicrypto_log_ctx_t.
*
* The log function in that code can be instantiated for example as:
*
* void log_printf(void * ctx, const char * format, ...)
* {
*     va_list argptr;
*     va_start(argptr, format);
*     vfprintf(stderr, format, argptr);
* }
*
* Using definitions from <stdio.h> and <stdarg.h>
*/

typedef struct st_ptls_minicrypto_log_ctx_t {
    void *ctx;
    void (*fn)(void *ctx, const char *format, ...);
} ptls_minicrypto_log_ctx_t;

size_t ptls_asn1_error_message(char const *error_label, size_t bytes_max, size_t byte_index, int level,
                               ptls_minicrypto_log_ctx_t *log_ctx);

void ptls_asn1_dump_content(const uint8_t *bytes, size_t bytes_max, size_t byte_index, ptls_minicrypto_log_ctx_t *log_ctx);

size_t ptls_asn1_read_type(const uint8_t *bytes, size_t bytes_max, int *structure_bit, int *type_class, uint32_t *type_number,
                           int *decode_error, int level, ptls_minicrypto_log_ctx_t *log_ctx);

void ptls_asn1_print_type(int type_class, uint32_t type_number, int level, ptls_minicrypto_log_ctx_t *log_ctx);

size_t ptls_asn1_read_length(const uint8_t *bytes, size_t bytes_max, size_t byte_index, uint32_t *length, int *indefinite_length,
                             size_t *last_byte, int *decode_error, int level, ptls_minicrypto_log_ctx_t *log_ctx);

size_t ptls_asn1_get_expected_type_and_length(const uint8_t *bytes, size_t bytes_max, size_t byte_index, uint8_t expected_type,
                                              uint32_t *length, int *indefinite_length, size_t *last_byte, int *decode_error,
                                              ptls_minicrypto_log_ctx_t *log_ctx);

size_t ptls_asn1_validation_recursive(const uint8_t *bytes, size_t bytes_max, int *decode_error, int level,
                                      ptls_minicrypto_log_ctx_t *log_ctx);

int ptls_asn1_validation(const uint8_t *bytes, size_t length, ptls_minicrypto_log_ctx_t *log_ctx);

#endif
