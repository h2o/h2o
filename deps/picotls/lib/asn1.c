/*
* Copyright (c) 2016 Christian Huitema <huitema@huitema.net>
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

/*
* Basic ASN1 validation and optional print-out
*/

#ifdef _WINDOWS
#include "wincompat.h"
#else
#include <sys/time.h>
#endif
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include "picotls.h"
#include "picotls/minicrypto.h"
#include "picotls/asn1.h"

static char const *asn1_type_classes[4] = {"Universal", "Application", "Context-specific", "Private"};

static char const *asn1_universal_types[] = {
    "End-of-Content",    "BOOLEAN",           "INTEGER",       "BIT STRING",     "OCTET STRING",    "NULL",
    "OBJECT IDENTIFIER", "Object Descriptor", "EXTERNAL",      "REAL",           "ENUMERATED",      "EMBEDDED PDV",
    "UTF8String",        "RELATIVE-OID",      "Reserved (16)", "Reserved (17)",  "SEQUENCE",        "SET",
    "NumericString",     "PrintableString",   "T61String",     "VideotexString", "IA5String",       "UTCTime",
    "GeneralizedTime",   "GraphicString",     "VisibleString", "GeneralString",  "UniversalString", "CHARACTER STRING",
    "BMPString"};

static size_t nb_asn1_universal_types = sizeof(asn1_universal_types) / sizeof(char const *);

static void ptls_asn1_print_indent(int level, ptls_minicrypto_log_ctx_t *log_ctx)
{
    for (int indent = 0; indent <= level; indent++) {
        log_ctx->fn(log_ctx->ctx, "   ");
    }
}

size_t ptls_asn1_error_message(char const *error_label, size_t bytes_max, size_t byte_index, int level,
                               ptls_minicrypto_log_ctx_t *log_ctx)
{
    if (log_ctx != NULL) {
        ptls_asn1_print_indent(level, log_ctx);
        log_ctx->fn(log_ctx->ctx, "Error: %s (near position: %d (0x%x) out of %d)", error_label, (int)byte_index,
                    (uint32_t)byte_index, (int)bytes_max);
    }
    return byte_index;
}

void ptls_asn1_dump_content(const uint8_t *bytes, size_t bytes_max, size_t byte_index, ptls_minicrypto_log_ctx_t *log_ctx)
{
    if (log_ctx != NULL && bytes_max > byte_index) {
        size_t nb_bytes = bytes_max - byte_index;

        log_ctx->fn(log_ctx->ctx, " ");

        for (size_t i = 0; i < 16 && i < nb_bytes; i++) {
            log_ctx->fn(log_ctx->ctx, "%02x", bytes[byte_index + i]);
        }

        if (nb_bytes > 16) {
            log_ctx->fn(log_ctx->ctx, "...");
        }
    }
}

size_t ptls_asn1_read_type(const uint8_t *bytes, size_t bytes_max, int *structure_bit, int *type_class, uint32_t *type_number,
                           int *decode_error, int level, ptls_minicrypto_log_ctx_t *log_ctx)
{
    /* Get the type byte */
    size_t byte_index = 1;
    uint8_t first_byte = bytes[0];
    *structure_bit = (first_byte >> 5) & 1;
    *type_class = (first_byte >> 6) & 3;
    *type_number = first_byte & 31;

    if (*type_number == 31) {
        uint32_t long_type = 0;
        const uint32_t type_number_limit = 0x07FFFFFFF;
        int next_byte;
        int end_found = 0;

        while (byte_index < bytes_max && long_type <= type_number_limit) {
            next_byte = bytes[byte_index++];
            long_type <<= 7;
            long_type |= next_byte & 127;
            if ((next_byte & 128) == 0) {
                end_found = 1;
                break;
            }
        }

        if (end_found) {
            *type_number = long_type;
        } else {
            /* This is an error */
            byte_index = ptls_asn1_error_message("Incorrect type coding", bytes_max, byte_index, level, log_ctx);
            *decode_error = PTLS_ERROR_BER_MALFORMED_TYPE;
        }
    }

    return byte_index;
}

void ptls_asn1_print_type(int type_class, uint32_t type_number, int level, ptls_minicrypto_log_ctx_t *log_ctx)
{
    /* Print the type */
    ptls_asn1_print_indent(level, log_ctx);
    if (type_class == 0 && type_number < nb_asn1_universal_types) {
        log_ctx->fn(log_ctx->ctx, "%s", asn1_universal_types[type_number]);
    } else if (type_class == 2) {
        log_ctx->fn(log_ctx->ctx, "[%d]", type_number);
    } else {
        log_ctx->fn(log_ctx->ctx, "%s[%d]", asn1_type_classes[type_class], type_number);
    }
}

size_t ptls_asn1_read_length(const uint8_t *bytes, size_t bytes_max, size_t byte_index, uint32_t *length, int *indefinite_length,
                             size_t *last_byte, int *decode_error, int level, ptls_minicrypto_log_ctx_t *log_ctx)
{
    int length_of_length = 0;

    *indefinite_length = 0;
    *length = 0;
    *last_byte = bytes_max;

    if (byte_index < bytes_max) {
        *length = bytes[byte_index++];
        if ((*length & 128) != 0) {
            length_of_length = *length & 127;
            *length = 0;

            if (byte_index + length_of_length >= bytes_max) {
                /* This is an error */
                byte_index = ptls_asn1_error_message("Incorrect length coding", bytes_max, byte_index, level, log_ctx);
                *decode_error = PTLS_ERROR_BER_MALFORMED_LENGTH;
            } else {
                for (int i = 0; i < length_of_length && byte_index < bytes_max; i++) {
                    *length <<= 8;
                    *length |= bytes[byte_index++];
                }

                if (length_of_length == 0) {
                    *last_byte = bytes_max;
                    *indefinite_length = 1;
                } else {
                    *last_byte = byte_index + *length;
                }
            }
        } else {
            *last_byte = byte_index + *length;
        }

        if (*decode_error == 0) {
            /* TODO: verify that the length makes sense */
            if (*last_byte > bytes_max) {
                byte_index = ptls_asn1_error_message("Length larger than message", bytes_max, byte_index, level, log_ctx);
                *decode_error = PTLS_ERROR_BER_EXCESSIVE_LENGTH;
            }
        }
    }

    return byte_index;
}

size_t ptls_asn1_get_expected_type_and_length(const uint8_t *bytes, size_t bytes_max, size_t byte_index, uint8_t expected_type,
                                              uint32_t *length, int *indefinite_length, size_t *last_byte, int *decode_error,
                                              ptls_minicrypto_log_ctx_t *log_ctx)
{
    int is_indefinite = 0;

    /* Check that the expected type is present */
    if (bytes[byte_index] != expected_type) {
        byte_index = ptls_asn1_error_message("Unexpected type", bytes_max, byte_index, 0, log_ctx);
        *decode_error = PTLS_ERROR_INCORRECT_ASN1_SYNTAX;
    } else {
        /* get length of element */
        byte_index++;
        byte_index =
            ptls_asn1_read_length(bytes, bytes_max, byte_index, length, &is_indefinite, last_byte, decode_error, 0, log_ctx);

        if (indefinite_length != NULL) {
            *indefinite_length = is_indefinite;
        } else if (is_indefinite) {
            byte_index = ptls_asn1_error_message("Incorrect length for DER", bytes_max, byte_index, 0, log_ctx);
            *decode_error = PTLS_ERROR_DER_INDEFINITE_LENGTH;
        }
    }

    return byte_index;
}

size_t ptls_asn1_validation_recursive(const uint8_t *bytes, size_t bytes_max, int *decode_error, int level,
                                      ptls_minicrypto_log_ctx_t *log_ctx)
{
    /* Get the type byte */
    int structure_bit = 0;
    int type_class = 0;
    uint32_t type_number = 0;
    uint32_t length = 0;
    int indefinite_length = 0;
    size_t last_byte = 0;
    /* Decode the type */
    size_t byte_index =
        ptls_asn1_read_type(bytes, bytes_max, &structure_bit, &type_class, &type_number, decode_error, level, log_ctx);

    if (*decode_error == 0 && log_ctx != NULL) {
        ptls_asn1_print_type(type_class, type_number, level, log_ctx);
    }

    /* Get the length */
    byte_index =
        ptls_asn1_read_length(bytes, bytes_max, byte_index, &length, &indefinite_length, &last_byte, decode_error, level, log_ctx);

    if (last_byte <= bytes_max) {
        if (structure_bit) {
            /* If structured, recurse on a loop */
            if (log_ctx != NULL) {
                log_ctx->fn(log_ctx->ctx, " {\n");
            }

            while (byte_index < last_byte) {
                if (indefinite_length != 0 && bytes[byte_index] == 0) {
                    if (byte_index + 2 > bytes_max || bytes[byte_index + 1] != 0) {
                        byte_index =
                            ptls_asn1_error_message("EOC: unexpected end of content", bytes_max, byte_index, level + 1, log_ctx);

                        *decode_error = PTLS_ERROR_BER_UNEXPECTED_EOC;
                    } else {
                        if (log_ctx != NULL) {
                            ptls_asn1_print_indent(level, log_ctx);
                            log_ctx->fn(log_ctx->ctx, "EOC\n");
                        }
                        byte_index += 2;
                        break;
                    }
                } else {
                    byte_index += ptls_asn1_validation_recursive(bytes + byte_index, last_byte - byte_index, decode_error,
                                                                 level + 1, log_ctx);

                    if (*decode_error) {
                        byte_index = bytes_max;
                        break;
                    }
                }

                if (log_ctx != NULL) {
                    if (byte_index < last_byte) {
                        log_ctx->fn(log_ctx->ctx, ",");
                    }
                    log_ctx->fn(log_ctx->ctx, "\n");
                }
            }

            if (log_ctx != NULL) {
                ptls_asn1_print_indent(level, log_ctx);
                log_ctx->fn(log_ctx->ctx, "}");
            }
        } else {
            ptls_asn1_dump_content(bytes, last_byte, byte_index, log_ctx);
            byte_index = last_byte;
        }
    }

    return byte_index;
}

int ptls_asn1_validation(const uint8_t *bytes, size_t length, ptls_minicrypto_log_ctx_t *log_ctx)
{
    int decode_error = 0;
    size_t decoded = ptls_asn1_validation_recursive(bytes, length, &decode_error, 0, log_ctx);

    if (decode_error == 0 && decoded < length) {
        decode_error = PTLS_ERROR_BER_ELEMENT_TOO_SHORT;
        if (log_ctx != NULL) {
            log_ctx->fn(log_ctx->ctx, "Type too short, %d bytes only out of %d\n", (int)decoded, (int)length);
        }
    }

    return decode_error;
}
