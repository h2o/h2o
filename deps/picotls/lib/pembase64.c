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
 * Manage Base64 encoding.
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
#include "picotls/pembase64.h"

static char ptls_base64_alphabet[] = {'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P',
                                      'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z', 'a', 'b', 'c', 'd', 'e', 'f',
                                      'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v',
                                      'w', 'x', 'y', 'z', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '+', '/'};

static signed char ptls_base64_values[] = {
    /* 0x00 to 0x0F */
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    /* 0x10 to 0x1F */
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    /* 0x20 to 0x2F. '+' at 2B, '/' at 2F  */
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, 62, -1, -1, -1, 63,
    /* 0x30 to 0x3F -- digits 0 to 9 at 0x30 to 0x39*/
    52, 53, 54, 55, 56, 57, 58, 59, 60, 61, -1, -1, -1, -1, -1, -1,
    /* 0x40 to 0x4F -- chars 'A' to 'O' at 0x41 to 0x4F */
    -1, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14,
    /* 0x50 to 0x5F -- chars 'P' to 'Z' at 0x50 to 0x5A */
    15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, -1, -1, -1, -1, -1,
    /* 0x60 to 0x6F -- chars 'a' to 'o' at 0x61 to 0x6F */
    -1, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40,
    /* 0x70 to 0x7F -- chars 'p' to 'z' at 0x70 to 0x7A */
    41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, -1, -1, -1, -1, -1};

static void ptls_base64_cell(const uint8_t *data, char *text)
{
    int n[4];

    n[0] = data[0] >> 2;
    n[1] = ((data[0] & 3) << 4) | (data[1] >> 4);
    n[2] = ((data[1] & 15) << 2) | (data[2] >> 6);
    n[3] = data[2] & 63;

    for (int i = 0; i < 4; i++) {
        text[i] = ptls_base64_alphabet[n[i]];
    }
}

size_t ptls_base64_howlong(size_t data_length)
{
    return (((data_length + 2) / 3) * 4);
}

int ptls_base64_encode(const uint8_t *data, size_t data_len, char *ptls_base64_text)
{
    int l = 0;
    int lt = 0;

    while ((data_len - l) >= 3) {
        ptls_base64_cell(data + l, ptls_base64_text + lt);
        l += 3;
        lt += 4;
    }

    switch (data_len - l) {
    case 0:
        break;
    case 1:
        ptls_base64_text[lt++] = ptls_base64_alphabet[data[l] >> 2];
        ptls_base64_text[lt++] = ptls_base64_alphabet[(data[l] & 3) << 4];
        ptls_base64_text[lt++] = '=';
        ptls_base64_text[lt++] = '=';
        break;
    case 2:
        ptls_base64_text[lt++] = ptls_base64_alphabet[data[l] >> 2];
        ptls_base64_text[lt++] = ptls_base64_alphabet[((data[l] & 3) << 4) | (data[l + 1] >> 4)];
        ptls_base64_text[lt++] = ptls_base64_alphabet[((data[l + 1] & 15) << 2)];
        ptls_base64_text[lt++] = '=';
        break;
    default:
        break;
    }
    ptls_base64_text[lt++] = 0;

    return lt;
}

/*
 * Take into input a line of text, so as to work by increments.
 * The intermediate text of the decoding is kept in a state variable.
 * The decoded data is accumulated in a PTLS buffer.
 * The parsing is consistent with the lax definition in RFC 7468
 */

void ptls_base64_decode_init(ptls_base64_decode_state_t *state)
{
    state->nbc = 0;
    state->nbo = 3;
    state->v = 0;
    state->status = PTLS_BASE64_DECODE_IN_PROGRESS;
}

int ptls_base64_decode(const char *text, ptls_base64_decode_state_t *state, ptls_buffer_t *buf)
{
    int ret = 0;
    uint8_t decoded[3];
    size_t text_index = 0;
    int c;
    signed char vc;

    /* skip initial blanks */
    while (text[text_index] != 0) {
        c = text[text_index];

        if (c == ' ' || c == '\t' || c == '\r' || c == '\n') {
            text_index++;
        } else {
            break;
        }
    }

    while (text[text_index] != 0 && ret == 0 && state->status == PTLS_BASE64_DECODE_IN_PROGRESS) {
        c = text[text_index++];

        vc = 0 < c && c < 0x7f ? ptls_base64_values[c] : -1;
        if (vc == -1) {
            if (state->nbc == 2 && c == '=' && text[text_index] == '=') {
                state->nbc = 4;
                text_index++;
                state->nbo = 1;
                state->v <<= 12;
            } else if (state->nbc == 3 && c == '=') {
                state->nbc = 4;
                state->nbo = 2;
                state->v <<= 6;
            } else {
                /* Skip final blanks */
                for (--text_index; text[text_index] != 0; ++text_index) {
                    c = text[text_index];
                    if (!(c == ' ' || c == '\t' || c == '\r' || c == '\n' || c == 0x0B || c == 0x0C))
                        break;
                }

                /* Should now be at end of buffer */
                if (text[text_index] == 0) {
                    break;
                } else {
                    /* Not at end of buffer, signal a decoding error */
                    state->nbo = 0;
                    state->status = PTLS_BASE64_DECODE_FAILED;
                    ret = PTLS_ERROR_INCORRECT_BASE64;
                }
            }
        } else {
            state->nbc++;
            state->v <<= 6;
            state->v |= vc;
        }

        if (ret == 0 && state->nbc == 4) {
            /* Convert to up to 3 octets */
            for (int j = 0; j < state->nbo; j++) {
                decoded[j] = (uint8_t)(state->v >> (8 * (2 - j)));
            }

            ret = ptls_buffer__do_pushv(buf, decoded, state->nbo);

            if (ret == 0) {
                /* test for fin or continuation */
                if (state->nbo < 3) {
                    /* Check that there are only trainling blanks on this line */
                    while (text[text_index] != 0) {
                        c = text[text_index++];

                        if (c == ' ' || c == '\t' || c == '\r' || c == '\n' || c == 0x0B || c == 0x0C) {
                            continue;
                        }
                    }
                    if (text[text_index] == 0) {
                        state->status = PTLS_BASE64_DECODE_DONE;
                    } else {
                        state->status = PTLS_BASE64_DECODE_FAILED;
                        ret = PTLS_ERROR_INCORRECT_BASE64;
                    }
                    break;
                } else {
                    state->v = 0;
                    state->nbo = 3;
                    state->nbc = 0;
                }
            }
        }
    }
    return ret;
}

/*
 * Reading a PEM file, to get an object:
 *
 * - Find first object, get the object name.
 * - If object label is what the application expects, parse, else skip to end.
 *
 * The following labels are defined in RFC 7468:
 *
 * Sec. Label                  ASN.1 Type              Reference Module
 * ----+----------------------+-----------------------+---------+----------
 * 5  CERTIFICATE            Certificate             [RFC5280] id-pkix1-e
 * 6  X509 CRL               CertificateList         [RFC5280] id-pkix1-e
 * 7  CERTIFICATE REQUEST    CertificationRequest    [RFC2986] id-pkcs10
 * 8  PKCS7                  ContentInfo             [RFC2315] id-pkcs7*
 * 9  CMS                    ContentInfo             [RFC5652] id-cms2004
 * 10 PRIVATE KEY            PrivateKeyInfo ::=      [RFC5208] id-pkcs8
 *                           OneAsymmetricKey        [RFC5958] id-aKPV1
 * 11 ENCRYPTED PRIVATE KEY  EncryptedPrivateKeyInfo [RFC5958] id-aKPV1
 * 12 ATTRIBUTE CERTIFICATE  AttributeCertificate    [RFC5755] id-acv2
 * 13 PUBLIC KEY             SubjectPublicKeyInfo    [RFC5280] id-pkix1-e
 */

static int ptls_compare_separator_line(const char *line, const char *begin_or_end, const char *label)
{
    int ret = strncmp(line, "-----", 5);
    size_t text_index = 5;

    if (ret == 0) {
        size_t begin_or_end_length = strlen(begin_or_end);
        ret = strncmp(line + text_index, begin_or_end, begin_or_end_length);
        text_index += begin_or_end_length;
    }

    if (ret == 0) {
        ret = line[text_index] - ' ';
        text_index++;
    }

    if (ret == 0) {
        size_t label_length = strlen(label);
        ret = strncmp(line + text_index, label, label_length);
        text_index += label_length;
    }

    if (ret == 0) {
        ret = strncmp(line + text_index, "-----", 5);
    }

    return ret;
}

static int ptls_get_pem_object(FILE *F, const char *label, ptls_buffer_t *buf)
{
    int ret = PTLS_ERROR_PEM_LABEL_NOT_FOUND;
    char line[256];
    ptls_base64_decode_state_t state;

    /* Get the label on a line by itself */
    while (fgets(line, 256, F)) {
        if (ptls_compare_separator_line(line, "BEGIN", label) == 0) {
            ret = 0;
            ptls_base64_decode_init(&state);
            break;
        }
    }
    /* Get the data in the buffer */
    while (ret == 0 && fgets(line, 256, F)) {
        if (ptls_compare_separator_line(line, "END", label) == 0) {
            if (state.status == PTLS_BASE64_DECODE_DONE || (state.status == PTLS_BASE64_DECODE_IN_PROGRESS && state.nbc == 0)) {
                ret = 0;
            } else {
                ret = PTLS_ERROR_INCORRECT_BASE64;
            }
            break;
        } else {
            ret = ptls_base64_decode(line, &state, buf);
        }
    }

    return ret;
}

int ptls_load_pem_objects(char const *pem_fname, const char *label, ptls_iovec_t *list, size_t list_max, size_t *nb_objects)
{
    FILE *F;
    int ret = 0;
    size_t count = 0;
#ifdef _WINDOWS
    errno_t err = fopen_s(&F, pem_fname, "r");
    if (err != 0) {
        ret = -1;
    }
#else
    F = fopen(pem_fname, "r");
    if (F == NULL) {
        ret = -1;
    }
#endif

    *nb_objects = 0;

    if (ret == 0) {
        while (count < list_max) {
            ptls_buffer_t buf;

            ptls_buffer_init(&buf, "", 0);

            ret = ptls_get_pem_object(F, label, &buf);

            if (ret == 0) {
                if (buf.off > 0 && buf.is_allocated) {
                    list[count].base = buf.base;
                    list[count].len = buf.off;
                    count++;
                } else {
                    ptls_buffer_dispose(&buf);
                }
            } else {
                ptls_buffer_dispose(&buf);
                break;
            }
        }
    }

    if (ret == PTLS_ERROR_PEM_LABEL_NOT_FOUND && count > 0) {
        ret = 0;
    }

    *nb_objects = count;

    if (F != NULL) {
        fclose(F);
    }

    return ret;
}

#define PTLS_MAX_CERTS_IN_CONTEXT 16

int ptls_load_certificates(ptls_context_t *ctx, char const *cert_pem_file)
{
    int ret = 0;

    ctx->certificates.list = (ptls_iovec_t *)malloc(PTLS_MAX_CERTS_IN_CONTEXT * sizeof(ptls_iovec_t));

    if (ctx->certificates.list == NULL) {
        ret = PTLS_ERROR_NO_MEMORY;
    } else {
        ret = ptls_load_pem_objects(cert_pem_file, "CERTIFICATE", ctx->certificates.list, PTLS_MAX_CERTS_IN_CONTEXT,
                                    &ctx->certificates.count);
    }

    return ret;
}
