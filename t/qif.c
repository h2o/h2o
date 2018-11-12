/*
 * Copyright (c) 2018 Fastly, Kazuho Oku
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
#include <ctype.h>
#include <errno.h>
#include <getopt.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "h2o/qpack.h"
#include "h2o/url.h"

static void write_int(FILE *fp, uint64_t v, size_t nbytes)
{
    size_t i;
    for (i = 0; i != nbytes; ++i)
        fputc((uint8_t)(v >> ((nbytes - i - 1) * 8)), fp);
}

static uint64_t read_int(FILE *fp, size_t nbytes)
{
    uint64_t v = 0;
    size_t i;
    int ch;
    for (i = 0; i != nbytes; ++i) {
        if ((ch = fgetc(fp)) == EOF)
            return UINT64_MAX;
        v = (v << 8) | ch;
    }
    return v;
}

static int encode_qif(FILE *inp, FILE *outp, unsigned header_table_size_bits, int is_resp)
{
    h2o_qpack_encoder_t *enc = h2o_qpack_create_encoder(header_table_size_bits);
    uint64_t stream_id = 1;
    h2o_mem_pool_t pool;
    struct {
        union {
            struct {
                h2o_iovec_t method, authority, path;
                const h2o_url_scheme_t *scheme;
            };
            struct {
                int status;
                size_t content_length;
            };
        };
        h2o_headers_t headers;
    } message;
    char line[4096];
    size_t len;

    h2o_mem_init_pool(&pool);

#define CLEAR()                                                                                                                    \
    do {                                                                                                                           \
        h2o_mem_clear_pool(&pool);                                                                                                 \
        memset(&message, 0, sizeof(message));                                                                                      \
        if (is_resp)                                                                                                               \
            message.content_length = SIZE_MAX;                                                                                     \
    } while (0)

#define EMIT()                                                                                                                     \
    do {                                                                                                                           \
        h2o_byte_vector_t output = {NULL};                                                                                         \
        if (!is_resp) {                                                                                                            \
            assert(message.method.base != NULL);                                                                                   \
            assert(message.scheme != NULL);                                                                                        \
            assert(message.authority.base != NULL);                                                                                \
            assert(message.path.base != NULL);                                                                                     \
            h2o_qpack_flatten_request(enc, &pool, &output, message.method, message.scheme, message.authority, message.path,        \
                                      message.headers.entries, message.headers.size);                                              \
        } else {                                                                                                                   \
            assert(100 <= message.status && message.status <= 999);                                                                \
            h2o_qpack_flatten_response(enc, &pool, &output, message.status, message.headers.entries, message.headers.size, NULL,   \
                                       message.content_length);                                                                    \
        }                                                                                                                          \
        write_int(outp, stream_id++, 8);                                                                                           \
        write_int(outp, (uint32_t)output.size, 4);                                                                                 \
        fwrite(output.entries, 1, output.size, outp);                                                                              \
        CLEAR();                                                                                                                   \
    } while (0)

    CLEAR();

    while (fgets(line, sizeof(line), inp) != NULL && (len = strlen(line)) != 0) {
        /* chop LF */
        assert(line[len - 1] == '\n');
        line[--len] = '\0';

        if (line[0] == '\0') {
            /* empty line */
            EMIT();
        } else if (line[0] == '#') {
            /* skip comment */
        } else {
            /* split line into name and value */
            size_t i;
            for (i = 1; i < len; ++i)
                if (isspace(line[i]))
                    break;
            assert(i < len);
            h2o_iovec_t name = h2o_strdup(&pool, line, i);
            for (++i; i < len; ++i)
                if (!isspace(line[i]))
                    break;
            assert(i <= len);
            h2o_iovec_t value = h2o_strdup(&pool, line + i, len - i);
            /* handle header */
            if (line[0] == ':') {
                /* pseudo header */
                if (!is_resp) {
                    if (h2o_memis(name.base, name.len, H2O_STRLIT(":method"))) {
                        message.method = value;
                    } else if (h2o_memis(name.base, name.len, H2O_STRLIT(":scheme"))) {
                        static const h2o_url_scheme_t *schemes[] = {&H2O_URL_SCHEME_HTTP, &H2O_URL_SCHEME_HTTPS, NULL};
                        for (i = 0; schemes[i] != NULL; ++i)
                            if (h2o_memis(value.base, value.len, schemes[i]->name.base, schemes[i]->name.len))
                                break;
                        assert(schemes[i] != NULL);
                        message.scheme = schemes[i];
                    } else if (h2o_memis(name.base, name.len, H2O_STRLIT(":authority"))) {
                        message.authority = value;
                    } else if (h2o_memis(name.base, name.len, H2O_STRLIT(":path"))) {
                        message.path = value;
                    } else {
                        assert(!"unexpected pseudo request header");
                    }
                } else {
                    if (h2o_memis(name.base, name.len, H2O_STRLIT(":status"))) {
                        sscanf(value.base, "%d", &message.status);
                    } else {
                        assert(!"unexpected pseudo response header");
                    }
                }
            } else if (is_resp && h2o_memis(name.base, name.len, H2O_STRLIT("content-length"))) {
                sscanf(value.base, "%zu", &message.content_length);
            } else {
                h2o_add_header_by_str(&pool, &message.headers, name.base, name.len, 1, NULL, value.base, value.len);
            }
        }
    }

    if (message.method.base != NULL || message.status != 0)
        EMIT();

    return 0;
#undef EMIT
#undef CLEAR
}

static int decode_qif(FILE *inp, FILE *outp, unsigned header_table_size_bits, int is_resp)
{
    h2o_qpack_decoder_t *dec = h2o_qpack_create_decoder(header_table_size_bits);
    uint64_t stream_id;
    h2o_byte_vector_t encoder_stream_buf = {NULL}; /* NOT governed by the memory pool */
    h2o_mem_pool_t pool;
    int ret;

    h2o_mem_init_pool(&pool);

    while ((stream_id = read_int(inp, 8)) != UINT64_MAX) {
        uint64_t chunk_size = read_int(inp, 4);
        assert(chunk_size != UINT64_MAX);
        uint8_t buf[chunk_size];
        if (fread(buf, 1, chunk_size, inp) != chunk_size) {
            fprintf(stderr, "failed to read the entire chunk\n");
            return 1;
        }
        if (stream_id == 0) {
            /* qpack encoder stream */
            h2o_vector_reserve(NULL, &encoder_stream_buf, encoder_stream_buf.size + chunk_size);
            memcpy(encoder_stream_buf.entries + encoder_stream_buf.size, buf, chunk_size);
            encoder_stream_buf.size += chunk_size;
            const uint8_t *p = encoder_stream_buf.entries;
            const char *err_desc = NULL;
            if ((ret = h2o_qpack_decoder_handle_input(dec, &p, p + encoder_stream_buf.size, &err_desc)) != 0) {
                fprintf(stderr, "failed to decode stream 0:%s\n", err_desc);
                return 1;
            }
            size_t remaining = encoder_stream_buf.entries + encoder_stream_buf.size - p;
            if (remaining != 0)
                memmove(encoder_stream_buf.entries, p, remaining);
            encoder_stream_buf.size = remaining;
        } else if (!is_resp) {
            /* request */
            h2o_iovec_t method = {NULL}, authority = {NULL}, path = {NULL};
            const h2o_url_scheme_t *scheme = NULL;
            h2o_headers_t headers = {NULL};
            int pseudo_header_exists_map = 0;
            size_t content_length, header_ack_len;
            uint8_t header_ack[H2O_HPACK_ENCODE_INT_MAX_LENGTH];
            const char *err_desc = NULL;
            if ((ret = h2o_qpack_parse_request(&pool, dec, stream_id, &method, &scheme, &authority, &path, &headers,
                                               &pseudo_header_exists_map, &content_length, NULL, header_ack, &header_ack_len, buf,
                                               chunk_size, &err_desc)) != 0) {
                fprintf(stderr, "failed to decode stream %" PRIu64 ":%s\n", stream_id, err_desc);
                return 1;
            }
#define REQUIRED_PSUEDO_HEADERS                                                                                                    \
    (H2O_HPACK_PARSE_HEADERS_METHOD_EXISTS | H2O_HPACK_PARSE_HEADERS_SCHEME_EXISTS | H2O_HPACK_PARSE_HEADERS_AUTHORITY_EXISTS |    \
     H2O_HPACK_PARSE_HEADERS_PATH_EXISTS)
            if ((pseudo_header_exists_map & REQUIRED_PSUEDO_HEADERS) != REQUIRED_PSUEDO_HEADERS) {
                fprintf(stderr, "some of the required pseudo headers are missing in stream id %" PRIu64 "\n", stream_id);
                return 1;
            }
#undef REQUIRED_PSEUDO_HEADERS
            fprintf(outp, "#stream\t%" PRIu64 "\n:method\t%.*s\n:scheme\t%.*s\n:authority\t%.*s\n:path\t%.*s\n", stream_id,
                    (int)method.len, method.base, (int)scheme->name.len, scheme->name.base, (int)authority.len, authority.base,
                    (int)path.len, path.base);
            if (content_length != SIZE_MAX)
                fprintf(outp, "content-length\t%zu\n", content_length);
            size_t i;
            for (i = 0; i != headers.size; ++i) {
                const h2o_header_t *header = headers.entries + i;
                fprintf(outp, "%.*s\t%.*s\n", (int)header->name->len, header->name->base, (int)header->value.len,
                        header->value.base);
            }
            h2o_mem_clear_pool(&pool);
            fputc('\n', outp);
        } else {
            /* response */
            assert(!"FIXME");
        }
    }

    return 0;
}

static void usage(const char *cmd)
{
    printf("Usage: %s [options] [input-file [output-file]]\n"
           "Options:\n"
           "  -d         decode (default is encode)\n"
           "  -r         handling series of responses (default is requests)\n"
           "  -s [bits]  header table size bits (default is 12; i.e. 4096 bytes)\n"
           "\n",
           cmd);
    exit(0);
}

int main(int argc, char **argv)
{
    unsigned header_table_size_bits = 12;
    int ch, decode = 0, is_resp = 0;

    while ((ch = getopt(argc, argv, "drs:h")) != -1) {
        switch (ch) {
        case 'd':
            decode = 1;
            break;
        case 'r':
            is_resp = 1;
            break;
        case 's':
            if (sscanf(optarg, "%u", &header_table_size_bits) != 1) {
                fprintf(stderr, "failed to header table size bits\n");
                exit(1);
            }
            break;
        default:
            usage(argv[0]);
            break;
        }
    }
    argc -= optind;
    argv += optind;
    if (argc != 0) {
        if (freopen(*argv, "r", stdin) == NULL) {
            fprintf(stderr, "failed to open file:%s:%s\n", *argv, strerror(errno));
            exit(1);
        }
        --argc;
        ++argv;
    }
    if (argc != 0) {
        if (freopen(*argv, "w", stdout) == NULL) {
            fprintf(stderr, "failed to open file:%s:%s\n", *argv, strerror(errno));
            exit(1);
        }
        --argc;
        ++argv;
    }

    return (decode ? decode_qif : encode_qif)(stdin, stdout, header_table_size_bits, is_resp);
}
