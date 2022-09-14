/*
 * Copyright (c) 2020 Fastly, Kazuho
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
#include <arpa/inet.h>
#include "h2o/memory.h"
#include "h2o/socket.h"
#include "h2o/string_.h"
#include "h2o/url.h"
#include "h2o/dsr.h"

h2o_iovec_t h2o_dsr_serialize_req(h2o_dsr_req_t *req)
{
    h2o_iovec_t output = h2o_iovec_init(
        h2o_mem_alloc(sizeof(
            "http-version=4294967295, quic=4294967295, cipher=65535, address=\"[0000:1111:2222:3333:4444:5555:6666:7777]:65535\"")),
        0);
    assert(req->http_version >= 0);

    output.len += sprintf(output.base + output.len, "http-version=%d", req->http_version);

    if (req->http_version == 0x300) {
        output.len += sprintf(output.base + output.len, ", quic=%" PRIu32 ", cipher=%" PRIu16 ", address=\"",
                              req->transport.quic.version, req->transport.quic.cipher);
        switch (req->transport.quic.address.sa.sa_family) {
        case AF_INET:
            inet_ntop(AF_INET, &req->transport.quic.address.sin.sin_addr, output.base + output.len, INET_ADDRSTRLEN);
            output.len += strlen(output.base + output.len);
            output.len += sprintf(output.base + output.len, ":%" PRIu16, ntohs(req->transport.quic.address.sin.sin_port));
            break;
        case AF_INET6:
            output.base[output.len++] = '[';
            inet_ntop(AF_INET6, &req->transport.quic.address.sin6.sin6_addr, output.base + output.len, INET6_ADDRSTRLEN);
            output.len += strlen(output.base + output.len);
            output.len += sprintf(output.base + output.len, "]:%" PRIu16, ntohs(req->transport.quic.address.sin.sin_port));
            break;
        default:
            h2o_fatal("unexpected address family");
            break;
        }
        output.base[output.len++] = '"';
    } else {
        assert(0 && "unexpected HTTP version in DSR request.");
    }
    output.base[output.len] = '\0';

    return output;
}

static ptls_cipher_suite_t *find_cipher(ptls_context_t *ptls, uint16_t id)
{
    ptls_cipher_suite_t **cipher;
    for (cipher = ptls->cipher_suites; *cipher != NULL; ++cipher)
        if ((*cipher)->id == id)
            break;
    return *cipher;
}

static int64_t parse_number(const char *p, size_t len, int64_t max_value)
{
    if (len == 0 || !('1' <= p[0] && p[0] <= '9'))
        return -1;
    uint64_t v = p[0] - '0';
    for (size_t i = 1; i < len; ++i) {
        if (!('0' <= p[i] && p[i] <= '9'))
            return -1;
        v = v * 10 + p[i] - '0';
        if (v >= max_value)
            return -1;
    }
    return v;
}

int h2o_dsr_parse_req(h2o_dsr_req_t *req, const char *_value, size_t _value_len, uint16_t default_port)
{
    h2o_iovec_t iter = h2o_iovec_init(_value, _value_len), value;
    const char *name;
    size_t name_len;
    int64_t n;

    memset(req, 0, sizeof(*req));
    req->transport.quic.address.sa.sa_family = AF_UNSPEC;

    while ((name = h2o_next_token(&iter, ',', ',', &name_len, &value)) != NULL) {
        if (h2o_memis(name, name_len, H2O_STRLIT("http-version"))) {
            /* parse http-version=768 (i.e. 0x300==http3) */
            int v;
            if ((v = parse_number(value.base, value.len, INT32_MAX)) < 0)
                return 0;
            req->http_version = v;
        } else if (h2o_memis(name, name_len, H2O_STRLIT("quic"))) {
            /* parse quic=4278190110 (i.e., draft-29) */
            if ((n = parse_number(value.base, value.len, UINT32_MAX)) < 0)
                return 0;
            req->transport.quic.version = (uint32_t)n;
        } else if (h2o_memis(name, name_len, H2O_STRLIT("cipher"))) {
            /* parse cipher=12345 (i.e. aes128gcmsha256) */
            if ((n = parse_number(value.base, value.len, UINT16_MAX)) < 0)
                return 0;
            req->transport.quic.cipher = (uint16_t)n;
        } else if (h2o_memis(name, name_len, H2O_STRLIT("address"))) {
            /* parse address="ip-address[:port]" */
            if (!(value.len >= 2 && value.base[0] == '"' && value.base[value.len - 1] == '"'))
                return 0;
            value.base += 1;
            value.len -= 2;
            h2o_iovec_t host;
            uint16_t port;
            if (h2o_url_parse_hostport(value.base, value.len, &host, &port) == NULL)
                return 0;
            if (port == 65535)
                port = default_port;
            /* convert address */
            char hostbuf[256];
            if (host.len >= sizeof(hostbuf))
                return 0;
            memcpy(hostbuf, host.base, host.len);
            hostbuf[host.len] = '\0';
            if (inet_pton(AF_INET, hostbuf, &req->transport.quic.address.sin.sin_addr) == 1) {
                req->transport.quic.address.sin.sin_family = AF_INET;
                req->transport.quic.address.sin.sin_port = htons(port);
            } else if (inet_pton(AF_INET6, hostbuf, &req->transport.quic.address.sin6.sin6_addr) == 1) {
                req->transport.quic.address.sin6.sin6_family = AF_INET6;
                req->transport.quic.address.sin6.sin6_port = htons(port);
            } else {
                return 0;
            }
        }
    }

    /* version-dependent validation */
    if (req->http_version == 0x300) {
        if (req->transport.quic.version == 0 || req->transport.quic.cipher == 0 ||
            req->transport.quic.address.sa.sa_family == AF_UNSPEC)
            return 0;
    } else {
        return 0;
    }

    return 1;
}

static size_t encode_address(char *const dst, struct sockaddr *sa)
{
    ptls_iovec_t ip;
    size_t off = 0;

    const in_port_t *port;
    switch (sa->sa_family) {
    case AF_INET: {
        struct sockaddr_in *sin = (void *)sa;
        ip = ptls_iovec_init(&sin->sin_addr.s_addr, 4);
        port = &sin->sin_port;
    } break;
    case AF_INET6: {
        struct sockaddr_in6 *sin6 = (void *)sa;
        ip = ptls_iovec_init(sin6->sin6_addr.s6_addr, 16);
        port = &sin6->sin6_port;
    } break;
    default:
        h2o_fatal("unsupported address type");
        break;
    }
    dst[off++] = (uint8_t)ip.len;
    memcpy(dst + off, ip.base, ip.len);
    off += ip.len;
    memcpy(dst + off, port, sizeof(*port));
    off += sizeof(*port);

    return off;
}

static ssize_t decode_address(const uint8_t *src, const uint8_t *end, struct sockaddr *sa)
{
    const uint8_t *src_begin = src;
    uint64_t iplen;
    void *sa_ip;
    in_port_t *sa_port;

    if ((iplen = ptls_decode_quicint(&src, end)) == UINT64_MAX)
        goto Incomplete;
    if (end - src < iplen + sizeof(*sa_port))
        goto Incomplete;
    switch (iplen) {
    case 4: {
        struct sockaddr_in *sin = (void *)sa;
        sin->sin_family = AF_INET;
        sa_ip = &sin->sin_addr.s_addr;
        sa_port = &sin->sin_port;
    } break;
    case 16: {
        struct sockaddr_in6 *sin6 = (void *)sa;
        sin6->sin6_family = AF_INET6;
        sa_ip = sin6->sin6_addr.s6_addr;
        sa_port = &sin6->sin6_port;
    } break;
    default:
        goto Invalid;
    }
    memcpy(sa_ip, src, iplen);
    src += iplen;
    memcpy(sa_port, src, sizeof(*sa_port));
    src += sizeof(*sa_port);

    return src - src_begin;
Invalid:
    return 0;
Incomplete:
    return -1;
}

static ssize_t decode_block(const uint8_t *src, const uint8_t *end, ptls_iovec_t *block, size_t capacity)
{
    const uint8_t *src_begin = src;
    uint64_t sz;

    if ((sz = ptls_decode_quicint(&src, end)) == UINT64_MAX)
        goto Incomplete;
    if (sz > capacity)
        goto Invalid;
    if (end - src < sz)
        goto Incomplete;

    *block = ptls_iovec_init(src, sz);
    src += sz;

    return src - src_begin;
Invalid:
    return 0;
Incomplete:
    return -1;
}

void h2o_dsr_quic_add_instruction(h2o_buffer_t **buf, h2o_dsr_quic_encoder_state_t *state, struct sockaddr *dest_addr,
                                  quicly_detached_send_packet_t *detached, uint64_t body_off, uint16_t body_len)
{
#define APPEND_BYTE(b) (*buf)->bytes[(*buf)->size++] = (b)
#define APPEND_VARINT(v) (*buf)->size = (char *)quicly_encodev((uint8_t *)((*buf)->bytes + (*buf)->size), (v)) - (*buf)->bytes
#define APPEND_VEC(p, l)                                                                                                           \
    do {                                                                                                                           \
        memcpy((*buf)->bytes + (*buf)->size, (p), (l));                                                                            \
        (*buf)->size += (l);                                                                                                       \
    } while (0)
#define APPEND_BLOCK(p, l)                                                                                                         \
    do {                                                                                                                           \
        APPEND_VARINT(l);                                                                                                          \
        APPEND_VEC((p), (l));                                                                                                      \
    } while (0)

    /* encode context when the first instruction send_packet instruction is to be sent (TODO handle key updates) */
    if (!state->context_sent) {
        h2o_buffer_init(buf, &h2o_socket_buffer_prototype);
        h2o_buffer_reserve(buf, 1024);
        /* type */
        APPEND_BYTE(H2O_DSR_DECODED_INSTRUCTION_SET_CONTEXT);
        /* write 4-tuple */
        (*buf)->size += encode_address((*buf)->bytes + (*buf)->size, dest_addr);
        /* write secrets */
        APPEND_BLOCK(detached->header_protection_secret, detached->cipher->hash->digest_size);
        APPEND_BLOCK(detached->aead_secret, detached->cipher->hash->digest_size);
        state->context_sent = 1;
    }

    /* calculate the size of the instruction */
    size_t inst_size = 1; /* for the type byte */
    inst_size += quicly_encodev_capacity(detached->datagram.len) + detached->datagram.len;
    inst_size += quicly_encodev_capacity(body_off);
    inst_size += quicly_encodev_capacity(body_len);
    inst_size += quicly_encodev_capacity(detached->packet_number);
    inst_size += quicly_encodev_capacity(detached->packet_from);
    inst_size += quicly_encodev_capacity(detached->packet_payload_from);

    /* reserve memory */
    h2o_buffer_reserve(buf, inst_size);

    /* encode the instruction */
    APPEND_BYTE(H2O_DSR_DECODED_INSTRUCTION_SEND_PACKET);
    APPEND_BLOCK(detached->datagram.base, detached->datagram.len);
    APPEND_VARINT(body_off);
    APPEND_VARINT(body_len);
    APPEND_VARINT(detached->packet_number);
    APPEND_VARINT(detached->packet_from);
    APPEND_VARINT(detached->packet_payload_from);
    assert((*buf)->size <= (*buf)->capacity);

#undef APPEND_BYTE
#undef APPEND_VARINT
#undef APPEND_VEC
#undef APPEND_BLOCK
}

ssize_t h2o_dsr_quic_decode_instruction(h2o_dsr_quic_decoded_instruction_t *instruction, const uint8_t *src, size_t len)
{
#define DECODE16(p)                                                                                                                \
    do {                                                                                                                           \
        uint64_t t;                                                                                                                \
        if ((t = ptls_decode_quicint(&src, end)) == UINT64_MAX) {                                                                  \
            goto Incomplete;                                                                                                       \
        } else if (t > UINT16_MAX) {                                                                                               \
            ret = 0; /* invalid */                                                                                                 \
            goto Invalid;                                                                                                          \
        }                                                                                                                          \
        *(p) = (uint16_t)t;                                                                                                        \
    } while (0)

    const uint8_t *src_begin = src, *end = src + len;
    size_t ret;

    instruction->type = *src++;

    switch (instruction->type) {
    case H2O_DSR_DECODED_INSTRUCTION_SET_CONTEXT:
        if ((ret = decode_address(src, end, &instruction->data.set_context.dest_addr.sa)) <= 0)
            return ret;
        src += ret;
        if ((ret = decode_block(src, end, &instruction->data.set_context.header_protection_secret, PTLS_MAX_DIGEST_SIZE)) <= 0)
            return ret;
        src += ret;
        if ((ret = decode_block(src, end, &instruction->data.set_context.aead_secret, PTLS_MAX_DIGEST_SIZE)) <= 0)
            return ret;
        src += ret;
        break;
    case H2O_DSR_DECODED_INSTRUCTION_SEND_PACKET:
        if ((ret = decode_block(src, end, &instruction->data.send_packet.prefix, UINT16_MAX)) <= 0)
            return ret;
        src += ret;
        if ((instruction->data.send_packet.body_off = ptls_decode_quicint(&src, end)) == UINT64_MAX)
            goto Incomplete;
        DECODE16(&instruction->data.send_packet.body_len);
        if ((instruction->data.send_packet._packet_number = ptls_decode_quicint(&src, end)) == UINT64_MAX)
            goto Incomplete;
        DECODE16(&instruction->data.send_packet._packet_from);
        DECODE16(&instruction->data.send_packet._packet_payload_from);
        /* check that the packet begins before the payload */
        if (!(instruction->data.send_packet._packet_from < instruction->data.send_packet._packet_payload_from))
            goto Invalid;
        /* check that the prefix expands into the payload */
        if (!(instruction->data.send_packet._packet_payload_from < instruction->data.send_packet.prefix.len))
            goto Invalid;
        break;
    default:
        goto Invalid;
    }

    return src - src_begin;

Invalid:
    return 0;
Incomplete:
    return -1;

#undef DECODE16
}

int h2o_dsr_init_quic_packet_encryptor(h2o_dsr_quic_packet_encryptor_t *encryptor, quicly_context_t *quic, uint32_t quic_version,
                                       uint16_t cipher_id)
{
    if (!quicly_is_supported_version(quic_version))
        return 0;
    encryptor->ctx = quic;
    if ((encryptor->cipher_suite = find_cipher(encryptor->ctx->tls, cipher_id)) == NULL)
        return 0;
    encryptor->header_protection_ctx = NULL;
    encryptor->aead_ctx = NULL;
    memset(encryptor->aead_secret, 0, sizeof(encryptor->aead_secret));

    return 1;
}

void h2o_dsr_dispose_quic_packet_encryptor(h2o_dsr_quic_packet_encryptor_t *encryptor)
{
    if (encryptor->header_protection_ctx != NULL)
        ptls_cipher_free(encryptor->header_protection_ctx);
    if (encryptor->aead_ctx != NULL)
        ptls_aead_free(encryptor->aead_ctx);
    ptls_clear_memory(encryptor->aead_secret, sizeof(encryptor->aead_secret));
}

int h2o_dsr_quic_packet_encryptor_set_context(h2o_dsr_quic_packet_encryptor_t *encryptor, ptls_iovec_t header_protection_secret,
                                              ptls_iovec_t aead_secret)
{
    size_t digest_size = encryptor->cipher_suite->hash->digest_size;

    /* validation */
    if (!(header_protection_secret.len == digest_size && aead_secret.len == digest_size))
        return 0;

    /* when invoked for the first time, build header protection context and the associated aead context */
    if (encryptor->header_protection_ctx == NULL) {
        if (encryptor->ctx->crypto_engine->setup_cipher(
                encryptor->ctx->crypto_engine, NULL, QUICLY_EPOCH_1RTT, 1, &encryptor->header_protection_ctx, &encryptor->aead_ctx,
                encryptor->cipher_suite->aead, encryptor->cipher_suite->hash, header_protection_secret.base) != 0)
            return 0;
        memcpy(encryptor->aead_secret, header_protection_secret.base, digest_size);
    }

    /* update AEAD context if necessary */
    if (encryptor->aead_ctx == NULL ||
        memcmp(encryptor->aead_secret, aead_secret.base, encryptor->cipher_suite->hash->digest_size) != 0) {
        if (encryptor->aead_ctx != NULL)
            ptls_aead_free(encryptor->aead_ctx);
        if (encryptor->ctx->crypto_engine->setup_cipher(encryptor->ctx->crypto_engine, NULL, QUICLY_EPOCH_1RTT, 1, NULL,
                                                        &encryptor->aead_ctx, encryptor->cipher_suite->aead,
                                                        encryptor->cipher_suite->hash, aead_secret.base) != 0)
            return 0;
        memcpy(encryptor->aead_secret, aead_secret.base, digest_size);
    }

    return 1;
}

void h2o_dsr_encrypt_quic_packet(h2o_dsr_quic_packet_encryptor_t *encryptor, h2o_dsr_quic_decoded_instruction_t *instruction,
                                 ptls_iovec_t datagram)
{
    assert(instruction->type == H2O_DSR_DECODED_INSTRUCTION_SEND_PACKET);
    encryptor->ctx->crypto_engine->encrypt_packet(encryptor->ctx->crypto_engine, NULL, encryptor->header_protection_ctx,
                                                  encryptor->aead_ctx, datagram, instruction->data.send_packet._packet_from,
                                                  instruction->data.send_packet._packet_payload_from,
                                                  instruction->data.send_packet._packet_number, 0);
}
