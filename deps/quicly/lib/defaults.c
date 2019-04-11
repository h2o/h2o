/*
 * Copyright (c) 2017-2019 Fastly, Kazuho Oku
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
#include <sys/time.h>
#include "quicly/defaults.h"

const quicly_context_t quicly_default_context = {
    NULL,                      /* tls */
    QUICLY_MAX_PACKET_SIZE,    /* max_packet_size */
    &quicly_loss_default_conf, /* loss */
    {
        {1 * 1024 * 1024, 1 * 1024 * 1024, 1 * 1024 * 1024}, /* max_stream_data */
        16 * 1024 * 1024,                                    /* max_data */
        10 * 60 * 1000,                                      /* idle_timeout (10 minutes) */
        100,                                                 /* max_concurrent_streams_bidi */
        0                                                    /* max_concurrent_streams_uni */
    },
    0, /* enforce_version_negotiation */
    0, /* is_clustered */
    &quicly_default_packet_allocator,
    NULL,
    NULL, /* on_stream_open */
    &quicly_default_stream_scheduler,
    NULL, /* on_conn_close */
    &quicly_default_now,
    {0, NULL}, /* event_log */
};

static quicly_datagram_t *default_alloc_packet(quicly_packet_allocator_t *self, socklen_t salen, size_t payloadsize)
{
    quicly_datagram_t *packet;

    if ((packet = malloc(offsetof(quicly_datagram_t, sa) + salen + payloadsize)) == NULL)
        return NULL;
    packet->salen = salen;
    packet->data.base = (uint8_t *)packet + offsetof(quicly_datagram_t, sa) + salen;

    return packet;
}

static void default_free_packet(quicly_packet_allocator_t *self, quicly_datagram_t *packet)
{
    free(packet);
}

quicly_packet_allocator_t quicly_default_packet_allocator = {default_alloc_packet, default_free_packet};

struct st_quicly_default_encrypt_cid_t {
    quicly_cid_encryptor_t super;
    ptls_cipher_context_t *cid_encrypt_ctx, *cid_decrypt_ctx;
    ptls_hash_context_t *stateless_reset_token_ctx;
};

static int expand_cid_encryption_key(ptls_cipher_algorithm_t *cipher, ptls_hash_algorithm_t *hash, void *cid_key, ptls_iovec_t key)
{
    return ptls_hkdf_expand_label(hash, cid_key, cipher->key_size, key, "cid", ptls_iovec_init(NULL, 0), "");
}

static void generate_stateless_reset_token(struct st_quicly_default_encrypt_cid_t *self, void *token, const void *cid)
{
    uint8_t md[PTLS_MAX_DIGEST_SIZE];
    self->stateless_reset_token_ctx->update(self->stateless_reset_token_ctx, cid, self->cid_encrypt_ctx->algo->block_size);
    self->stateless_reset_token_ctx->final(self->stateless_reset_token_ctx, md, PTLS_HASH_FINAL_MODE_RESET);
    memcpy(token, md, QUICLY_STATELESS_RESET_TOKEN_LEN);
}

static void default_encrypt_cid(quicly_cid_encryptor_t *_self, quicly_cid_t *encrypted, void *stateless_reset_token,
                                const quicly_cid_plaintext_t *plaintext)
{
    struct st_quicly_default_encrypt_cid_t *self = (void *)_self;
    uint8_t buf[16], *p;

    /* encode */
    p = buf;
    switch (self->cid_encrypt_ctx->algo->block_size) {
    case 8:
        break;
    case 16:
        p = quicly_encode64(p, plaintext->node_id);
        break;
    default:
        assert(!"unexpected block size");
        break;
    }
    p = quicly_encode32(p, plaintext->master_id);
    p = quicly_encode32(p, (plaintext->thread_id << 8) | plaintext->path_id);
    assert(p - buf == self->cid_encrypt_ctx->algo->block_size);

    /* generate CID */
    ptls_cipher_encrypt(self->cid_encrypt_ctx, encrypted->cid, buf, self->cid_encrypt_ctx->algo->block_size);
    encrypted->len = self->cid_encrypt_ctx->algo->block_size;

    /* generate stateless reset token if requested */
    if (stateless_reset_token != NULL)
        generate_stateless_reset_token(self, stateless_reset_token, encrypted->cid);
}

static size_t default_decrypt_cid(quicly_cid_encryptor_t *_self, quicly_cid_plaintext_t *plaintext, const void *encrypted,
                                  size_t len)
{
    struct st_quicly_default_encrypt_cid_t *self = (void *)_self;
    uint8_t ptbuf[16], tmpbuf[16];
    const uint8_t *p;
    size_t cid_len;

    cid_len = self->cid_decrypt_ctx->algo->block_size;

    /* normalize the input, so that we would get consistent routing */
    if (len != 0 && len != cid_len) {
        if (len > cid_len)
            len = cid_len;
        memcpy(tmpbuf, encrypted, cid_len);
        if (len < cid_len)
            memset(tmpbuf + len, 0, cid_len - len);
        encrypted = tmpbuf;
    }

    /* decrypt */
    ptls_cipher_encrypt(self->cid_decrypt_ctx, ptbuf, encrypted, cid_len);

    /* decode */
    p = ptbuf;
    if (cid_len == 16) {
        plaintext->node_id = quicly_decode64(&p);
    } else {
        plaintext->node_id = 0;
    }
    plaintext->master_id = quicly_decode32(&p);
    plaintext->thread_id = quicly_decode24(&p);
    plaintext->path_id = *p++;
    assert(p - ptbuf == cid_len);

    return cid_len;
}

static int default_generate_stateless_reset_token(quicly_cid_encryptor_t *_self, void *token, const void *cid)
{
    struct st_quicly_default_encrypt_cid_t *self = (void *)_self;
    generate_stateless_reset_token(self, token, cid);
    return 1;
}

quicly_cid_encryptor_t *quicly_new_default_cid_encryptor(ptls_cipher_algorithm_t *cipher, ptls_hash_algorithm_t *hash,
                                                         ptls_iovec_t key)
{
    uint8_t key_digestbuf[PTLS_MAX_DIGEST_SIZE], cid_keybuf[PTLS_MAX_SECRET_SIZE], reset_keybuf[PTLS_MAX_DIGEST_SIZE];
    ptls_cipher_context_t *cid_encrypt_ctx = NULL, *cid_decrypt_ctx = NULL;
    ptls_hash_context_t *stateless_reset_token_ctx = NULL;
    struct st_quicly_default_encrypt_cid_t *self = NULL;

    if (key.len > hash->block_size) {
        ptls_calc_hash(hash, key_digestbuf, key.base, key.len);
        key = ptls_iovec_init(key_digestbuf, hash->digest_size);
    }

    if (expand_cid_encryption_key(cipher, hash, cid_keybuf, key) != 0)
        goto Exit;
    if (ptls_hkdf_expand_label(hash, reset_keybuf, hash->digest_size, key, "reset", ptls_iovec_init(NULL, 0), "") != 0)
        goto Exit;
    if ((cid_encrypt_ctx = ptls_cipher_new(cipher, 1, cid_keybuf)) == NULL)
        goto Exit;
    if ((cid_decrypt_ctx = ptls_cipher_new(cipher, 0, cid_keybuf)) == NULL)
        goto Exit;
    if ((stateless_reset_token_ctx = ptls_hmac_create(hash, reset_keybuf, hash->digest_size)) == NULL)
        goto Exit;
    if ((self = malloc(sizeof(*self))) == NULL)
        goto Exit;

    *self =
        (struct st_quicly_default_encrypt_cid_t){{default_encrypt_cid, default_decrypt_cid, default_generate_stateless_reset_token},
                                                 cid_encrypt_ctx,
                                                 cid_decrypt_ctx,
                                                 stateless_reset_token_ctx};
    cid_encrypt_ctx = NULL;
    cid_decrypt_ctx = NULL;
    stateless_reset_token_ctx = NULL;

Exit:
    if (stateless_reset_token_ctx != NULL)
        stateless_reset_token_ctx->final(stateless_reset_token_ctx, NULL, PTLS_HASH_FINAL_MODE_FREE);
    if (cid_encrypt_ctx != NULL)
        ptls_cipher_free(cid_encrypt_ctx);
    if (cid_decrypt_ctx != NULL)
        ptls_cipher_free(cid_decrypt_ctx);
    ptls_clear_memory(key_digestbuf, sizeof(key_digestbuf));
    ptls_clear_memory(cid_keybuf, sizeof(cid_keybuf));
    ptls_clear_memory(reset_keybuf, sizeof(reset_keybuf));
    return &self->super;
}

void quicly_free_default_cid_encryptor(quicly_cid_encryptor_t *_self)
{
    struct st_quicly_default_encrypt_cid_t *self = (void *)_self;

    ptls_cipher_free(self->cid_encrypt_ctx);
    ptls_cipher_free(self->cid_decrypt_ctx);
    self->stateless_reset_token_ctx->final(self->stateless_reset_token_ctx, NULL, PTLS_HASH_FINAL_MODE_FREE);
    free(self);
}

static int default_stream_scheduler_can_send(quicly_stream_scheduler_t *self, quicly_conn_t *_conn, int including_new_data)
{
    struct _st_quicly_conn_public_t *conn = (struct _st_quicly_conn_public_t *)_conn;
    if (including_new_data) {
        if (quicly_linklist_is_linked(&conn->_default_scheduler.new_data))
            return 1;
    }
    if (quicly_linklist_is_linked(&conn->_default_scheduler.non_new_data))
        return 1;
    return 0;
}

static int default_stream_scheduler_do_send(quicly_stream_scheduler_t *self, quicly_conn_t *_conn, quicly_send_context_t *s)
{
#define SEND_ONE(anchor)                                                                                                           \
    do {                                                                                                                           \
        quicly_stream_t *stream =                                                                                                  \
            (void *)((char *)(anchor)->next - offsetof(quicly_stream_t, _send_aux.pending_link.default_scheduler));                \
        if ((ret = quicly_send_stream(stream, s)) != 0)                                                                            \
            goto Exit;                                                                                                             \
    } while (0)

    struct _st_quicly_conn_public_t *conn = (struct _st_quicly_conn_public_t *)_conn;
    int ret = 0;

    /* retransmits and fin-only STREAM frames */
    while (quicly_can_send_stream_data((quicly_conn_t *)conn, s, 0) &&
           quicly_linklist_is_linked(&conn->_default_scheduler.non_new_data))
        SEND_ONE(&conn->_default_scheduler.non_new_data);
    /* STREAMS with data */
    while (quicly_can_send_stream_data((quicly_conn_t *)conn, s, 1) &&
           quicly_linklist_is_linked(&conn->_default_scheduler.new_data)) {
        SEND_ONE(&conn->_default_scheduler.new_data);
    }

Exit:
    return ret;

#undef SEND_ONE
}

static void default_stream_scheduler_clear(quicly_stream_scheduler_t *self, quicly_stream_t *stream)
{
    quicly_linklist_unlink(&stream->_send_aux.pending_link.default_scheduler);
}

static void schedule_to_slot(quicly_linklist_t *slot, quicly_stream_t *stream)
{
    if (quicly_linklist_is_linked(&stream->_send_aux.pending_link.default_scheduler))
        quicly_linklist_unlink(&stream->_send_aux.pending_link.default_scheduler);
    quicly_linklist_insert(slot, &stream->_send_aux.pending_link.default_scheduler);
}

static void default_stream_scheduler_set_new_data(quicly_stream_scheduler_t *self, quicly_stream_t *stream)
{
    struct _st_quicly_conn_public_t *conn = (struct _st_quicly_conn_public_t *)stream->conn;
    schedule_to_slot(&conn->_default_scheduler.new_data, stream);
}

static void default_stream_scheduler_set_non_new_data(quicly_stream_scheduler_t *self, quicly_stream_t *stream)
{
    struct _st_quicly_conn_public_t *conn = (struct _st_quicly_conn_public_t *)stream->conn;
    schedule_to_slot(&conn->_default_scheduler.non_new_data, stream);
}

quicly_stream_scheduler_t quicly_default_stream_scheduler = {default_stream_scheduler_can_send, default_stream_scheduler_do_send,
                                                             default_stream_scheduler_clear, default_stream_scheduler_set_new_data,
                                                             default_stream_scheduler_set_non_new_data};

quicly_stream_t *quicly_default_alloc_stream(quicly_context_t *ctx)
{
    return malloc(sizeof(quicly_stream_t));
}

void quicly_default_free_stream(quicly_stream_t *stream)
{
    free(stream);
}

static int64_t default_now(quicly_now_t *self)
{
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return (int64_t)tv.tv_sec * 1000 + tv.tv_usec / 1000;
}

quicly_now_t quicly_default_now = {default_now};

struct st_quicly_default_event_log_t {
    quicly_event_logger_t super;
    FILE *fp;
};

static void default_event_log(quicly_event_logger_t *_self, quicly_event_type_t type, const quicly_event_attribute_t *attributes,
                              size_t num_attributes)
{
    struct st_quicly_default_event_log_t *self = (void *)_self;
    ptls_buffer_t buf;
    uint8_t smallbuf[256];
    size_t i, j;

    ptls_buffer_init(&buf, smallbuf, sizeof(smallbuf));

#define EMIT(s)                                                                                                                    \
    do {                                                                                                                           \
        const char *_s = (s);                                                                                                      \
        size_t _l = strlen(_s);                                                                                                    \
        if (ptls_buffer_reserve(&buf, _l) != 0)                                                                                    \
            goto Exit;                                                                                                             \
        memcpy(buf.base + buf.off, _s, _l);                                                                                        \
        buf.off += _l;                                                                                                             \
    } while (0)

    EMIT("{\"type\":\"");
    EMIT(quicly_event_type_names[type]);
    EMIT("\"");
    for (i = 0; i != num_attributes; ++i) {
        const quicly_event_attribute_t *attr = attributes + i;
        if (attr->type == QUICLY_EVENT_ATTRIBUTE_NULL)
            continue;
        EMIT(", \"");
        EMIT(quicly_event_attribute_names[attr->type]);
        if (QUICLY_EVENT_ATTRIBUTE_TYPE_INT_MIN <= attr->type && attr->type < QUICLY_EVENT_ATTRIBUTE_TYPE_INT_MAX) {
            char int64buf[sizeof("-9223372036854775808")];
            sprintf(int64buf, "\":%" PRId64, attr->value.i);
            EMIT(int64buf);
        } else if (QUICLY_EVENT_ATTRIBUTE_TYPE_VEC_MIN <= attr->type && attr->type < QUICLY_EVENT_ATTRIBUTE_TYPE_VEC_MAX) {
            EMIT("\":\"");
            if (ptls_buffer_reserve(&buf, attr->value.v.len * 2) != 0)
                goto Exit;
            for (j = 0; j != attr->value.v.len; ++j) {
                quicly_byte_to_hex((void *)(buf.base + buf.off), attr->value.v.base[j]);
                buf.off += 2;
            }
            EMIT("\"");
        } else {
            assert(!"unexpected type");
        }
    }
    EMIT("}\n");

#undef EMIT

    fwrite(buf.base, 1, buf.off, self->fp);

Exit:
    ptls_buffer_dispose(&buf);
}

quicly_event_logger_t *quicly_new_default_event_logger(FILE *fp)
{
    struct st_quicly_default_event_log_t *self;

    if ((self = malloc(sizeof(*self))) == NULL)
        return NULL;
    *self = (struct st_quicly_default_event_log_t){{default_event_log}, fp};
    return &self->super;
}

void quicly_free_default_event_logger(quicly_event_logger_t *_self)
{
    struct st_quicly_default_event_log_t *self = (void *)_self;
    free(self);
}
