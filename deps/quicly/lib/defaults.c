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

#define DEFAULT_INITIAL_EGRESS_MAX_UDP_PAYLOAD_SIZE 1280
#define DEFAULT_MAX_UDP_PAYLOAD_SIZE 1472
#define DEFAULT_MAX_PACKETS_PER_KEY 16777216
#define DEFAULT_MAX_CRYPTO_BYTES 65536
#define DEFAULT_PRE_VALIDATION_AMPLIFICATION_LIMIT 3

/* profile that employs IETF specified values */
const quicly_context_t quicly_spec_context = {NULL,                                                 /* tls */
                                              DEFAULT_INITIAL_EGRESS_MAX_UDP_PAYLOAD_SIZE,          /* client_initial_size */
                                              QUICLY_LOSS_SPEC_CONF,                                /* loss */
                                              {{1 * 1024 * 1024, 1 * 1024 * 1024, 1 * 1024 * 1024}, /* max_stream_data */
                                               16 * 1024 * 1024,                                    /* max_data */
                                               30 * 1000,                                           /* idle_timeout (30 seconds) */
                                               100, /* max_concurrent_streams_bidi */
                                               0,   /* max_concurrent_streams_uni */
                                               DEFAULT_MAX_UDP_PAYLOAD_SIZE},
                                              DEFAULT_MAX_PACKETS_PER_KEY,
                                              DEFAULT_MAX_CRYPTO_BYTES,
                                              QUICLY_PROTOCOL_VERSION_CURRENT,
                                              DEFAULT_PRE_VALIDATION_AMPLIFICATION_LIMIT,
                                              0, /* is_clustered */
                                              0, /* enlarge_client_hello */
                                              NULL,
                                              NULL, /* on_stream_open */
                                              &quicly_default_stream_scheduler,
                                              NULL, /* on_conn_close */
                                              &quicly_default_now,
                                              NULL,
                                              NULL,
                                              &quicly_default_crypto_engine,
                                              &quicly_default_init_cc};

/* profile with a focus on reducing latency for the HTTP use case */
const quicly_context_t quicly_performant_context = {NULL,                                                 /* tls */
                                                    DEFAULT_INITIAL_EGRESS_MAX_UDP_PAYLOAD_SIZE,          /* client_initial_size */
                                                    QUICLY_LOSS_PERFORMANT_CONF,                          /* loss */
                                                    {{1 * 1024 * 1024, 1 * 1024 * 1024, 1 * 1024 * 1024}, /* max_stream_data */
                                                     16 * 1024 * 1024,                                    /* max_data */
                                                     30 * 1000, /* idle_timeout (30 seconds) */
                                                     100,       /* max_concurrent_streams_bidi */
                                                     0,         /* max_concurrent_streams_uni */
                                                     DEFAULT_MAX_UDP_PAYLOAD_SIZE},
                                                    DEFAULT_MAX_PACKETS_PER_KEY,
                                                    DEFAULT_MAX_CRYPTO_BYTES,
                                                    QUICLY_PROTOCOL_VERSION_CURRENT,
                                                    DEFAULT_PRE_VALIDATION_AMPLIFICATION_LIMIT,
                                                    0, /* is_clustered */
                                                    0, /* enlarge_client_hello */
                                                    NULL,
                                                    NULL, /* on_stream_open */
                                                    &quicly_default_stream_scheduler,
                                                    NULL, /* on_conn_close */
                                                    &quicly_default_now,
                                                    NULL,
                                                    NULL,
                                                    &quicly_default_crypto_engine,
                                                    &quicly_default_init_cc};

/**
 * The context of the default CID encryptor.  All the contexts being used here are ECB ciphers and therefore stateless - they can be
 * used concurrently from multiple threads.
 */
struct st_quicly_default_encrypt_cid_t {
    quicly_cid_encryptor_t super;
    ptls_cipher_context_t *cid_encrypt_ctx, *cid_decrypt_ctx, *reset_token_ctx;
};

static void generate_reset_token(struct st_quicly_default_encrypt_cid_t *self, void *token, const void *cid)
{
    uint8_t expandbuf[QUICLY_STATELESS_RESET_TOKEN_LEN];

    assert(self->reset_token_ctx->algo->block_size == QUICLY_STATELESS_RESET_TOKEN_LEN);

    /* expand the input to full size, if CID is shorter than the size of the reset token */
    if (self->cid_encrypt_ctx->algo->block_size != QUICLY_STATELESS_RESET_TOKEN_LEN) {
        assert(self->cid_encrypt_ctx->algo->block_size < QUICLY_STATELESS_RESET_TOKEN_LEN);
        memset(expandbuf, 0, sizeof(expandbuf));
        memcpy(expandbuf, cid, self->cid_encrypt_ctx->algo->block_size);
        cid = expandbuf;
    }

    /* transform */
    ptls_cipher_encrypt(self->reset_token_ctx, token, cid, QUICLY_STATELESS_RESET_TOKEN_LEN);
}

static void default_encrypt_cid(quicly_cid_encryptor_t *_self, quicly_cid_t *encrypted, void *reset_token,
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
    if (reset_token != NULL)
        generate_reset_token(self, reset_token, encrypted->cid);
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

static int default_generate_reset_token(quicly_cid_encryptor_t *_self, void *token, const void *cid)
{
    struct st_quicly_default_encrypt_cid_t *self = (void *)_self;
    generate_reset_token(self, token, cid);
    return 1;
}

quicly_cid_encryptor_t *quicly_new_default_cid_encryptor(ptls_cipher_algorithm_t *cid_cipher,
                                                         ptls_cipher_algorithm_t *reset_token_cipher, ptls_hash_algorithm_t *hash,
                                                         ptls_iovec_t key)
{
    struct st_quicly_default_encrypt_cid_t *self;
    uint8_t digestbuf[PTLS_MAX_DIGEST_SIZE], keybuf[PTLS_MAX_SECRET_SIZE];

    assert(cid_cipher->block_size == 8 || cid_cipher->block_size == 16);
    assert(reset_token_cipher->block_size == 16);

    if (key.len > hash->block_size) {
        ptls_calc_hash(hash, digestbuf, key.base, key.len);
        key = ptls_iovec_init(digestbuf, hash->digest_size);
    }

    if ((self = malloc(sizeof(*self))) == NULL)
        goto Fail;
    *self = (struct st_quicly_default_encrypt_cid_t){{default_encrypt_cid, default_decrypt_cid, default_generate_reset_token}};

    if (ptls_hkdf_expand_label(hash, keybuf, cid_cipher->key_size, key, "cid", ptls_iovec_init(NULL, 0), "") != 0)
        goto Fail;
    if ((self->cid_encrypt_ctx = ptls_cipher_new(cid_cipher, 1, keybuf)) == NULL)
        goto Fail;
    if ((self->cid_decrypt_ctx = ptls_cipher_new(cid_cipher, 0, keybuf)) == NULL)
        goto Fail;
    if (ptls_hkdf_expand_label(hash, keybuf, reset_token_cipher->key_size, key, "reset", ptls_iovec_init(NULL, 0), "") != 0)
        goto Fail;
    if ((self->reset_token_ctx = ptls_cipher_new(reset_token_cipher, 1, keybuf)) == NULL)
        goto Fail;

    ptls_clear_memory(digestbuf, sizeof(digestbuf));
    ptls_clear_memory(keybuf, sizeof(keybuf));
    return &self->super;

Fail:
    if (self != NULL) {
        if (self->cid_encrypt_ctx != NULL)
            ptls_cipher_free(self->cid_encrypt_ctx);
        if (self->cid_decrypt_ctx != NULL)
            ptls_cipher_free(self->cid_decrypt_ctx);
        if (self->reset_token_ctx != NULL)
            ptls_cipher_free(self->reset_token_ctx);
        free(self);
    }
    ptls_clear_memory(digestbuf, sizeof(digestbuf));
    ptls_clear_memory(keybuf, sizeof(keybuf));
    return NULL;
}

void quicly_free_default_cid_encryptor(quicly_cid_encryptor_t *_self)
{
    struct st_quicly_default_encrypt_cid_t *self = (void *)_self;

    ptls_cipher_free(self->cid_encrypt_ctx);
    ptls_cipher_free(self->cid_decrypt_ctx);
    ptls_cipher_free(self->reset_token_ctx);
    free(self);
}

/**
 * See doc-comment of `st_quicly_default_scheduler_state_t` to understand the logic.
 */
static int default_stream_scheduler_can_send(quicly_stream_scheduler_t *self, quicly_conn_t *conn, int conn_is_saturated)
{
    struct st_quicly_default_scheduler_state_t *sched = &((struct _st_quicly_conn_public_t *)conn)->_default_scheduler;

    if (!conn_is_saturated) {
        /* not saturated */
        quicly_linklist_insert_list(&sched->active, &sched->blocked);
    } else {
        /* The code below is disabled, because H2O's scheduler doesn't allow you to "walk" the priority tree without actually
         * running the round robin, and we want quicly's default to behave like H2O so that we can catch errors.  The downside is
         * that there'd be at most one spurious call of `quicly_send` when the connection is saturated, but that should be fine.
         */
        if (0) {
            /* Saturated. Lazily move such streams to the "blocked" list, at the same time checking if anything can be sent. */
            while (quicly_linklist_is_linked(&sched->active)) {
                quicly_stream_t *stream =
                    (void *)((char *)sched->active.next - offsetof(quicly_stream_t, _send_aux.pending_link.default_scheduler));
                if (quicly_stream_can_send(stream, 0))
                    return 1;
                quicly_linklist_unlink(&stream->_send_aux.pending_link.default_scheduler);
                quicly_linklist_insert(sched->blocked.prev, &stream->_send_aux.pending_link.default_scheduler);
            }
        }
    }

    return quicly_linklist_is_linked(&sched->active);
}

static void link_stream(struct st_quicly_default_scheduler_state_t *sched, quicly_stream_t *stream, int conn_is_blocked)
{
    if (!quicly_linklist_is_linked(&stream->_send_aux.pending_link.default_scheduler)) {
        quicly_linklist_t *slot = &sched->active;
        if (conn_is_blocked && !quicly_stream_can_send(stream, 0))
            slot = &sched->blocked;
        quicly_linklist_insert(slot->prev, &stream->_send_aux.pending_link.default_scheduler);
    }
}

/**
 * See doc-comment of `st_quicly_default_scheduler_state_t` to understand the logic.
 */
static int default_stream_scheduler_do_send(quicly_stream_scheduler_t *self, quicly_conn_t *conn, quicly_send_context_t *s)
{
    struct st_quicly_default_scheduler_state_t *sched = &((struct _st_quicly_conn_public_t *)conn)->_default_scheduler;
    int conn_is_blocked = quicly_is_blocked(conn), ret = 0;

    if (!conn_is_blocked)
        quicly_linklist_insert_list(&sched->active, &sched->blocked);

    while (quicly_can_send_data((quicly_conn_t *)conn, s) && quicly_linklist_is_linked(&sched->active)) {
        /* detach the first active stream */
        quicly_stream_t *stream =
            (void *)((char *)sched->active.next - offsetof(quicly_stream_t, _send_aux.pending_link.default_scheduler));
        quicly_linklist_unlink(&stream->_send_aux.pending_link.default_scheduler);
        /* relink the stream to the blocked list if necessary */
        if (conn_is_blocked && !quicly_stream_can_send(stream, 0)) {
            quicly_linklist_insert(sched->blocked.prev, &stream->_send_aux.pending_link.default_scheduler);
            continue;
        }
        /* send! */
        if ((ret = quicly_send_stream(stream, s)) != 0) {
            /* FIXME Stop quicly_send_stream emitting SENDBUF_FULL (happpens when CWND is congested). Otherwise, we need to make
             * adjustments to the scheduler after popping a stream */
            if (ret == QUICLY_ERROR_SENDBUF_FULL) {
                assert(quicly_stream_can_send(stream, 1));
                link_stream(sched, stream, conn_is_blocked);
            }
            break;
        }
        /* reschedule */
        conn_is_blocked = quicly_is_blocked(conn);
        if (quicly_stream_can_send(stream, 1))
            link_stream(sched, stream, conn_is_blocked);
    }

    return ret;
}

/**
 * See doc-comment of `st_quicly_default_scheduler_state_t` to understand the logic.
 */
static int default_stream_scheduler_update_state(quicly_stream_scheduler_t *self, quicly_stream_t *stream)
{
    struct st_quicly_default_scheduler_state_t *sched = &((struct _st_quicly_conn_public_t *)stream->conn)->_default_scheduler;

    if (quicly_stream_can_send(stream, 1)) {
        /* activate if not */
        link_stream(sched, stream, quicly_is_blocked(stream->conn));
    } else {
        /* disactivate if active */
        if (quicly_linklist_is_linked(&stream->_send_aux.pending_link.default_scheduler))
            quicly_linklist_unlink(&stream->_send_aux.pending_link.default_scheduler);
    }

    return 0;
}

quicly_stream_scheduler_t quicly_default_stream_scheduler = {default_stream_scheduler_can_send, default_stream_scheduler_do_send,
                                                             default_stream_scheduler_update_state};

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
    int64_t tv_now = (int64_t)tv.tv_sec * 1000 + tv.tv_usec / 1000;

    /* make sure that the time does not get rewind */
    static __thread int64_t now;
    if (now < tv_now)
        now = tv_now;
    return now;
}

quicly_now_t quicly_default_now = {default_now};

static int default_setup_cipher(quicly_crypto_engine_t *engine, quicly_conn_t *conn, size_t epoch, int is_enc,
                                ptls_cipher_context_t **hp_ctx, ptls_aead_context_t **aead_ctx, ptls_aead_algorithm_t *aead,
                                ptls_hash_algorithm_t *hash, const void *secret)
{
    uint8_t hpkey[PTLS_MAX_SECRET_SIZE];
    int ret;

    if (hp_ctx != NULL)
        *hp_ctx = NULL;
    *aead_ctx = NULL;

    /* generate new header protection key */
    if (hp_ctx != NULL) {
        if ((ret = ptls_hkdf_expand_label(hash, hpkey, aead->ctr_cipher->key_size, ptls_iovec_init(secret, hash->digest_size),
                                          "quic hp", ptls_iovec_init(NULL, 0), NULL)) != 0)
            goto Exit;
        if ((*hp_ctx = ptls_cipher_new(aead->ctr_cipher, is_enc, hpkey)) == NULL) {
            ret = PTLS_ERROR_NO_MEMORY;
            goto Exit;
        }
    }

    /* generate new AEAD context */
    if ((*aead_ctx = ptls_aead_new(aead, hash, is_enc, secret, QUICLY_AEAD_BASE_LABEL)) == NULL) {
        ret = PTLS_ERROR_NO_MEMORY;
        goto Exit;
    }
    if (QUICLY_DEBUG) {
        char *secret_hex = quicly_hexdump(secret, hash->digest_size, SIZE_MAX),
             *hpkey_hex = quicly_hexdump(hpkey, aead->ctr_cipher->key_size, SIZE_MAX);
        fprintf(stderr, "%s:\n  aead-secret: %s\n  hp-key: %s\n", __FUNCTION__, secret_hex, hpkey_hex);
        free(secret_hex);
        free(hpkey_hex);
    }

    ret = 0;
Exit:
    if (ret != 0) {
        if (*aead_ctx != NULL) {
            ptls_aead_free(*aead_ctx);
            *aead_ctx = NULL;
        }
        if (*hp_ctx != NULL) {
            ptls_cipher_free(*hp_ctx);
            *hp_ctx = NULL;
        }
    }
    ptls_clear_memory(hpkey, sizeof(hpkey));
    return ret;
}

static void default_finalize_send_packet(quicly_crypto_engine_t *engine, quicly_conn_t *conn,
                                         ptls_cipher_context_t *header_protect_ctx, ptls_aead_context_t *packet_protect_ctx,
                                         ptls_iovec_t datagram, size_t first_byte_at, size_t payload_from, uint64_t packet_number,
                                         int coalesced)
{
    ptls_aead_supplementary_encryption_t supp = {.ctx = header_protect_ctx,
                                                 .input = datagram.base + payload_from - QUICLY_SEND_PN_SIZE + QUICLY_MAX_PN_SIZE};

    ptls_aead_encrypt_s(packet_protect_ctx, datagram.base + payload_from, datagram.base + payload_from,
                        datagram.len - payload_from - packet_protect_ctx->algo->tag_size, packet_number,
                        datagram.base + first_byte_at, payload_from - first_byte_at, &supp);

    datagram.base[first_byte_at] ^= supp.output[0] & (QUICLY_PACKET_IS_LONG_HEADER(datagram.base[first_byte_at]) ? 0xf : 0x1f);
    for (size_t i = 0; i != QUICLY_SEND_PN_SIZE; ++i)
        datagram.base[payload_from + i - QUICLY_SEND_PN_SIZE] ^= supp.output[i + 1];
}

quicly_crypto_engine_t quicly_default_crypto_engine = {default_setup_cipher, default_finalize_send_packet};
