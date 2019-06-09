/*
 * Copyright (c) 2015 DeNA Co., Ltd., Kazuho Oku
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
#include <inttypes.h>
#include <pthread.h>
#include <sys/stat.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/ssl.h>
#include "h2o/hiredis_.h"
#include "yoml-parser.h"
#include "yrmcds.h"
#if H2O_USE_PICOTLS
#include "picotls.h"
#include "picotls/openssl.h"
#endif
#include "h2o/file.h"
#include "h2o.h"
#include "h2o/configurator.h"
#include "standalone.h"

struct st_session_ticket_generating_updater_conf_t {
    const EVP_CIPHER *cipher;
    const EVP_MD *md;
};

struct st_session_ticket_file_updater_conf_t {
    const char *filename;
};

static struct {
    struct {
        void (*setup)(SSL_CTX **contexts, size_t num_contexts);
        union {
            struct {
                char *prefix;
                size_t num_threads;
            } memcached;
            struct {
                char *prefix;
            } redis;
        } vars;
    } cache;
    struct {
        void *(*update_thread)(void *conf);
        union {
            struct st_session_ticket_generating_updater_conf_t generating;
            struct {
                struct st_session_ticket_generating_updater_conf_t generating; /* at same address as conf.ticket.vars.generating */
                h2o_iovec_t key;
            } memcached;
            struct {
                struct st_session_ticket_generating_updater_conf_t generating; /* same as above */
                h2o_iovec_t key;
            } redis;
            struct st_session_ticket_file_updater_conf_t file;
        } vars;
    } ticket;
    unsigned lifetime;
    union {
        struct {
            char *host;
            uint16_t port;
            int text_protocol;
        } memcached;
        struct {
            char *host;
            uint16_t port;
        } redis;
    } store;
} conf;

H2O_NORETURN static void *cache_cleanup_thread(void *_contexts)
{
    SSL_CTX **contexts = _contexts;

    while (1) {
        size_t i;
        for (i = 0; contexts[i] != NULL; ++i)
            SSL_CTX_flush_sessions(contexts[i], time(NULL));
        sleep(conf.lifetime / 4);
    }
}

static void spawn_cache_cleanup_thread(SSL_CTX **_contexts, size_t num_contexts)
{
    /* copy the list of contexts */
    SSL_CTX **contexts = h2o_mem_alloc(sizeof(*contexts) * (num_contexts + 1));
    h2o_memcpy(contexts, _contexts, sizeof(*contexts) * num_contexts);
    contexts[num_contexts] = NULL;

    /* launch the thread */
    pthread_t tid;
    pthread_attr_t attr;
    pthread_attr_init(&attr);
    pthread_attr_setdetachstate(&attr, 1);
    h2o_multithread_create_thread(&tid, &attr, cache_cleanup_thread, contexts);
}

static void setup_cache_disable(SSL_CTX **contexts, size_t num_contexts)
{
    size_t i;
    for (i = 0; i != num_contexts; ++i)
        SSL_CTX_set_session_cache_mode(contexts[i], SSL_SESS_CACHE_OFF);
}

static void setup_cache_enable(SSL_CTX **contexts, size_t num_contexts, int async_resumption)
{
    size_t i;
    for (i = 0; i != num_contexts; ++i) {
        SSL_CTX_set_session_cache_mode(contexts[i], SSL_SESS_CACHE_SERVER | SSL_SESS_CACHE_NO_AUTO_CLEAR);
        SSL_CTX_set_timeout(contexts[i], conf.lifetime);
        if (async_resumption)
            h2o_socket_ssl_async_resumption_setup_ctx(contexts[i]);
    }
    spawn_cache_cleanup_thread(contexts, num_contexts);
}

static void setup_cache_internal(SSL_CTX **contexts, size_t num_contexts)
{
    setup_cache_enable(contexts, num_contexts, 0);
}

static void setup_cache_memcached(SSL_CTX **contexts, size_t num_contexts)
{
    h2o_memcached_context_t *memc_ctx =
        h2o_memcached_create_context(conf.store.memcached.host, conf.store.memcached.port, conf.store.memcached.text_protocol,
                                     conf.cache.vars.memcached.num_threads, conf.cache.vars.memcached.prefix);
    h2o_accept_setup_memcached_ssl_resumption(memc_ctx, conf.lifetime);
    setup_cache_enable(contexts, num_contexts, 1);
}

static void setup_cache_redis(SSL_CTX **contexts, size_t num_contexts)
{
    h2o_accept_setup_redis_ssl_resumption(conf.store.redis.host, conf.store.redis.port, conf.lifetime,
                                          conf.cache.vars.redis.prefix);
    setup_cache_enable(contexts, num_contexts, 1);
}

static void cache_init_defaults(void)
{
    conf.cache.setup = setup_cache_internal;
}

#if H2O_USE_SESSION_TICKETS

struct st_session_ticket_t {
    unsigned char name[16];
    struct {
        const EVP_CIPHER *cipher;
        unsigned char *key;
    } cipher;
    struct {
        const EVP_MD *md;
        unsigned char *key;
    } hmac;
    uint64_t not_before;
    uint64_t not_after;
};

typedef H2O_VECTOR(struct st_session_ticket_t *) session_ticket_vector_t;

static struct {
    pthread_rwlock_t rwlock;
    session_ticket_vector_t tickets; /* sorted from newer to older */
} session_tickets = {
/* we need writer-preferred lock, but on linux PTHREAD_RWLOCK_INITIALIZER is reader-preferred */
#ifdef PTHREAD_RWLOCK_WRITER_NONRECURSIVE_INITIALIZER_NP
    PTHREAD_RWLOCK_WRITER_NONRECURSIVE_INITIALIZER_NP
#else
    PTHREAD_RWLOCK_INITIALIZER
#endif
    ,
    {NULL} /* tickets */
};

static struct st_session_ticket_t *new_ticket(const EVP_CIPHER *cipher, const EVP_MD *md, uint64_t not_before, uint64_t not_after,
                                              int fill_in)
{
    int key_len = EVP_CIPHER_key_length(cipher), block_size = EVP_MD_block_size(md);
    struct st_session_ticket_t *ticket = h2o_mem_alloc(sizeof(*ticket) + key_len + block_size);

    ticket->cipher.cipher = cipher;
    ticket->cipher.key = (unsigned char *)ticket + sizeof(*ticket);
    ticket->hmac.md = md;
    ticket->hmac.key = ticket->cipher.key + key_len;
    ticket->not_before = not_before;
    ticket->not_after = not_after;
    if (fill_in) {
        RAND_bytes(ticket->name, sizeof(ticket->name));
        RAND_bytes(ticket->cipher.key, key_len);
        RAND_bytes(ticket->hmac.key, block_size);
    }

    return ticket;
}

static void free_ticket(struct st_session_ticket_t *ticket)
{
    int key_len = EVP_CIPHER_key_length(ticket->cipher.cipher), block_size = EVP_MD_block_size(ticket->hmac.md);
    h2o_mem_set_secure(ticket, 0, sizeof(*ticket) + key_len + block_size);
    free(ticket);
}

static int ticket_sort_compare(const void *_x, const void *_y)
{
    struct st_session_ticket_t *x = *(void **)_x, *y = *(void **)_y;

    if (x->not_before != y->not_before)
        return x->not_before > y->not_before ? -1 : 1;
    return memcmp(x->name, y->name, sizeof(x->name));
}

static void free_tickets(session_ticket_vector_t *tickets)
{
    size_t i;
    for (i = 0; i != tickets->size; ++i)
        free_ticket(tickets->entries[i]);
    free(tickets->entries);
    memset(tickets, 0, sizeof(*tickets));
}

static struct st_session_ticket_t *find_ticket_for_encryption(session_ticket_vector_t *tickets, uint64_t now)
{
    size_t i;

    for (i = 0; i != tickets->size; ++i) {
        struct st_session_ticket_t *ticket = tickets->entries[i];
        if (ticket->not_before <= now) {
            if (now <= ticket->not_after) {
                return ticket;
            } else {
                return NULL;
            }
        }
    }
    return NULL;
}

static int ticket_key_callback(unsigned char *key_name, unsigned char *iv, EVP_CIPHER_CTX *ctx, HMAC_CTX *hctx, int enc)
{
    int ret;
    pthread_rwlock_rdlock(&session_tickets.rwlock);

    if (enc) {
        RAND_bytes(iv, EVP_MAX_IV_LENGTH);
        struct st_session_ticket_t *ticket = find_ticket_for_encryption(&session_tickets.tickets, time(NULL)), *temp_ticket = NULL;
        if (ticket != NULL) {
        } else {
            /* create a dummy ticket and use (this is the only way to continue the handshake; contrary to the man pages, OpenSSL
             * crashes if we return zero */
            ticket = temp_ticket = new_ticket(EVP_aes_256_cbc(), EVP_sha256(), 0, UINT64_MAX, 1);
        }
        memcpy(key_name, ticket->name, sizeof(ticket->name));
        ret = EVP_EncryptInit_ex(ctx, ticket->cipher.cipher, NULL, ticket->cipher.key, iv);
        assert(ret);
        ret = HMAC_Init_ex(hctx, ticket->hmac.key, EVP_MD_block_size(ticket->hmac.md), ticket->hmac.md, NULL);
        assert(ret);
        if (temp_ticket != NULL)
            free_ticket(ticket);
        ret = 1;
    } else {
        struct st_session_ticket_t *ticket;
        size_t i;
        for (i = 0; i != session_tickets.tickets.size; ++i) {
            ticket = session_tickets.tickets.entries[i];
            if (memcmp(ticket->name, key_name, sizeof(ticket->name)) == 0)
                goto Found;
        }
        /* not found */
        ret = 0;
        goto Exit;
    Found:
        ret = EVP_DecryptInit_ex(ctx, ticket->cipher.cipher, NULL, ticket->cipher.key, iv);
        assert(ret);
        ret = HMAC_Init_ex(hctx, ticket->hmac.key, EVP_MD_block_size(ticket->hmac.md), ticket->hmac.md, NULL);
        assert(ret);
        /* Request renewal if the youngest key is active */
        if (i != 0 && session_tickets.tickets.entries[i - 1]->not_before <= time(NULL))
            ret = 2;
        else
            ret = 1;
    }

Exit:
    pthread_rwlock_unlock(&session_tickets.rwlock);
    return ret;
}

static int ticket_key_callback_ossl(SSL *ssl, unsigned char *key_name, unsigned char *iv, EVP_CIPHER_CTX *ctx, HMAC_CTX *hctx,
                                    int enc)
{
    return ticket_key_callback(key_name, iv, ctx, hctx, enc);
}

#if H2O_USE_PICOTLS

static int encrypt_ticket_key_ptls(ptls_encrypt_ticket_t *self, ptls_t *tls, int is_encrypt, ptls_buffer_t *dst, ptls_iovec_t src)
{
    return (is_encrypt ? ptls_openssl_encrypt_ticket : ptls_openssl_decrypt_ticket)(dst, src, ticket_key_callback);
}

#endif

static int update_tickets(session_ticket_vector_t *tickets, uint64_t now)
{
    int altered = 0, has_valid_ticket;

    /* remove old entries */
    while (tickets->size != 0) {
        struct st_session_ticket_t *oldest = tickets->entries[tickets->size - 1];
        if (now <= oldest->not_after)
            break;
        tickets->entries[--tickets->size] = NULL;
        free_ticket(oldest);
        altered = 1;
    }

    /* create new entry if necessary */
    has_valid_ticket = find_ticket_for_encryption(tickets, now) != NULL;
    if (!has_valid_ticket || (tickets->entries[0]->not_before + conf.lifetime / 4 < now)) {
        uint64_t not_before = has_valid_ticket ? now + 60 : now;
        struct st_session_ticket_t *ticket = new_ticket(conf.ticket.vars.generating.cipher, conf.ticket.vars.generating.md,
                                                        not_before, not_before + conf.lifetime - 1, 1);
        h2o_vector_reserve(NULL, tickets, tickets->size + 1);
        memmove(tickets->entries + 1, tickets->entries, sizeof(tickets->entries[0]) * tickets->size);
        ++tickets->size;
        tickets->entries[0] = ticket;
        altered = 1;
    }

    return altered;
}

H2O_NORETURN static void *ticket_internal_updater(void *unused)
{
    while (1) {
        pthread_rwlock_wrlock(&session_tickets.rwlock);
        update_tickets(&session_tickets.tickets, time(NULL));
        pthread_rwlock_unlock(&session_tickets.rwlock);
        /* sleep for certain amount of time */
        sleep(120 - (h2o_rand() >> 16) % 7);
    }
}

static int serialize_ticket_entry(char *buf, size_t bufsz, struct st_session_ticket_t *ticket)
{
    char *name_buf = alloca(sizeof(ticket->name) * 2 + 1);
    h2o_hex_encode(name_buf, ticket->name, sizeof(ticket->name));
    int key_len = EVP_CIPHER_key_length(ticket->cipher.cipher), block_size = EVP_MD_block_size(ticket->hmac.md);
    char *key_buf = alloca((key_len + block_size) * 2 + 1);
    h2o_hex_encode(key_buf, ticket->cipher.key, key_len);
    h2o_hex_encode(key_buf + key_len * 2, ticket->hmac.key, block_size);

    return snprintf(buf, bufsz,
                    "- name: %s\n"
                    "  cipher: %s\n"
                    "  hash: %s\n"
                    "  key: %s\n"
                    "  not_before: %" PRIu64 "\n"
                    "  not_after: %" PRIu64 "\n",
                    name_buf, OBJ_nid2sn(EVP_CIPHER_type(ticket->cipher.cipher)), OBJ_nid2sn(EVP_MD_type(ticket->hmac.md)), key_buf,
                    ticket->not_before, ticket->not_after);
}

static struct st_session_ticket_t *parse_ticket_entry(yoml_t *element, char *errstr)
{
    yoml_t *t;
    struct st_session_ticket_t *ticket;
    unsigned char name[sizeof(ticket->name) + 1], *key;
    const EVP_CIPHER *cipher;
    const EVP_MD *hash;
    uint64_t not_before, not_after;

    errstr[0] = '\0';

    if (element->type != YOML_TYPE_MAPPING) {
        strcpy(errstr, "node is not a mapping");
        return NULL;
    }

#define FETCH(n, post)                                                                                                             \
    do {                                                                                                                           \
        if ((t = yoml_get(element, n)) == NULL) {                                                                                  \
            strcpy(errstr, " mandatory attribute `" n "` is missing");                                                             \
            return NULL;                                                                                                           \
        }                                                                                                                          \
        if (t->type != YOML_TYPE_SCALAR) {                                                                                         \
            strcpy(errstr, "attribute `" n "` is not a string");                                                                   \
            return NULL;                                                                                                           \
        }                                                                                                                          \
        post                                                                                                                       \
    } while (0)

    FETCH("name", {
        if (strlen(t->data.scalar) != sizeof(ticket->name) * 2) {
            strcpy(errstr, "length of `name` attribute is not 32 bytes");
            return NULL;
        }
        if (h2o_hex_decode(name, t->data.scalar, sizeof(ticket->name) * 2) != 0) {
            strcpy(errstr, "failed to decode the hex-encoded name");
            return NULL;
        }
    });
    FETCH("cipher", {
        if ((cipher = EVP_get_cipherbyname(t->data.scalar)) == NULL) {
            strcpy(errstr, "cannot find the named cipher algorithm");
            return NULL;
        }
    });
    FETCH("hash", {
        if ((hash = EVP_get_digestbyname(t->data.scalar)) == NULL) {
            strcpy(errstr, "cannot find the named hash algorgithm");
            return NULL;
        }
    });
    FETCH("key", {
        size_t keylen = EVP_CIPHER_key_length(cipher) + EVP_MD_block_size(hash);
        if (strlen(t->data.scalar) != keylen * 2) {
            sprintf(errstr, "length of the `key` attribute is incorrect (is %zu, must be %zu)\n", strlen(t->data.scalar),
                    keylen * 2);
            return NULL;
        }
        key = alloca(keylen + 1);
        if (h2o_hex_decode(key, t->data.scalar, keylen * 2) != 0) {
            strcpy(errstr, "failed to decode the hex-encoded key");
            return NULL;
        }
    });
    FETCH("not_before", {
        if (sscanf(t->data.scalar, "%" SCNu64, &not_before) != 1) {
            strcpy(errstr, "failed to parse the `not_before` attribute");
            return NULL;
        }
    });
    FETCH("not_after", {
        if (sscanf(t->data.scalar, "%" SCNu64, &not_after) != 1) {
            strcpy(errstr, "failed to parse the `not_after` attribute");
            return NULL;
        }
    });
    if (!(not_before <= not_after)) {
        strcpy(errstr, "`not_after` is not equal to or greater than `not_before`");
        return NULL;
    }

#undef FETCH

    ticket = new_ticket(cipher, hash, not_before, not_after, 0);
    memcpy(ticket->name, name, sizeof(ticket->name));
    memcpy(ticket->cipher.key, key, EVP_CIPHER_key_length(cipher));
    memcpy(ticket->hmac.key, key + EVP_CIPHER_key_length(cipher), EVP_MD_block_size(hash));
    return ticket;
}

static int parse_tickets(session_ticket_vector_t *tickets, const void *src, size_t len, char *errstr)
{
    yaml_parser_t parser;
    yoml_t *doc;
    size_t i;

    *tickets = (session_ticket_vector_t){NULL};
    yaml_parser_initialize(&parser);

    yaml_parser_set_input_string(&parser, src, len);
    yoml_parse_args_t parse_args = {NULL, h2o_mem_set_secure};
    if ((doc = yoml_parse_document(&parser, NULL, &parse_args)) == NULL) {
        sprintf(errstr, "parse error at line %d:%s\n", (int)parser.problem_mark.line, parser.problem);
        goto Error;
    }
    if (doc->type != YOML_TYPE_SEQUENCE) {
        strcpy(errstr, "root element is not a sequence");
        goto Error;
    }
    for (i = 0; i != doc->data.sequence.size; ++i) {
        char errbuf[256];
        struct st_session_ticket_t *ticket = parse_ticket_entry(doc->data.sequence.elements[i], errbuf);
        if (ticket == NULL) {
            sprintf(errstr, "at element index %zu:%s\n", i, errbuf);
            goto Error;
        }
        h2o_vector_reserve(NULL, tickets, tickets->size + 1);
        tickets->entries[tickets->size++] = ticket;
    }

    yoml_free(doc, h2o_mem_set_secure);
    yaml_parser_delete(&parser);
    return 0;
Error:
    if (doc != NULL)
        yoml_free(doc, h2o_mem_set_secure);
    yaml_parser_delete(&parser);
    free_tickets(tickets);
    return -1;
}

static h2o_iovec_t serialize_tickets(session_ticket_vector_t *tickets)
{
    h2o_iovec_t data = {h2o_mem_alloc(tickets->size * 1024 + 1), 0};
    size_t i;

    for (i = 0; i != tickets->size; ++i) {
        struct st_session_ticket_t *ticket = tickets->entries[i];
        size_t l = serialize_ticket_entry(data.base + data.len, 1024, ticket);
        if (l > 1024) {
            fprintf(stderr, "[src/ssl.c] %s:internal buffer overflow\n", __func__);
            goto Error;
        }
        data.len += l;
    }

    return data;
Error:
    free(data.base);
    return (h2o_iovec_t){NULL};
}

static int ticket_memcached_update_tickets(yrmcds *conn, h2o_iovec_t key, time_t now)
{
    yrmcds_response resp;
    yrmcds_error err;
    uint32_t serial;
    session_ticket_vector_t tickets = {NULL};
    h2o_iovec_t tickets_serialized = {NULL};
    int retry = 0;
    char errbuf[256];

    /* retrieve tickets on memcached */
    if ((err = yrmcds_get(conn, key.base, key.len, 0, &serial)) != 0) {
        fprintf(stderr, "[lib/ssl.c] %s:yrmcds_get failed:%s\n", __func__, yrmcds_strerror(err));
        goto Exit;
    }
    if ((err = yrmcds_recv(conn, &resp)) != 0) {
        fprintf(stderr, "[lib/ssl.c] %s:yrmcds_recv failed:%s\n", __func__, yrmcds_strerror(err));
        goto Exit;
    }
    if (resp.serial != serial) {
        fprintf(stderr, "[lib/ssl.c] %s:unexpected response\n", __func__);
        goto Exit;
    }
    if (resp.status == YRMCDS_STATUS_OK) {
        int r = parse_tickets(&tickets, resp.data, resp.data_len, errbuf);
        h2o_mem_set_secure((void *)resp.data, 0, resp.data_len);
        if (r != 0) {
            fprintf(stderr, "[lib/ssl.c] %s:failed to parse response:%s\n", __func__, errbuf);
            goto Exit;
        }
    }
    if (tickets.size > 1)
        qsort(tickets.entries, tickets.size, sizeof(tickets.entries[0]), ticket_sort_compare);

    /* if we need to update the tickets, atomically update the value in memcached, and request refetch to the caller */
    if (update_tickets(&tickets, now) != 0) {
        tickets_serialized = serialize_tickets(&tickets);
        if (resp.status == YRMCDS_STATUS_NOTFOUND) {
            if ((err = yrmcds_add(conn, key.base, key.len, tickets_serialized.base, tickets_serialized.len, 0, conf.lifetime, 0, 0,
                                  &serial)) != 0) {
                fprintf(stderr, "[lib/ssl.c] %s:yrmcds_add failed:%s\n", __func__, yrmcds_strerror(err));
                goto Exit;
            }
        } else {
            if ((err = yrmcds_set(conn, key.base, key.len, tickets_serialized.base, tickets_serialized.len, 0, conf.lifetime,
                                  resp.cas_unique, 0, &serial)) != 0) {
                fprintf(stderr, "[lib/ssl.c] %s:yrmcds_set failed:%s\n", __func__, yrmcds_strerror(err));
                goto Exit;
            }
        }
        if ((err = yrmcds_recv(conn, &resp)) != 0) {
            fprintf(stderr, "[lib/ssl.c] %s:yrmcds_recv failed:%s\n", __func__, yrmcds_strerror(err));
            goto Exit;
        }
        retry = 1;
        goto Exit;
    }

    /* store the results */
    pthread_rwlock_wrlock(&session_tickets.rwlock);
    h2o_mem_swap(&session_tickets.tickets, &tickets, sizeof(tickets));
    pthread_rwlock_unlock(&session_tickets.rwlock);

Exit:
    free(tickets_serialized.base);
    free_tickets(&tickets);
    return retry;
}

H2O_NORETURN static void *ticket_memcached_updater(void *unused)
{
    while (1) {
        /* connect */
        yrmcds conn;
        yrmcds_error err;
        size_t failcnt;
        for (failcnt = 0; (err = yrmcds_connect(&conn, conf.store.memcached.host, conf.store.memcached.port)) != YRMCDS_OK;
             ++failcnt) {
            if (failcnt == 0)
                fprintf(stderr, "[src/ssl.c] failed to connect to memcached at %s:%" PRIu16 ", %s\n", conf.store.memcached.host,
                        conf.store.memcached.port, yrmcds_strerror(err));
            sleep(10);
        }
        if (conf.store.memcached.text_protocol)
            yrmcds_text_mode(&conn);
        /* connected */
        while (ticket_memcached_update_tickets(&conn, conf.ticket.vars.memcached.key, time(NULL)))
            ;
        /* disconnect */
        yrmcds_close(&conn);
        sleep(60);
    }
}

static int ticket_redis_update_tickets(redisContext *ctx, h2o_iovec_t key, time_t now)
{
    redisReply *reply;
    session_ticket_vector_t tickets = {NULL};
    h2o_iovec_t tickets_serialized = {NULL};
    int retry = 0;
    char errbuf[256];

    if ((reply = redisCommand(ctx, "GET %s", key.base)) == NULL) {
        fprintf(stderr, "[lib/ssl.c] %s:redisCommand GET failed:%s\n", __func__, ctx->errstr);
        goto Exit;
    }
    if (reply->type == REDIS_REPLY_STRING) {
        int r = parse_tickets(&tickets, reply->str, reply->len, errbuf);
        freeReplyObject(reply);
        if (r != 0) {
            fprintf(stderr, "[lib/ssl.c] %s:failed to parse response:%s\n", __func__, errbuf);
            goto Exit;
        }
    }
    if (tickets.size > 1)
        qsort(tickets.entries, tickets.size, sizeof(tickets.entries[0]), ticket_sort_compare);

    if (update_tickets(&tickets, now) != 0) {
        tickets_serialized = serialize_tickets(&tickets);
        if ((reply = redisCommand(ctx, "SETEX %s %d %s", key.base, conf.lifetime, tickets_serialized.base)) == NULL) {
            fprintf(stderr, "[lib/ssl.c] %s:redisCommand SETEX failed:%s\n", __func__, ctx->errstr);
            goto Exit;
        }
        freeReplyObject(reply);

        retry = 1;
        goto Exit;
    }

    /* store the results */
    pthread_rwlock_wrlock(&session_tickets.rwlock);
    h2o_mem_swap(&session_tickets.tickets, &tickets, sizeof(tickets));
    pthread_rwlock_unlock(&session_tickets.rwlock);

Exit:
    free(tickets_serialized.base);
    free_tickets(&tickets);
    return retry;
}

H2O_NORETURN static void *ticket_redis_updater(void *unused)
{
    while (1) {
        /* connect */
        redisContext *ctx;
        size_t failcnt;
        for (failcnt = 0; (ctx = redisConnect(conf.store.redis.host, conf.store.redis.port)) == NULL || ctx->err != 0; ++failcnt) {
            if (failcnt == 0)
                fprintf(stderr, "[src/ssl.c] failed to connect to redis at %s:%" PRIu16 ", %s\n", conf.store.redis.host,
                        conf.store.redis.port, ctx == NULL ? "redis context allocation failed" : ctx->errstr);
            if (ctx != NULL)
                redisFree(ctx);
            sleep(10);
        }
        /* connected */
        while (ticket_redis_update_tickets(ctx, conf.ticket.vars.redis.key, time(NULL)))
            ;
        /* disconnect */
        redisFree(ctx);

        sleep(10);
    }
}

static int load_tickets_file(const char *fn)
{
#define ERR_PREFIX "failed to load session ticket secrets from file:%s:"

    h2o_iovec_t data = {NULL};
    session_ticket_vector_t tickets = {NULL};
    char errbuf[256];
    int ret = -1;

    /* load yaml */
    data = h2o_file_read(fn);
    if (data.base == NULL) {
        char errbuf[256];
        strerror_r(errno, errbuf, sizeof(errbuf));
        fprintf(stderr, ERR_PREFIX "%s\n", fn, errbuf);
        goto Exit;
    }
    /* parse the data */
    if (parse_tickets(&tickets, data.base, data.len, errbuf) != 0) {
        fprintf(stderr, ERR_PREFIX "%s\n", fn, errbuf);
        goto Exit;
    }
    /* sort the ticket entries being read */
    if (tickets.size > 1)
        qsort(tickets.entries, tickets.size, sizeof(tickets.entries[0]), ticket_sort_compare);
    /* replace the ticket list */
    pthread_rwlock_wrlock(&session_tickets.rwlock);
    h2o_mem_swap(&session_tickets.tickets, &tickets, sizeof(tickets));
    pthread_rwlock_unlock(&session_tickets.rwlock);

    ret = 0;
Exit:
    free(data.base);
    free_tickets(&tickets);
    return ret;

#undef ERR_PREFIX
}

H2O_NORETURN static void *ticket_file_updater(void *unused)
{
    time_t last_mtime = 1; /* file is loaded if mtime changes, 0 is used to indicate that the file was missing */

    while (1) {
        struct stat st;
        if (stat(conf.ticket.vars.file.filename, &st) != 0) {
            if (last_mtime != 0) {
                char errbuf[256];
                strerror_r(errno, errbuf, sizeof(errbuf));
                fprintf(stderr, "cannot load session ticket secrets from file:%s:%s\n", conf.ticket.vars.file.filename, errbuf);
            }
            last_mtime = 0;
        } else if (last_mtime != st.st_mtime) {
            /* (re)load */
            last_mtime = st.st_mtime;
            if (load_tickets_file(conf.ticket.vars.file.filename) == 0)
                fprintf(stderr, "session ticket secrets have been (re)loaded\n");
        }
        sleep(10);
    }
}

static void ticket_init_defaults(void)
{
    conf.ticket.update_thread = ticket_internal_updater;
    /* to protect the secret >>>2030 we need AES-256 (http://www.keylength.com/en/4/) */
    conf.ticket.vars.generating.cipher = EVP_aes_256_cbc();
    /* integrity checks are only necessary at the time of handshake, and sha256 (recommended by RFC 5077) is sufficient */
    conf.ticket.vars.generating.md = EVP_sha256();
}

#endif

int ssl_session_resumption_on_config(h2o_configurator_command_t *cmd, h2o_configurator_context_t *ctx, yoml_t *node)
{
    enum {
        MODE_CACHE = 1,
        MODE_TICKET = 2,
    };
    int modes;
    yoml_t **mode_node, **cache_store, **cache_memcached_num_threads, **cache_memcached_prefix, **cache_redis_prefix,
        **ticket_store, **ticket_cipher, **ticket_hash, **ticket_memcached_prefix, **ticket_redis_prefix, **ticket_file,
        **memcached_node, **redis_node, **lifetime;

    if (h2o_configurator_parse_mapping(
            cmd, node, "mode:*",
            "cache-store:*,cache-memcached-num-threads:*,cache-memcached-prefix:s,cache-redis-prefix:s,"
            "ticket-store:*,ticket-cipher:s,ticket-hash:s,ticket-memcached-prefix:s,ticket-redis-prefix:s,"
            "ticket-file:s,memcached:m,redis:m,lifetime:*",
            &mode_node, &cache_store, &cache_memcached_num_threads, &cache_memcached_prefix, &cache_redis_prefix, &ticket_store,
            &ticket_cipher, &ticket_hash, &ticket_memcached_prefix, &ticket_redis_prefix, &ticket_file, &memcached_node,
            &redis_node, &lifetime) != 0)
        return -1;

    switch (h2o_configurator_get_one_of(cmd, *mode_node, "off,cache,ticket,all")) {
    case 0:
        modes = 0;
        break;
    case 1:
        modes = MODE_CACHE;
        break;
    case 2:
        modes = MODE_TICKET;
        break;
    case 3:
        modes = MODE_CACHE;
#if H2O_USE_SESSION_TICKETS
        modes |= MODE_TICKET;
#endif
        break;
    default:
        return -1;
    }

    if ((modes & MODE_CACHE) != 0) {
        cache_init_defaults();
        if (cache_store != NULL) {
            switch (h2o_configurator_get_one_of(cmd, *cache_store, "internal,memcached,redis")) {
            case 0:
                /* preserve the default */
                break;
            case 1:
                conf.cache.setup = setup_cache_memcached;
                break;
            case 2:
                conf.cache.setup = setup_cache_redis;
                break;
            default:
                return -1;
            }
        }
        if (conf.cache.setup == setup_cache_memcached) {
            conf.cache.vars.memcached.num_threads = 1;
            conf.cache.vars.memcached.prefix = "h2o:ssl-session-cache:";
            if (cache_memcached_num_threads != NULL) {
                if (h2o_configurator_scanf(cmd, *cache_memcached_num_threads, "%zu", &conf.cache.vars.memcached.num_threads) != 0)
                    return -1;
                if (conf.cache.vars.memcached.num_threads == 0) {
                    h2o_configurator_errprintf(cmd, *cache_memcached_num_threads,
                                               "`cache-memcached-num-threads` must be a positive number");
                    return -1;
                }
            }
            if (cache_memcached_prefix != NULL)
                conf.cache.vars.memcached.prefix = h2o_strdup(NULL, (*cache_memcached_prefix)->data.scalar, SIZE_MAX).base;
        } else if (conf.cache.setup == setup_cache_redis) {
            conf.cache.vars.redis.prefix = "h2o:ssl-session-cache:";
            if (cache_redis_prefix != NULL)
                conf.cache.vars.redis.prefix = h2o_strdup(NULL, (*cache_redis_prefix)->data.scalar, SIZE_MAX).base;
        }
    } else {
        conf.cache.setup = setup_cache_disable;
    }

    if ((modes & MODE_TICKET) != 0) {
#if H2O_USE_SESSION_TICKETS
        ticket_init_defaults();
        if (ticket_store != NULL) {
            switch (h2o_configurator_get_one_of(cmd, *ticket_store, "internal,file,memcached,redis")) {
            case 0:
                /* preserve the defaults */
                break;
            case 1:
                conf.ticket.update_thread = ticket_file_updater;
                break;
            case 2:
                conf.ticket.update_thread = ticket_memcached_updater;
                break;
            case 3:
                conf.ticket.update_thread = ticket_redis_updater;
                break;
            default:
                return -1;
            }
        }
        if (conf.ticket.update_thread == ticket_internal_updater || conf.ticket.update_thread == ticket_memcached_updater ||
            conf.ticket.update_thread == ticket_redis_updater) {
            /* generating updater takes two arguments: cipher, hash */
            if (ticket_cipher != NULL &&
                (conf.ticket.vars.generating.cipher = EVP_get_cipherbyname((*ticket_cipher)->data.scalar)) == NULL) {
                h2o_configurator_errprintf(cmd, *ticket_cipher, "unknown cipher algorithm");
                return -1;
            }
            if (ticket_hash != NULL &&
                (conf.ticket.vars.generating.md = EVP_get_digestbyname((*ticket_hash)->data.scalar)) == NULL) {
                h2o_configurator_errprintf(cmd, *ticket_hash, "unknown hash algorithm");
                return -1;
            }
            if (conf.ticket.update_thread == ticket_memcached_updater) {
                conf.ticket.vars.memcached.key = h2o_iovec_init(H2O_STRLIT("h2o:ssl-session-key"));
                if (ticket_memcached_prefix != NULL)
                    conf.ticket.vars.memcached.key = h2o_strdup(NULL, (*ticket_memcached_prefix)->data.scalar, SIZE_MAX);
            } else if (conf.ticket.update_thread == ticket_redis_updater) {
                conf.ticket.vars.redis.key = h2o_iovec_init(H2O_STRLIT("h2o:ssl-session-key"));
                if (ticket_redis_prefix != NULL)
                    conf.ticket.vars.redis.key = h2o_strdup(NULL, (*ticket_redis_prefix)->data.scalar, SIZE_MAX);
            }
        } else if (conf.ticket.update_thread == ticket_file_updater) {
            /* file updater reads the contents of the file and uses it as the session ticket secret */
            if (ticket_file == NULL) {
                h2o_configurator_errprintf(cmd, node, "mandatory attribute `file` is missing");
                return -1;
            }
            conf.ticket.vars.file.filename = h2o_strdup(NULL, (*ticket_file)->data.scalar, SIZE_MAX).base;
        }
#else
        h2o_configurator_errprintf(
            cmd, mode, "ticket-based session resumption cannot be used, the server is built without support for the feature");
        return -1;
#endif
    } else {
        conf.ticket.update_thread = NULL;
    }

    if (memcached_node != NULL) {
        yoml_t **host, **port, **protocol;
        if (h2o_configurator_parse_mapping(cmd, *memcached_node, "host:s", "port:*,protocol:*", &host, &port, &protocol) != 0)
            return -1;
        conf.store.memcached.host = h2o_strdup(NULL, (*host)->data.scalar, SIZE_MAX).base;
        conf.store.memcached.port = 11211;
        conf.store.memcached.text_protocol = 0;
        if (port != NULL && h2o_configurator_scanf(cmd, *port, "%" SCNu16, &conf.store.memcached.port) != 0)
            return -1;
        if (protocol != NULL &&
            (conf.store.memcached.text_protocol = (int)h2o_configurator_get_one_of(cmd, *protocol, "BINARY,ASCII")) == -1)
            return -1;
    }

    if (redis_node != NULL) {
        yoml_t **host, **port;
        if (h2o_configurator_parse_mapping(cmd, *redis_node, "host:s", "port:*", &host, &port) != 0)
            return -1;
        conf.store.redis.host = h2o_strdup(NULL, (*host)->data.scalar, SIZE_MAX).base;
        conf.store.redis.port = 6379;
        if (port != NULL && h2o_configurator_scanf(cmd, *port, "%" SCNu16, &conf.store.redis.port) != 0)
            return -1;
    }

    int uses_memcached = conf.cache.setup == setup_cache_memcached;
#if H2O_USE_SESSION_TICKETS
    uses_memcached = (uses_memcached || conf.ticket.update_thread == ticket_memcached_updater);
#endif
    if (uses_memcached && conf.store.memcached.host == NULL) {
        h2o_configurator_errprintf(cmd, node, "configuration of memcached is missing");
        return -1;
    }

    int uses_redis = conf.cache.setup == setup_cache_redis;
#if H2O_USE_SESSION_TICKETS
    uses_redis = (uses_redis || conf.ticket.update_thread == ticket_redis_updater);
#endif
    if (uses_redis && conf.store.redis.host == NULL) {
        h2o_configurator_errprintf(cmd, node, "configuration of redis is missing");
        return -1;
    }

    if (lifetime != NULL) {
        if (h2o_configurator_scanf(cmd, *lifetime, "%u", &conf.lifetime) != 0)
            return -1;
        if (conf.lifetime == 0) {
            h2o_configurator_errprintf(cmd, *lifetime, "`lifetime` must be a positive number");
            return -1;
        }
    }

    return 0;
}

void ssl_setup_session_resumption(SSL_CTX **contexts, size_t num_contexts)
{
    if (conf.cache.setup != NULL)
        conf.cache.setup(contexts, num_contexts);

#if H2O_USE_SESSION_TICKETS
    if (num_contexts == 0)
        return;

    if (conf.ticket.update_thread != NULL) {
        /* start session ticket updater thread */
        pthread_t tid;
        pthread_attr_t attr;
        pthread_attr_init(&attr);
        pthread_attr_setdetachstate(&attr, 1);
        h2o_multithread_create_thread(&tid, &attr, conf.ticket.update_thread, NULL);
        size_t i;
        for (i = 0; i != num_contexts; ++i) {
            SSL_CTX *ctx = contexts[i];
            SSL_CTX_set_tlsext_ticket_key_cb(ctx, ticket_key_callback_ossl);
#if H2O_USE_PICOTLS
            ptls_context_t *pctx = h2o_socket_ssl_get_picotls_context(ctx);
            if (pctx != NULL) {
                static ptls_encrypt_ticket_t encryptor = {encrypt_ticket_key_ptls};
                pctx->ticket_lifetime = 86400 * 7; // FIXME conf.lifetime;
                pctx->encrypt_ticket = &encryptor;
            }
#endif
        }
    } else {
        size_t i;
        for (i = 0; i != num_contexts; ++i)
            SSL_CTX_set_options(contexts[i], SSL_CTX_get_options(contexts[i]) | SSL_OP_NO_TICKET);
    }
#endif
}

static pthread_mutex_t *mutexes;

static void lock_callback(int mode, int n, const char *file, int line)
{
    if ((mode & CRYPTO_LOCK) != 0) {
        pthread_mutex_lock(mutexes + n);
    } else if ((mode & CRYPTO_UNLOCK) != 0) {
        pthread_mutex_unlock(mutexes + n);
    } else {
        assert(!"unexpected mode");
    }
}

static unsigned long thread_id_callback(void)
{
    return (unsigned long)pthread_self();
}

static int add_lock_callback(int *num, int amount, int type, const char *file, int line)
{
    (void)type;
    (void)file;
    (void)line;

    return __sync_add_and_fetch(num, amount);
}

void init_openssl(void)
{
    int nlocks = CRYPTO_num_locks(), i;
    mutexes = h2o_mem_alloc(sizeof(*mutexes) * nlocks);
    for (i = 0; i != nlocks; ++i)
        pthread_mutex_init(mutexes + i, NULL);
    CRYPTO_set_locking_callback(lock_callback);
    CRYPTO_set_id_callback(thread_id_callback);
    CRYPTO_set_add_lock_callback(add_lock_callback);

    /* Dynamic locks are only used by the CHIL engine at this time */

    SSL_load_error_strings();
    SSL_library_init();
    OpenSSL_add_all_algorithms();

    cache_init_defaults();
#if H2O_USE_SESSION_TICKETS
    ticket_init_defaults();
#endif
    conf.lifetime = 3600; /* default value for session timeout is 1 hour */
}
