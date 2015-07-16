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
#include <inttypes.h>
#include <sys/stat.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/ssl.h>
#include "yoml-parser.h"
#include "h2o.h"
#include "h2o/configurator.h"
#include "standalone.h"

struct st_session_ticket_internal_updater_conf_t {
    const EVP_CIPHER *cipher;
    const EVP_MD *md;
    unsigned lifetime;
};

struct st_session_ticket_file_updater_conf_t {
    const char *filename;
};

static struct {
    void *(*update_thread)(void *conf);
    union {
        struct st_session_ticket_internal_updater_conf_t internal;
        struct st_session_ticket_file_updater_conf_t file;
    } vars;
} conf;

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
    PTHREAD_RWLOCK_INITIALIZER, /* rwlock (FIXME need to favor writer over readers explicitly, the default of Linux is known to be
                                   the otherwise) */
    {}                          /* tickets */
};

static int session_ticket_key_callback(SSL *ssl, unsigned char *key_name, unsigned char *iv, EVP_CIPHER_CTX *ctx, HMAC_CTX *hctx,
                                       int enc)
{
    int ret;
    pthread_rwlock_rdlock(&session_tickets.rwlock);

    if (enc) {
        if (session_tickets.tickets.size == 0) {
            ret = -1;
            goto Exit;
        }
        struct st_session_ticket_t *ticket = session_tickets.tickets.entries[0];
        memcpy(key_name, ticket->name, sizeof(ticket->name));
        RAND_pseudo_bytes(iv, EVP_MAX_IV_LENGTH);
        EVP_EncryptInit_ex(ctx, ticket->cipher.cipher, NULL, ticket->cipher.key, NULL);
        HMAC_Init_ex(hctx, ticket->hmac.key, ticket->hmac.md->block_size, ticket->hmac.md, NULL);
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
        EVP_DecryptInit_ex(ctx, ticket->cipher.cipher, NULL, ticket->cipher.key, NULL);
        HMAC_Init_ex(hctx, ticket->hmac.key, ticket->hmac.md->block_size, ticket->hmac.md, NULL);
        ret = i == 0 ? 1 : 2; /* request renew if the key is not the newest one */
    }

Exit:
    pthread_rwlock_unlock(&session_tickets.rwlock);
    return ret;
}

struct st_session_ticket_t *session_ticket_new(const EVP_CIPHER *cipher, const EVP_MD *md, uint64_t not_before, uint64_t not_after,
                                               int fill_in)
{
    struct st_session_ticket_t *ticket = h2o_mem_alloc(sizeof(*ticket) + cipher->key_len + md->block_size);

    ticket->cipher.cipher = cipher;
    ticket->cipher.key = (unsigned char *)ticket + sizeof(*ticket);
    ticket->hmac.md = md;
    ticket->hmac.key = ticket->cipher.key + cipher->key_len;
    ticket->not_before = not_before;
    ticket->not_after = not_after;
    if (fill_in) {
        RAND_pseudo_bytes(ticket->name, sizeof(ticket->name));
        RAND_pseudo_bytes(ticket->cipher.key, ticket->cipher.cipher->key_len);
        RAND_pseudo_bytes(ticket->hmac.key, ticket->hmac.md->block_size);
    }

    return ticket;
}

static void session_ticket_free(struct st_session_ticket_t *ticket)
{
    h2o_mem_set_secure(ticket, 0, sizeof(*ticket) + ticket->cipher.cipher->key_len + ticket->hmac.md->block_size);
    free(ticket);
}

static int session_ticket_sort_compare(const void *_x, const void *_y)
{
    struct st_session_ticket_t *x = *(void **)_x, *y = *(void **)_y;

    if (x->not_before != y->not_before)
        return x->not_before > y->not_before ? -1 : 1;
    return memcmp(x->name, y->name, sizeof(x->name));
}

static void session_ticket_free_vector(session_ticket_vector_t *tickets)
{
    size_t i;
    for (i = 0; i != tickets->size; ++i)
        session_ticket_free(tickets->entries[i]);
    free(tickets->entries);
    memset(tickets, 0, sizeof(*tickets));
}

static void *session_ticket_internal_updater(void *_conf)
{
    struct st_session_ticket_internal_updater_conf_t *conf = _conf;

    while (1) {
        uint64_t newest_not_before = 0, oldest_not_after = UINT64_MAX, now = time(NULL);

        /* obtain modification times */
        pthread_rwlock_rdlock(&session_tickets.rwlock);
        if (session_tickets.tickets.size != 0) {
            newest_not_before = session_tickets.tickets.entries[0]->not_before;
            oldest_not_after = session_tickets.tickets.entries[session_tickets.tickets.size - 1]->not_after;
        }
        pthread_rwlock_unlock(&session_tickets.rwlock);

        /* insert new entry if necessary */
        if (newest_not_before + conf->lifetime / 4 <= now) {
            struct st_session_ticket_t *new_ticket = session_ticket_new(conf->cipher, conf->md, now, now + conf->lifetime - 1, 1);
            pthread_rwlock_wrlock(&session_tickets.rwlock);
            h2o_vector_reserve(NULL, (void *)&session_tickets.tickets, sizeof(session_tickets.tickets.entries[0]),
                               session_tickets.tickets.size + 1);
            memmove(session_tickets.tickets.entries + 1, session_tickets.tickets.entries,
                    sizeof(session_tickets.tickets.entries[0]) * session_tickets.tickets.size);
            session_tickets.tickets.entries[0] = new_ticket;
            ++session_tickets.tickets.size;
            pthread_rwlock_unlock(&session_tickets.rwlock);
        }

        /* free expired entries if necessary */
        if (oldest_not_after < now) {
            while (1) {
                struct st_session_ticket_t *expiring_ticket = NULL;
                pthread_rwlock_wrlock(&session_tickets.rwlock);
                if (session_tickets.tickets.size != 0 &&
                    session_tickets.tickets.entries[session_tickets.tickets.size - 1]->not_after < now) {
                    expiring_ticket = session_tickets.tickets.entries[session_tickets.tickets.size - 1];
                    session_tickets.tickets.entries[session_tickets.tickets.size - 1] = NULL;
                    --session_tickets.tickets.size;
                }
                pthread_rwlock_unlock(&session_tickets.rwlock);
                if (expiring_ticket == NULL)
                    break;
                session_ticket_free(expiring_ticket);
            }
        }

        /* sleep for certain amount of time */
        sleep(120 - (rand() >> 16) % 7);
    }
}

static struct st_session_ticket_t *session_ticket_parse_element(yoml_t *element, char *errstr)
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
        size_t keylen = cipher->key_len + hash->block_size;
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

    ticket = session_ticket_new(cipher, hash, not_before, not_after, 0);
    memcpy(ticket->name, name, sizeof(ticket->name));
    memcpy(ticket->cipher.key, key, cipher->key_len);
    memcpy(ticket->hmac.key, key + cipher->key_len, hash->block_size);
    return ticket;
}

static int session_ticket_file_updater_load_file(struct st_session_ticket_file_updater_conf_t *conf)
{
#define ERR_PREFIX "failed to load session ticket secrets from file:%s:"

    yoml_t *yoml = NULL;
    FILE *fp;
    yaml_parser_t parser;
    session_ticket_vector_t tickets = {};
    size_t i;
    int ret = -1;

    yaml_parser_initialize(&parser);

    /* load yaml */
    if ((fp = fopen(conf->filename, "rb")) == NULL) {
        char errbuf[256];
        strerror_r(errno, errbuf, sizeof(errbuf));
        fprintf(stderr, ERR_PREFIX "%s\n", conf->filename, errbuf);
        goto Exit;
    }
    yaml_parser_set_input_file(&parser, fp);
    if ((yoml = yoml_parse_document(&parser, NULL, conf->filename)) == NULL) {
        fprintf(stderr, ERR_PREFIX "parse error at line %d:%s\n", conf->filename, (int)parser.problem_mark.line, parser.problem);
        goto Exit;
    }
    /* parse the data */
    if (yoml->type != YOML_TYPE_SEQUENCE) {
        fprintf(stderr, ERR_PREFIX "root element is not a sequence\n", conf->filename);
        goto Exit;
    }
    for (i = 0; i != yoml->data.sequence.size; ++i) {
        char errbuf[256];
        struct st_session_ticket_t *ticket = session_ticket_parse_element(yoml->data.sequence.elements[i], errbuf);
        if (ticket == NULL) {
            fprintf(stderr, ERR_PREFIX "at element index %zu:%s\n", conf->filename, i, errbuf);
            goto Exit;
        }
        h2o_vector_reserve(NULL, (void *)&tickets, sizeof(tickets.entries[0]), tickets.size + 1);
        tickets.entries[tickets.size++] = ticket;
    }
    /* sort the ticket entries being read */
    qsort(tickets.entries, tickets.size, sizeof(tickets.entries[0]), session_ticket_sort_compare);
    /* replace the ticket list */
    pthread_rwlock_wrlock(&session_tickets.rwlock);
    session_ticket_free_vector(&session_tickets.tickets);
    session_tickets.tickets = tickets;
    pthread_rwlock_unlock(&session_tickets.rwlock);
    tickets = (session_ticket_vector_t){};

    ret = 0;

Exit:
    if (fp != NULL)
        fclose(fp);
    yaml_parser_delete(&parser);
    if (yoml != NULL)
        yoml_free(yoml);
    session_ticket_free_vector(&tickets);
    return ret;

#undef ERR_PREFIX
}

static void *session_ticket_file_updater(void *_conf)
{
    struct st_session_ticket_file_updater_conf_t *conf = _conf;
    time_t last_mtime = 1; /* file is loaded if mtime changes, 0 is used to indicate that the file was missing */

    while (1) {
        struct stat st;
        if (stat(conf->filename, &st) != 0) {
            if (last_mtime != 0) {
                char errbuf[256];
                strerror_r(errno, errbuf, sizeof(errbuf));
                fprintf(stderr, "cannot load session ticket secrets from file:%s:%s\n", conf->filename, errbuf);
            }
            last_mtime = 0;
        } else if (last_mtime != st.st_mtime) {
            /* (re)load */
            last_mtime = st.st_mtime;
            if (session_ticket_file_updater_load_file(conf) == 0)
                fprintf(stderr, "session ticket secrets have been (re)loaded\n");
        }
        sleep(10);
    }
}

static void init_internal_defaults(void)
{
    /* to protect the secret >>>2030 we need AES-256 (http://www.keylength.com/en/4/), sha1 is used only during the communication
     * and can be short */
    conf.update_thread = session_ticket_internal_updater;
    conf.vars.internal.cipher = EVP_aes_256_cbc();
    conf.vars.internal.md = EVP_sha1();
    conf.vars.internal.lifetime = 3600; /* 1 hour */
}

#endif

int ssl_session_ticket_on_config(h2o_configurator_command_t *cmd, h2o_configurator_context_t *ctx, yoml_t *node)
{
    yoml_t *mode;

    if ((mode = yoml_get(node, "mode")) == NULL) {
        h2o_configurator_errprintf(cmd, node, "mandatory attribute `mode` is missing");
        return -1;
    }

    if (mode->type == YOML_TYPE_SCALAR) {
        if (strcasecmp(mode->data.scalar, "off") == 0) {

            /* mode: off */
            conf.update_thread = NULL;
            return 0;

        } else if (strcasecmp(mode->data.scalar, "internal") == 0) {

/* mode: internal takes three arguments: cipher, hash, duration */
#if H2O_USE_SESSION_TICKETS
            yoml_t *t;
            init_internal_defaults();
            if ((t = yoml_get(node, "cipher")) != NULL) {
                if (t->type != YOML_TYPE_SCALAR || (conf.vars.internal.cipher = EVP_get_cipherbyname(t->data.scalar)) == NULL) {
                    h2o_configurator_errprintf(cmd, t, "unknown cipher algorithm");
                    return -1;
                }
            }
            if ((t = yoml_get(node, "hash")) != NULL) {
                if (t->type != YOML_TYPE_SCALAR || (conf.vars.internal.md = EVP_get_digestbyname(t->data.scalar)) == NULL) {
                    h2o_configurator_errprintf(cmd, t, "unknown hash algorithm");
                    return -1;
                }
            }
            if ((t = yoml_get(node, "lifetime")) != NULL) {
                if (t->type != YOML_TYPE_SCALAR || sscanf(t->data.scalar, "%u", &conf.vars.internal.lifetime) != 1 ||
                    conf.vars.internal.lifetime == 0) {
                    h2o_configurator_errprintf(cmd, t, "`liftime` must be a positive number (in seconds)");
                    return -1;
                }
            }
            return 0;
#else
            goto NoSessionTickets;
#endif
        } else if (strcasecmp(mode->data.scalar, "file") == 0) {

/* mode: file reads the contents of the file and uses it as the session ticket secret */
#if H2O_USE_SESSION_TICKETS
            yoml_t *t;
            if ((t = yoml_get(node, "file")) == NULL) {
                h2o_configurator_errprintf(cmd, node, "mandatory attribute `file` is missing");
                return -1;
            }
            if (t->type != YOML_TYPE_SCALAR) {
                h2o_configurator_errprintf(cmd, node, "`file` must be a string");
                return -1;
            }
            conf.update_thread = session_ticket_file_updater;
            conf.vars.file.filename = h2o_strdup(NULL, t->data.scalar, SIZE_MAX).base;
            return 0;
#else
            goto NoSessionTickets;
#endif
        }
    }

    h2o_configurator_errprintf(cmd, mode, "`mode` must be one of: `internal`, `off`");
    return -1;
#if !H2O_USE_SESSION_TICKETS
NoSessionTickets:
    h2o_configurator_errprintf(cmd, mode,
                               "`disabled` is the only mode supported (the server is built without support for ticket-based session"
                               "resumption)");
    return -1;
#endif
}

void ssl_session_ticket_init(void)
{
#if H2O_USE_SESSION_TICKETS
    init_internal_defaults();
#endif
}

void ssl_session_ticket_setup(SSL_CTX **contexts, size_t num_contexts)
{
#if H2O_USE_SESSION_TICKETS
    size_t i;

    if (num_contexts == 0)
        return;

    if (conf.update_thread != NULL) {
        /* start session ticket updater thread */
        pthread_t tid;
        pthread_attr_t attr;
        pthread_attr_init(&attr);
        pthread_attr_setdetachstate(&attr, 1);
        h2o_multithread_create_thread(&tid, &attr, conf.update_thread, &conf.vars);
        for (i = 0; i != num_contexts; ++i)
            SSL_CTX_set_tlsext_ticket_key_cb(contexts[i], session_ticket_key_callback);
    } else {
        for (i = 0; i != num_contexts; ++i)
            SSL_CTX_set_options(contexts[i], SSL_CTX_get_options(contexts[i]) | SSL_OP_NO_TICKET);
    }
#endif
}
