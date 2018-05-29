/*
 * Copyright (c) 2015 Kazuho Oku, DeNA Co., Ltd.
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
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <limits.h>
#include <pthread.h>
#include <pwd.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <unistd.h>
#include <openssl/rand.h>
#include <openssl/ssl.h>
#include <openssl/rsa.h>
#include <openssl/bn.h>
#ifdef __linux__
#include <sys/prctl.h>
#endif
#include "neverbleed.h"

#if (!defined(LIBRESSL_VERSION_NUMBER) && OPENSSL_VERSION_NUMBER >= 0x1010000fL)
#define OPENSSL_1_1_API 1
#else
#define OPENSSL_1_1_API 0
#endif

enum neverbleed_type { NEVERBLEED_TYPE_ERROR, NEVERBLEED_TYPE_RSA, NEVERBLEED_TYPE_ECDSA };

struct expbuf_t {
    char *buf;
    char *start;
    char *end;
    size_t capacity;
};

struct st_neverbleed_rsa_exdata_t {
    neverbleed_t *nb;
    size_t key_index;
};

struct st_neverbleed_thread_data_t {
    pid_t self_pid;
    int fd;
};

static void warnvf(const char *fmt, va_list args)
{
    char errbuf[256];

    if (errno != 0) {
        strerror_r(errno, errbuf, sizeof(errbuf));
    } else {
        errbuf[0] = '\0';
    }

    fprintf(stderr, "[openssl-privsep] ");
    vfprintf(stderr, fmt, args);
    if (errbuf[0] != '\0')
        fputs(errbuf, stderr);
    fputc('\n', stderr);
}

__attribute__((format(printf, 1, 2))) static void warnf(const char *fmt, ...)
{
    va_list args;

    va_start(args, fmt);
    warnvf(fmt, args);
    va_end(args);
}

__attribute__((format(printf, 1, 2), noreturn)) static void dief(const char *fmt, ...)
{
    va_list args;

    va_start(args, fmt);
    warnvf(fmt, args);
    va_end(args);

    abort();
}

static char *dirname(const char *path)
{
    const char *last_slash = strrchr(path, '/');
    char *ret;

    if (last_slash == NULL) {
        errno = 0;
        dief("dirname: no slash in given path:%s", path);
    }
    if ((ret = malloc(last_slash + 1 - path)) == NULL)
        dief("no memory");
    memcpy(ret, path, last_slash - path);
    ret[last_slash - path] = '\0';
    return ret;
}

static void set_cloexec(int fd)
{
    if (fcntl(fd, F_SETFD, O_CLOEXEC) == -1)
        dief("failed to set O_CLOEXEC to fd %d", fd);
}

static int read_nbytes(int fd, void *p, size_t sz)
{
    while (sz != 0) {
        ssize_t r;
        while ((r = read(fd, p, sz)) == -1 && errno == EINTR)
            ;
        if (r == -1) {
            return -1;
        } else if (r == 0) {
            errno = 0;
            return -1;
        }
        p = (char *)p + r;
        sz -= r;
    }
    return 0;
}

static size_t expbuf_size(struct expbuf_t *buf)
{
    return buf->end - buf->start;
}

static void expbuf_dispose(struct expbuf_t *buf)
{
    if (buf->capacity != 0)
        OPENSSL_cleanse(buf->buf, buf->capacity);
    free(buf->buf);
    memset(buf, 0, sizeof(*buf));
}

static void expbuf_reserve(struct expbuf_t *buf, size_t extra)
{
    char *n;

    if (extra <= buf->buf + buf->capacity - buf->end)
        return;

    if (buf->capacity == 0)
        buf->capacity = 4096;
    while (buf->buf + buf->capacity - buf->end < extra)
        buf->capacity *= 2;
    if ((n = realloc(buf->buf, buf->capacity)) == NULL)
        dief("realloc failed");
    buf->start += n - buf->buf;
    buf->end += n - buf->buf;
    buf->buf = n;
}

static void expbuf_push_num(struct expbuf_t *buf, size_t v)
{
    expbuf_reserve(buf, sizeof(v));
    memcpy(buf->end, &v, sizeof(v));
    buf->end += sizeof(v);
}

static void expbuf_push_str(struct expbuf_t *buf, const char *s)
{
    size_t l = strlen(s) + 1;
    expbuf_reserve(buf, l);
    memcpy(buf->end, s, l);
    buf->end += l;
}

static void expbuf_push_bytes(struct expbuf_t *buf, const void *p, size_t l)
{
    expbuf_push_num(buf, l);
    expbuf_reserve(buf, l);
    memcpy(buf->end, p, l);
    buf->end += l;
}

static int expbuf_shift_num(struct expbuf_t *buf, size_t *v)
{
    if (expbuf_size(buf) < sizeof(*v))
        return -1;
    memcpy(v, buf->start, sizeof(*v));
    buf->start += sizeof(*v);
    return 0;
}

static char *expbuf_shift_str(struct expbuf_t *buf)
{
    char *nul = memchr(buf->start, '\0', expbuf_size(buf)), *ret;
    if (nul == NULL)
        return NULL;
    ret = buf->start;
    buf->start = nul + 1;
    return ret;
}

static void *expbuf_shift_bytes(struct expbuf_t *buf, size_t *l)
{
    void *ret;
    if (expbuf_shift_num(buf, l) != 0)
        return NULL;
    if (expbuf_size(buf) < *l)
        return NULL;
    ret = buf->start;
    buf->start += *l;
    return ret;
}

static int expbuf_write(struct expbuf_t *buf, int fd)
{
    struct iovec vecs[2] = {{NULL}};
    size_t bufsz = expbuf_size(buf);
    int vecindex;
    ssize_t r;

    vecs[0].iov_base = &bufsz;
    vecs[0].iov_len = sizeof(bufsz);
    vecs[1].iov_base = buf->start;
    vecs[1].iov_len = bufsz;

    for (vecindex = 0; vecindex != sizeof(vecs) / sizeof(vecs[0]);) {
        while ((r = writev(fd, vecs + vecindex, sizeof(vecs) / sizeof(vecs[0]) - vecindex)) == -1 && errno == EINTR)
            ;
        if (r == -1)
            return -1;
        assert(r != 0);
        while (r != 0 && r >= vecs[vecindex].iov_len) {
            r -= vecs[vecindex].iov_len;
            ++vecindex;
        }
        if (r != 0) {
            vecs[vecindex].iov_base = (char *)vecs[vecindex].iov_base + r;
            vecs[vecindex].iov_len -= r;
        }
    }

    return 0;
}

static int expbuf_read(struct expbuf_t *buf, int fd)
{
    size_t sz;

    if (read_nbytes(fd, &sz, sizeof(sz)) != 0)
        return -1;
    expbuf_reserve(buf, sz);
    if (read_nbytes(fd, buf->end, sz) != 0)
        return -1;
    buf->end += sz;
    return 0;
}

#if !defined(NAME_MAX) || defined(__linux__)
/* readdir(3) is known to be thread-safe on Linux and should be thread-safe on a platform that does not have a predefined value for
   NAME_MAX */
#define FOREACH_DIRENT(dp, dent)                                                                                                   \
    struct dirent *dent;                                                                                                           \
    while ((dent = readdir(dp)) != NULL)
#else
#define FOREACH_DIRENT(dp, dent)                                                                                                   \
    struct {                                                                                                                       \
        struct dirent d;                                                                                                           \
        char s[NAME_MAX + 1];                                                                                                      \
    } dent_;                                                                                                                       \
    struct dirent *dentp, *dent = &dent_.d;                                                                                        \
    int ret;                                                                                                                       \
    while ((ret = readdir_r(dp, dent, &dentp)) == 0 && dentp != NULL)
#endif /* FOREACH_DIRENT */

static void unlink_dir(const char *path)
{
    DIR *dp;
    char buf[PATH_MAX];

    if ((dp = opendir(path)) != NULL) {
        FOREACH_DIRENT(dp, entp)
        {
            if (strcmp(entp->d_name, ".") == 0 || strcmp(entp->d_name, "..") == 0)
                continue;
            snprintf(buf, sizeof(buf), "%s/%s", path, entp->d_name);
            unlink_dir(buf);
        }
        closedir(dp);
    }
    unlink(path);
    rmdir(path);
}

void dispose_thread_data(void *_thdata)
{
    struct st_neverbleed_thread_data_t *thdata = _thdata;
    assert(thdata->fd >= 0);
    close(thdata->fd);
    thdata->fd = -1;
}

struct st_neverbleed_thread_data_t *get_thread_data(neverbleed_t *nb)
{
    struct st_neverbleed_thread_data_t *thdata;
    pid_t self_pid = getpid();
    ssize_t r;

    if ((thdata = pthread_getspecific(nb->thread_key)) != NULL) {
        if (thdata->self_pid == self_pid)
            return thdata;
        /* we have been forked! */
        close(thdata->fd);
    } else {
        if ((thdata = malloc(sizeof(*thdata))) == NULL)
            dief("malloc failed");
    }

    thdata->self_pid = self_pid;
#ifdef SOCK_CLOEXEC
    if ((thdata->fd = socket(PF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0)) == -1)
        dief("socket(2) failed");
#else
    if ((thdata->fd = socket(PF_UNIX, SOCK_STREAM, 0)) == -1)
        dief("socket(2) failed");
    set_cloexec(thdata->fd);
#endif
    while (connect(thdata->fd, (void *)&nb->sun_, sizeof(nb->sun_)) != 0)
        if (errno != EINTR)
            dief("failed to connect to privsep daemon");
    while ((r = write(thdata->fd, nb->auth_token, sizeof(nb->auth_token))) == -1 && errno == EINTR)
        ;
    if (r != sizeof(nb->auth_token))
        dief("failed to send authentication token");
    pthread_setspecific(nb->thread_key, thdata);

    return thdata;
}

static void get_privsep_data(const RSA *rsa, struct st_neverbleed_rsa_exdata_t **exdata,
                             struct st_neverbleed_thread_data_t **thdata)
{
    *exdata = RSA_get_ex_data(rsa, 0);
    if (*exdata == NULL) {
        errno = 0;
        dief("invalid internal ref");
    }
    *thdata = get_thread_data((*exdata)->nb);
}

static const size_t default_reserved_size = 8192;

struct key_slots {
    size_t size;
    size_t reserved_size;
    /* bit array slots:
     *   1-bit slot available
     *   0-bit slot unavailable
     */
    uint8_t *bita_avail;
};

static struct {
    struct {
        pthread_mutex_t lock;
        RSA **keys;
        struct key_slots rsa_slots;
        EC_KEY **ecdsa_keys;
        struct key_slots ecdsa_slots;
    } keys;
    neverbleed_t *nb;
} daemon_vars = {{PTHREAD_MUTEX_INITIALIZER}};

static RSA *daemon_get_rsa(size_t key_index)
{
    RSA *rsa;

    pthread_mutex_lock(&daemon_vars.keys.lock);
    rsa = daemon_vars.keys.keys[key_index];
    if (rsa)
        RSA_up_ref(rsa);
    pthread_mutex_unlock(&daemon_vars.keys.lock);

    return rsa;
}

/*
 *  Returns an available slot in bit array B
 *  or if not found, returns SIZE_MAX
 */
static size_t bita_ffirst(const uint8_t *b, const size_t tot, size_t bits)
{
    if (bits >= tot)
        return SIZE_MAX;

    uint64_t w = *((uint64_t *) b);
    /* __builtin_ffsll returns one plus the index of the least significant 1-bit, or zero if not found */
    uint32_t r = __builtin_ffsll(w);
    if (r)
        return bits + r - 1; /* adjust result */

    return bita_ffirst(&b[8], tot, bits + 64);
}

/*
 * bit operation helpers for the bit-array in key_slots
 */
#define BITMASK(b) (1 << ((b) % CHAR_BIT))
#define BITBYTE(b) ((b) / CHAR_BIT)
#define BITSET(a, b) ((a)[BITBYTE(b)] |= BITMASK(b))
#define BITUNSET(a, b) ((a)[BITBYTE(b)] &= ~BITMASK(b))
#define BITBYTES(nb) ((nb + CHAR_BIT - 1) / CHAR_BIT)
#define BITCHECK(a, b) ((a)[BITBYTE(b)] & BITMASK(b))

static void adjust_slots_reserved_size(int type, struct key_slots *slots)
{
#define ROUND2WORD(n) (n + 64 - 1 - (n + 64 - 1) % 64)
    if (!slots->reserved_size || (slots->size >= slots->reserved_size)) {
        size_t size = slots->reserved_size ? ROUND2WORD((size_t)(slots->reserved_size * 0.50) + slots->reserved_size)
                : default_reserved_size;
#undef ROUND2WORD

        switch (type) {
        case NEVERBLEED_TYPE_RSA:
            if ((daemon_vars.keys.keys = realloc(daemon_vars.keys.keys, sizeof(*daemon_vars.keys.keys) * size)) == NULL)
                dief("no memory");
            break;
        case NEVERBLEED_TYPE_ECDSA:
            if ((daemon_vars.keys.ecdsa_keys = realloc(daemon_vars.keys.ecdsa_keys, sizeof(*daemon_vars.keys.ecdsa_keys) * size)) == NULL)
                dief("no memory");
            break;
        default:
            dief("invalid type adjusting reserved");
        }

        uint8_t *b;
        if ((b = realloc(slots->bita_avail, BITBYTES(size))) == NULL)
            dief("no memory");

        /* set all bits to 1 making all slots available */
        memset(&b[BITBYTES(slots->reserved_size)], 0xff, BITBYTES(size - slots->reserved_size));

        slots->bita_avail = b;
        slots->reserved_size = size;
    }
}

static size_t daemon_set_rsa(RSA *rsa)
{
    pthread_mutex_lock(&daemon_vars.keys.lock);

    adjust_slots_reserved_size(NEVERBLEED_TYPE_RSA, &daemon_vars.keys.rsa_slots);

    size_t index = bita_ffirst(daemon_vars.keys.rsa_slots.bita_avail, daemon_vars.keys.rsa_slots.reserved_size, 0);

    if (index == SIZE_MAX)
        dief("no available slot for key");

    /* set slot as unavailable */
    BITUNSET(daemon_vars.keys.rsa_slots.bita_avail, index);

    daemon_vars.keys.rsa_slots.size++;
    daemon_vars.keys.keys[index] = rsa;
    RSA_up_ref(rsa);
    pthread_mutex_unlock(&daemon_vars.keys.lock);

    return index;
}

static int priv_encdec_proxy(const char *cmd, int flen, const unsigned char *from, unsigned char *_to, RSA *rsa, int padding)
{
    struct st_neverbleed_rsa_exdata_t *exdata;
    struct st_neverbleed_thread_data_t *thdata;
    struct expbuf_t buf = {NULL};
    size_t ret;
    unsigned char *to;
    size_t tolen;

    get_privsep_data(rsa, &exdata, &thdata);

    expbuf_push_str(&buf, cmd);
    expbuf_push_bytes(&buf, from, flen);
    expbuf_push_num(&buf, exdata->key_index);
    expbuf_push_num(&buf, padding);
    if (expbuf_write(&buf, thdata->fd) != 0)
        dief(errno != 0 ? "write error" : "connection closed by daemon");
    expbuf_dispose(&buf);

    if (expbuf_read(&buf, thdata->fd) != 0)
        dief(errno != 0 ? "read error" : "connection closed by daemon");
    if (expbuf_shift_num(&buf, &ret) != 0 || (to = expbuf_shift_bytes(&buf, &tolen)) == NULL) {
        errno = 0;
        dief("failed to parse response");
    }
    memcpy(_to, to, tolen);
    expbuf_dispose(&buf);

    return (int)ret;
}

static int priv_encdec_stub(const char *name,
                            int (*func)(int flen, const unsigned char *from, unsigned char *to, RSA *rsa, int padding),
                            struct expbuf_t *buf)
{
    unsigned char *from, to[4096];
    size_t flen;
    size_t key_index, padding;
    RSA *rsa;
    int ret;

    if ((from = expbuf_shift_bytes(buf, &flen)) == NULL || expbuf_shift_num(buf, &key_index) != 0 ||
        expbuf_shift_num(buf, &padding) != 0) {
        errno = 0;
        warnf("%s: failed to parse request", name);
        return -1;
    }
    if ((rsa = daemon_get_rsa(key_index)) == NULL) {
        errno = 0;
        warnf("%s: invalid key index:%zu\n", name, key_index);
        return -1;
    }
    ret = func((int)flen, from, to, rsa, (int)padding);
    expbuf_dispose(buf);
    RSA_free(rsa);

    expbuf_push_num(buf, ret);
    expbuf_push_bytes(buf, to, ret > 0 ? ret : 0);

    return 0;
}

static int priv_enc_proxy(int flen, const unsigned char *from, unsigned char *to, RSA *rsa, int padding)
{
    return priv_encdec_proxy("priv_enc", flen, from, to, rsa, padding);
}

static int priv_enc_stub(struct expbuf_t *buf)
{
    return priv_encdec_stub(__FUNCTION__, RSA_private_encrypt, buf);
}

static int priv_dec_proxy(int flen, const unsigned char *from, unsigned char *to, RSA *rsa, int padding)
{
    return priv_encdec_proxy("priv_dec", flen, from, to, rsa, padding);
}

static int priv_dec_stub(struct expbuf_t *buf)
{
    return priv_encdec_stub(__FUNCTION__, RSA_private_decrypt, buf);
}

static int sign_proxy(int type, const unsigned char *m, unsigned int m_len, unsigned char *_sigret, unsigned *_siglen,
                      const RSA *rsa)
{
    struct st_neverbleed_rsa_exdata_t *exdata;
    struct st_neverbleed_thread_data_t *thdata;
    struct expbuf_t buf = {NULL};
    size_t ret, siglen;
    unsigned char *sigret;

    get_privsep_data(rsa, &exdata, &thdata);

    expbuf_push_str(&buf, "sign");
    expbuf_push_num(&buf, type);
    expbuf_push_bytes(&buf, m, m_len);
    expbuf_push_num(&buf, exdata->key_index);
    if (expbuf_write(&buf, thdata->fd) != 0)
        dief(errno != 0 ? "write error" : "connection closed by daemon");
    expbuf_dispose(&buf);

    if (expbuf_read(&buf, thdata->fd) != 0)
        dief(errno != 0 ? "read error" : "connection closed by daemon");
    if (expbuf_shift_num(&buf, &ret) != 0 || (sigret = expbuf_shift_bytes(&buf, &siglen)) == NULL) {
        errno = 0;
        dief("failed to parse response");
    }
    memcpy(_sigret, sigret, siglen);
    *_siglen = (unsigned)siglen;
    expbuf_dispose(&buf);

    return (int)ret;
}

static int sign_stub(struct expbuf_t *buf)
{
    unsigned char *m, sigret[4096];
    size_t type, m_len, key_index;
    RSA *rsa;
    unsigned siglen = 0;
    int ret;

    if (expbuf_shift_num(buf, &type) != 0 || (m = expbuf_shift_bytes(buf, &m_len)) == NULL ||
        expbuf_shift_num(buf, &key_index) != 0) {
        errno = 0;
        warnf("%s: failed to parse request", __FUNCTION__);
        return -1;
    }
    if ((rsa = daemon_get_rsa(key_index)) == NULL) {
        errno = 0;
        warnf("%s: invalid key index:%zu", __FUNCTION__, key_index);
        return -1;
    }
    ret = RSA_sign((int)type, m, (unsigned)m_len, sigret, &siglen, rsa);
    expbuf_dispose(buf);
    RSA_free(rsa);

    expbuf_push_num(buf, ret);
    expbuf_push_bytes(buf, sigret, ret == 1 ? siglen : 0);

    return 0;
}

#if !OPENSSL_1_1_API

static void RSA_get0_key(const RSA *rsa, const BIGNUM **n, const BIGNUM **e, const BIGNUM **d)
{
    if (n) {
        *n = rsa->n;
    }

    if (e) {
        *e = rsa->e;
    }

    if (d) {
        *d = rsa->d;
    }
}

static int RSA_set0_key(RSA *rsa, BIGNUM *n, BIGNUM *e, BIGNUM *d)
{
    if (n == NULL || e == NULL) {
        return 0;
    }

    BN_free(rsa->n);
    BN_free(rsa->e);
    BN_free(rsa->d);
    rsa->n = n;
    rsa->e = e;
    rsa->d = d;

    return 1;
}

static void RSA_set_flags(RSA *r, int flags)
{
    r->flags |= flags;
}
#endif

static EVP_PKEY *create_pkey(neverbleed_t *nb, size_t key_index, const char *ebuf, const char *nbuf)
{
    struct st_neverbleed_rsa_exdata_t *exdata;
    RSA *rsa;
    EVP_PKEY *pkey;
    BIGNUM *e = NULL, *n = NULL;

    if ((exdata = malloc(sizeof(*exdata))) == NULL) {
        fprintf(stderr, "no memory\n");
        abort();
    }
    exdata->nb = nb;
    exdata->key_index = key_index;

    rsa = RSA_new_method(nb->engine);
    RSA_set_ex_data(rsa, 0, exdata);
    if (BN_hex2bn(&e, ebuf) == 0) {
        fprintf(stderr, "failed to parse e:%s\n", ebuf);
        abort();
    }
    if (BN_hex2bn(&n, nbuf) == 0) {
        fprintf(stderr, "failed to parse n:%s\n", nbuf);
        abort();
    }
    RSA_set0_key(rsa, n, e, NULL);
    RSA_set_flags(rsa, RSA_FLAG_EXT_PKEY);

    pkey = EVP_PKEY_new();
    EVP_PKEY_set1_RSA(pkey, rsa);
    RSA_free(rsa);

    return pkey;
}

#if OPENSSL_1_1_API

static EC_KEY *daemon_get_ecdsa(size_t key_index)
{
    EC_KEY *ec_key;

    pthread_mutex_lock(&daemon_vars.keys.lock);
    ec_key = daemon_vars.keys.ecdsa_keys[key_index];
    if (ec_key)
        EC_KEY_up_ref(ec_key);
    pthread_mutex_unlock(&daemon_vars.keys.lock);

    return ec_key;
}

static size_t daemon_set_ecdsa(EC_KEY *ec_key)
{
    pthread_mutex_lock(&daemon_vars.keys.lock);

    adjust_slots_reserved_size(NEVERBLEED_TYPE_ECDSA, &daemon_vars.keys.ecdsa_slots);

    size_t index = bita_ffirst(daemon_vars.keys.ecdsa_slots.bita_avail, daemon_vars.keys.ecdsa_slots.reserved_size, 0);

    if (index == SIZE_MAX)
        dief("no available slot for key");

    /* set slot as unavailable */
    BITUNSET(daemon_vars.keys.ecdsa_slots.bita_avail, index);

    daemon_vars.keys.ecdsa_slots.size++;
    daemon_vars.keys.ecdsa_keys[index] = ec_key;
    EC_KEY_up_ref(ec_key);
    pthread_mutex_unlock(&daemon_vars.keys.lock);

    return index;
}

static int ecdsa_sign_stub(struct expbuf_t *buf)
{
    unsigned char *m, sigret[4096];
    size_t type, m_len, key_index;
    EC_KEY *ec_key;
    unsigned siglen = 0;
    int ret;

    if (expbuf_shift_num(buf, &type) != 0 || (m = expbuf_shift_bytes(buf, &m_len)) == NULL ||
        expbuf_shift_num(buf, &key_index) != 0) {
        errno = 0;
        warnf("%s: failed to parse request", __FUNCTION__);
        return -1;
    }
    if ((ec_key = daemon_get_ecdsa(key_index)) == NULL) {
        errno = 0;
        warnf("%s: invalid key index:%zu", __FUNCTION__, key_index);
        return -1;
    }

    ret = ECDSA_sign((int)type, m, (unsigned)m_len, sigret, &siglen, ec_key);
    expbuf_dispose(buf);

    EC_KEY_free(ec_key);

    expbuf_push_num(buf, ret);
    expbuf_push_bytes(buf, sigret, ret == 1 ? siglen : 0);

    return 0;
}

static void ecdsa_get_privsep_data(const EC_KEY *ec_key, struct st_neverbleed_rsa_exdata_t **exdata,
                                   struct st_neverbleed_thread_data_t **thdata)
{
    *exdata = EC_KEY_get_ex_data(ec_key, 0);
    if (*exdata == NULL) {
        errno = 0;
        dief("invalid internal ref");
    }
    *thdata = get_thread_data((*exdata)->nb);
}

static int ecdsa_sign_proxy(int type, const unsigned char *m, int m_len, unsigned char *_sigret, unsigned int *_siglen,
                            const BIGNUM *kinv, const BIGNUM *rp, EC_KEY *ec_key)
{
    struct st_neverbleed_rsa_exdata_t *exdata;
    struct st_neverbleed_thread_data_t *thdata;
    struct expbuf_t buf = {};
    size_t ret, siglen;
    unsigned char *sigret;

    ecdsa_get_privsep_data(ec_key, &exdata, &thdata);

    /* as far as I've tested so far, kinv and rp are always NULL.
       Looks like setup_sign will precompute this, but it is only
       called sign_sig, and it seems to be not used in TLS ECDSA */
    if (kinv != NULL || rp != NULL) {
        errno = 0;
        dief("unexpected non-NULL kinv and rp");
    }

    expbuf_push_str(&buf, "ecdsa_sign");
    expbuf_push_num(&buf, type);
    expbuf_push_bytes(&buf, m, m_len);
    expbuf_push_num(&buf, exdata->key_index);
    if (expbuf_write(&buf, thdata->fd) != 0)
        dief(errno != 0 ? "write error" : "connection closed by daemon");
    expbuf_dispose(&buf);

    if (expbuf_read(&buf, thdata->fd) != 0)
        dief(errno != 0 ? "read error" : "connection closed by daemon");
    if (expbuf_shift_num(&buf, &ret) != 0 || (sigret = expbuf_shift_bytes(&buf, &siglen)) == NULL) {
        errno = 0;
        dief("failed to parse response");
    }
    memcpy(_sigret, sigret, siglen);
    *_siglen = (unsigned)siglen;
    expbuf_dispose(&buf);

    return (int)ret;
}

static EVP_PKEY *ecdsa_create_pkey(neverbleed_t *nb, size_t key_index, int curve_name, const char *ec_pubkeybuf)
{
    struct st_neverbleed_rsa_exdata_t *exdata;
    EC_KEY *ec_key;
    EC_GROUP *ec_group;
    BIGNUM *ec_pubkeybn = NULL;
    EC_POINT *ec_pubkey;
    EVP_PKEY *pkey;

    if ((exdata = malloc(sizeof(*exdata))) == NULL) {
        fprintf(stderr, "no memory\n");
        abort();
    }
    exdata->nb = nb;
    exdata->key_index = key_index;

    ec_key = EC_KEY_new_method(nb->engine);
    EC_KEY_set_ex_data(ec_key, 0, exdata);

    ec_group = EC_GROUP_new_by_curve_name(curve_name);
    if (!ec_group) {
        fprintf(stderr, "could not create EC_GROUP\n");
        abort();
    }

    EC_KEY_set_group(ec_key, ec_group);

    if (BN_hex2bn(&ec_pubkeybn, ec_pubkeybuf) == 0) {
        fprintf(stderr, "failed to parse ECDSA ephemeral public key:%s\n", ec_pubkeybuf);
        abort();
    }

    if ((ec_pubkey = EC_POINT_bn2point(ec_group, ec_pubkeybn, NULL, NULL)) == NULL) {
        fprintf(stderr, "failed to get ECDSA ephemeral public key from BIGNUM\n");
        abort();
    }

    EC_KEY_set_public_key(ec_key, ec_pubkey);

    pkey = EVP_PKEY_new();
    EVP_PKEY_set1_EC_KEY(pkey, ec_key);

    EC_POINT_free(ec_pubkey);
    BN_free(ec_pubkeybn);
    EC_GROUP_free(ec_group);
    EC_KEY_free(ec_key);

    return pkey;
}

static void priv_ecdsa_finish(EC_KEY *key)
{
    struct st_neverbleed_rsa_exdata_t *exdata;
    struct st_neverbleed_thread_data_t *thdata;

    ecdsa_get_privsep_data(key, &exdata, &thdata);

    struct expbuf_t buf = {NULL};
    size_t ret;

    expbuf_push_str(&buf, "del_ecdsa_key");
    expbuf_push_num(&buf, exdata->key_index);
    if (expbuf_write(&buf, thdata->fd) != 0)
        dief(errno != 0 ? "write error" : "connection closed by daemon");
    expbuf_dispose(&buf);

    if (expbuf_read(&buf, thdata->fd) != 0)
        dief(errno != 0 ? "read error" : "connection closed by daemon");
    if (expbuf_shift_num(&buf, &ret) != 0) {
        errno = 0;
        dief("failed to parse response");
    }
    expbuf_dispose(&buf);
}

static int del_ecdsa_key_stub(struct expbuf_t *buf)
{
    size_t key_index;
    int ret = 0;

    if (expbuf_shift_num(buf, &key_index) != 0) {
        errno = 0;
        warnf("%s: failed to parse request", __FUNCTION__);
        return -1;
    }

    if (!daemon_vars.keys.ecdsa_keys || key_index >= daemon_vars.keys.ecdsa_slots.reserved_size) {
        errno = 0;
        warnf("%s: invalid key index %zu", __FUNCTION__, key_index);
        goto respond;
    }

    if (BITCHECK(daemon_vars.keys.ecdsa_slots.bita_avail, key_index)) {
        warnf("%s: index not in use %zu", __FUNCTION__, key_index);
        goto respond;
    }

    pthread_mutex_lock(&daemon_vars.keys.lock);
    /* set slot as available */
    BITSET(daemon_vars.keys.ecdsa_slots.bita_avail, key_index);
    daemon_vars.keys.ecdsa_slots.size--;
    EC_KEY_free(daemon_vars.keys.ecdsa_keys[key_index]);
    daemon_vars.keys.ecdsa_keys[key_index] = NULL;
    pthread_mutex_unlock(&daemon_vars.keys.lock);

    ret = 1;

respond:
    expbuf_dispose(buf);
    expbuf_push_num(buf, ret);
    return 0;
}

#endif

int neverbleed_load_private_key_file(neverbleed_t *nb, SSL_CTX *ctx, const char *fn, char *errbuf)
{
    struct st_neverbleed_thread_data_t *thdata = get_thread_data(nb);
    struct expbuf_t buf = {NULL};
    int ret = 1;
    size_t index, type;
    EVP_PKEY *pkey;

    expbuf_push_str(&buf, "load_key");
    expbuf_push_str(&buf, fn);
    if (expbuf_write(&buf, thdata->fd) != 0)
        dief(errno != 0 ? "write error" : "connection closed by daemon");
    expbuf_dispose(&buf);

    if (expbuf_read(&buf, thdata->fd) != 0)
        dief(errno != 0 ? "read error" : "connection closed by daemon");
    if (expbuf_shift_num(&buf, &type) != 0 || expbuf_shift_num(&buf, &index) != 0) {
        errno = 0;
        dief("failed to parse response");
    }

    switch (type) {
    case NEVERBLEED_TYPE_RSA: {
        char *estr, *nstr;

        if ((estr = expbuf_shift_str(&buf)) == NULL || (nstr = expbuf_shift_str(&buf)) == NULL) {
            errno = 0;
            dief("failed to parse response");
        }
        pkey = create_pkey(nb, index, estr, nstr);
        break;
    }
#if OPENSSL_1_1_API
    case NEVERBLEED_TYPE_ECDSA: {
        char *ec_pubkeystr;
        size_t curve_name;

        if (expbuf_shift_num(&buf, &curve_name) != 0 || (ec_pubkeystr = expbuf_shift_str(&buf)) == NULL) {
            errno = 0;
            dief("failed to parse response");
        }
        pkey = ecdsa_create_pkey(nb, index, curve_name, ec_pubkeystr);
        break;
    }
#endif
    default: {
        char *errstr;

        if ((errstr = expbuf_shift_str(&buf)) == NULL) {
            errno = 0;
            dief("failed to parse response");
        }

        snprintf(errbuf, NEVERBLEED_ERRBUF_SIZE, "%s", errstr);
        return -1;
    }
    }

    expbuf_dispose(&buf);

    /* success */
    if (SSL_CTX_use_PrivateKey(ctx, pkey) != 1) {
        snprintf(errbuf, NEVERBLEED_ERRBUF_SIZE, "SSL_CTX_use_PrivateKey failed");
        ret = 0;
    }

    EVP_PKEY_free(pkey);
    return ret;
}

static int load_key_stub(struct expbuf_t *buf)
{
    char *fn;
    FILE *fp = NULL;
    RSA *rsa = NULL;
    size_t key_index = SIZE_MAX;
    char *estr = NULL, *nstr = NULL, errbuf[NEVERBLEED_ERRBUF_SIZE] = "";
    size_t type = NEVERBLEED_TYPE_ERROR;
    EVP_PKEY *pkey = NULL;
    const EC_GROUP *ec_group;
    BIGNUM *ec_pubkeybn = NULL;
    char *ec_pubkeystr = NULL;

    if ((fn = expbuf_shift_str(buf)) == NULL) {
        warnf("%s: failed to parse request", __FUNCTION__);
        return -1;
    }

    if ((fp = fopen(fn, "rt")) == NULL) {
        strerror_r(errno, errbuf, sizeof(errbuf));
        goto Respond;
    }

    if ((pkey = PEM_read_PrivateKey(fp, NULL, NULL, NULL)) == NULL) {
        snprintf(errbuf, sizeof(errbuf), "failed to parse the private key");
        goto Respond;
    }

    switch (EVP_PKEY_base_id(pkey)) {
    case EVP_PKEY_RSA: {
        const BIGNUM *e, *n;

        rsa = EVP_PKEY_get1_RSA(pkey);
        type = NEVERBLEED_TYPE_RSA;
        key_index = daemon_set_rsa(rsa);
        RSA_get0_key(rsa, &n, &e, NULL);
        estr = BN_bn2hex(e);
        nstr = BN_bn2hex(n);
        break;
    }
    case EVP_PKEY_EC: {
#if OPENSSL_1_1_API
        const EC_POINT *ec_pubkey;
        EC_KEY *ec_key;

        ec_key = EVP_PKEY_get0_EC_KEY(pkey);
        type = NEVERBLEED_TYPE_ECDSA;
        key_index = daemon_set_ecdsa(ec_key);
        ec_group = EC_KEY_get0_group(ec_key);
        ec_pubkey = EC_KEY_get0_public_key(ec_key);
        ec_pubkeybn = BN_new();
        if (!EC_POINT_point2bn(ec_group, ec_pubkey, POINT_CONVERSION_COMPRESSED, ec_pubkeybn, NULL)) {
            type = NEVERBLEED_TYPE_ERROR;
            snprintf(errbuf, sizeof(errbuf), "failed to convert ECDSA public key to BIGNUM");
            goto Respond;
        }
        ec_pubkeystr = BN_bn2hex(ec_pubkeybn);
        break;
#else
        snprintf(errbuf, sizeof(errbuf), "ECDSA support requires OpenSSL >= 1.1.0");
        goto Respond;
#endif
    }
    default:
        snprintf(errbuf, sizeof(errbuf), "unsupported private key: %d", EVP_PKEY_base_id(pkey));
        goto Respond;
    }

Respond:
    expbuf_dispose(buf);
    expbuf_push_num(buf, type);
    expbuf_push_num(buf, key_index);
    switch (type) {
    case NEVERBLEED_TYPE_RSA:
        expbuf_push_str(buf, estr != NULL ? estr : "");
        expbuf_push_str(buf, nstr != NULL ? nstr : "");
        break;
    case NEVERBLEED_TYPE_ECDSA:
        expbuf_push_num(buf, EC_GROUP_get_curve_name(ec_group));
        expbuf_push_str(buf, ec_pubkeystr);
        break;
    default:
        expbuf_push_str(buf, errbuf);
    }
    if (rsa != NULL)
        RSA_free(rsa);
    if (pkey != NULL)
        EVP_PKEY_free(pkey);
    if (estr != NULL)
        OPENSSL_free(estr);
    if (nstr != NULL)
        OPENSSL_free(nstr);
    if (ec_pubkeystr != NULL)
        OPENSSL_free(ec_pubkeystr);
    if (ec_pubkeybn != NULL)
        BN_free(ec_pubkeybn);
    if (fp != NULL)
        fclose(fp);

    return 0;
}

int neverbleed_setuidgid(neverbleed_t *nb, const char *user, int change_socket_ownership)
{
    struct st_neverbleed_thread_data_t *thdata = get_thread_data(nb);
    struct expbuf_t buf = {NULL};
    size_t ret;

    expbuf_push_str(&buf, "setuidgid");
    expbuf_push_str(&buf, user);
    expbuf_push_num(&buf, change_socket_ownership);
    if (expbuf_write(&buf, thdata->fd) != 0)
        dief(errno != 0 ? "write error" : "connection closed by daemon");
    expbuf_dispose(&buf);

    if (expbuf_read(&buf, thdata->fd) != 0)
        dief(errno != 0 ? "read error" : "connection closed by daemon");
    if (expbuf_shift_num(&buf, &ret) != 0) {
        errno = 0;
        dief("failed to parse response");
    }
    expbuf_dispose(&buf);

    return (int)ret;
}

static int setuidgid_stub(struct expbuf_t *buf)
{
    const char *user;
    size_t change_socket_ownership;
    struct passwd pwbuf, *pw;
    char pwstrbuf[65536]; /* should be large enough */
    int ret = -1;

    if ((user = expbuf_shift_str(buf)) == NULL || expbuf_shift_num(buf, &change_socket_ownership) != 0) {
        errno = 0;
        warnf("%s: failed to parse request", __FUNCTION__);
        return -1;
    }

    errno = 0;
    if (getpwnam_r(user, &pwbuf, pwstrbuf, sizeof(pwstrbuf), &pw) != 0) {
        warnf("%s: getpwnam_r failed", __FUNCTION__);
        goto Respond;
    }
    if (pw == NULL) {
        warnf("%s: failed to obtain information of user:%s", __FUNCTION__, user);
        goto Respond;
    }

    if (change_socket_ownership) {
        char *dir;
        if (chown(daemon_vars.nb->sun_.sun_path, pw->pw_uid, pw->pw_gid) != 0)
            dief("chown failed for:%s", daemon_vars.nb->sun_.sun_path);
        dir = dirname(daemon_vars.nb->sun_.sun_path);
        if (chown(dir, pw->pw_uid, pw->pw_gid) != 0)
            dief("chown failed for:%s", dir);
        free(dir);
    }

    /* setuidgid */
    if (setgid(pw->pw_gid) != 0) {
        warnf("%s: setgid(%d) failed", __FUNCTION__, (int)pw->pw_gid);
        goto Respond;
    }
    if (initgroups(pw->pw_name, pw->pw_gid) != 0) {
        warnf("%s: initgroups(%s, %d) failed", __FUNCTION__, pw->pw_name, (int)pw->pw_gid);
        goto Respond;
    }
    if (setuid(pw->pw_uid) != 0) {
        warnf("%s: setuid(%d) failed\n", __FUNCTION__, (int)pw->pw_uid);
        goto Respond;
    }
    ret = 0;

Respond:
    expbuf_dispose(buf);
    expbuf_push_num(buf, ret);
    return 0;
}

__attribute__((noreturn)) static void *daemon_close_notify_thread(void *_close_notify_fd)
{
    int close_notify_fd = (int)((char *)_close_notify_fd - (char *)NULL);
    char b;
    ssize_t r;

Redo:
    r = read(close_notify_fd, &b, 1);
    if (r == -1 && errno == EINTR)
        goto Redo;
    if (r > 0)
        goto Redo;
    /* close or error */

    /* unlink the temporary directory and socket file */
    unlink_dir(dirname(daemon_vars.nb->sun_.sun_path));

    _exit(0);
}

static int priv_rsa_finish(RSA *rsa)
{
    struct st_neverbleed_rsa_exdata_t *exdata;
    struct st_neverbleed_thread_data_t *thdata;

    get_privsep_data(rsa, &exdata, &thdata);

    struct expbuf_t buf = {NULL};
    size_t ret;

    expbuf_push_str(&buf, "del_rsa_key");
    expbuf_push_num(&buf, exdata->key_index);
    if (expbuf_write(&buf, thdata->fd) != 0)
        dief(errno != 0 ? "write error" : "connection closed by daemon");
    expbuf_dispose(&buf);

    if (expbuf_read(&buf, thdata->fd) != 0)
        dief(errno != 0 ? "read error" : "connection closed by daemon");
    if (expbuf_shift_num(&buf, &ret) != 0) {
        errno = 0;
        dief("failed to parse response");
    }
    expbuf_dispose(&buf);

    return (int)ret;
}

static int del_rsa_key_stub(struct expbuf_t *buf)
{
    size_t key_index;

    int ret = 0;

    if (expbuf_shift_num(buf, &key_index) != 0) {
        errno = 0;
        warnf("%s: failed to parse request", __FUNCTION__);
        return -1;
    }

    if (!daemon_vars.keys.keys || key_index >= daemon_vars.keys.rsa_slots.reserved_size) {
        errno = 0;
        warnf("%s: invalid key index %zu", __FUNCTION__, key_index);
        goto respond;
    }

    if (BITCHECK(daemon_vars.keys.rsa_slots.bita_avail, key_index)) {
        warnf("%s: index not in use %zu", __FUNCTION__, key_index);
        goto respond;
    }

    pthread_mutex_lock(&daemon_vars.keys.lock);
    /* set slot as available */
    BITSET(daemon_vars.keys.rsa_slots.bita_avail, key_index);
    daemon_vars.keys.rsa_slots.size--;
    RSA_free(daemon_vars.keys.keys[key_index]);
    daemon_vars.keys.keys[key_index] = NULL;
    pthread_mutex_unlock(&daemon_vars.keys.lock);

    ret = 1;

respond:
    expbuf_dispose(buf);
    expbuf_push_num(buf, ret);
    return 0;
}

static void *daemon_conn_thread(void *_sock_fd)
{
    int sock_fd = (int)((char *)_sock_fd - (char *)NULL);
    struct expbuf_t buf = {NULL};
    unsigned char auth_token[NEVERBLEED_AUTH_TOKEN_SIZE];

    /* authenticate */
    if (read_nbytes(sock_fd, &auth_token, sizeof(auth_token)) != 0) {
        warnf("failed to receive authencication token from client");
        goto Exit;
    }
    if (memcmp(auth_token, daemon_vars.nb->auth_token, NEVERBLEED_AUTH_TOKEN_SIZE) != 0) {
        warnf("client authentication failed");
        goto Exit;
    }

    while (1) {
        char *cmd;
        if (expbuf_read(&buf, sock_fd) != 0) {
            if (errno != 0)
                warnf("read error");
            break;
        }
        if ((cmd = expbuf_shift_str(&buf)) == NULL) {
            errno = 0;
            warnf("failed to parse request");
            break;
        }
        if (strcmp(cmd, "priv_enc") == 0) {
            if (priv_enc_stub(&buf) != 0)
                break;
        } else if (strcmp(cmd, "priv_dec") == 0) {
            if (priv_dec_stub(&buf) != 0)
                break;
        } else if (strcmp(cmd, "sign") == 0) {
            if (sign_stub(&buf) != 0)
                break;
#if OPENSSL_1_1_API
        } else if (strcmp(cmd, "ecdsa_sign") == 0) {
            if (ecdsa_sign_stub(&buf) != 0)
                break;
        } else if (strcmp(cmd, "del_ecdsa_key") == 0) {
            if (del_ecdsa_key_stub(&buf) != 0)
                break;
#endif
        } else if (strcmp(cmd, "load_key") == 0) {
            if (load_key_stub(&buf) != 0)
                break;
        } else if (strcmp(cmd, "del_rsa_key") == 0) {
            if (del_rsa_key_stub(&buf) != 0)
                break;
        } else if (strcmp(cmd, "setuidgid") == 0) {
            if (setuidgid_stub(&buf) != 0)
                break;
        } else {
            warnf("unknown command:%s", cmd);
            break;
        }
        if (expbuf_write(&buf, sock_fd) != 0) {
            warnf(errno != 0 ? "write error" : "connection closed by client");
            break;
        }
        expbuf_dispose(&buf);
    }

Exit:
    expbuf_dispose(&buf);
    close(sock_fd);

    return NULL;
}

__attribute__((noreturn)) static void daemon_main(int listen_fd, int close_notify_fd, const char *tempdir)
{
    pthread_t tid;
    pthread_attr_t thattr;
    int sock_fd;

    { /* close all descriptors (except STDIN, STDOUT, STRERR, listen_fd, close_notify_fd) */
        int fd = (int)sysconf(_SC_OPEN_MAX) - 1;
        for (; fd > 2; --fd) {
            if (fd == listen_fd || fd == close_notify_fd)
                continue;
            close(fd);
        }
    }

    pthread_attr_init(&thattr);
    pthread_attr_setdetachstate(&thattr, 1);

    if (pthread_create(&tid, &thattr, daemon_close_notify_thread, (char *)NULL + close_notify_fd) != 0)
        dief("pthread_create failed");

    while (1) {
        while ((sock_fd = accept(listen_fd, NULL, NULL)) == -1)
            ;
        if (pthread_create(&tid, &thattr, daemon_conn_thread, (char *)NULL + sock_fd) != 0)
            dief("pthread_create failed");
    }
}

#if !OPENSSL_1_1_API

static RSA_METHOD static_rsa_method = {
    "privsep RSA method", /* name */
    NULL,                 /* rsa_pub_enc */
    NULL,                 /* rsa_pub_dec */
    priv_enc_proxy,       /* rsa_priv_enc */
    priv_dec_proxy,       /* rsa_priv_dec */
    NULL,                 /* rsa_mod_exp */
    NULL,                 /* bn_mod_exp */
    NULL,                 /* init */
    priv_rsa_finish,      /* finish */
    RSA_FLAG_SIGN_VER,    /* flags */
    NULL,                 /* app data */
    sign_proxy,           /* rsa_sign */
    NULL,                 /* rsa_verify */
    NULL                  /* rsa_keygen */
};

#endif

int neverbleed_init(neverbleed_t *nb, char *errbuf)
{
    int pipe_fds[2] = {-1, -1}, listen_fd = -1;
    char *tempdir = NULL;
#if OPENSSL_1_1_API
    const RSA_METHOD *default_method = RSA_PKCS1_OpenSSL();
    EC_KEY_METHOD *ecdsa_method;
    const EC_KEY_METHOD *ecdsa_default_method;
    RSA_METHOD *rsa_method = RSA_meth_new("privsep RSA method", 0);

    RSA_meth_set_priv_enc(rsa_method, priv_enc_proxy);
    RSA_meth_set_priv_dec(rsa_method, priv_dec_proxy);
    RSA_meth_set_sign(rsa_method, sign_proxy);

    RSA_meth_set_pub_enc(rsa_method, RSA_meth_get_pub_enc(default_method));
    RSA_meth_set_pub_dec(rsa_method, RSA_meth_get_pub_dec(default_method));
    RSA_meth_set_verify(rsa_method, RSA_meth_get_verify(default_method));

    RSA_meth_set_finish(rsa_method, priv_rsa_finish);

    /* setup EC_KEY_METHOD for ECDSA */
    ecdsa_default_method = EC_KEY_get_default_method();
    ecdsa_method = EC_KEY_METHOD_new(ecdsa_default_method);

    EC_KEY_METHOD_set_keygen(ecdsa_method, NULL);
    EC_KEY_METHOD_set_compute_key(ecdsa_method, NULL);
    /* it seems sign_sig and sign_setup is not used in TLS ECDSA. */
    EC_KEY_METHOD_set_sign(ecdsa_method, ecdsa_sign_proxy, NULL, NULL);
    EC_KEY_METHOD_set_init(ecdsa_method, NULL, priv_ecdsa_finish, NULL, NULL, NULL, NULL);
#else
    const RSA_METHOD *default_method = RSA_PKCS1_SSLeay();
    RSA_METHOD *rsa_method = &static_rsa_method;

    rsa_method->rsa_pub_enc = default_method->rsa_pub_enc;
    rsa_method->rsa_pub_dec = default_method->rsa_pub_dec;
    rsa_method->rsa_verify = default_method->rsa_verify;
#endif

    /* setup the daemon */
    if (pipe(pipe_fds) != 0) {
        snprintf(errbuf, NEVERBLEED_ERRBUF_SIZE, "pipe(2) failed:%s", strerror(errno));
        goto Fail;
    }
    set_cloexec(pipe_fds[1]);
    if ((tempdir = strdup("/tmp/openssl-privsep.XXXXXX")) == NULL) {
        snprintf(errbuf, NEVERBLEED_ERRBUF_SIZE, "no memory");
        goto Fail;
    }
    if (mkdtemp(tempdir) == NULL) {
        snprintf(errbuf, NEVERBLEED_ERRBUF_SIZE, "failed to create temporary directory under /tmp:%s", strerror(errno));
        goto Fail;
    }
    memset(&nb->sun_, 0, sizeof(nb->sun_));
    nb->sun_.sun_family = AF_UNIX;
    snprintf(nb->sun_.sun_path, sizeof(nb->sun_.sun_path), "%s/_", tempdir);
    RAND_bytes(nb->auth_token, sizeof(nb->auth_token));
    if ((listen_fd = socket(PF_UNIX, SOCK_STREAM, 0)) == -1) {
        snprintf(errbuf, NEVERBLEED_ERRBUF_SIZE, "socket(2) failed:%s", strerror(errno));
        goto Fail;
    }
    if (bind(listen_fd, (void *)&nb->sun_, sizeof(nb->sun_)) != 0) {
        snprintf(errbuf, NEVERBLEED_ERRBUF_SIZE, "failed to bind to %s:%s", nb->sun_.sun_path, strerror(errno));
        goto Fail;
    }
    if (listen(listen_fd, SOMAXCONN) != 0) {
        snprintf(errbuf, NEVERBLEED_ERRBUF_SIZE, "listen(2) failed:%s", strerror(errno));
        goto Fail;
    }
    nb->daemon_pid = fork();
    switch (nb->daemon_pid) {
    case -1:
        snprintf(errbuf, NEVERBLEED_ERRBUF_SIZE, "fork(2) failed:%s", strerror(errno));
        goto Fail;
    case 0:
        close(pipe_fds[1]);
#ifdef __linux__
        prctl(PR_SET_DUMPABLE, 0, 0, 0, 0);
#endif
        daemon_vars.nb = nb;
        daemon_main(listen_fd, pipe_fds[0], tempdir);
        break;
    default:
        break;
    }
    close(listen_fd);
    listen_fd = -1;
    close(pipe_fds[0]);
    pipe_fds[0] = -1;

    /* setup engine */
    if ((nb->engine = ENGINE_new()) == NULL || !ENGINE_set_id(nb->engine, "neverbleed") ||
        !ENGINE_set_name(nb->engine, "privilege separation software engine") || !ENGINE_set_RSA(nb->engine, rsa_method)
#if OPENSSL_1_1_API
        || !ENGINE_set_EC(nb->engine, ecdsa_method)
#endif
            ) {
        snprintf(errbuf, NEVERBLEED_ERRBUF_SIZE, "failed to initialize the OpenSSL engine");
        goto Fail;
    }
    ENGINE_add(nb->engine);

    /* setup thread key */
    pthread_key_create(&nb->thread_key, dispose_thread_data);

    free(tempdir);
    return 0;
Fail:
    if (pipe_fds[0] != -1)
        close(pipe_fds[0]);
    if (pipe_fds[1] != -1)
        close(pipe_fds[1]);
    if (tempdir != NULL) {
        unlink_dir(tempdir);
        free(tempdir);
    }
    if (listen_fd != -1)
        close(listen_fd);
    if (nb->engine != NULL) {
        ENGINE_free(nb->engine);
        nb->engine = NULL;
    }
    return -1;
}
