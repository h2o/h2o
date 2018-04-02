/*
 * Copyright (c) 2016 DeNA Co., Ltd., Kazuho Oku
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
#ifndef h2o__openssl_backport_h
#define h2o__openssl_backport_h

#include <stdlib.h>

/* backports for OpenSSL 1.0.2 */
#if OPENSSL_VERSION_NUMBER < 0x10100000L || (defined(LIBRESSL_VERSION_NUMBER) && LIBRESSL_VERSION_NUMBER < 0x2070000fL)

#define BIO_get_data(bio) ((bio)->ptr)
#define BIO_set_data(bio, p) ((bio)->ptr = (p))
#define BIO_get_init(bio) ((bio)->init)
#define BIO_set_init(bio, i) ((bio)->init = (i))
#define BIO_get_shutdown(bio) ((bio)->shutdown)
#define BIO_set_shutdown(bio, shut) ((bio)->shutdown = (shut))

static inline BIO_METHOD *BIO_meth_new(int type, const char *name)
{
    BIO_METHOD *bm = (BIO_METHOD *)malloc(sizeof(*bm));
    if (bm != NULL) {
        memset(bm, 0, sizeof(*bm));
        bm->type = type;
        bm->name = name;
    }
    return bm;
}

#define BIO_meth_set_write(bm, cb) ((bm)->bwrite = cb)
#define BIO_meth_set_read(bm, cb) ((bm)->bread = cb)
#define BIO_meth_set_puts(bm, cb) ((bm)->bputs = cb)
#define BIO_meth_set_ctrl(bm, cb) ((bm)->ctrl = cb)

#define SSL_CTX_up_ref(ctx) CRYPTO_add(&(ctx)->references, 1, CRYPTO_LOCK_SSL_CTX)

#define X509_STORE_up_ref(store) CRYPTO_add(&(store)->references, 1, CRYPTO_LOCK_X509_STORE)

#endif

/* backports for OpenSSL 1.0.1 and LibreSSL */
#if OPENSSL_VERSION_NUMBER < 0x10002000L || (defined(LIBRESSL_VERSION_NUMBER) && LIBRESSL_VERSION_NUMBER < 0x2070000fL)

#define SSL_is_server(ssl) ((ssl)->server)

#endif

#endif
