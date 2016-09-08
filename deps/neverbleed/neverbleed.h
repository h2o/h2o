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
#ifndef NEVERBLEED_H
#define NEVERBLEED_H

#include <pthread.h>
#include <sys/un.h>
#include <openssl/engine.h>

#ifdef __cplusplus
extern "C" {
#endif

#define NEVERBLEED_ERRBUF_SIZE (256)
#define NEVERBLEED_AUTH_TOKEN_SIZE 32

typedef struct st_neverbleed_t {
    ENGINE *engine;
    pid_t daemon_pid;
    struct sockaddr_un sun_;
    pthread_key_t thread_key;
    unsigned char auth_token[NEVERBLEED_AUTH_TOKEN_SIZE];
} neverbleed_t;

/**
 * initializes the privilege separation engine (returns 0 if successful)
 */
int neverbleed_init(neverbleed_t *nb, char *errbuf);
/**
 * loads a private key file (returns 1 if successful)
 */
int neverbleed_load_private_key_file(neverbleed_t *nb, SSL_CTX *ctx, const char *fn, char *errbuf);
/**
 * setuidgid (also changes the file permissions so that `user` can connect to the daemon, if change_socket_ownership is non-zero)
 */
int neverbleed_setuidgid(neverbleed_t *nb, const char *user, int change_socket_ownership);

#ifdef __cplusplus
}
#endif

#endif
