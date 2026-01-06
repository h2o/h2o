/*
 * Copyright (c) 2014 DeNA Co., Ltd.
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
#include <errno.h>
#include <limits.h>
#include <netinet/in.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <unistd.h>
#include "h2o.h"
#include "h2o/http1.h"
#include "h2o/http2.h"
#include "h2o/memcached.h"
#ifndef H2O_USE_HTTP3
#define H2O_USE_HTTP3 1
#endif
#if H2O_USE_HTTP3
#include "h2o/http3_server.h"
#include "h2o/http3_common.h"
#include "picotls.h"
#include "picotls/openssl.h"
#include "quicly.h"
#include "quicly/defaults.h"
#endif

#define USE_HTTPS 1
#define USE_MEMCACHED 0
#define USE_HTTP3 H2O_USE_HTTP3
#define HTTP3_PORT 7891

static h2o_pathconf_t *register_handler(h2o_hostconf_t *hostconf, const char *path, int (*on_req)(h2o_handler_t *, h2o_req_t *))
{
    h2o_pathconf_t *pathconf = h2o_config_register_path(hostconf, path, 0);
    h2o_handler_t *handler = h2o_create_handler(pathconf, sizeof(*handler));
    handler->on_req = on_req;
    return pathconf;
}

static int chunked_test(h2o_handler_t *self, h2o_req_t *req)
{
    static h2o_generator_t generator = {NULL, NULL};

    if (!h2o_memis(req->method.base, req->method.len, H2O_STRLIT("GET")))
        return -1;

    h2o_iovec_t body = h2o_strdup(&req->pool, "hello world\n", SIZE_MAX);
    req->res.status = 200;
    req->res.reason = "OK";
    h2o_add_header(&req->pool, &req->res.headers, H2O_TOKEN_CONTENT_TYPE, NULL, H2O_STRLIT("text/plain"));
    h2o_start_response(req, &generator);
    h2o_send(req, &body, 1, 1);

    return 0;
}

static int reproxy_test(h2o_handler_t *self, h2o_req_t *req)
{
    if (!h2o_memis(req->method.base, req->method.len, H2O_STRLIT("GET")))
        return -1;

    req->res.status = 200;
    req->res.reason = "OK";
    h2o_add_header(&req->pool, &req->res.headers, H2O_TOKEN_X_REPROXY_URL, NULL, H2O_STRLIT("http://www.ietf.org/"));
    h2o_send_inline(req, H2O_STRLIT("you should never see this!\n"));

    return 0;
}

static int post_test(h2o_handler_t *self, h2o_req_t *req)
{
    if (h2o_memis(req->method.base, req->method.len, H2O_STRLIT("POST")) &&
        h2o_memis(req->path_normalized.base, req->path_normalized.len, H2O_STRLIT("/post-test/"))) {
        static h2o_generator_t generator = {NULL, NULL};
        req->res.status = 200;
        req->res.reason = "OK";
        h2o_add_header(&req->pool, &req->res.headers, H2O_TOKEN_CONTENT_TYPE, NULL, H2O_STRLIT("text/plain; charset=utf-8"));
        h2o_start_response(req, &generator);
        h2o_send(req, &req->entity, 1, 1);
        return 0;
    }

    return -1;
}

static h2o_globalconf_t config;
static h2o_context_t ctx;
static h2o_multithread_receiver_t libmemcached_receiver;
static h2o_accept_ctx_t accept_ctx;

#if USE_HTTP3
static h2o_http3_server_ctx_t http3_ctx;
static quicly_context_t quic_ctx;
static ptls_context_t ptls_ctx;
static ptls_openssl_sign_certificate_t sign_certificate;
static quicly_cid_plaintext_t next_cid;
static h2o_accept_ctx_t http3_accept_ctx;
#endif

#if H2O_USE_LIBUV

static void on_accept(uv_stream_t *listener, int status)
{
    uv_tcp_t *conn;
    h2o_socket_t *sock;

    if (status != 0)
        return;

    conn = h2o_mem_alloc(sizeof(*conn));
    uv_tcp_init(listener->loop, conn);

    if (uv_accept(listener, (uv_stream_t *)conn) != 0) {
        uv_close((uv_handle_t *)conn, (uv_close_cb)free);
        return;
    }

    sock = h2o_uv_socket_create((uv_handle_t *)conn, (uv_close_cb)free);
    h2o_accept(&accept_ctx, sock);
}

static int create_listener(void)
{
    static uv_tcp_t listener;
    struct sockaddr_in addr;
    int r;

    uv_tcp_init(ctx.loop, &listener);
    uv_ip4_addr("127.0.0.1", 7890, &addr);
    if ((r = uv_tcp_bind(&listener, (struct sockaddr *)&addr, 0)) != 0) {
        fprintf(stderr, "uv_tcp_bind:%s\n", uv_strerror(r));
        goto Error;
    }
    if ((r = uv_listen((uv_stream_t *)&listener, 128, on_accept)) != 0) {
        fprintf(stderr, "uv_listen:%s\n", uv_strerror(r));
        goto Error;
    }

    return 0;
Error:
    uv_close((uv_handle_t *)&listener, NULL);
    return r;
}

#else

static void on_accept(h2o_socket_t *listener, const char *err)
{
    h2o_socket_t *sock;

    if (err != NULL) {
        return;
    }

    if ((sock = h2o_evloop_socket_accept(listener)) == NULL)
        return;
    h2o_accept(&accept_ctx, sock);
}

static int create_listener(void)
{
    struct sockaddr_in addr;
    int fd, reuseaddr_flag = 1;
    h2o_socket_t *sock;

    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(0x7f000001);
    addr.sin_port = htons(7890);

    if ((fd = socket(AF_INET, SOCK_STREAM, 0)) == -1 ||
        setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &reuseaddr_flag, sizeof(reuseaddr_flag)) != 0 ||
        bind(fd, (struct sockaddr *)&addr, sizeof(addr)) != 0 || listen(fd, SOMAXCONN) != 0) {
        return -1;
    }

    sock = h2o_evloop_socket_create(ctx.loop, fd, H2O_SOCKET_FLAG_DONT_READ);
    h2o_socket_read_start(sock, on_accept);

    return 0;
}

#endif

#if USE_HTTP3
static int on_client_hello_cb(ptls_on_client_hello_t *self, ptls_t *tls, ptls_on_client_hello_parameters_t *params)
{
    if (params->incompatible_version)
        return 0;

    if (params->negotiated_protocols.count != 0) {
        size_t i, j;
        for (i = 0; i != sizeof(h2o_http3_alpn) / sizeof(h2o_http3_alpn[0]); ++i) {
            for (j = 0; j != params->negotiated_protocols.count; ++j)
                if (h2o_memis(h2o_http3_alpn[i].base, h2o_http3_alpn[i].len, params->negotiated_protocols.list[j].base,
                              params->negotiated_protocols.list[j].len))
                    goto Found;
        }
        return PTLS_ALERT_NO_APPLICATION_PROTOCOL;
    Found: {
        int ret = ptls_set_negotiated_protocol(tls, (const char *)h2o_http3_alpn[i].base, h2o_http3_alpn[i].len);
        if (ret != 0)
            return ret;
    }
    }
    return 0;
}

static ptls_on_client_hello_t on_client_hello = {on_client_hello_cb};

static int setup_ptls_context(const char *cert_file, const char *key_file)
{
    ptls_ctx = (ptls_context_t){
        .random_bytes = ptls_openssl_random_bytes,
        .get_time = &ptls_get_time,
        .key_exchanges = ptls_openssl_key_exchanges,
        .cipher_suites = ptls_openssl_cipher_suites,
        .sign_certificate = &sign_certificate.super,
        .on_client_hello = &on_client_hello,
    };

    if (ptls_load_certificates(&ptls_ctx, cert_file) != 0) {
        fprintf(stderr, "failed to load certificates from %s\n", cert_file);
        return -1;
    }

    FILE *fp = fopen(key_file, "r");
    if (fp == NULL) {
        fprintf(stderr, "failed to open key file: %s\n", key_file);
        return -1;
    }
    EVP_PKEY *pkey = PEM_read_PrivateKey(fp, NULL, NULL, NULL);
    fclose(fp);
    if (pkey == NULL) {
        fprintf(stderr, "failed to load private key from %s\n", key_file);
        return -1;
    }

    if (ptls_openssl_init_sign_certificate(&sign_certificate, pkey) != 0) {
        fprintf(stderr, "failed to setup private key\n");
        EVP_PKEY_free(pkey);
        return -1;
    }
    EVP_PKEY_free(pkey);

    return 0;
}

static int setup_quic_context(void)
{
    static uint8_t cid_key[32] = {0};
    ptls_openssl_random_bytes(cid_key, sizeof(cid_key));

    quic_ctx = quicly_spec_context;
    quic_ctx.tls = &ptls_ctx;
    quic_ctx.now = &quicly_default_now;
    quic_ctx.init_cc = &quicly_default_init_cc;
    quic_ctx.crypto_engine = &quicly_default_crypto_engine;

    quic_ctx.cid_encryptor =
        quicly_new_default_cid_encryptor(&ptls_openssl_aes128ecb, &ptls_openssl_aes128ecb, &ptls_openssl_sha256,
                                         ptls_iovec_init(cid_key, sizeof(cid_key)));
    if (quic_ctx.cid_encryptor == NULL) {
        fprintf(stderr, "failed to create CID encryptor\n");
        return -1;
    }

    quicly_amend_ptls_context(&ptls_ctx);
    h2o_http3_server_amend_quicly_context(&config, &quic_ctx);

    next_cid = (quicly_cid_plaintext_t){
        .master_id = 0,
        .thread_id = 0,
        .node_id = 0,
    };

    return 0;
}

static int create_udp_listener(h2o_socket_t **sock_out)
{
    struct sockaddr_in addr;
    int fd, optval = 1;

    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(0x7f000001);
    addr.sin_port = htons(HTTP3_PORT);

    if ((fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) == -1) {
        perror("socket(SOCK_DGRAM)");
        return -1;
    }

    if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(optval)) != 0) {
        perror("setsockopt(SO_REUSEADDR)");
        close(fd);
        return -1;
    }

#if defined(IP_PKTINFO)
    if (setsockopt(fd, IPPROTO_IP, IP_PKTINFO, &optval, sizeof(optval)) != 0) {
        perror("setsockopt(IP_PKTINFO)");
        close(fd);
        return -1;
    }
#elif defined(IP_RECVDSTADDR)
    if (setsockopt(fd, IPPROTO_IP, IP_RECVDSTADDR, &optval, sizeof(optval)) != 0) {
        perror("setsockopt(IP_RECVDSTADDR)");
        close(fd);
        return -1;
    }
#endif

    if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
        perror("bind(UDP)");
        close(fd);
        return -1;
    }

    h2o_socket_set_df_bit(fd, AF_INET);

    /* QUIC reads datagrams directly using recvmsg / recvmmsg; prevent the socket layer from consuming UDP payloads. */
    *sock_out = h2o_evloop_socket_create(ctx.loop, fd, H2O_SOCKET_FLAG_DONT_READ);

    return 0;
}

static h2o_quic_conn_t *on_http3_accept(h2o_quic_ctx_t *quic_ctx, quicly_address_t *destaddr, quicly_address_t *srcaddr,
                                        quicly_decoded_packet_t *packet)
{
    h2o_http3_server_ctx_t *h3ctx = H2O_STRUCT_FROM_MEMBER(h2o_http3_server_ctx_t, super, quic_ctx);

    h2o_http3_conn_t *conn = h2o_http3_server_accept(h3ctx, destaddr, srcaddr, packet, NULL, &H2O_HTTP3_CONN_CALLBACKS);

    if (conn == NULL) {
        return NULL;
    }
    if (&conn->super == &h2o_quic_accept_conn_decryption_failed) {
        return NULL;
    }
    if (conn == &h2o_http3_accept_conn_closed) {
        return NULL;
    }

    return &conn->super;
}
#endif

static int setup_ssl(const char *cert_file, const char *key_file, const char *ciphers)
{
    SSL_load_error_strings();
    SSL_library_init();
    OpenSSL_add_all_algorithms();

    accept_ctx.ssl_ctx = SSL_CTX_new(SSLv23_server_method());
    SSL_CTX_set_options(accept_ctx.ssl_ctx, SSL_OP_NO_SSLv2);

    if (USE_MEMCACHED) {
        accept_ctx.libmemcached_receiver = &libmemcached_receiver;
        h2o_accept_setup_memcached_ssl_resumption(h2o_memcached_create_context("127.0.0.1", 11211, 0, 1, "h2o:ssl-resumption:"),
                                                  86400);
        h2o_socket_ssl_async_resumption_setup_ctx(accept_ctx.ssl_ctx);
    }

#ifdef SSL_CTX_set_ecdh_auto
    SSL_CTX_set_ecdh_auto(accept_ctx.ssl_ctx, 1);
#endif

    /* load certificate and private key */
    if (SSL_CTX_use_certificate_chain_file(accept_ctx.ssl_ctx, cert_file) != 1) {
        fprintf(stderr, "an error occurred while trying to load server certificate file:%s\n", cert_file);
        return -1;
    }
    if (SSL_CTX_use_PrivateKey_file(accept_ctx.ssl_ctx, key_file, SSL_FILETYPE_PEM) != 1) {
        fprintf(stderr, "an error occurred while trying to load private key file:%s\n", key_file);
        return -1;
    }

    if (SSL_CTX_set_cipher_list(accept_ctx.ssl_ctx, ciphers) != 1) {
        fprintf(stderr, "ciphers could not be set: %s\n", ciphers);
        return -1;
    }

/* setup protocol negotiation methods */
#if H2O_USE_NPN
    h2o_ssl_register_npn_protocols(accept_ctx.ssl_ctx, h2o_http2_npn_protocols);
#endif
#if H2O_USE_ALPN
    h2o_ssl_register_alpn_protocols(accept_ctx.ssl_ctx, h2o_http2_alpn_protocols);
#endif

    return 0;
}

int main(int argc, char **argv)
{
    h2o_hostconf_t *hostconf;
    h2o_access_log_filehandle_t *logfh = h2o_access_log_open_handle("/dev/stdout", NULL, H2O_LOGCONF_ESCAPE_APACHE);
    h2o_pathconf_t *pathconf;

    signal(SIGPIPE, SIG_IGN);

    h2o_config_init(&config);
    hostconf = h2o_config_register_host(&config, h2o_iovec_init(H2O_STRLIT("default")), 65535);

    pathconf = register_handler(hostconf, "/post-test", post_test);
    if (logfh != NULL)
        h2o_access_log_register(pathconf, logfh);

    pathconf = register_handler(hostconf, "/chunked-test", chunked_test);
    if (logfh != NULL)
        h2o_access_log_register(pathconf, logfh);

    pathconf = register_handler(hostconf, "/reproxy-test", reproxy_test);
    h2o_reproxy_register(pathconf);
    if (logfh != NULL)
        h2o_access_log_register(pathconf, logfh);

    pathconf = h2o_config_register_path(hostconf, "/", 0);
    h2o_file_register(pathconf, "examples/doc_root", NULL, NULL, 0);
    if (logfh != NULL)
        h2o_access_log_register(pathconf, logfh);

#if H2O_USE_LIBUV
    uv_loop_t loop;
    uv_loop_init(&loop);
    h2o_context_init(&ctx, &loop, &config);
#else
    h2o_context_init(&ctx, h2o_evloop_create(), &config);
#endif
    if (USE_MEMCACHED)
        h2o_multithread_register_receiver(ctx.queue, &libmemcached_receiver, h2o_memcached_receiver);

    if (USE_HTTPS && setup_ssl("examples/h2o/server.crt", "examples/h2o/server.key",
                               "DEFAULT:!MD5:!DSS:!DES:!RC4:!RC2:!SEED:!IDEA:!NULL:!ADH:!EXP:!SRP:!PSK") != 0)
        goto Error;

    accept_ctx.ctx = &ctx;
    accept_ctx.hosts = config.hosts;

    if (create_listener() != 0) {
        fprintf(stderr, "failed to listen to 127.0.0.1:7890:%s\n", strerror(errno));
        goto Error;
    }
    printf("HTTP/1 and HTTP/2 listening on https://127.0.0.1:7890 (TCP)\n");

#if USE_HTTP3 && !H2O_USE_LIBUV
    if (setup_ptls_context("examples/h2o/server.crt", "examples/h2o/server.key") != 0)
        goto Error;

    if (setup_quic_context() != 0)
        goto Error;

    h2o_socket_t *udp_sock;
    if (create_udp_listener(&udp_sock) != 0) {
        fprintf(stderr, "failed to create UDP listener on 127.0.0.1:%d\n", HTTP3_PORT);
        goto Error;
    }

    http3_accept_ctx.ctx = &ctx;
    http3_accept_ctx.hosts = config.hosts;

    h2o_http3_server_init_context(&ctx, &http3_ctx.super, ctx.loop, udp_sock, &quic_ctx, &next_cid, on_http3_accept, NULL,
                                  config.http3.use_gso);
    http3_ctx.accept_ctx = &http3_accept_ctx;

    printf("HTTP/3 listening on https://127.0.0.1:%d (UDP/QUIC)\n", HTTP3_PORT);
#endif

#if H2O_USE_LIBUV
    uv_run(ctx.loop, UV_RUN_DEFAULT);
#else
    while (h2o_evloop_run(ctx.loop, INT32_MAX) == 0)
        ;
#endif

Error:
    return 1;
}
