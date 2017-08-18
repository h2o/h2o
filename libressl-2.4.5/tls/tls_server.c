/* $OpenBSD: tls_server.c,v 1.18 2015/09/29 10:17:04 deraadt Exp $ */
/*
 * Copyright (c) 2014 Joel Sing <jsing@openbsd.org>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#include <openssl/ec.h>
#include <openssl/err.h>
#include <openssl/ssl.h>

#include <tls.h>
#include "tls_internal.h"

struct tls *
tls_server(void)
{
	struct tls *ctx;

	if ((ctx = tls_new()) == NULL)
		return (NULL);

	ctx->flags |= TLS_SERVER;

	return (ctx);
}

struct tls *
tls_server_conn(struct tls *ctx)
{
	struct tls *conn_ctx;

	if ((conn_ctx = tls_new()) == NULL)
		return (NULL);

	conn_ctx->flags |= TLS_SERVER_CONN;

	return (conn_ctx);
}

int
tls_configure_server(struct tls *ctx)
{
	EC_KEY *ecdh_key;
	unsigned char sid[SSL_MAX_SSL_SESSION_ID_LENGTH];

	if ((ctx->ssl_ctx = SSL_CTX_new(SSLv23_server_method())) == NULL) {
		tls_set_errorx(ctx, "ssl context failure");
		goto err;
	}

	if (tls_configure_ssl(ctx) != 0)
		goto err;
	if (tls_configure_keypair(ctx, ctx->ssl_ctx, ctx->config->keypair, 1) != 0)
		goto err;
	if (ctx->config->verify_client != 0) {
		int verify = SSL_VERIFY_PEER;
		if (ctx->config->verify_client == 1)
			verify |= SSL_VERIFY_FAIL_IF_NO_PEER_CERT;
		if (tls_configure_ssl_verify(ctx, verify) == -1)
			goto err;
	}

	if (ctx->config->dheparams == -1)
		SSL_CTX_set_dh_auto(ctx->ssl_ctx, 1);
	else if (ctx->config->dheparams == 1024)
		SSL_CTX_set_dh_auto(ctx->ssl_ctx, 2);

	if (ctx->config->ecdhecurve == -1) {
		SSL_CTX_set_ecdh_auto(ctx->ssl_ctx, 1);
	} else if (ctx->config->ecdhecurve != NID_undef) {
		if ((ecdh_key = EC_KEY_new_by_curve_name(
		    ctx->config->ecdhecurve)) == NULL) {
			tls_set_errorx(ctx, "failed to set ECDHE curve");
			goto err;
		}
		SSL_CTX_set_options(ctx->ssl_ctx, SSL_OP_SINGLE_ECDH_USE);
		SSL_CTX_set_tmp_ecdh(ctx->ssl_ctx, ecdh_key);
		EC_KEY_free(ecdh_key);
	}

	if (ctx->config->ciphers_server == 1)
		SSL_CTX_set_options(ctx->ssl_ctx,
		    SSL_OP_CIPHER_SERVER_PREFERENCE);

	/*
	 * Set session ID context to a random value.  We don't support
	 * persistent caching of sessions so it is OK to set a temporary
	 * session ID context that is valid during run time.
	 */
	arc4random_buf(sid, sizeof(sid));
	if (!SSL_CTX_set_session_id_context(ctx->ssl_ctx, sid, sizeof(sid))) {
		tls_set_errorx(ctx, "failed to set session id context");
		goto err;
	}

	return (0);

 err:
	return (-1);
}

int
tls_accept_socket(struct tls *ctx, struct tls **cctx, int socket)
{
	return (tls_accept_fds(ctx, cctx, socket, socket));
}

int
tls_accept_fds(struct tls *ctx, struct tls **cctx, int fd_read, int fd_write)
{
	struct tls *conn_ctx = NULL;

	if ((ctx->flags & TLS_SERVER) == 0) {
		tls_set_errorx(ctx, "not a server context");
		goto err;
	}

	if ((conn_ctx = tls_server_conn(ctx)) == NULL) {
		tls_set_errorx(ctx, "connection context failure");
		goto err;
	}

	if ((conn_ctx->ssl_conn = SSL_new(ctx->ssl_ctx)) == NULL) {
		tls_set_errorx(ctx, "ssl failure");
		goto err;
	}
	if (SSL_set_app_data(conn_ctx->ssl_conn, conn_ctx) != 1) {
		tls_set_errorx(ctx, "ssl application data failure");
		goto err;
	}
	if (SSL_set_rfd(conn_ctx->ssl_conn, fd_read) != 1 ||
	    SSL_set_wfd(conn_ctx->ssl_conn, fd_write) != 1) {
		tls_set_errorx(ctx, "ssl file descriptor failure");
		goto err;
	}

	*cctx = conn_ctx;

	return (0);

 err:
	tls_free(conn_ctx);

	*cctx = NULL;

	return (-1);
}

int
tls_handshake_server(struct tls *ctx)
{
	int ssl_ret;
	int rv = -1;

	if ((ctx->flags & TLS_SERVER_CONN) == 0) {
		tls_set_errorx(ctx, "not a server connection context");
		goto err;
	}

	ERR_clear_error();
	if ((ssl_ret = SSL_accept(ctx->ssl_conn)) != 1) {
		rv = tls_ssl_error(ctx, ctx->ssl_conn, ssl_ret, "handshake");
		goto err;
	}

	ctx->state |= TLS_HANDSHAKE_COMPLETE;
	rv = 0;

 err:
	return (rv);
}
