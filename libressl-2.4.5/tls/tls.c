/* $OpenBSD: tls.c,v 1.40 2016/07/06 16:16:36 jsing Exp $ */
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

#include <sys/socket.h>

#include <errno.h>
#include <limits.h>
#include <stdlib.h>
#include <unistd.h>

#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/x509.h>

#include <tls.h>
#include "tls_internal.h"

static struct tls_config *tls_config_default;

int
tls_init(void)
{
	static int tls_initialised = 0;

	if (tls_initialised)
		return (0);

	SSL_load_error_strings();
	SSL_library_init();

	if (BIO_sock_init() != 1)
		return (-1);

	if ((tls_config_default = tls_config_new()) == NULL)
		return (-1);

	tls_initialised = 1;

	return (0);
}

const char *
tls_error(struct tls *ctx)
{
	return ctx->error.msg;
}

static int
tls_error_vset(struct tls_error *error, int errnum, const char *fmt, va_list ap)
{
	char *errmsg = NULL;
	int rv = -1;

	free(error->msg);
	error->msg = NULL;
	error->num = errnum;

	if (vasprintf(&errmsg, fmt, ap) == -1) {
		errmsg = NULL;
		goto err;
	}

	if (errnum == -1) {
		error->msg = errmsg;
		return (0);
	}

	if (asprintf(&error->msg, "%s: %s", errmsg, strerror(errnum)) == -1) {
		error->msg = NULL;
		goto err;
	}
	rv = 0;

 err:
	free(errmsg);

	return (rv);
}

int
tls_error_set(struct tls_error *error, const char *fmt, ...)
{
	va_list ap;
	int errnum, rv;

	errnum = errno;

	va_start(ap, fmt);
	rv = tls_error_vset(error, errnum, fmt, ap);
	va_end(ap);

	return (rv);
}

int
tls_error_setx(struct tls_error *error, const char *fmt, ...)
{
	va_list ap;
	int rv;

	va_start(ap, fmt);
	rv = tls_error_vset(error, -1, fmt, ap);
	va_end(ap);

	return (rv);
}

int
tls_config_set_error(struct tls_config *config, const char *fmt, ...)
{
	va_list ap;
	int errnum, rv;

	errnum = errno;

	va_start(ap, fmt);
	rv = tls_error_vset(&config->error, errnum, fmt, ap);
	va_end(ap);

	return (rv);
}

int
tls_config_set_errorx(struct tls_config *config, const char *fmt, ...)
{
	va_list ap;
	int rv;

	va_start(ap, fmt);
	rv = tls_error_vset(&config->error, -1, fmt, ap);
	va_end(ap);

	return (rv);
}

int
tls_set_error(struct tls *ctx, const char *fmt, ...)
{
	va_list ap;
	int errnum, rv;

	errnum = errno;

	va_start(ap, fmt);
	rv = tls_error_vset(&ctx->error, errnum, fmt, ap);
	va_end(ap);

	return (rv);
}

int
tls_set_errorx(struct tls *ctx, const char *fmt, ...)
{
	va_list ap;
	int rv;

	va_start(ap, fmt);
	rv = tls_error_vset(&ctx->error, -1, fmt, ap);
	va_end(ap);

	return (rv);
}

struct tls *
tls_new(void)
{
	struct tls *ctx;

	if ((ctx = calloc(1, sizeof(*ctx))) == NULL)
		return (NULL);

	ctx->config = tls_config_default;

	tls_reset(ctx);

	return (ctx);
}

int
tls_configure(struct tls *ctx, struct tls_config *config)
{
	if (config == NULL)
		config = tls_config_default;

	ctx->config = config;

	if ((ctx->flags & TLS_SERVER) != 0)
		return (tls_configure_server(ctx));

	return (0);
}

int
tls_configure_keypair(struct tls *ctx, SSL_CTX *ssl_ctx,
    struct tls_keypair *keypair, int required)
{
	EVP_PKEY *pkey = NULL;
	X509 *cert = NULL;
	BIO *bio = NULL;

	if (!required &&
	    keypair->cert_mem == NULL &&
	    keypair->key_mem == NULL &&
	    keypair->cert_file == NULL &&
	    keypair->key_file == NULL)
		return(0);

	if (keypair->cert_mem != NULL) {
		if (keypair->cert_len > INT_MAX) {
			tls_set_errorx(ctx, "certificate too long");
			goto err;
		}

		if (SSL_CTX_use_certificate_chain_mem(ssl_ctx,
		    keypair->cert_mem, keypair->cert_len) != 1) {
			tls_set_errorx(ctx, "failed to load certificate");
			goto err;
		}
		cert = NULL;
	}
	if (keypair->key_mem != NULL) {
		if (keypair->key_len > INT_MAX) {
			tls_set_errorx(ctx, "key too long");
			goto err;
		}

		if ((bio = BIO_new_mem_buf(keypair->key_mem,
		    keypair->key_len)) == NULL) {
			tls_set_errorx(ctx, "failed to create buffer");
			goto err;
		}
		if ((pkey = PEM_read_bio_PrivateKey(bio, NULL, NULL,
		    NULL)) == NULL) {
			tls_set_errorx(ctx, "failed to read private key");
			goto err;
		}
		if (SSL_CTX_use_PrivateKey(ssl_ctx, pkey) != 1) {
			tls_set_errorx(ctx, "failed to load private key");
			goto err;
		}
		BIO_free(bio);
		bio = NULL;
		EVP_PKEY_free(pkey);
		pkey = NULL;
	}

	if (keypair->cert_file != NULL) {
		if (SSL_CTX_use_certificate_chain_file(ssl_ctx,
		    keypair->cert_file) != 1) {
			tls_set_errorx(ctx, "failed to load certificate file");
			goto err;
		}
	}
	if (keypair->key_file != NULL) {
		if (SSL_CTX_use_PrivateKey_file(ssl_ctx,
		    keypair->key_file, SSL_FILETYPE_PEM) != 1) {
			tls_set_errorx(ctx, "failed to load private key file");
			goto err;
		}
	}

	if (SSL_CTX_check_private_key(ssl_ctx) != 1) {
		tls_set_errorx(ctx, "private/public key mismatch");
		goto err;
	}

	return (0);

 err:
	EVP_PKEY_free(pkey);
	X509_free(cert);
	BIO_free(bio);

	return (1);
}

int
tls_configure_ssl(struct tls *ctx)
{
	SSL_CTX_set_mode(ctx->ssl_ctx, SSL_MODE_ENABLE_PARTIAL_WRITE);
	SSL_CTX_set_mode(ctx->ssl_ctx, SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER);

	SSL_CTX_set_options(ctx->ssl_ctx, SSL_OP_NO_SSLv2);
	SSL_CTX_set_options(ctx->ssl_ctx, SSL_OP_NO_SSLv3);

	SSL_CTX_clear_options(ctx->ssl_ctx, SSL_OP_NO_TLSv1);
	SSL_CTX_clear_options(ctx->ssl_ctx, SSL_OP_NO_TLSv1_1);
	SSL_CTX_clear_options(ctx->ssl_ctx, SSL_OP_NO_TLSv1_2);

	if ((ctx->config->protocols & TLS_PROTOCOL_TLSv1_0) == 0)
		SSL_CTX_set_options(ctx->ssl_ctx, SSL_OP_NO_TLSv1);
	if ((ctx->config->protocols & TLS_PROTOCOL_TLSv1_1) == 0)
		SSL_CTX_set_options(ctx->ssl_ctx, SSL_OP_NO_TLSv1_1);
	if ((ctx->config->protocols & TLS_PROTOCOL_TLSv1_2) == 0)
		SSL_CTX_set_options(ctx->ssl_ctx, SSL_OP_NO_TLSv1_2);

	if (ctx->config->ciphers != NULL) {
		if (SSL_CTX_set_cipher_list(ctx->ssl_ctx,
		    ctx->config->ciphers) != 1) {
			tls_set_errorx(ctx, "failed to set ciphers");
			goto err;
		}
	}

	if (ctx->config->verify_time == 0) {
		X509_VERIFY_PARAM_set_flags(ctx->ssl_ctx->param,
		    X509_V_FLAG_NO_CHECK_TIME);
	}

	return (0);

 err:
	return (-1);
}

int
tls_configure_ssl_verify(struct tls *ctx, int verify)
{
	SSL_CTX_set_verify(ctx->ssl_ctx, verify, NULL);

	if (ctx->config->ca_mem != NULL) {
		/* XXX do this in set. */
		if (ctx->config->ca_len > INT_MAX) {
			tls_set_errorx(ctx, "ca too long");
			goto err;
		}
		if (SSL_CTX_load_verify_mem(ctx->ssl_ctx,
		    ctx->config->ca_mem, ctx->config->ca_len) != 1) {
			tls_set_errorx(ctx, "ssl verify memory setup failure");
			goto err;
		}
	} else if (SSL_CTX_load_verify_locations(ctx->ssl_ctx,
	    ctx->config->ca_file, ctx->config->ca_path) != 1) {
		tls_set_errorx(ctx, "ssl verify setup failure");
		goto err;
	}
	if (ctx->config->verify_depth >= 0)
		SSL_CTX_set_verify_depth(ctx->ssl_ctx,
		    ctx->config->verify_depth);

	return (0);

 err:
	return (-1);
}

void
tls_free(struct tls *ctx)
{
	if (ctx == NULL)
		return;
	tls_reset(ctx);
	free(ctx);
}

void
tls_reset(struct tls *ctx)
{
	SSL_CTX_free(ctx->ssl_ctx);
	SSL_free(ctx->ssl_conn);
	X509_free(ctx->ssl_peer_cert);

	ctx->ssl_conn = NULL;
	ctx->ssl_ctx = NULL;
	ctx->ssl_peer_cert = NULL;

	ctx->socket = -1;
	ctx->state = 0;

	free(ctx->servername);
	ctx->servername = NULL;

	free(ctx->error.msg);
	ctx->error.msg = NULL;
	ctx->error.num = -1;

	tls_free_conninfo(ctx->conninfo);
	free(ctx->conninfo);
	ctx->conninfo = NULL;
}

int
tls_ssl_error(struct tls *ctx, SSL *ssl_conn, int ssl_ret, const char *prefix)
{
	const char *errstr = "unknown error";
	unsigned long err;
	int ssl_err;

	ssl_err = SSL_get_error(ssl_conn, ssl_ret);
	switch (ssl_err) {
	case SSL_ERROR_NONE:
	case SSL_ERROR_ZERO_RETURN:
		return (0);

	case SSL_ERROR_WANT_READ:
		return (TLS_WANT_POLLIN);

	case SSL_ERROR_WANT_WRITE:
		return (TLS_WANT_POLLOUT);

	case SSL_ERROR_SYSCALL:
		if ((err = ERR_peek_error()) != 0) {
			errstr = ERR_error_string(err, NULL);
		} else if (ssl_ret == 0) {
			if ((ctx->state & TLS_HANDSHAKE_COMPLETE) != 0) {
				ctx->state |= TLS_EOF_NO_CLOSE_NOTIFY;
				return (0);
			}
			errstr = "unexpected EOF";
		} else if (ssl_ret == -1) {
			errstr = strerror(errno);
		}
		tls_set_errorx(ctx, "%s failed: %s", prefix, errstr);
		return (-1);

	case SSL_ERROR_SSL:
		if ((err = ERR_peek_error()) != 0) {
			errstr = ERR_error_string(err, NULL);
		}
		tls_set_errorx(ctx, "%s failed: %s", prefix, errstr);
		return (-1);

	case SSL_ERROR_WANT_CONNECT:
	case SSL_ERROR_WANT_ACCEPT:
	case SSL_ERROR_WANT_X509_LOOKUP:
	default:
		tls_set_errorx(ctx, "%s failed (%i)", prefix, ssl_err);
		return (-1);
	}
}

int
tls_handshake(struct tls *ctx)
{
	int rv = -1;

	if ((ctx->flags & (TLS_CLIENT | TLS_SERVER_CONN)) == 0) {
		tls_set_errorx(ctx, "invalid operation for context");
		goto out;
	}

	if (ctx->conninfo == NULL &&
	    (ctx->conninfo = calloc(1, sizeof(*ctx->conninfo))) == NULL)
		goto out;

	if ((ctx->flags & TLS_CLIENT) != 0)
		rv = tls_handshake_client(ctx);
	else if ((ctx->flags & TLS_SERVER_CONN) != 0)
		rv = tls_handshake_server(ctx);

	if (rv == 0) {
		ctx->ssl_peer_cert =  SSL_get_peer_certificate(ctx->ssl_conn);
		if (tls_get_conninfo(ctx) == -1)
		    rv = -1;
	}
 out:
	/* Prevent callers from performing incorrect error handling */
	errno = 0;
	return (rv);
}

ssize_t
tls_read(struct tls *ctx, void *buf, size_t buflen)
{
	ssize_t rv = -1;
	int ssl_ret;

	if ((ctx->state & TLS_HANDSHAKE_COMPLETE) == 0) {
		if ((rv = tls_handshake(ctx)) != 0)
			goto out;
	}

	if (buflen > INT_MAX) {
		tls_set_errorx(ctx, "buflen too long");
		goto out;
	}

	ERR_clear_error();
	if ((ssl_ret = SSL_read(ctx->ssl_conn, buf, buflen)) > 0) {
		rv = (ssize_t)ssl_ret;
		goto out;
	}
	rv = (ssize_t)tls_ssl_error(ctx, ctx->ssl_conn, ssl_ret, "read");

 out:
	/* Prevent callers from performing incorrect error handling */
	errno = 0;
	return (rv);
}

ssize_t
tls_write(struct tls *ctx, const void *buf, size_t buflen)
{
	ssize_t rv = -1;
	int ssl_ret;

	if ((ctx->state & TLS_HANDSHAKE_COMPLETE) == 0) {
		if ((rv = tls_handshake(ctx)) != 0)
			goto out;
	}

	if (buflen > INT_MAX) {
		tls_set_errorx(ctx, "buflen too long");
		goto out;
	}

	ERR_clear_error();
	if ((ssl_ret = SSL_write(ctx->ssl_conn, buf, buflen)) > 0) {
		rv = (ssize_t)ssl_ret;
		goto out;
	}
	rv =  (ssize_t)tls_ssl_error(ctx, ctx->ssl_conn, ssl_ret, "write");

 out:
	/* Prevent callers from performing incorrect error handling */
	errno = 0;
	return (rv);
}

int
tls_close(struct tls *ctx)
{
	int ssl_ret;
	int rv = 0;

	if ((ctx->flags & (TLS_CLIENT | TLS_SERVER_CONN)) == 0) {
		tls_set_errorx(ctx, "invalid operation for context");
		rv = -1;
		goto out;
	}

	if (ctx->ssl_conn != NULL) {
		ERR_clear_error();
		ssl_ret = SSL_shutdown(ctx->ssl_conn);
		if (ssl_ret < 0) {
			rv = tls_ssl_error(ctx, ctx->ssl_conn, ssl_ret,
			    "shutdown");
			if (rv == TLS_WANT_POLLIN || rv == TLS_WANT_POLLOUT)
				goto out;
		}
	}

	if (ctx->socket != -1) {
		if (shutdown(ctx->socket, SHUT_RDWR) != 0) {
			if (rv == 0 &&
			    errno != ENOTCONN && errno != ECONNRESET) {
				tls_set_error(ctx, "shutdown");
				rv = -1;
			}
		}
		if (close(ctx->socket) != 0) {
			if (rv == 0) {
				tls_set_error(ctx, "close");
				rv = -1;
			}
		}
		ctx->socket = -1;
	}

	if ((ctx->state & TLS_EOF_NO_CLOSE_NOTIFY) != 0) {
		tls_set_errorx(ctx, "EOF without close notify");
		rv = -1;
	}

 out:
	/* Prevent callers from performing incorrect error handling */
	errno = 0;
	return (rv);
}
