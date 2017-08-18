/* $OpenBSD: tls_conninfo.c,v 1.4 2015/10/07 23:25:45 beck Exp $ */
/*
 * Copyright (c) 2015 Joel Sing <jsing@openbsd.org>
 * Copyright (c) 2015 Bob Beck <beck@openbsd.org>
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

#include <stdio.h>

#include <openssl/x509.h>

#include <tls.h>
#include "tls_internal.h"

static int
tls_hex_string(const unsigned char *in, size_t inlen, char **out,
    size_t *outlen)
{
	static const char hex[] = "0123456789abcdef";
	size_t i, len;
	char *p;

	if (outlen != NULL)
		*outlen = 0;

	if (inlen >= SIZE_MAX)
		return (-1);
	if ((*out = reallocarray(NULL, inlen + 1, 2)) == NULL)
		return (-1);

	p = *out;
	len = 0;
	for (i = 0; i < inlen; i++) {
		p[len++] = hex[(in[i] >> 4) & 0x0f];
		p[len++] = hex[in[i] & 0x0f];
	}
	p[len++] = 0;

	if (outlen != NULL)
		*outlen = len;

	return (0);
}

static int
tls_get_peer_cert_hash(struct tls *ctx, char **hash)
{
	char d[EVP_MAX_MD_SIZE], *dhex = NULL;
	int dlen, rv = -1;

	*hash = NULL;
	if (ctx->ssl_peer_cert == NULL)
		return (0);

	if (X509_digest(ctx->ssl_peer_cert, EVP_sha256(), d, &dlen) != 1) {
		tls_set_errorx(ctx, "digest failed");
		goto err;
	}

	if (tls_hex_string(d, dlen, &dhex, NULL) != 0) {
		tls_set_errorx(ctx, "digest hex string failed");
		goto err;
	}

	if (asprintf(hash, "SHA256:%s", dhex) == -1) {
		tls_set_errorx(ctx, "out of memory");
		*hash = NULL;
		goto err;
	}

	rv = 0;

err:
	free(dhex);

	return (rv);
}

static int
tls_get_peer_cert_issuer(struct tls *ctx,  char **issuer)
{
	X509_NAME *name = NULL;

	*issuer = NULL;
	if (ctx->ssl_peer_cert == NULL)
		return (-1);
	if ((name = X509_get_issuer_name(ctx->ssl_peer_cert)) == NULL)
		return (-1);
	*issuer = X509_NAME_oneline(name, 0, 0);
	if (*issuer == NULL)
		return (-1);
	return (0);
}

static int
tls_get_peer_cert_subject(struct tls *ctx, char **subject)
{
	X509_NAME *name = NULL;

	*subject = NULL;
	if (ctx->ssl_peer_cert == NULL)
		return (-1);
	if ((name = X509_get_subject_name(ctx->ssl_peer_cert)) == NULL)
		return (-1);
	*subject = X509_NAME_oneline(name, 0, 0);
	if (*subject == NULL)
		return (-1);
	return (0);
}

static int
tls_get_peer_cert_times(struct tls *ctx, time_t *notbefore, time_t *notafter)
{
	struct tm before_tm, after_tm;
	ASN1_TIME *before, *after;
	int rv = -1;

	memset(&before_tm, 0, sizeof(before_tm));
	memset(&after_tm, 0, sizeof(after_tm));

	if (ctx->ssl_peer_cert != NULL) {
		if ((before = X509_get_notBefore(ctx->ssl_peer_cert)) == NULL)
			goto err;
		if ((after = X509_get_notAfter(ctx->ssl_peer_cert)) == NULL)
			goto err;
		if (asn1_time_parse(before->data, before->length, &before_tm, 0)
		    == -1)
			goto err;
		if (asn1_time_parse(after->data, after->length, &after_tm, 0)
		    == -1)
			goto err;
		if ((*notbefore = timegm(&before_tm)) == -1)
			goto err;
		if ((*notafter = timegm(&after_tm)) == -1)
			goto err;
	}
	rv = 0;
 err:
	return (rv);
}

int
tls_get_conninfo(struct tls *ctx) {
	const char * tmp;
	if (ctx->ssl_peer_cert != NULL) {
		if (tls_get_peer_cert_hash(ctx, &ctx->conninfo->hash) == -1)
			goto err;
		if (tls_get_peer_cert_subject(ctx, &ctx->conninfo->subject)
		    == -1)
			goto err;
		if (tls_get_peer_cert_issuer(ctx, &ctx->conninfo->issuer) == -1)
			goto err;
		if (tls_get_peer_cert_times(ctx, &ctx->conninfo->notbefore,
		    &ctx->conninfo->notafter) == -1)
			goto err;
	}
	if ((tmp = SSL_get_version(ctx->ssl_conn)) == NULL)
		goto err;
	ctx->conninfo->version = strdup(tmp);
	if (ctx->conninfo->version == NULL)
		goto err;
	if ((tmp = SSL_get_cipher(ctx->ssl_conn)) == NULL)
		goto err;
	ctx->conninfo->cipher = strdup(tmp);
	if (ctx->conninfo->cipher == NULL)
		goto err;
	return (0);
err:
	tls_free_conninfo(ctx->conninfo);
	return (-1);
}

void
tls_free_conninfo(struct tls_conninfo *conninfo) {
	if (conninfo != NULL) {
		free(conninfo->hash);
		conninfo->hash = NULL;
		free(conninfo->subject);
		conninfo->subject = NULL;
		free(conninfo->issuer);
		conninfo->issuer = NULL;
		free(conninfo->version);
		conninfo->version = NULL;
		free(conninfo->cipher);
		conninfo->cipher = NULL;
	}
}

const char *
tls_conn_cipher(struct tls *ctx)
{
	if (ctx->conninfo == NULL)
		return (NULL);
	return (ctx->conninfo->cipher);
}

const char *
tls_conn_version(struct tls *ctx)
{
	if (ctx->conninfo == NULL)
		return (NULL);
	return (ctx->conninfo->version);
}
