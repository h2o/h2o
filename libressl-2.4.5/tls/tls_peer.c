/* $OpenBSD: tls_peer.c,v 1.4 2015/09/12 21:00:38 beck Exp $ */
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

const char *
tls_peer_cert_hash(struct tls *ctx)
{
	if (ctx->conninfo)
		return (ctx->conninfo->hash);
	return NULL;
}
const char *
tls_peer_cert_issuer(struct tls *ctx)
{
	if (ctx->conninfo)
		return (ctx->conninfo->issuer);
	return NULL;
}

const char *
tls_peer_cert_subject(struct tls *ctx)
{
	if (ctx->conninfo)
		return (ctx->conninfo->subject);
	return NULL;
}

int
tls_peer_cert_provided(struct tls *ctx)
{
	return (ctx->ssl_peer_cert != NULL);
}

int
tls_peer_cert_contains_name(struct tls *ctx, const char *name)
{
	if (ctx->ssl_peer_cert == NULL)
		return (0);

	return (tls_check_name(ctx, ctx->ssl_peer_cert, name) == 0);
}

time_t
tls_peer_cert_notbefore(struct tls *ctx)
{
	if (ctx->ssl_peer_cert == NULL)
		return (-1);
	if (ctx->conninfo == NULL)
		return (-1);
	return (ctx->conninfo->notbefore);
}

time_t
tls_peer_cert_notafter(struct tls *ctx)
{
	if (ctx->ssl_peer_cert == NULL)
		return (-1);
	if (ctx->conninfo == NULL)
		return (-1);
	return (ctx->conninfo->notafter);
}

