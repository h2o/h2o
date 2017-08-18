/*	$OpenBSD: cipher_list.c,v 1.2 2015/06/28 00:08:27 doug Exp $	*/
/*
 * Copyright (c) 2015 Doug Hogan <doug@openbsd.org>
 * Copyright (c) 2015 Joel Sing <jsing@openbsd.org>
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

/*
 * Test TLS ssl bytes (aka cipher suites) to cipher list and back.
 *
 * TLSv1.0 - RFC 2246 section 7.4.1.2 (ClientHello struct)
 * TLSv1.1 - RFC 4346 section 7.4.1.2 (ClientHello struct)
 * TLSv1.2 - RFC 5246 section 7.4.1.2 (ClientHello struct)
 *
 * In all of these standards, the relevant structures are:
 *
 * uint8 CipherSuite[2];
 *
 * struct {
 *    ...
 *    CipherSuite cipher_suites<2..2^16-2>
 *    ...
 * } ClientHello;
 */

#include <openssl/ssl.h>

#include <stdio.h>
#include <string.h>

#include "tests.h"

static uint8_t cipher_bytes[] = {
	0xcc, 0x14,	/* ECDHE-ECDSA-CHACHA20-POLY1305 */
	0xcc, 0x13,	/* ECDHE-RSA-CHACHA20-POLY1305 */
	0xcc, 0x15,	/* DHE-RSA-CHACHA20-POLY1305 */
	0x00, 0x9c,	/* AES128-GCM-SHA256 */
	0x00, 0x3d,	/* AES256-SHA256 */
	0x00, 0x09,	/* DES-CBC-SHA */
};

static uint16_t cipher_values[] = {
	0xcc14,		/* ECDHE-ECDSA-CHACHA20-POLY1305 */
	0xcc13,		/* ECDHE-RSA-CHACHA20-POLY1305 */
	0xcc15,		/* DHE-RSA-CHACHA20-POLY1305 */
	0x009c,		/* AES128-GCM-SHA256 */
	0x003d,		/* AES256-SHA256 */
	0x0009,		/* DES-CBC-SHA */
};

#define N_CIPHERS (sizeof(cipher_bytes) / 2)

extern STACK_OF(SSL_CIPHER) *ssl_bytes_to_cipher_list(SSL *s,
    const unsigned char *p, int num);
extern int ssl_cipher_list_to_bytes(SSL *s, STACK_OF(SSL_CIPHER) *sk,
    unsigned char *p);

static int
ssl_bytes_to_list_alloc(SSL *s, STACK_OF(SSL_CIPHER) **ciphers)
{
	SSL_CIPHER *cipher;
	uint16_t value;
	int i;

	*ciphers = ssl_bytes_to_cipher_list(s, cipher_bytes,
	    sizeof(cipher_bytes));
	CHECK(*ciphers != NULL);
	CHECK(sk_SSL_CIPHER_num(*ciphers) == N_CIPHERS);
	for (i = 0; i < sk_SSL_CIPHER_num(*ciphers); i++) {
		cipher = sk_SSL_CIPHER_value(*ciphers, i);
		CHECK(cipher != NULL);
		value = SSL_CIPHER_get_value(cipher);
		CHECK(value == cipher_values[i]);
	}

	return 1;
}

static int
ssl_list_to_bytes_scsv(SSL *s, STACK_OF(SSL_CIPHER) **ciphers)
{
	unsigned char *buf = NULL;
	size_t buflen;
	int len;
	int ret = 0;

	/* Space for cipher bytes, plus reneg SCSV and two spare bytes. */
	CHECK(sk_SSL_CIPHER_num(*ciphers) == N_CIPHERS);
	buflen = sizeof(cipher_bytes) + 2 + 2;
	CHECK((buf = calloc(1, buflen)) != NULL);

	len = ssl_cipher_list_to_bytes(s, *ciphers, buf);
	CHECK_GOTO(len > 0 && (size_t)len == buflen - 2);
	CHECK_GOTO(memcmp(buf, cipher_bytes, sizeof(cipher_bytes)) == 0);
	CHECK_GOTO(buf[buflen - 4] == 0x00 && buf[buflen - 3] == 0xff);
	CHECK_GOTO(buf[buflen - 2] == 0x00 && buf[buflen - 1] == 0x00);

	ret = 1;

err:
	free(buf);
	return ret;
}

static int
ssl_list_to_bytes_no_scsv(SSL *s, STACK_OF(SSL_CIPHER) **ciphers)
{
	unsigned char *buf = NULL;
	size_t buflen;
	int len;
	int ret = 0;

	/* Space for cipher bytes and two spare bytes */
	CHECK(sk_SSL_CIPHER_num(*ciphers) == N_CIPHERS);
	buflen = sizeof(cipher_bytes) + 2;
	CHECK((buf = calloc(1, buflen)) != NULL);
	buf[buflen - 2] = 0xfe;
	buf[buflen - 1] = 0xab;

	/* Set renegotiate so it doesn't add SCSV */
	s->renegotiate = 1;

	len = ssl_cipher_list_to_bytes(s, *ciphers, buf);
	CHECK_GOTO(len > 0 && (size_t)len == buflen - 2);
	CHECK_GOTO(memcmp(buf, cipher_bytes, sizeof(cipher_bytes)) == 0);
	CHECK_GOTO(buf[buflen - 2] == 0xfe && buf[buflen - 1] == 0xab);

	ret = 1;

err:
	free(buf);
	return ret;
}

static int
ssl_bytes_to_list_invalid(SSL *s, STACK_OF(SSL_CIPHER) **ciphers)
{
	uint8_t empty_cipher_bytes[] = {0};

	sk_SSL_CIPHER_free(*ciphers);

	/* Invalid length: CipherSuite is 2 bytes so it must be even */
	*ciphers = ssl_bytes_to_cipher_list(s, cipher_bytes,
	    sizeof(cipher_bytes) - 1);
	CHECK(*ciphers == NULL);

	/* Invalid length: cipher_suites must be at least 2 */
	*ciphers = ssl_bytes_to_cipher_list(s, empty_cipher_bytes,
	    sizeof(empty_cipher_bytes));
	CHECK(*ciphers == NULL);

	/* Invalid length: cipher_suites must be at most 2^16-2 */
	*ciphers = ssl_bytes_to_cipher_list(s, cipher_bytes, 0x10000);
	CHECK(*ciphers == NULL);

	/* Invalid len: prototype is signed, but it shouldn't accept len < 0 */
	*ciphers = ssl_bytes_to_cipher_list(s, cipher_bytes, -2);
	CHECK(*ciphers == NULL);

	return 1;
}

int
main(void)
{
	STACK_OF(SSL_CIPHER) *ciphers = NULL;
	SSL_CTX *ctx = NULL;
	SSL *s = NULL;
	int rv = 1;

	SSL_library_init();

	/* Use TLSv1.2 client to get all ciphers. */
	CHECK_GOTO((ctx = SSL_CTX_new(TLSv1_2_client_method())) != NULL);
	CHECK_GOTO((s = SSL_new(ctx)) != NULL);

	if (!ssl_bytes_to_list_alloc(s, &ciphers))
		goto err;
	if (!ssl_list_to_bytes_scsv(s, &ciphers))
		goto err;
	if (!ssl_list_to_bytes_no_scsv(s, &ciphers))
		goto err;
	if (!ssl_bytes_to_list_invalid(s, &ciphers))
		goto err;

	rv = 0;

err:
	sk_SSL_CIPHER_free(ciphers);
	SSL_CTX_free(ctx);
	SSL_free(s);

	if (!rv)
		printf("PASS %s\n", __FILE__);
	return rv;
}
