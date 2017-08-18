/*
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

#include <openssl/ssl.h>

#include <err.h>
#include <stdio.h>
#include <string.h>

static int
get_put_test(const char *name, const SSL_METHOD *method)
{
	STACK_OF(SSL_CIPHER) *ciphers;
	const SSL_CIPHER *cipher;
	unsigned char buf[2];
	SSL_CTX *ssl_ctx = NULL;
	SSL *ssl = NULL;
	int ret = 1;
	int i, len;

	if ((len = method->put_cipher_by_char(NULL, NULL)) != 2) {
		fprintf(stderr,
		    "%s: put_cipher_by_char() returned len %i (want 2)\n",
		    name, len);
		return (1);
	}

	if ((ssl_ctx = SSL_CTX_new(method)) == NULL) {
		fprintf(stderr, "%s: SSL_CTX_new() returned NULL\n", name);
		goto failure;
	}
	if ((ssl = SSL_new(ssl_ctx)) == NULL) {
		fprintf(stderr, "%s: SSL_new() returned NULL\n", name);
		goto failure;
	}

	if ((ciphers = SSL_get_ciphers(ssl)) == NULL) {
		fprintf(stderr, "%s: no ciphers\n", name);
		goto failure;
	}

	for (i = 0; i < sk_SSL_CIPHER_num(ciphers); i++) {
		cipher = sk_SSL_CIPHER_value(ciphers, i);
		if ((len = method->put_cipher_by_char(cipher, buf)) != 2) {
			fprintf(stderr,
			    "%s: put_cipher_by_char() returned len %i for %s "
			    "(want 2)\n",
			    name, len, SSL_CIPHER_get_name(cipher));
			goto failure;
		}
		if ((cipher = method->get_cipher_by_char(buf)) == NULL) {
			fprintf(stderr,
			    "%s: get_cipher_by_char() returned NULL for %s\n",
			    name, SSL_CIPHER_get_name(cipher));
			goto failure;
		}
	}

	ret = 0;

failure:
	SSL_CTX_free(ssl_ctx);
	SSL_free(ssl);

	return (ret);
}

static int
cipher_get_put_tests(void)
{
	int failed = 0;

	failed |= get_put_test("SSLv23", SSLv23_method());
	failed |= get_put_test("SSLv23_client", SSLv23_client_method());
	failed |= get_put_test("SSLv23_server", SSLv23_server_method());

	failed |= get_put_test("TLSv1", TLSv1_method());
	failed |= get_put_test("TLSv1_client", TLSv1_client_method());
	failed |= get_put_test("TLSv1_server", TLSv1_server_method());

	failed |= get_put_test("TLSv1_1", TLSv1_1_method());
	failed |= get_put_test("TLSv1_1_client", TLSv1_1_client_method());
	failed |= get_put_test("TLSv1_1_server", TLSv1_1_server_method());

	failed |= get_put_test("TLSv1_2", TLSv1_2_method());
	failed |= get_put_test("TLSv1_2_client", TLSv1_2_client_method());
	failed |= get_put_test("TLSv1_2_server", TLSv1_2_server_method());

	failed |= get_put_test("DTLSv1", DTLSv1_method());
	failed |= get_put_test("DTLSv1_client", DTLSv1_client_method());
	failed |= get_put_test("DTLSv1_server", DTLSv1_server_method());

	return failed;
}

static int
cipher_get_by_value_tests(void)
{
	STACK_OF(SSL_CIPHER) *ciphers;
	const SSL_CIPHER *cipher;
	SSL_CTX *ssl_ctx = NULL;
	SSL *ssl = NULL;
	unsigned long id;
	uint16_t value;
	int ret = 1;
	int i;

	if ((ssl_ctx = SSL_CTX_new(SSLv23_method())) == NULL) {
		fprintf(stderr, "SSL_CTX_new() returned NULL\n");
		goto failure;
	}
	if ((ssl = SSL_new(ssl_ctx)) == NULL) {
		fprintf(stderr, "SSL_new() returned NULL\n");
		goto failure;
	}

	if ((ciphers = SSL_get_ciphers(ssl)) == NULL) {
		fprintf(stderr, "no ciphers\n");
		goto failure;
	}

	for (i = 0; i < sk_SSL_CIPHER_num(ciphers); i++) {
		cipher = sk_SSL_CIPHER_value(ciphers, i);

		id = SSL_CIPHER_get_id(cipher);
		if (SSL_CIPHER_get_by_id(id) == NULL) {
			fprintf(stderr, "SSL_CIPHER_get_by_id() failed "
			    "for %s (0x%lx)\n", SSL_CIPHER_get_name(cipher),
			    id);
			goto failure;
		}

		value = SSL_CIPHER_get_value(cipher);
		if (SSL_CIPHER_get_by_value(value) == NULL) {
			fprintf(stderr, "SSL_CIPHER_get_by_value() failed "
			    "for %s (0x%04hx)\n", SSL_CIPHER_get_name(cipher),
			    value);
			goto failure;
		}
	}

	ret = 0;

failure:
	SSL_CTX_free(ssl_ctx);
	SSL_free(ssl);

	return (ret);
}

int
main(int argc, char **argv)
{
	int failed = 0;

	SSL_library_init();

	failed |= cipher_get_put_tests();
	failed |= cipher_get_by_value_tests();

	return (failed);
}
