/* $OpenBSD: ciphers.c,v 1.7 2015/10/10 22:28:51 doug Exp $ */
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

#include <stdio.h>
#include <stdlib.h>

#include <openssl/err.h>
#include <openssl/ssl.h>

#include "apps.h"
#include "progs.h"

struct {
	int usage;
	int verbose;
} ciphers_config;

struct option ciphers_options[] = {
	{
		.name = "h",
		.type = OPTION_FLAG,
		.opt.flag = &ciphers_config.usage,
	},
	{
		.name = "?",
		.type = OPTION_FLAG,
		.opt.flag = &ciphers_config.usage,
	},
	{
		.name = "tls1",
		.desc = "This option is deprecated since it is the default",
		.type = OPTION_DISCARD,
	},
	{
		.name = "v",
		.desc = "Provide cipher listing",
		.type = OPTION_VALUE,
		.opt.value = &ciphers_config.verbose,
		.value = 1,
	},
	{
		.name = "V",
		.desc = "Provide cipher listing with cipher suite values",
		.type = OPTION_VALUE,
		.opt.value = &ciphers_config.verbose,
		.value = 2,
	},
	{ NULL },
};

static void
ciphers_usage(void)
{
	fprintf(stderr, "usage: ciphers [-hVv] [-tls1] [cipherlist]\n");
	options_usage(ciphers_options);
}

int
ciphers_main(int argc, char **argv)
{
	char *cipherlist = NULL;
	STACK_OF(SSL_CIPHER) *ciphers;
	const SSL_CIPHER *cipher;
	SSL_CTX *ssl_ctx = NULL;
	SSL *ssl = NULL;
	uint16_t value;
	int i, rv = 0;
	char *desc;

	if (single_execution) {
		if (pledge("stdio rpath", NULL) == -1) {
			perror("pledge");
			exit(1);
		}
	}

	memset(&ciphers_config, 0, sizeof(ciphers_config));

	if (options_parse(argc, argv, ciphers_options, &cipherlist,
	    NULL) != 0) {
		ciphers_usage();
		return (1);
	}

	if (ciphers_config.usage) {
		ciphers_usage();
		return (1);
	}

	if ((ssl_ctx = SSL_CTX_new(TLSv1_client_method())) == NULL)
		goto err;

	if (cipherlist != NULL) {
		if (SSL_CTX_set_cipher_list(ssl_ctx, cipherlist) == 0)
			goto err;
	}

	if ((ssl = SSL_new(ssl_ctx)) == NULL)
		goto err;

	if ((ciphers = SSL_get_ciphers(ssl)) == NULL)
		goto err;

	for (i = 0; i < sk_SSL_CIPHER_num(ciphers); i++) {
		cipher = sk_SSL_CIPHER_value(ciphers, i);
		if (ciphers_config.verbose == 0) {
			fprintf(stdout, "%s%s", (i ? ":" : ""),
			    SSL_CIPHER_get_name(cipher));
			continue;
		}
		if (ciphers_config.verbose > 1) {
			value = SSL_CIPHER_get_value(cipher);
			fprintf(stdout, "%-*s0x%02X,0x%02X - ", 10, "",
				((value >> 8) & 0xff), (value & 0xff));
		}
		desc = SSL_CIPHER_description(cipher, NULL, 0);
		if (strcmp(desc, "OPENSSL_malloc Error") == 0) {
			fprintf(stderr, "out of memory\n");
			goto err;
		}
		fprintf(stdout, "%s", desc);
		free(desc);
	}
	if (ciphers_config.verbose == 0)
		fprintf(stdout, "\n");

	goto done;

err:
	ERR_print_errors_fp(stderr);
	rv = 1;

done:
	SSL_CTX_free(ssl_ctx);
	SSL_free(ssl);

	return (rv);
}
