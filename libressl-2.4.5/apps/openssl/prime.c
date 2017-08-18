/* $OpenBSD: prime.c,v 1.9 2015/10/10 22:28:51 doug Exp $ */
/* ====================================================================
 * Copyright (c) 2004 The OpenSSL Project.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * 3. All advertising materials mentioning features or use of this
 *    software must display the following acknowledgment:
 *    "This product includes software developed by the OpenSSL Project
 *    for use in the OpenSSL Toolkit. (http://www.openssl.org/)"
 *
 * 4. The names "OpenSSL Toolkit" and "OpenSSL Project" must not be used to
 *    endorse or promote products derived from this software without
 *    prior written permission. For written permission, please contact
 *    openssl-core@openssl.org.
 *
 * 5. Products derived from this software may not be called "OpenSSL"
 *    nor may "OpenSSL" appear in their names without prior written
 *    permission of the OpenSSL Project.
 *
 * 6. Redistributions of any form whatsoever must retain the following
 *    acknowledgment:
 *    "This product includes software developed by the OpenSSL Project
 *    for use in the OpenSSL Toolkit (http://www.openssl.org/)"
 *
 * THIS SOFTWARE IS PROVIDED BY THE OpenSSL PROJECT ``AS IS'' AND ANY
 * EXPRESSED OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE OpenSSL PROJECT OR
 * ITS CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */

#include <string.h>
#include <limits.h>

#include "apps.h"

#include <openssl/bn.h>
#include <openssl/err.h>

struct {
	int bits;
	int checks;
	int generate;
	int hex;
	int safe;
} prime_config;

struct option prime_options[] = {
	{
		.name = "bits",
		.argname = "n",
		.desc = "Number of bits in the generated prime number",
		.type = OPTION_ARG_INT,
		.opt.value = &prime_config.bits,
	},
	{
		.name = "checks",
		.argname = "n",
		.desc = "Miller-Rabin probablistic primality test iterations",
		.type = OPTION_ARG_INT,
		.opt.value = &prime_config.checks,
	},
	{
		.name = "generate",
		.desc = "Generate a pseudo-random prime number",
		.type = OPTION_FLAG,
		.opt.flag = &prime_config.generate,
	},
	{
		.name = "hex",
		.desc = "Hexadecimal prime numbers",
		.type = OPTION_FLAG,
		.opt.flag = &prime_config.hex,
	},
	{
		.name = "safe",
		.desc = "Generate only \"safe\" prime numbers",
		.type = OPTION_FLAG,
		.opt.flag = &prime_config.safe,
	},
	{NULL},
};

static void
prime_usage()
{
	fprintf(stderr,
	    "usage: prime [-bits n] [-checks n] [-generate] [-hex] [-safe] "
	    "p\n");
	options_usage(prime_options);
}

int
prime_main(int argc, char **argv)
{
	BIGNUM *bn = NULL;
	char *prime = NULL;
	BIO *bio_out;
	char *s;
	int ret = 1;

	if (single_execution) {
		if (pledge("stdio rpath", NULL) == -1) {
			perror("pledge");
			exit(1);
		}
	}

	memset(&prime_config, 0, sizeof(prime_config));

	/* Default iterations for Miller-Rabin probabilistic primality test. */
	prime_config.checks = 20;

	if (options_parse(argc, argv, prime_options, &prime, NULL) != 0) {
		prime_usage();
		return (1);
	}

	if (prime == NULL && prime_config.generate == 0) {
		BIO_printf(bio_err, "No prime specified.\n");
		prime_usage();
		return (1);
	}

	if ((bio_out = BIO_new(BIO_s_file())) == NULL) {
		ERR_print_errors(bio_err);
		return (1);
	}
	BIO_set_fp(bio_out, stdout, BIO_NOCLOSE);

	if (prime_config.generate != 0) {
		if (prime_config.bits == 0) {
			BIO_printf(bio_err, "Specify the number of bits.\n");
			goto end;
		}
		bn = BN_new();
		if (!bn) {
			BIO_printf(bio_err, "Out of memory.\n");
			goto end;
		}
		if (!BN_generate_prime_ex(bn, prime_config.bits,
		    prime_config.safe, NULL, NULL, NULL)) {
			BIO_printf(bio_err, "Prime generation error.\n");
			goto end;
		}
		s = prime_config.hex ? BN_bn2hex(bn) : BN_bn2dec(bn);
		if (s == NULL) {
			BIO_printf(bio_err, "Out of memory.\n");
			goto end;
		}
		BIO_printf(bio_out, "%s\n", s);
		free(s);
	} else {
		if (prime_config.hex) {
			if (!BN_hex2bn(&bn, prime)) {
				BIO_printf(bio_err, "%s is an invalid hex "
				    "value.\n", prime);
				goto end;
			}
		} else {
			if (!BN_dec2bn(&bn, prime)) {
				BIO_printf(bio_err, "%s is an invalid decimal "
				    "value.\n", prime);
				goto end;
			}
		}

		BIO_printf(bio_out, "%s is %sprime\n", prime,
		    BN_is_prime_ex(bn, prime_config.checks,
			NULL, NULL) ? "" : "not ");
	}

	ret = 0;

end:
	BN_free(bn);
	BIO_free_all(bio_out);

	return (ret);
}
