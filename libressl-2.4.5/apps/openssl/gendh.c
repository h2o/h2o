/* $OpenBSD: gendh.c,v 1.6 2015/10/10 22:28:51 doug Exp $ */
/* Copyright (C) 1995-1998 Eric Young (eay@cryptsoft.com)
 * All rights reserved.
 *
 * This package is an SSL implementation written
 * by Eric Young (eay@cryptsoft.com).
 * The implementation was written so as to conform with Netscapes SSL.
 *
 * This library is free for commercial and non-commercial use as long as
 * the following conditions are aheared to.  The following conditions
 * apply to all code found in this distribution, be it the RC4, RSA,
 * lhash, DES, etc., code; not just the SSL code.  The SSL documentation
 * included with this distribution is covered by the same copyright terms
 * except that the holder is Tim Hudson (tjh@cryptsoft.com).
 *
 * Copyright remains Eric Young's, and as such any Copyright notices in
 * the code are not to be removed.
 * If this package is used in a product, Eric Young should be given attribution
 * as the author of the parts of the library used.
 * This can be in the form of a textual message at program startup or
 * in documentation (online or textual) provided with the package.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *    "This product includes cryptographic software written by
 *     Eric Young (eay@cryptsoft.com)"
 *    The word 'cryptographic' can be left out if the rouines from the library
 *    being used are not cryptographic related :-).
 * 4. If you include any Windows specific code (or a derivative thereof) from
 *    the apps directory (application code) you must include an acknowledgement:
 *    "This product includes software written by Tim Hudson (tjh@cryptsoft.com)"
 *
 * THIS SOFTWARE IS PROVIDED BY ERIC YOUNG ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * The licence and distribution terms for any publically available version or
 * derivative of this code cannot be changed.  i.e. this code cannot simply be
 * copied and put under another distribution licence
 * [including the GNU Public Licence.]
 */

#include <openssl/opensslconf.h>

/* Until the key-gen callbacks are modified to use newer prototypes, we allow
 * deprecated functions for openssl-internal code */
#ifdef OPENSSL_NO_DEPRECATED
#undef OPENSSL_NO_DEPRECATED
#endif

#ifndef OPENSSL_NO_DH

#include <sys/types.h>
#include <sys/stat.h>

#include <limits.h>
#include <stdio.h>
#include <string.h>

#include "apps.h"

#include <openssl/bio.h>
#include <openssl/bn.h>
#include <openssl/dh.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/x509.h>

#define DEFBITS	512

static int dh_cb(int p, int n, BN_GENCB * cb);

static struct {
	int g;
	char *outfile;
} gendh_config;

static struct option gendh_options[] = {
	{
		.name = "2",
		.desc = "Generate DH parameters with a generator value of 2 "
		    "(default)",
		.type = OPTION_VALUE,
		.value = 2,
		.opt.value = &gendh_config.g,
	},
	{
		.name = "5",
		.desc = "Generate DH parameters with a generator value of 5",
		.type = OPTION_VALUE,
		.value = 5,
		.opt.value = &gendh_config.g,
	},
	{
		.name = "out",
		.argname = "file",
		.desc = "Output file (default stdout)",
		.type = OPTION_ARG,
		.opt.arg = &gendh_config.outfile,
	},
	{ NULL },
};

static void
gendh_usage(void)
{
	fprintf(stderr,
	    "usage: gendh [-2 | -5] [-out file] [numbits]\n\n");
	options_usage(gendh_options);
}

int
gendh_main(int argc, char **argv)
{
	BN_GENCB cb;
	DH *dh = NULL;
	int ret = 1, numbits = DEFBITS;
	BIO *out = NULL;
	char *strbits = NULL;

	if (single_execution) {
		if (pledge("stdio rpath wpath cpath", NULL) == -1) {
			perror("pledge");
			exit(1);
		}
	}

	BN_GENCB_set(&cb, dh_cb, bio_err);

	memset(&gendh_config, 0, sizeof(gendh_config));

	gendh_config.g = 2;

	if (options_parse(argc, argv, gendh_options, &strbits, NULL) != 0) {
		gendh_usage();
		goto end;
	}

	if (strbits != NULL) {
		const char *errstr;
		numbits = strtonum(strbits, 0, INT_MAX, &errstr);
		if (errstr) {
			fprintf(stderr, "Invalid number of bits: %s\n", errstr);
			goto end;
		}
	}

	out = BIO_new(BIO_s_file());
	if (out == NULL) {
		ERR_print_errors(bio_err);
		goto end;
	}
	if (gendh_config.outfile == NULL) {
		BIO_set_fp(out, stdout, BIO_NOCLOSE);
	} else {
		if (BIO_write_filename(out, gendh_config.outfile) <= 0) {
			perror(gendh_config.outfile);
			goto end;
		}
	}

	BIO_printf(bio_err, "Generating DH parameters, %d bit long safe prime,"
	    " generator %d\n", numbits, gendh_config.g);
	BIO_printf(bio_err, "This is going to take a long time\n");

	if (((dh = DH_new()) == NULL) ||
	    !DH_generate_parameters_ex(dh, numbits, gendh_config.g, &cb))
		goto end;

	if (!PEM_write_bio_DHparams(out, dh))
		goto end;
	ret = 0;
end:
	if (ret != 0)
		ERR_print_errors(bio_err);
	if (out != NULL)
		BIO_free_all(out);
	if (dh != NULL)
		DH_free(dh);

	return (ret);
}

static int
dh_cb(int p, int n, BN_GENCB * cb)
{
	char c = '*';

	if (p == 0)
		c = '.';
	if (p == 1)
		c = '+';
	if (p == 2)
		c = '*';
	if (p == 3)
		c = '\n';
	BIO_write(cb->arg, &c, 1);
	(void) BIO_flush(cb->arg);
	return 1;
}
#endif
