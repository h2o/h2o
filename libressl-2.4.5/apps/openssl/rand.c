/* $OpenBSD: rand.c,v 1.9 2015/10/10 22:28:51 doug Exp $ */
/* ====================================================================
 * Copyright (c) 1998-2001 The OpenSSL Project.  All rights reserved.
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
 * ====================================================================
 *
 * This product includes cryptographic software written by Eric Young
 * (eay@cryptsoft.com).  This product includes software written by Tim
 * Hudson (tjh@cryptsoft.com).
 *
 */

#include <ctype.h>
#include <stdio.h>
#include <string.h>

#include "apps.h"

#include <openssl/bio.h>
#include <openssl/err.h>

struct {
	int base64;
	int hex;
	char *outfile;
} rand_config;

struct option rand_options[] = {
	{
		.name = "base64",
		.desc = "Perform base64 encoding on output",
		.type = OPTION_FLAG,
		.opt.flag = &rand_config.base64,
	},
	{
		.name = "hex",
		.desc = "Hexadecimal output",
		.type = OPTION_FLAG,
		.opt.flag = &rand_config.hex,
	},
	{
		.name = "out",
		.argname = "file",
		.desc = "Write to the given file instead of standard output",
		.type = OPTION_ARG,
		.opt.arg = &rand_config.outfile,
	},
	{NULL},
};

static void
rand_usage()
{
	fprintf(stderr,
	    "usage: rand [-base64 | -hex] [-out file] num\n");
	options_usage(rand_options);
}

int
rand_main(int argc, char **argv)
{
	char *num_bytes = NULL;
	int ret = 1;
	int badopt = 0;
	int num = -1;
	int i, r;
	BIO *out = NULL;

	if (single_execution) {
		if (pledge("stdio rpath wpath cpath", NULL) == -1) {
			perror("pledge");
			exit(1);
		}
	}

	memset(&rand_config, 0, sizeof(rand_config));

	if (options_parse(argc, argv, rand_options, &num_bytes, NULL) != 0) {
		rand_usage();
		return (1);
	}

	if (num_bytes != NULL) {
		r = sscanf(num_bytes, "%d", &num);
		if (r == 0 || num < 0)
			badopt = 1;
	} else
		badopt = 1;

	if (rand_config.hex && rand_config.base64)
		badopt = 1;

	if (badopt) {
		rand_usage();
		goto err;
	}

	out = BIO_new(BIO_s_file());
	if (out == NULL)
		goto err;
	if (rand_config.outfile != NULL)
		r = BIO_write_filename(out, rand_config.outfile);
	else
		r = BIO_set_fp(out, stdout, BIO_NOCLOSE | BIO_FP_TEXT);
	if (r <= 0)
		goto err;
	if (rand_config.base64) {
		BIO *b64 = BIO_new(BIO_f_base64());
		if (b64 == NULL)
			goto err;
		out = BIO_push(b64, out);
	}

	while (num > 0) {
		unsigned char buf[4096];
		int chunk;

		chunk = num;
		if (chunk > (int) sizeof(buf))
			chunk = sizeof(buf);
		arc4random_buf(buf, chunk);
		if (rand_config.hex) {
			for (i = 0; i < chunk; i++)
				BIO_printf(out, "%02x", buf[i]);
		} else
			BIO_write(out, buf, chunk);
		num -= chunk;
	}

	if (rand_config.hex)
		BIO_puts(out, "\n");
	(void) BIO_flush(out);

	ret = 0;

err:
	ERR_print_errors(bio_err);
	if (out)
		BIO_free_all(out);

	return (ret);
}
