/* $OpenBSD: pkeyparam.c,v 1.8 2015/10/10 22:28:51 doug Exp $ */
/* Written by Dr Stephen N Henson (steve@openssl.org) for the OpenSSL
 * project 2006
 */
/* ====================================================================
 * Copyright (c) 2006 The OpenSSL Project.  All rights reserved.
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
 *    for use in the OpenSSL Toolkit. (http://www.OpenSSL.org/)"
 *
 * 4. The names "OpenSSL Toolkit" and "OpenSSL Project" must not be used to
 *    endorse or promote products derived from this software without
 *    prior written permission. For written permission, please contact
 *    licensing@OpenSSL.org.
 *
 * 5. Products derived from this software may not be called "OpenSSL"
 *    nor may "OpenSSL" appear in their names without prior written
 *    permission of the OpenSSL Project.
 *
 * 6. Redistributions of any form whatsoever must retain the following
 *    acknowledgment:
 *    "This product includes software developed by the OpenSSL Project
 *    for use in the OpenSSL Toolkit (http://www.OpenSSL.org/)"
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

#include <stdio.h>
#include <string.h>

#include "apps.h"

#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>

struct {
	char *infile;
	int noout;
	char *outfile;
	int text;
} pkeyparam_config;

struct option pkeyparam_options[] = {
	{
		.name = "in",
		.argname = "file",
		.desc = "Input file (default stdin)",
		.type = OPTION_ARG,
		.opt.arg = &pkeyparam_config.infile,
	},
	{
		.name = "noout",
		.desc = "Do not print encoded version of the parameters",
		.type = OPTION_FLAG,
		.opt.flag = &pkeyparam_config.noout,
	},
	{
		.name = "out",
		.argname = "file",
		.desc = "Output file (default stdout)",
		.type = OPTION_ARG,
		.opt.arg = &pkeyparam_config.outfile,
	},
	{
		.name = "text",
		.desc = "Print out the parameters in plain text",
		.type = OPTION_FLAG,
		.opt.flag = &pkeyparam_config.text,
	},
	{ NULL },
};

static void
pkeyparam_usage()
{
	fprintf(stderr,
	    "usage: pkeyparam [-in file] [-noout] [-out file] "
	    "[-text]\n");
	options_usage(pkeyparam_options);
}

int
pkeyparam_main(int argc, char **argv)
{
	BIO *in = NULL, *out = NULL;
	EVP_PKEY *pkey = NULL;
	int ret = 1;

	if (single_execution) {
		if (pledge("stdio rpath wpath cpath", NULL) == -1) {
			perror("pledge");
			exit(1);
		}
	}

	memset(&pkeyparam_config, 0, sizeof(pkeyparam_config));

	if (options_parse(argc, argv, pkeyparam_options, NULL, NULL) != 0) {
		pkeyparam_usage();
		return (1);
	}

	if (pkeyparam_config.infile) {
		if (!(in = BIO_new_file(pkeyparam_config.infile, "r"))) {
			BIO_printf(bio_err, "Can't open input file %s\n",
			    pkeyparam_config.infile);
			goto end;
		}
	} else
		in = BIO_new_fp(stdin, BIO_NOCLOSE);

	if (pkeyparam_config.outfile) {
		if (!(out = BIO_new_file(pkeyparam_config.outfile, "w"))) {
			BIO_printf(bio_err, "Can't open output file %s\n",
			    pkeyparam_config.outfile);
			goto end;
		}
	} else {
		out = BIO_new_fp(stdout, BIO_NOCLOSE);
	}

	pkey = PEM_read_bio_Parameters(in, NULL);
	if (!pkey) {
		BIO_printf(bio_err, "Error reading parameters\n");
		ERR_print_errors(bio_err);
		goto end;
	}
	if (!pkeyparam_config.noout)
		PEM_write_bio_Parameters(out, pkey);

	if (pkeyparam_config.text)
		EVP_PKEY_print_params(out, pkey, 0, NULL);

	ret = 0;

end:
	EVP_PKEY_free(pkey);
	BIO_free_all(out);
	BIO_free(in);

	return ret;
}
