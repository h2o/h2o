/* $OpenBSD: pkcs7.c,v 1.7 2015/10/10 22:28:51 doug Exp $ */
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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "apps.h"

#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/objects.h>
#include <openssl/pem.h>
#include <openssl/pkcs7.h>
#include <openssl/x509.h>

static struct {
	char *infile;
	int informat;
	int noout;
	char *outfile;
	int outformat;
	int p7_print;
	int print_certs;
	int text;
} pkcs7_config;

static struct option pkcs7_options[] = {
	{
		.name = "in",
		.argname = "file",
		.desc = "Input file (default stdin)",
		.type = OPTION_ARG,
		.opt.arg = &pkcs7_config.infile,
	},
	{
		.name = "inform",
		.argname = "format",
		.desc = "Input format (DER or PEM (default))",
		.type = OPTION_ARG_FORMAT,
		.opt.value = &pkcs7_config.informat,
	},
	{
		.name = "noout",
		.desc = "Do not output encoded version of PKCS#7 structure",
		.type = OPTION_FLAG,
		.opt.flag = &pkcs7_config.noout,
	},
	{
		.name = "out",
		.argname = "file",
		.desc = "Output file (default stdout)",
		.type = OPTION_ARG,
		.opt.arg = &pkcs7_config.outfile,
	},
	{
		.name = "outform",
		.argname = "format",
		.desc = "Output format (DER or PEM (default))",
		.type = OPTION_ARG_FORMAT,
		.opt.value = &pkcs7_config.outformat,
	},
	{
		.name = "print",
		.desc = "Output ASN.1 representation of PKCS#7 structure",
		.type = OPTION_FLAG,
		.opt.flag = &pkcs7_config.p7_print,
	},
	{
		.name = "print_certs",
		.desc = "Print out any certificates or CRLs contained in file",
		.type = OPTION_FLAG,
		.opt.flag = &pkcs7_config.print_certs,
	},
	{
		.name = "text",
		.desc = "Print out full certificate details",
		.type = OPTION_FLAG,
		.opt.flag = &pkcs7_config.text,
	},
	{ NULL },
};

static void
pkcs7_usage()
{
	fprintf(stderr, "usage: pkcs7 [-in file] "
	    "[-inform DER | PEM] [-noout]\n"
	    "    [-out file] [-outform DER | PEM] [-print_certs] [-text]\n\n");
        options_usage(pkcs7_options);
}

int
pkcs7_main(int argc, char **argv)
{
	PKCS7 *p7 = NULL;
	BIO *in = NULL, *out = NULL;
	int ret = 1;
	int i;

	if (single_execution) {
		if (pledge("stdio rpath wpath cpath", NULL) == -1) {
			perror("pledge");
			exit(1);
		}
	}

	memset(&pkcs7_config, 0, sizeof(pkcs7_config));

	pkcs7_config.informat = FORMAT_PEM;
	pkcs7_config.outformat = FORMAT_PEM;

	if (options_parse(argc, argv, pkcs7_options, NULL, NULL) != 0) {
		pkcs7_usage();
		goto end;
	}

	in = BIO_new(BIO_s_file());
	out = BIO_new(BIO_s_file());
	if ((in == NULL) || (out == NULL)) {
		ERR_print_errors(bio_err);
		goto end;
	}
	if (pkcs7_config.infile == NULL)
		BIO_set_fp(in, stdin, BIO_NOCLOSE);
	else {
		if (BIO_read_filename(in, pkcs7_config.infile) <= 0) {
			perror(pkcs7_config.infile);
			goto end;
		}
	}

	if (pkcs7_config.informat == FORMAT_ASN1)
		p7 = d2i_PKCS7_bio(in, NULL);
	else if (pkcs7_config.informat == FORMAT_PEM)
		p7 = PEM_read_bio_PKCS7(in, NULL, NULL, NULL);
	else {
		BIO_printf(bio_err, "bad input format specified for pkcs7 object\n");
		goto end;
	}
	if (p7 == NULL) {
		BIO_printf(bio_err, "unable to load PKCS7 object\n");
		ERR_print_errors(bio_err);
		goto end;
	}
	if (pkcs7_config.outfile == NULL) {
		BIO_set_fp(out, stdout, BIO_NOCLOSE);
	} else {
		if (BIO_write_filename(out, pkcs7_config.outfile) <= 0) {
			perror(pkcs7_config.outfile);
			goto end;
		}
	}

	if (pkcs7_config.p7_print)
		PKCS7_print_ctx(out, p7, 0, NULL);

	if (pkcs7_config.print_certs) {
		STACK_OF(X509) * certs = NULL;
		STACK_OF(X509_CRL) * crls = NULL;

		i = OBJ_obj2nid(p7->type);
		switch (i) {
		case NID_pkcs7_signed:
			certs = p7->d.sign->cert;
			crls = p7->d.sign->crl;
			break;
		case NID_pkcs7_signedAndEnveloped:
			certs = p7->d.signed_and_enveloped->cert;
			crls = p7->d.signed_and_enveloped->crl;
			break;
		default:
			break;
		}

		if (certs != NULL) {
			X509 *x;

			for (i = 0; i < sk_X509_num(certs); i++) {
				x = sk_X509_value(certs, i);
				if (pkcs7_config.text)
					X509_print(out, x);
				else
					dump_cert_text(out, x);

				if (!pkcs7_config.noout)
					PEM_write_bio_X509(out, x);
				BIO_puts(out, "\n");
			}
		}
		if (crls != NULL) {
			X509_CRL *crl;

			for (i = 0; i < sk_X509_CRL_num(crls); i++) {
				crl = sk_X509_CRL_value(crls, i);

				X509_CRL_print(out, crl);

				if (!pkcs7_config.noout)
					PEM_write_bio_X509_CRL(out, crl);
				BIO_puts(out, "\n");
			}
		}
		ret = 0;
		goto end;
	}
	if (!pkcs7_config.noout) {
		if (pkcs7_config.outformat == FORMAT_ASN1)
			i = i2d_PKCS7_bio(out, p7);
		else if (pkcs7_config.outformat == FORMAT_PEM)
			i = PEM_write_bio_PKCS7(out, p7);
		else {
			BIO_printf(bio_err, "bad output format specified for outfile\n");
			goto end;
		}

		if (!i) {
			BIO_printf(bio_err, "unable to write pkcs7 object\n");
			ERR_print_errors(bio_err);
			goto end;
		}
	}
	ret = 0;
end:
	if (p7 != NULL)
		PKCS7_free(p7);
	if (in != NULL)
		BIO_free(in);
	if (out != NULL)
		BIO_free_all(out);

	return (ret);
}
