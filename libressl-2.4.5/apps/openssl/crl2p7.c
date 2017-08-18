/* $OpenBSD: crl2p7.c,v 1.5 2015/10/10 22:28:51 doug Exp $ */
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

/* This was written by Gordon Chaffee <chaffee@plateau.cs.berkeley.edu>
 * and donated 'to the cause' along with lots and lots of other fixes to
 * the library. */

#include <sys/types.h>

#include <stdio.h>
#include <string.h>

#include "apps.h"

#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/objects.h>
#include <openssl/pem.h>
#include <openssl/pkcs7.h>
#include <openssl/x509.h>

static int add_certs_from_file(STACK_OF(X509) * stack, char *certfile);

static struct {
	STACK_OF(OPENSSL_STRING) *certflst;
	char *infile;
	int informat;
	int nocrl;
	char *outfile;
	int outformat;
} crl2p7_config;

static int
crl2p7_opt_certfile(char *arg)
{
	if (crl2p7_config.certflst == NULL)
		crl2p7_config.certflst = sk_OPENSSL_STRING_new_null();
	if (crl2p7_config.certflst == NULL) {
		fprintf(stderr, "out of memory\n");
		return (1);
	}
	if (!sk_OPENSSL_STRING_push(crl2p7_config.certflst, arg)) {
		fprintf(stderr, "out of memory\n");
		return (1);
	}

	return (0);
}

static struct option crl2p7_options[] = {
	{
		.name = "certfile",
		.argname = "file",
		.desc = "Chain of PEM certificates to a trusted CA",
		.type = OPTION_ARG_FUNC,
		.opt.argfunc = crl2p7_opt_certfile,
	},
	{
		.name = "in",
		.argname = "file",
		.desc = "Input file (default stdin)",
		.type = OPTION_ARG,
		.opt.arg = &crl2p7_config.infile,
	},
	{
		.name = "inform",
		.argname = "format",
		.desc = "Input format (DER or PEM (default))",
		.type = OPTION_ARG_FORMAT,
		.opt.value = &crl2p7_config.informat,
	},
	{
		.name = "nocrl",
		.desc = "Do not read CRL from input or include CRL in output",
		.type = OPTION_FLAG,
		.opt.flag = &crl2p7_config.nocrl,
	},
	{
		.name = "out",
		.argname = "file",
		.desc = "Output file (default stdout)",
		.type = OPTION_ARG,
		.opt.arg = &crl2p7_config.outfile,
	},
	{
		.name = "outform",
		.argname = "format",
		.desc = "Output format (DER or PEM (default))",
		.type = OPTION_ARG_FORMAT,
		.opt.value = &crl2p7_config.outformat,
	},
	{ NULL },
};

static void
crl2p7_usage(void)
{
	fprintf(stderr,
	    "usage: crl2p7 [-certfile file] [-in file] [-inform DER | PEM]\n"
	    "    [-nocrl] [-out file] [-outform DER | PEM]\n\n");
	options_usage(crl2p7_options);
}

int
crl2pkcs7_main(int argc, char **argv)
{
	int i;
	BIO *in = NULL, *out = NULL;
	char *certfile;
	PKCS7 *p7 = NULL;
	PKCS7_SIGNED *p7s = NULL;
	X509_CRL *crl = NULL;
	STACK_OF(X509_CRL) *crl_stack = NULL;
	STACK_OF(X509) *cert_stack = NULL;
	int ret = 1;

	if (single_execution) {
		if (pledge("stdio rpath wpath cpath", NULL) == -1) {
			perror("pledge");
			exit(1);
		}
	}

	memset(&crl2p7_config, 0, sizeof(crl2p7_config));

	crl2p7_config.informat = FORMAT_PEM;
	crl2p7_config.outformat = FORMAT_PEM;

	if (options_parse(argc, argv, crl2p7_options, NULL, NULL) != 0) {
		crl2p7_usage();
		goto end;
	}

	in = BIO_new(BIO_s_file());
	out = BIO_new(BIO_s_file());
	if (in == NULL || out == NULL) {
		ERR_print_errors(bio_err);
		goto end;
	}
	if (!crl2p7_config.nocrl) {
		if (crl2p7_config.infile == NULL)
			BIO_set_fp(in, stdin, BIO_NOCLOSE);
		else {
			if (BIO_read_filename(in, crl2p7_config.infile) <= 0) {
				perror(crl2p7_config.infile);
				goto end;
			}
		}

		if (crl2p7_config.informat == FORMAT_ASN1)
			crl = d2i_X509_CRL_bio(in, NULL);
		else if (crl2p7_config.informat == FORMAT_PEM)
			crl = PEM_read_bio_X509_CRL(in, NULL, NULL, NULL);
		else {
			BIO_printf(bio_err,
			    "bad input format specified for input crl\n");
			goto end;
		}
		if (crl == NULL) {
			BIO_printf(bio_err, "unable to load CRL\n");
			ERR_print_errors(bio_err);
			goto end;
		}
	}
	if ((p7 = PKCS7_new()) == NULL)
		goto end;
	if ((p7s = PKCS7_SIGNED_new()) == NULL)
		goto end;
	p7->type = OBJ_nid2obj(NID_pkcs7_signed);
	p7->d.sign = p7s;
	p7s->contents->type = OBJ_nid2obj(NID_pkcs7_data);

	if (!ASN1_INTEGER_set(p7s->version, 1))
		goto end;
	if ((crl_stack = sk_X509_CRL_new_null()) == NULL)
		goto end;
	p7s->crl = crl_stack;
	if (crl != NULL) {
		sk_X509_CRL_push(crl_stack, crl);
		crl = NULL;	/* now part of p7 for freeing */
	}
	if ((cert_stack = sk_X509_new_null()) == NULL)
		goto end;
	p7s->cert = cert_stack;

	if (crl2p7_config.certflst) {
		for (i = 0; i < sk_OPENSSL_STRING_num(crl2p7_config.certflst); i++) {
			certfile = sk_OPENSSL_STRING_value(crl2p7_config.certflst, i);
			if (add_certs_from_file(cert_stack, certfile) < 0) {
				BIO_printf(bio_err,
				    "error loading certificates\n");
				ERR_print_errors(bio_err);
				goto end;
			}
		}
	}

	sk_OPENSSL_STRING_free(crl2p7_config.certflst);

	if (crl2p7_config.outfile == NULL) {
		BIO_set_fp(out, stdout, BIO_NOCLOSE);
	} else {
		if (BIO_write_filename(out, crl2p7_config.outfile) <= 0) {
			perror(crl2p7_config.outfile);
			goto end;
		}
	}

	if (crl2p7_config.outformat == FORMAT_ASN1)
		i = i2d_PKCS7_bio(out, p7);
	else if (crl2p7_config.outformat == FORMAT_PEM)
		i = PEM_write_bio_PKCS7(out, p7);
	else {
		BIO_printf(bio_err,
		    "bad output format specified for outfile\n");
		goto end;
	}
	if (!i) {
		BIO_printf(bio_err, "unable to write pkcs7 object\n");
		ERR_print_errors(bio_err);
		goto end;
	}
	ret = 0;

end:
	if (in != NULL)
		BIO_free(in);
	if (out != NULL)
		BIO_free_all(out);
	if (p7 != NULL)
		PKCS7_free(p7);
	if (crl != NULL)
		X509_CRL_free(crl);

	return (ret);
}

static int
add_certs_from_file(STACK_OF(X509) *stack, char *certfile)
{
	BIO *in = NULL;
	int count = 0;
	int ret = -1;
	STACK_OF(X509_INFO) *sk = NULL;
	X509_INFO *xi;

	in = BIO_new(BIO_s_file());
	if (in == NULL || BIO_read_filename(in, certfile) <= 0) {
		BIO_printf(bio_err, "error opening the file, %s\n", certfile);
		goto end;
	}
	/* This loads from a file, a stack of x509/crl/pkey sets */
	sk = PEM_X509_INFO_read_bio(in, NULL, NULL, NULL);
	if (sk == NULL) {
		BIO_printf(bio_err, "error reading the file, %s\n", certfile);
		goto end;
	}
	/* scan over it and pull out the CRL's */
	while (sk_X509_INFO_num(sk)) {
		xi = sk_X509_INFO_shift(sk);
		if (xi->x509 != NULL) {
			sk_X509_push(stack, xi->x509);
			xi->x509 = NULL;
			count++;
		}
		X509_INFO_free(xi);
	}

	ret = count;

end:
	/* never need to free x */
	if (in != NULL)
		BIO_free(in);
	if (sk != NULL)
		sk_X509_INFO_free(sk);
	return (ret);
}
