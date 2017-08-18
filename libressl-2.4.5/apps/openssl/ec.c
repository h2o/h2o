/* $OpenBSD: ec.c,v 1.7 2015/10/17 07:51:10 semarie Exp $ */
/*
 * Written by Nils Larsch for the OpenSSL project.
 */
/* ====================================================================
 * Copyright (c) 1998-2005 The OpenSSL Project.  All rights reserved.
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

#include <openssl/opensslconf.h>

#ifndef OPENSSL_NO_EC

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "apps.h"

#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>

static struct {
	int asn1_flag;
	const EVP_CIPHER *enc;
	point_conversion_form_t form;
	char *infile;
	int informat;
	char *outfile;
	int outformat;
	int new_asn1_flag;
	int new_form;
	int noout;
	int param_out;
	char *passargin;
	char *passargout;
	int pubin;
	int pubout;
	int text;
} ec_config;

static int
ec_opt_enc(int argc, char **argv, int *argsused)
{
	char *name = argv[0];

	if (*name++ != '-')
		return (1);

	if ((ec_config.enc = EVP_get_cipherbyname(name)) != NULL) {
		*argsused = 1;
		return (0);
	}

	return (1);
}

static int
ec_opt_form(char *arg)
{
	if (strcmp(arg, "compressed") == 0)
		ec_config.form = POINT_CONVERSION_COMPRESSED;
	else if (strcmp(arg, "uncompressed") == 0)
		ec_config.form = POINT_CONVERSION_UNCOMPRESSED;
	else if (strcmp(arg, "hybrid") == 0)
		ec_config.form = POINT_CONVERSION_HYBRID;
	else {
		fprintf(stderr, "Invalid point conversion: %s\n", arg);
		return (1);
	}

	ec_config.new_form = 1;
	return (0);
}

static int
ec_opt_named(char *arg)
{
	if (strcmp(arg, "named_curve") == 0)
		ec_config.asn1_flag = OPENSSL_EC_NAMED_CURVE;
	else if (strcmp(arg, "explicit") == 0)
		ec_config.asn1_flag = 0;
	else {
		fprintf(stderr, "Invalid curve type: %s\n", arg);
		return (1);
	}

	ec_config.new_asn1_flag = 1;
	return (0);
}

static struct option ec_options[] = {
	{
		.name = "conv_form",
		.argname = "form",
		.desc = "Specify the point conversion form (default"
		    " \"named_curve\")",
		.type = OPTION_ARG_FUNC,
		.opt.argfunc = ec_opt_form,
	},
	{
		.name = "in",
		.argname = "file",
		.desc = "Input file (default stdin)",
		.type = OPTION_ARG,
		.opt.arg = &ec_config.infile,
	},
	{
		.name = "inform",
		.argname = "format",
		.desc = "Input format (DER or PEM (default))",
		.type = OPTION_ARG_FORMAT,
		.opt.value = &ec_config.informat,
	},
	{
		.name = "noout",
		.desc = "No output",
		.type = OPTION_FLAG,
		.opt.flag = &ec_config.noout,
	},
	{
		.name = "out",
		.argname = "file",
		.desc = "Output file (default stdout)",
		.type = OPTION_ARG,
		.opt.arg = &ec_config.outfile,
	},
	{
		.name = "outform",
		.argname = "format",
		.desc = "Output format (DER or PEM (default))",
		.type = OPTION_ARG_FORMAT,
		.opt.value = &ec_config.outformat,
	},
	{
		.name = "param_enc",
		.argname = "type",
		.desc = "Specify the way the ec parameters are encoded"
		    " (default \"uncompressed\")",
		.type = OPTION_ARG_FUNC,
		.opt.argfunc = ec_opt_named,
	},
	{
		.name = "param_out",
		.desc = "Print the elliptic curve parameters",
		.type = OPTION_FLAG,
		.opt.flag = &ec_config.param_out,
	},
	{
		.name = "passin",
		.argname = "source",
		.desc = "Input file passphrase source",
		.type = OPTION_ARG,
		.opt.arg = &ec_config.passargin,
	},
	{
		.name = "passout",
		.argname = "source",
		.desc = "Output file passphrase source",
		.type = OPTION_ARG,
		.opt.arg = &ec_config.passargout,
	},
	{
		.name = "pubin",
		.desc = "Read public key instead of private key from input",
		.type = OPTION_FLAG,
		.opt.flag = &ec_config.pubin,
	},
	{
		.name = "pubout",
		.desc = "Output public key instead of private key in output",
		.type = OPTION_FLAG,
		.opt.flag = &ec_config.pubout,
	},
	{
		.name = "text",
		.desc = "Print the public/private key components and parameters",
		.type = OPTION_FLAG,
		.opt.flag = &ec_config.text,
	},
	{
		.name = NULL,
		.desc = "Cipher to encrypt the output if using PEM format",
		.type = OPTION_ARGV_FUNC,
		.opt.argvfunc = ec_opt_enc,
	},
	{ NULL },
};

static void
show_ciphers(const OBJ_NAME *name, void *arg)
{
	static int n;

	if (!islower((unsigned char)*name->name))
		return;

	fprintf(stderr, " -%-24s%s", name->name, (++n % 3 ? "" : "\n"));
}

static void
ec_usage(void)
{
	fprintf(stderr,
	    "usage: ec [-conv_form form] [-in file]\n"
	    "    [-inform format] [-noout] [-out file] [-outform format]\n"
	    "    [-param_enc type] [-param_out] [-passin file]\n"
	    "    [-passout file] [-pubin] [-pubout] [-text] [-ciphername]\n\n");
	options_usage(ec_options);

	fprintf(stderr, "\n");

	fprintf(stderr, "Valid ciphername values:\n\n");
	OBJ_NAME_do_all_sorted(OBJ_NAME_TYPE_CIPHER_METH, show_ciphers, NULL);
	fprintf(stderr, "\n");
}

int
ec_main(int argc, char **argv)
{
	int ret = 1;
	EC_KEY *eckey = NULL;
	const EC_GROUP *group;
	int i;
	BIO *in = NULL, *out = NULL;
	char *passin = NULL, *passout = NULL;

	if (single_execution) {
		if (pledge("stdio rpath wpath cpath tty", NULL) == -1) {
			perror("pledge");
			exit(1);
		}
	}

	memset(&ec_config, 0, sizeof(ec_config));

	ec_config.asn1_flag = OPENSSL_EC_NAMED_CURVE;
	ec_config.form = POINT_CONVERSION_UNCOMPRESSED;
	ec_config.informat = FORMAT_PEM;
	ec_config.outformat = FORMAT_PEM;

	if (options_parse(argc, argv, ec_options, NULL, NULL) != 0) {
		ec_usage();
		goto end;
	}

	if (!app_passwd(bio_err, ec_config.passargin, ec_config.passargout,
	    &passin, &passout)) {
		BIO_printf(bio_err, "Error getting passwords\n");
		goto end;
	}
	in = BIO_new(BIO_s_file());
	out = BIO_new(BIO_s_file());
	if (in == NULL || out == NULL) {
		ERR_print_errors(bio_err);
		goto end;
	}
	if (ec_config.infile == NULL)
		BIO_set_fp(in, stdin, BIO_NOCLOSE);
	else {
		if (BIO_read_filename(in, ec_config.infile) <= 0) {
			perror(ec_config.infile);
			goto end;
		}
	}

	BIO_printf(bio_err, "read EC key\n");
	if (ec_config.informat == FORMAT_ASN1) {
		if (ec_config.pubin)
			eckey = d2i_EC_PUBKEY_bio(in, NULL);
		else
			eckey = d2i_ECPrivateKey_bio(in, NULL);
	} else if (ec_config.informat == FORMAT_PEM) {
		if (ec_config.pubin)
			eckey = PEM_read_bio_EC_PUBKEY(in, NULL, NULL,
			    NULL);
		else
			eckey = PEM_read_bio_ECPrivateKey(in, NULL, NULL,
			    passin);
	} else {
		BIO_printf(bio_err, "bad input format specified for key\n");
		goto end;
	}
	if (eckey == NULL) {
		BIO_printf(bio_err, "unable to load Key\n");
		ERR_print_errors(bio_err);
		goto end;
	}
	if (ec_config.outfile == NULL) {
		BIO_set_fp(out, stdout, BIO_NOCLOSE);
	} else {
		if (BIO_write_filename(out, ec_config.outfile) <= 0) {
			perror(ec_config.outfile);
			goto end;
		}
	}

	group = EC_KEY_get0_group(eckey);

	if (ec_config.new_form)
		EC_KEY_set_conv_form(eckey, ec_config.form);

	if (ec_config.new_asn1_flag)
		EC_KEY_set_asn1_flag(eckey, ec_config.asn1_flag);

	if (ec_config.text)
		if (!EC_KEY_print(out, eckey, 0)) {
			perror(ec_config.outfile);
			ERR_print_errors(bio_err);
			goto end;
		}
	if (ec_config.noout) {
		ret = 0;
		goto end;
	}
	BIO_printf(bio_err, "writing EC key\n");
	if (ec_config.outformat == FORMAT_ASN1) {
		if (ec_config.param_out)
			i = i2d_ECPKParameters_bio(out, group);
		else if (ec_config.pubin || ec_config.pubout)
			i = i2d_EC_PUBKEY_bio(out, eckey);
		else
			i = i2d_ECPrivateKey_bio(out, eckey);
	} else if (ec_config.outformat == FORMAT_PEM) {
		if (ec_config.param_out)
			i = PEM_write_bio_ECPKParameters(out, group);
		else if (ec_config.pubin || ec_config.pubout)
			i = PEM_write_bio_EC_PUBKEY(out, eckey);
		else
			i = PEM_write_bio_ECPrivateKey(out, eckey,
			    ec_config.enc, NULL, 0, NULL, passout);
	} else {
		BIO_printf(bio_err, "bad output format specified for "
		    "outfile\n");
		goto end;
	}

	if (!i) {
		BIO_printf(bio_err, "unable to write private key\n");
		ERR_print_errors(bio_err);
	} else
		ret = 0;
end:
	BIO_free(in);
	if (out)
		BIO_free_all(out);
	if (eckey)
		EC_KEY_free(eckey);
	free(passin);
	free(passout);

	return (ret);
}
#endif
