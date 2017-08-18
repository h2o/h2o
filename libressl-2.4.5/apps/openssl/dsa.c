/* $OpenBSD: dsa.c,v 1.7 2015/10/17 07:51:10 semarie Exp $ */
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

#include <openssl/opensslconf.h>	/* for OPENSSL_NO_DSA */

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <string.h>

#include "apps.h"

#include <openssl/bio.h>
#include <openssl/bn.h>
#include <openssl/dsa.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/x509.h>

static struct {
	const EVP_CIPHER *enc;
	char *infile;
	int informat;
	int modulus;
	int noout;
	char *outfile;
	int outformat;
	char *passargin;
	char *passargout;
	int pubin;
	int pubout;
	int pvk_encr;
	int text;
} dsa_config;

static int
dsa_opt_enc(int argc, char **argv, int *argsused)
{
	char *name = argv[0];

	if (*name++ != '-')
		return (1);

	if ((dsa_config.enc = EVP_get_cipherbyname(name)) != NULL) {
		*argsused = 1;
		return (0);
	}

	return (1);
}

static struct option dsa_options[] = {
	{
		.name = "in",
		.argname = "file",
		.desc = "Input file (default stdin)",
		.type = OPTION_ARG,
		.opt.arg = &dsa_config.infile,
	},
	{
		.name = "inform",
		.argname = "format",
		.desc = "Input format (PEM (default) or any other supported"
		    " format)",
		.type = OPTION_ARG_FORMAT,
		.opt.value = &dsa_config.informat,
	},
	{
		.name = "noout",
		.desc = "No output",
		.type = OPTION_FLAG,
		.opt.flag = &dsa_config.noout,
	},
	{
		.name = "out",
		.argname = "file",
		.desc = "Output file (default stdout)",
		.type = OPTION_ARG,
		.opt.arg = &dsa_config.outfile,
	},
	{
		.name = "outform",
		.argname = "format",
		.desc = "Output format (DER, MSBLOB, PEM (default) or PVK)",
		.type = OPTION_ARG_FORMAT,
		.opt.value = &dsa_config.outformat,
	},
	{
		.name = "passin",
		.argname = "source",
		.desc = "Input file passphrase source",
		.type = OPTION_ARG,
		.opt.arg = &dsa_config.passargin,
	},
	{
		.name = "passout",
		.argname = "source",
		.desc = "Output file passphrase source",
		.type = OPTION_ARG,
		.opt.arg = &dsa_config.passargout,
	},
	{
		.name = "pubin",
		.desc = "Read a public key from the input file instead of"
		    " private key",
		.type = OPTION_FLAG,
		.opt.flag = &dsa_config.pubin,
	},
	{
		.name = "pubout",
		.desc = "Output a public key instead of private key",
		.type = OPTION_FLAG,
		.opt.flag = &dsa_config.pubout,
	},
	{
		.name = "pvk-none",
		.desc = "PVK encryption level",
		.type = OPTION_VALUE,
		.value = 0,
		.opt.value = &dsa_config.pvk_encr,
	},
	{
		.name = "pvk-strong",
		.desc = "PVK encryption level (default)",
		.type = OPTION_VALUE,
		.value = 2,
		.opt.value = &dsa_config.pvk_encr,
	},
	{
		.name = "pvk-weak",
		.desc = "PVK encryption level",
		.type = OPTION_VALUE,
		.value = 1,
		.opt.value = &dsa_config.pvk_encr,
	},
	{
		.name = "text",
		.desc = "Print the key in text form",
		.type = OPTION_FLAG,
		.opt.flag = &dsa_config.text,
	},
	{
		.name = NULL,
		.type = OPTION_ARGV_FUNC,
		.opt.argvfunc = dsa_opt_enc,
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
dsa_usage(void)
{
	fprintf(stderr,
	    "usage: dsa [-in file] [-inform format] [-noout]\n"
	    "    [-out file] [-outform format] [-passin src] [-passout src]\n"
	    "    [-pubin] [-pubout] [-pvk-none | -pvk-strong | -pvk-weak]\n"
	    "    [-text] [-ciphername]\n\n");
	options_usage(dsa_options);
	fprintf(stderr, "\n");

	fprintf(stderr, "Valid ciphername values:\n\n");
	OBJ_NAME_do_all_sorted(OBJ_NAME_TYPE_CIPHER_METH, show_ciphers, NULL);
	fprintf(stderr, "\n");
}

int
dsa_main(int argc, char **argv)
{
	int ret = 1;
	DSA *dsa = NULL;
	int i;
	BIO *in = NULL, *out = NULL;
	char *passin = NULL, *passout = NULL;

	if (single_execution) {
		if (pledge("stdio rpath wpath cpath tty", NULL) == -1) {
			perror("pledge");
			exit(1);
		}
	}

	memset(&dsa_config, 0, sizeof(dsa_config));

	dsa_config.pvk_encr = 2;
	dsa_config.informat = FORMAT_PEM;
	dsa_config.outformat = FORMAT_PEM;

	if (options_parse(argc, argv, dsa_options, NULL, NULL) != 0) {
		dsa_usage();
		goto end;
	}

	if (!app_passwd(bio_err, dsa_config.passargin, dsa_config.passargout,
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
	if (dsa_config.infile == NULL)
		BIO_set_fp(in, stdin, BIO_NOCLOSE);
	else {
		if (BIO_read_filename(in, dsa_config.infile) <= 0) {
			perror(dsa_config.infile);
			goto end;
		}
	}

	BIO_printf(bio_err, "read DSA key\n");

	{
		EVP_PKEY *pkey;

		if (dsa_config.pubin)
			pkey = load_pubkey(bio_err, dsa_config.infile,
			    dsa_config.informat, 1, passin, "Public Key");
		else
			pkey = load_key(bio_err, dsa_config.infile,
			    dsa_config.informat, 1, passin, "Private Key");

		if (pkey) {
			dsa = EVP_PKEY_get1_DSA(pkey);
			EVP_PKEY_free(pkey);
		}
	}
	if (dsa == NULL) {
		BIO_printf(bio_err, "unable to load Key\n");
		ERR_print_errors(bio_err);
		goto end;
	}
	if (dsa_config.outfile == NULL) {
		BIO_set_fp(out, stdout, BIO_NOCLOSE);
	} else {
		if (BIO_write_filename(out, dsa_config.outfile) <= 0) {
			perror(dsa_config.outfile);
			goto end;
		}
	}

	if (dsa_config.text) {
		if (!DSA_print(out, dsa, 0)) {
			perror(dsa_config.outfile);
			ERR_print_errors(bio_err);
			goto end;
		}
	}
	if (dsa_config.modulus) {
		fprintf(stdout, "Public Key=");
		BN_print(out, dsa->pub_key);
		fprintf(stdout, "\n");
	}
	if (dsa_config.noout)
		goto end;
	BIO_printf(bio_err, "writing DSA key\n");
	if (dsa_config.outformat == FORMAT_ASN1) {
		if (dsa_config.pubin || dsa_config.pubout)
			i = i2d_DSA_PUBKEY_bio(out, dsa);
		else
			i = i2d_DSAPrivateKey_bio(out, dsa);
	} else if (dsa_config.outformat == FORMAT_PEM) {
		if (dsa_config.pubin || dsa_config.pubout)
			i = PEM_write_bio_DSA_PUBKEY(out, dsa);
		else
			i = PEM_write_bio_DSAPrivateKey(out, dsa, dsa_config.enc,
			    NULL, 0, NULL, passout);
#if !defined(OPENSSL_NO_RSA) && !defined(OPENSSL_NO_RC4)
	} else if (dsa_config.outformat == FORMAT_MSBLOB ||
	    dsa_config.outformat == FORMAT_PVK) {
		EVP_PKEY *pk;
		pk = EVP_PKEY_new();
		EVP_PKEY_set1_DSA(pk, dsa);
		if (dsa_config.outformat == FORMAT_PVK)
			i = i2b_PVK_bio(out, pk, dsa_config.pvk_encr, 0,
			    passout);
		else if (dsa_config.pubin || dsa_config.pubout)
			i = i2b_PublicKey_bio(out, pk);
		else
			i = i2b_PrivateKey_bio(out, pk);
		EVP_PKEY_free(pk);
#endif
	} else {
		BIO_printf(bio_err, "bad output format specified for outfile\n");
		goto end;
	}
	if (i <= 0) {
		BIO_printf(bio_err, "unable to write private key\n");
		ERR_print_errors(bio_err);
	} else
		ret = 0;
end:
	BIO_free(in);
	if (out != NULL)
		BIO_free_all(out);
	if (dsa != NULL)
		DSA_free(dsa);
	free(passin);
	free(passout);

	return (ret);
}
