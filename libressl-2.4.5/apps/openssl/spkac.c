/* $OpenBSD: spkac.c,v 1.7 2015/10/17 07:51:10 semarie Exp $ */
/* Written by Dr Stephen N Henson (steve@openssl.org) for the OpenSSL
 * project 1999. Based on an original idea by Massimiliano Pala
 * (madwolf@openca.org).
 */
/* ====================================================================
 * Copyright (c) 1999 The OpenSSL Project.  All rights reserved.
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
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "apps.h"
#include "progs.h"

#include <openssl/bio.h>
#include <openssl/conf.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/lhash.h>
#include <openssl/pem.h>
#include <openssl/x509.h>

static struct {
	char *challenge;
	char *infile;
	char *keyfile;
	int noout;
	char *outfile;
	char *passargin;
	int pubkey;
	char *spkac;
	char *spksect;
	int verify;
} spkac_config;

static struct option spkac_options[] = {
	{
		.name = "challenge",
		.argname = "string",
		.desc = "Specify challenge string if SPKAC is generated",
		.type = OPTION_ARG,
		.opt.arg = &spkac_config.challenge,
	},
	{
		.name = "in",
		.argname = "file",
		.desc = "Input file (default stdin)",
		.type = OPTION_ARG,
		.opt.arg = &spkac_config.infile,
	},
	{
		.name = "key",
		.argname = "file",
		.desc = "Create SPKAC using private key file",
		.type = OPTION_ARG,
		.opt.arg = &spkac_config.keyfile,
	},
	{
		.name = "noout",
		.desc = "Do not print text version of SPKAC",
		.type = OPTION_FLAG,
		.opt.flag = &spkac_config.noout,
	},
	{
		.name = "out",
		.argname = "file",
		.desc = "Output file (default stdout)",
		.type = OPTION_ARG,
		.opt.arg = &spkac_config.outfile,
	},
	{
		.name = "passin",
		.argname = "src",
		.desc = "Input file passphrase source",
		.type = OPTION_ARG,
		.opt.arg = &spkac_config.passargin,
	},
	{
		.name = "pubkey",
		.desc = "Output public key of an SPKAC (not used if creating)",
		.type = OPTION_FLAG,
		.opt.flag = &spkac_config.pubkey,
	},
	{
		.name = "spkac",
		.argname = "name",
		.desc = "SPKAC name (default \"SPKAC\")",
		.type = OPTION_ARG,
		.opt.arg = &spkac_config.spkac,
	},
	{
		.name = "spksect",
		.argname = "name",
		.desc = "Name of the section containing SPKAC (default"
		" \"default\")",
		.type = OPTION_ARG,
		.opt.arg = &spkac_config.spksect,
	},
	{
		.name = "verify",
		.desc = "Verify digital signature on supplied SPKAC",
		.type = OPTION_FLAG,
		.opt.flag = &spkac_config.verify,
	},
	{ NULL }
};

static void
spkac_usage(void)
{
	fprintf(stderr,
	    "usage: spkac [-challenge string] [-in file] "
	    "[-key file] [-noout]\n"
	    "    [-out file] [-passin src] [-pubkey] [-spkac name] "
	    "[-spksect section]\n"
	    "    [-verify]\n\n");
	options_usage(spkac_options);
}

int
spkac_main(int argc, char **argv)
{
	int i, ret = 1;
	BIO *in = NULL, *out = NULL;
	char *passin = NULL;
	char *spkstr = NULL;
	CONF *conf = NULL;
	NETSCAPE_SPKI *spki = NULL;
	EVP_PKEY *pkey = NULL;

	if (single_execution) {
		if (pledge("stdio rpath wpath cpath tty", NULL) == -1) {
			perror("pledge");
			exit(1);
		}
	}

	memset(&spkac_config, 0, sizeof(spkac_config));
	spkac_config.spkac = "SPKAC";
	spkac_config.spksect = "default";

	if (options_parse(argc, argv, spkac_options, NULL, NULL) != 0) {
		spkac_usage();
		return (1);
	}

	if (!app_passwd(bio_err, spkac_config.passargin, NULL, &passin, NULL)) {
		BIO_printf(bio_err, "Error getting password\n");
		goto end;
	}

	if (spkac_config.keyfile) {
		pkey = load_key(bio_err,
		    strcmp(spkac_config.keyfile, "-") ? spkac_config.keyfile
		    : NULL, FORMAT_PEM, 1, passin, "private key");
		if (!pkey) {
			goto end;
		}
		spki = NETSCAPE_SPKI_new();
		if (spkac_config.challenge)
			ASN1_STRING_set(spki->spkac->challenge,
			    spkac_config.challenge,
			    (int) strlen(spkac_config.challenge));
		NETSCAPE_SPKI_set_pubkey(spki, pkey);
		NETSCAPE_SPKI_sign(spki, pkey, EVP_md5());
		spkstr = NETSCAPE_SPKI_b64_encode(spki);
		if (spkstr == NULL) {
			BIO_printf(bio_err, "Error encoding SPKAC\n");
			ERR_print_errors(bio_err);
			goto end;
		}

		if (spkac_config.outfile)
			out = BIO_new_file(spkac_config.outfile, "w");
		else
			out = BIO_new_fp(stdout, BIO_NOCLOSE);

		if (!out) {
			BIO_printf(bio_err, "Error opening output file\n");
			ERR_print_errors(bio_err);
		} else {
			BIO_printf(out, "SPKAC=%s\n", spkstr);
			ret = 0;
		}
		free(spkstr);
		goto end;
	}
	if (spkac_config.infile)
		in = BIO_new_file(spkac_config.infile, "r");
	else
		in = BIO_new_fp(stdin, BIO_NOCLOSE);

	if (!in) {
		BIO_printf(bio_err, "Error opening input file\n");
		ERR_print_errors(bio_err);
		goto end;
	}
	conf = NCONF_new(NULL);
	i = NCONF_load_bio(conf, in, NULL);

	if (!i) {
		BIO_printf(bio_err, "Error parsing config file\n");
		ERR_print_errors(bio_err);
		goto end;
	}
	spkstr = NCONF_get_string(conf, spkac_config.spksect,
	    spkac_config.spkac);

	if (!spkstr) {
		BIO_printf(bio_err, "Can't find SPKAC called \"%s\"\n",
		    spkac_config.spkac);
		ERR_print_errors(bio_err);
		goto end;
	}
	spki = NETSCAPE_SPKI_b64_decode(spkstr, -1);

	if (!spki) {
		BIO_printf(bio_err, "Error loading SPKAC\n");
		ERR_print_errors(bio_err);
		goto end;
	}
	if (spkac_config.outfile)
		out = BIO_new_file(spkac_config.outfile, "w");
	else {
		out = BIO_new_fp(stdout, BIO_NOCLOSE);
	}

	if (!out) {
		BIO_printf(bio_err, "Error opening output file\n");
		ERR_print_errors(bio_err);
		goto end;
	}
	if (!spkac_config.noout)
		NETSCAPE_SPKI_print(out, spki);
	pkey = NETSCAPE_SPKI_get_pubkey(spki);
	if (spkac_config.verify) {
		i = NETSCAPE_SPKI_verify(spki, pkey);
		if (i > 0)
			BIO_printf(bio_err, "Signature OK\n");
		else {
			BIO_printf(bio_err, "Signature Failure\n");
			ERR_print_errors(bio_err);
			goto end;
		}
	}
	if (spkac_config.pubkey)
		PEM_write_bio_PUBKEY(out, pkey);

	ret = 0;

end:
	NCONF_free(conf);
	NETSCAPE_SPKI_free(spki);
	BIO_free(in);
	BIO_free_all(out);
	EVP_PKEY_free(pkey);
	free(passin);

	return (ret);
}
