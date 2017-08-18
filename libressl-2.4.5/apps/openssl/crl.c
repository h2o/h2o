/* $OpenBSD: crl.c,v 1.8 2015/10/10 22:28:51 doug Exp $ */
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

#include "apps.h"

#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

static struct {
	char *cafile;
	char *capath;
	int crlnumber;
	int fingerprint;
	int hash;
	int hash_old;
	char *infile;
	int informat;
	int issuer;
	int lastupdate;
	char *nameopt;
	int nextupdate;
	int noout;
	char *outfile;
	int outformat;
	int text;
	int verify;
} crl_config;

static struct option crl_options[] = {
	{
		.name = "CAfile",
		.argname = "file",
		.desc = "Verify the CRL using certificates in the given file",
		.type = OPTION_ARG,
		.opt.arg = &crl_config.cafile,
	},
	{
		.name = "CApath",
		.argname = "path",
		.desc = "Verify the CRL using certificates in the given path",
		.type = OPTION_ARG,
		.opt.arg = &crl_config.capath,
	},
	{
		.name = "crlnumber",
		.desc = "Print the CRL number",
		.type = OPTION_FLAG_ORD,
		.opt.flag = &crl_config.crlnumber,
	},
	{
		.name = "fingerprint",
		.desc = "Print the CRL fingerprint",
		.type = OPTION_FLAG_ORD,
		.opt.flag = &crl_config.fingerprint,
	},
	{
		.name = "hash",
		.desc = "Print the hash of the issuer name",
		.type = OPTION_FLAG_ORD,
		.opt.flag = &crl_config.hash,
	},
	{
		.name = "hash_old",
		.desc = "Print an old-style (MD5) hash of the issuer name",
		.type = OPTION_FLAG_ORD,
		.opt.flag = &crl_config.hash_old,
	},
	{
		.name = "in",
		.argname = "file",
		.desc = "Input file to read from (stdin if unspecified)",
		.type = OPTION_ARG,
		.opt.arg = &crl_config.infile,
	},
	{
		.name = "inform",
		.argname = "format",
		.desc = "Input format (DER or PEM)",
		.type = OPTION_ARG_FORMAT,
		.opt.value = &crl_config.informat,
	},
	{
		.name = "issuer",
		.desc = "Print the issuer name",
		.type = OPTION_FLAG_ORD,
		.opt.flag = &crl_config.issuer,
	},
	{
		.name = "lastupdate",
		.desc = "Print the lastUpdate field",
		.type = OPTION_FLAG_ORD,
		.opt.flag = &crl_config.lastupdate,
	},
	{
		.name = "nameopt",
		.argname = "options",
		.desc = "Specify certificate name options",
		.type = OPTION_ARG,
		.opt.arg = &crl_config.nameopt,
	},
	{
		.name = "nextupdate",
		.desc = "Print the nextUpdate field",
		.type = OPTION_FLAG_ORD,
		.opt.flag = &crl_config.nextupdate,
	},
	{
		.name = "noout",
		.desc = "Do not output the encoded version of the CRL",
		.type = OPTION_FLAG,
		.opt.flag = &crl_config.noout,
	},
	{
		.name = "out",
		.argname = "file",
		.desc = "Output file to write to (stdout if unspecified)",
		.type = OPTION_ARG,
		.opt.arg = &crl_config.outfile,
	},
	{
		.name = "outform",
		.argname = "format",
		.desc = "Output format (DER or PEM)",
		.type = OPTION_ARG_FORMAT,
		.opt.value = &crl_config.outformat,
	},
	{
		.name = "text",
		.desc = "Print out the CRL in text form",
		.type = OPTION_FLAG,
		.opt.flag = &crl_config.text,
	},
	{
		.name = "verify",
		.desc = "Verify the signature on the CRL",
		.type = OPTION_FLAG,
		.opt.flag = &crl_config.verify,
	},
	{NULL},
};

static void
crl_usage(void)
{
	fprintf(stderr,
	    "usage: crl [-CAfile file] [-CApath dir] [-fingerprint] [-hash]\n"
	    "    [-in file] [-inform DER | PEM] [-issuer] [-lastupdate]\n"
	    "    [-nextupdate] [-noout] [-out file] [-outform DER | PEM]\n"
	    "    [-text]\n\n");
	options_usage(crl_options);
}

static X509_CRL *load_crl(char *file, int format);
static BIO *bio_out = NULL;

int
crl_main(int argc, char **argv)
{
	unsigned long nmflag = 0;
	X509_CRL *x = NULL;
	int ret = 1, i;
	BIO *out = NULL;
	X509_STORE *store = NULL;
	X509_STORE_CTX ctx;
	X509_LOOKUP *lookup = NULL;
	X509_OBJECT xobj;
	EVP_PKEY *pkey;
	const EVP_MD *digest;
	char *digest_name = NULL;

	if (single_execution) {
		if (pledge("stdio rpath wpath cpath", NULL) == -1) {
			perror("pledge");
			exit(1);
		}
	}

	if (bio_out == NULL) {
		if ((bio_out = BIO_new(BIO_s_file())) != NULL) {
			BIO_set_fp(bio_out, stdout, BIO_NOCLOSE);
		}
	}

	digest = EVP_sha1();

	memset(&crl_config, 0, sizeof(crl_config));
	crl_config.informat = FORMAT_PEM;
	crl_config.outformat = FORMAT_PEM;

	if (options_parse(argc, argv, crl_options, &digest_name, NULL) != 0) {
		crl_usage();
		goto end;
	}

	if (crl_config.cafile != NULL || crl_config.capath != NULL)
		crl_config.verify = 1;

	if (crl_config.nameopt != NULL) {
		if (set_name_ex(&nmflag, crl_config.nameopt) != 1) {
			fprintf(stderr,
			    "Invalid -nameopt argument '%s'\n",
			    crl_config.nameopt);
			goto end;
		}
	}

	if (digest_name != NULL) {
		if ((digest = EVP_get_digestbyname(digest_name)) == NULL) {
			fprintf(stderr,
			    "Unknown message digest algorithm '%s'\n",
			    digest_name);
			goto end;
		}
	}

	x = load_crl(crl_config.infile, crl_config.informat);
	if (x == NULL)
		goto end;

	if (crl_config.verify) {
		store = X509_STORE_new();
		lookup = X509_STORE_add_lookup(store, X509_LOOKUP_file());
		if (lookup == NULL)
			goto end;
		if (!X509_LOOKUP_load_file(lookup, crl_config.cafile,
		    X509_FILETYPE_PEM))
			X509_LOOKUP_load_file(lookup, NULL,
			    X509_FILETYPE_DEFAULT);

		lookup = X509_STORE_add_lookup(store, X509_LOOKUP_hash_dir());
		if (lookup == NULL)
			goto end;
		if (!X509_LOOKUP_add_dir(lookup, crl_config.capath,
		    X509_FILETYPE_PEM))
			X509_LOOKUP_add_dir(lookup, NULL,
			    X509_FILETYPE_DEFAULT);
		ERR_clear_error();

		if (!X509_STORE_CTX_init(&ctx, store, NULL, NULL)) {
			BIO_printf(bio_err,
			    "Error initialising X509 store\n");
			goto end;
		}
		i = X509_STORE_get_by_subject(&ctx, X509_LU_X509,
		    X509_CRL_get_issuer(x), &xobj);
		if (i <= 0) {
			BIO_printf(bio_err,
			    "Error getting CRL issuer certificate\n");
			goto end;
		}
		pkey = X509_get_pubkey(xobj.data.x509);
		X509_OBJECT_free_contents(&xobj);
		if (!pkey) {
			BIO_printf(bio_err,
			    "Error getting CRL issuer public key\n");
			goto end;
		}
		i = X509_CRL_verify(x, pkey);
		EVP_PKEY_free(pkey);
		if (i < 0)
			goto end;
		if (i == 0)
			BIO_printf(bio_err, "verify failure\n");
		else
			BIO_printf(bio_err, "verify OK\n");
	}

	/* Print requested information the order that the flags were given. */
	for (i = 1; i <= argc; i++) {
		if (crl_config.issuer == i) {
			print_name(bio_out, "issuer=",
			    X509_CRL_get_issuer(x), nmflag);
		}
		if (crl_config.crlnumber == i) {
			ASN1_INTEGER *crlnum;
			crlnum = X509_CRL_get_ext_d2i(x,
			    NID_crl_number, NULL, NULL);
			BIO_printf(bio_out, "crlNumber=");
			if (crlnum) {
				i2a_ASN1_INTEGER(bio_out, crlnum);
				ASN1_INTEGER_free(crlnum);
			} else
				BIO_puts(bio_out, "<NONE>");
			BIO_printf(bio_out, "\n");
		}
		if (crl_config.hash == i) {
			BIO_printf(bio_out, "%08lx\n",
			    X509_NAME_hash(X509_CRL_get_issuer(x)));
		}
#ifndef OPENSSL_NO_MD5
		if (crl_config.hash_old == i) {
			BIO_printf(bio_out, "%08lx\n",
			    X509_NAME_hash_old(X509_CRL_get_issuer(x)));
		}
#endif
		if (crl_config.lastupdate == i) {
			BIO_printf(bio_out, "lastUpdate=");
			ASN1_TIME_print(bio_out,
			    X509_CRL_get_lastUpdate(x));
			BIO_printf(bio_out, "\n");
		}
		if (crl_config.nextupdate == i) {
			BIO_printf(bio_out, "nextUpdate=");
			if (X509_CRL_get_nextUpdate(x))
				ASN1_TIME_print(bio_out,
				    X509_CRL_get_nextUpdate(x));
			else
				BIO_printf(bio_out, "NONE");
			BIO_printf(bio_out, "\n");
		}
		if (crl_config.fingerprint == i) {
			int j;
			unsigned int n;
			unsigned char md[EVP_MAX_MD_SIZE];

			if (!X509_CRL_digest(x, digest, md, &n)) {
				BIO_printf(bio_err, "out of memory\n");
				goto end;
			}
			BIO_printf(bio_out, "%s Fingerprint=",
			    OBJ_nid2sn(EVP_MD_type(digest)));
			for (j = 0; j < (int) n; j++) {
				BIO_printf(bio_out, "%02X%c", md[j],
				    (j + 1 == (int)n) ? '\n' : ':');
			}
		}
	}

	out = BIO_new(BIO_s_file());
	if (out == NULL) {
		ERR_print_errors(bio_err);
		goto end;
	}
	if (crl_config.outfile == NULL) {
		BIO_set_fp(out, stdout, BIO_NOCLOSE);
	} else {
		if (BIO_write_filename(out, crl_config.outfile) <= 0) {
			perror(crl_config.outfile);
			goto end;
		}
	}

	if (crl_config.text)
		X509_CRL_print(out, x);

	if (crl_config.noout) {
		ret = 0;
		goto end;
	}
	if (crl_config.outformat == FORMAT_ASN1)
		i = (int) i2d_X509_CRL_bio(out, x);
	else if (crl_config.outformat == FORMAT_PEM)
		i = PEM_write_bio_X509_CRL(out, x);
	else {
		BIO_printf(bio_err,
		    "bad output format specified for outfile\n");
		goto end;
	}
	if (!i) {
		BIO_printf(bio_err, "unable to write CRL\n");
		goto end;
	}
	ret = 0;

end:
	BIO_free_all(out);
	BIO_free_all(bio_out);
	bio_out = NULL;
	X509_CRL_free(x);
	if (store) {
		X509_STORE_CTX_cleanup(&ctx);
		X509_STORE_free(store);
	}

	return (ret);
}

static X509_CRL *
load_crl(char *infile, int format)
{
	X509_CRL *x = NULL;
	BIO *in = NULL;

	in = BIO_new(BIO_s_file());
	if (in == NULL) {
		ERR_print_errors(bio_err);
		goto end;
	}
	if (infile == NULL)
		BIO_set_fp(in, stdin, BIO_NOCLOSE);
	else {
		if (BIO_read_filename(in, infile) <= 0) {
			perror(infile);
			goto end;
		}
	}
	if (format == FORMAT_ASN1)
		x = d2i_X509_CRL_bio(in, NULL);
	else if (format == FORMAT_PEM)
		x = PEM_read_bio_X509_CRL(in, NULL, NULL, NULL);
	else {
		BIO_printf(bio_err,
		    "bad input format specified for input crl\n");
		goto end;
	}
	if (x == NULL) {
		BIO_printf(bio_err, "unable to load CRL\n");
		ERR_print_errors(bio_err);
		goto end;
	}

end:
	BIO_free(in);
	return (x);
}
