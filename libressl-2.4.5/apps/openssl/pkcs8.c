/* $OpenBSD: pkcs8.c,v 1.8 2015/10/17 07:51:10 semarie Exp $ */
/* Written by Dr Stephen N Henson (steve@openssl.org) for the OpenSSL
 * project 1999-2004.
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
#include <string.h>

#include "apps.h"
#include "progs.h"

#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/pkcs12.h>

static struct {
	const EVP_CIPHER *cipher;
	char *infile;
	int informat;
	int iter;
	int nocrypt;
	char *outfile;
	int outformat;
	int p8_broken;
	char *passargin;
	char *passargout;
	int pbe_nid;
	int topk8;
} pkcs8_config;

static int
pkcs8_opt_v1(char *arg)
{
	if ((pkcs8_config.pbe_nid = OBJ_txt2nid(arg)) == NID_undef) {
		fprintf(stderr, "Unknown PBE algorithm '%s'\n", arg);
		return (1);
	}

	return (0);
}

static int
pkcs8_opt_v2(char *arg)
{
	if ((pkcs8_config.cipher = EVP_get_cipherbyname(arg)) == NULL) {
		fprintf(stderr, "Unknown cipher '%s'\n", arg);
		return (1);
	}

	return (0);
}

static struct option pkcs8_options[] = {
	{
		.name = "embed",
		.desc = "Generate DSA keys in a broken format",
		.type = OPTION_VALUE,
		.value = PKCS8_EMBEDDED_PARAM,
		.opt.value = &pkcs8_config.p8_broken,
	},
	{
		.name = "in",
		.argname = "file",
		.desc = "Input file (default stdin)",
		.type = OPTION_ARG,
		.opt.arg = &pkcs8_config.infile,
	},
	{
		.name = "inform",
		.argname = "format",
		.desc = "Input format (DER or PEM (default))",
		.type = OPTION_ARG_FORMAT,
		.opt.value = &pkcs8_config.informat,
	},
	{
		.name = "nocrypt",
		.desc = "Use or expect unencrypted private key",
		.type = OPTION_FLAG,
		.opt.flag = &pkcs8_config.nocrypt,
	},
	{
		.name = "noiter",
		.desc = "Use 1 as iteration count",
		.type = OPTION_VALUE,
		.value = 1,
		.opt.value = &pkcs8_config.iter,
	},
	{
		.name = "nooct",
		.desc = "Generate RSA keys in a broken format (no octet)",
		.type = OPTION_VALUE,
		.value = PKCS8_NO_OCTET,
		.opt.value = &pkcs8_config.p8_broken,
	},
	{
		.name = "nsdb",
		.desc = "Generate DSA keys in the broken Netscape DB format",
		.type = OPTION_VALUE,
		.value = PKCS8_NS_DB,
		.opt.value = &pkcs8_config.p8_broken,
	},
	{
		.name = "out",
		.argname = "file",
		.desc = "Output file (default stdout)",
		.type = OPTION_ARG,
		.opt.arg = &pkcs8_config.outfile,
	},
	{
		.name = "outform",
		.argname = "format",
		.desc = "Output format (DER or PEM (default))",
		.type = OPTION_ARG_FORMAT,
		.opt.value = &pkcs8_config.outformat,
	},
	{
		.name = "passin",
		.argname = "source",
		.desc = "Input file passphrase source",
		.type = OPTION_ARG,
		.opt.arg = &pkcs8_config.passargin,
	},
	{
		.name = "passout",
		.argname = "source",
		.desc = "Output file passphrase source",
		.type = OPTION_ARG,
		.opt.arg = &pkcs8_config.passargout,
	},
	{
		.name = "topk8",
		.desc = "Read traditional format key and write PKCS#8 format"
		    " key",
		.type = OPTION_FLAG,
		.opt.flag = &pkcs8_config.topk8,
	},
	{
		.name = "v1",
		.argname = "algorithm",
		.desc = "Use PKCS#5 v1.5 or PKCS#12 with given algorithm",
		.type = OPTION_ARG_FUNC,
		.opt.argfunc = pkcs8_opt_v1,
	},
	{
		.name = "v2",
		.argname = "cipher",
		.desc = "Use PKCS#5 v2.0 with given cipher",
		.type = OPTION_ARG_FUNC,
		.opt.argfunc = pkcs8_opt_v2,
	},
	{ NULL },
};

static void
pkcs8_usage()
{
	fprintf(stderr, "usage: pkcs8 [-embed] [-in file] "
	    "[-inform fmt] [-nocrypt]\n"
	    "    [-noiter] [-nooct] [-nsdb] [-out file] [-outform fmt] "
	    "[-passin src]\n"
	    "    [-passout src] [-topk8] [-v1 alg] [-v2 alg]\n\n");
	options_usage(pkcs8_options);
}

int
pkcs8_main(int argc, char **argv)
{
	BIO *in = NULL, *out = NULL;
	X509_SIG *p8 = NULL;
	PKCS8_PRIV_KEY_INFO *p8inf = NULL;
	EVP_PKEY *pkey = NULL;
	char pass[50], *passin = NULL, *passout = NULL, *p8pass = NULL;
	int ret = 1;

	if (single_execution) {
		if (pledge("stdio rpath wpath cpath tty", NULL) == -1) {
			perror("pledge");
			exit(1);
		}
	}

	memset(&pkcs8_config, 0, sizeof(pkcs8_config));

	pkcs8_config.iter = PKCS12_DEFAULT_ITER;
	pkcs8_config.informat = FORMAT_PEM;
	pkcs8_config.outformat = FORMAT_PEM;
	pkcs8_config.p8_broken = PKCS8_OK;
	pkcs8_config.pbe_nid = -1;

	if (options_parse(argc, argv, pkcs8_options, NULL, NULL) != 0) {
		pkcs8_usage();
		return (1);
	}

	if (!app_passwd(bio_err, pkcs8_config.passargin,
	    pkcs8_config.passargout, &passin, &passout)) {
		BIO_printf(bio_err, "Error getting passwords\n");
		goto end;
	}
	if ((pkcs8_config.pbe_nid == -1) && !pkcs8_config.cipher)
		pkcs8_config.pbe_nid = NID_pbeWithMD5AndDES_CBC;

	if (pkcs8_config.infile) {
		if (!(in = BIO_new_file(pkcs8_config.infile, "rb"))) {
			BIO_printf(bio_err,
			    "Can't open input file '%s'\n",
			    pkcs8_config.infile);
			goto end;
		}
	} else
		in = BIO_new_fp(stdin, BIO_NOCLOSE);

	if (pkcs8_config.outfile) {
		if (!(out = BIO_new_file(pkcs8_config.outfile, "wb"))) {
			BIO_printf(bio_err, "Can't open output file '%s'\n",
			    pkcs8_config.outfile);
			goto end;
		}
	} else {
		out = BIO_new_fp(stdout, BIO_NOCLOSE);
	}
	if (pkcs8_config.topk8) {
		pkey = load_key(bio_err, pkcs8_config.infile,
		    pkcs8_config.informat, 1, passin, "key");
		if (!pkey)
			goto end;
		if (!(p8inf = EVP_PKEY2PKCS8_broken(pkey,
		    pkcs8_config.p8_broken))) {
			BIO_printf(bio_err, "Error converting key\n");
			ERR_print_errors(bio_err);
			goto end;
		}
		if (pkcs8_config.nocrypt) {
			if (pkcs8_config.outformat == FORMAT_PEM)
				PEM_write_bio_PKCS8_PRIV_KEY_INFO(out, p8inf);
			else if (pkcs8_config.outformat == FORMAT_ASN1)
				i2d_PKCS8_PRIV_KEY_INFO_bio(out, p8inf);
			else {
				BIO_printf(bio_err,
				    "Bad format specified for key\n");
				goto end;
			}
		} else {
			if (passout)
				p8pass = passout;
			else {
				p8pass = pass;
				if (EVP_read_pw_string(pass, sizeof pass,
				    "Enter Encryption Password:", 1))
					goto end;
			}
			if (!(p8 = PKCS8_encrypt(pkcs8_config.pbe_nid,
			    pkcs8_config.cipher, p8pass, strlen(p8pass),
			    NULL, 0, pkcs8_config.iter, p8inf))) {
				BIO_printf(bio_err, "Error encrypting key\n");
				ERR_print_errors(bio_err);
				goto end;
			}
			if (pkcs8_config.outformat == FORMAT_PEM)
				PEM_write_bio_PKCS8(out, p8);
			else if (pkcs8_config.outformat == FORMAT_ASN1)
				i2d_PKCS8_bio(out, p8);
			else {
				BIO_printf(bio_err,
				    "Bad format specified for key\n");
				goto end;
			}
		}

		ret = 0;
		goto end;
	}
	if (pkcs8_config.nocrypt) {
		if (pkcs8_config.informat == FORMAT_PEM)
			p8inf = PEM_read_bio_PKCS8_PRIV_KEY_INFO(in, NULL,
			    NULL, NULL);
		else if (pkcs8_config.informat == FORMAT_ASN1)
			p8inf = d2i_PKCS8_PRIV_KEY_INFO_bio(in, NULL);
		else {
			BIO_printf(bio_err, "Bad format specified for key\n");
			goto end;
		}
	} else {
		if (pkcs8_config.informat == FORMAT_PEM)
			p8 = PEM_read_bio_PKCS8(in, NULL, NULL, NULL);
		else if (pkcs8_config.informat == FORMAT_ASN1)
			p8 = d2i_PKCS8_bio(in, NULL);
		else {
			BIO_printf(bio_err, "Bad format specified for key\n");
			goto end;
		}

		if (!p8) {
			BIO_printf(bio_err, "Error reading key\n");
			ERR_print_errors(bio_err);
			goto end;
		}
		if (passin)
			p8pass = passin;
		else {
			p8pass = pass;
			EVP_read_pw_string(pass, sizeof pass,
			    "Enter Password:", 0);
		}
		p8inf = PKCS8_decrypt(p8, p8pass, strlen(p8pass));
	}

	if (!p8inf) {
		BIO_printf(bio_err, "Error decrypting key\n");
		ERR_print_errors(bio_err);
		goto end;
	}
	if (!(pkey = EVP_PKCS82PKEY(p8inf))) {
		BIO_printf(bio_err, "Error converting key\n");
		ERR_print_errors(bio_err);
		goto end;
	}
	if (p8inf->broken) {
		BIO_printf(bio_err, "Warning: broken key encoding: ");
		switch (p8inf->broken) {
		case PKCS8_NO_OCTET:
			BIO_printf(bio_err, "No Octet String in PrivateKey\n");
			break;

		case PKCS8_EMBEDDED_PARAM:
			BIO_printf(bio_err,
			    "DSA parameters included in PrivateKey\n");
			break;

		case PKCS8_NS_DB:
			BIO_printf(bio_err,
			    "DSA public key include in PrivateKey\n");
			break;

		case PKCS8_NEG_PRIVKEY:
			BIO_printf(bio_err, "DSA private key value is negative\n");
			break;

		default:
			BIO_printf(bio_err, "Unknown broken type\n");
			break;
		}
	}
	if (pkcs8_config.outformat == FORMAT_PEM)
		PEM_write_bio_PrivateKey(out, pkey, NULL, NULL, 0, NULL,
		    passout);
	else if (pkcs8_config.outformat == FORMAT_ASN1)
		i2d_PrivateKey_bio(out, pkey);
	else {
		BIO_printf(bio_err, "Bad format specified for key\n");
		goto end;
	}
	ret = 0;

end:
	X509_SIG_free(p8);
	PKCS8_PRIV_KEY_INFO_free(p8inf);
	EVP_PKEY_free(pkey);
	BIO_free_all(out);
	BIO_free(in);
	free(passin);
	free(passout);

	return ret;
}
