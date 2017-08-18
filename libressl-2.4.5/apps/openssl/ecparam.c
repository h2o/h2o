/* $OpenBSD: ecparam.c,v 1.14 2015/10/10 22:28:51 doug Exp $ */
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
/* ====================================================================
 * Copyright 2002 Sun Microsystems, Inc. ALL RIGHTS RESERVED.
 *
 * Portions of the attached software ("Contribution") are developed by
 * SUN MICROSYSTEMS, INC., and are contributed to the OpenSSL project.
 *
 * The Contribution is licensed pursuant to the OpenSSL open source
 * license provided above.
 *
 * The elliptic curve binary polynomial software is originally written by
 * Sheueling Chang Shantz and Douglas Stebila of Sun Microsystems Laboratories.
 *
 */

#include <openssl/opensslconf.h>

#ifndef OPENSSL_NO_EC

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "apps.h"

#include <openssl/bio.h>
#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/x509.h>

static int ecparam_print_var(BIO *, BIGNUM *, const char *, int,
    unsigned char *);

static struct {
	int C;
	int asn1_flag;
	int check;
	char *curve_name;
	point_conversion_form_t form;
	int genkey;
	char *infile;
	int informat;
	int list_curves;
	int new_asn1_flag;
	int new_form;
	int no_seed;
	int noout;
	char *outfile;
	int outformat;
	int text;
} ecparam_config;

static int
ecparam_opt_form(char *arg)
{
	if (strcmp(arg, "compressed") == 0)
		ecparam_config.form = POINT_CONVERSION_COMPRESSED;
	else if (strcmp(arg, "uncompressed") == 0)
		ecparam_config.form = POINT_CONVERSION_UNCOMPRESSED;
	else if (strcmp(arg, "hybrid") == 0)
		ecparam_config.form = POINT_CONVERSION_HYBRID;
	else
		return (1);

	ecparam_config.new_form = 1;
	return (0);
}

static int
ecparam_opt_enctype(char *arg)
{
	if (strcmp(arg, "explicit") == 0)
		ecparam_config.asn1_flag = 0;
	else if (strcmp(arg, "named_curve") == 0)
		ecparam_config.asn1_flag = OPENSSL_EC_NAMED_CURVE;
	else
		return (1);

	ecparam_config.new_asn1_flag = 1;
	return (0);
}

struct option ecparam_options[] = {
	{
		.name = "C",
		.desc = "Convert the EC parameters into C code",
		.type = OPTION_FLAG,
		.opt.flag = &ecparam_config.C,
	},
	{
		.name = "check",
		.desc = "Validate the elliptic curve parameters",
		.type = OPTION_FLAG,
		.opt.flag = &ecparam_config.check,
	},
	{
		.name = "conv_form",
		.argname = "form",
		.desc = "Specify point conversion form:\n"
		    "  compressed, uncompressed (default), hybrid",
		.type = OPTION_ARG_FUNC,
		.opt.argfunc = ecparam_opt_form,
	},
	{
		.name = "genkey",
		.desc = "Generate an EC private key using the specified "
		    "parameters",
		.type = OPTION_FLAG,
		.opt.flag = &ecparam_config.genkey,
	},
	{
		.name = "in",
		.argname = "file",
		.desc = "Input file to read parameters from (default stdin)",
		.type = OPTION_ARG,
		.opt.arg = &ecparam_config.infile,
	},
	{
		.name = "inform",
		.argname = "format",
		.desc = "Input format (DER or PEM)",
		.type = OPTION_ARG_FORMAT,
		.opt.value = &ecparam_config.informat,
	},
	{
		.name = "list_curves",
		.desc = "Print list of all currently implemented EC "
		    "parameter names",
		.type = OPTION_FLAG,
		.opt.flag = &ecparam_config.list_curves,
	},
	{
		.name = "name",
		.argname = "curve",
		.desc = "Use the EC parameters with the specified name",
		.type = OPTION_ARG,
		.opt.arg = &ecparam_config.curve_name,
	},
	{
		.name = "no_seed",
		.desc = "Do not output seed with explicit parameter encoding",
		.type = OPTION_FLAG,
		.opt.flag = &ecparam_config.no_seed,
	},
	{
		.name = "noout",
		.desc = "Do not output encoded version of EC parameters",
		.type = OPTION_FLAG,
		.opt.flag = &ecparam_config.noout,
	},
	{
		.name = "out",
		.argname = "file",
		.desc = "Output file to write parameters to (default stdout)",
		.type = OPTION_ARG,
		.opt.arg = &ecparam_config.outfile,
	},
	{
		.name = "outform",
		.argname = "format",
		.desc = "Output format (DER or PEM)",
		.type = OPTION_ARG_FORMAT,
		.opt.value = &ecparam_config.outformat,
	},
	{
		.name = "param_enc",
		.argname = "type",
		.desc = "Specify EC parameter ASN.1 encoding type:\n"
		    "  explicit, named_curve (default)",
		.type = OPTION_ARG_FUNC,
		.opt.argfunc = ecparam_opt_enctype,
	},
	{
		.name = "text",
		.desc = "Print out the EC parameters in human readable form",
		.type = OPTION_FLAG,
		.opt.flag = &ecparam_config.text,
	},
	{NULL},
};

static void
ecparam_usage(void)
{
	fprintf(stderr, "usage: ecparam [-C] [-check] [-conv_form arg] "
	    " [-genkey]\n"
	    "    [-in file] [-inform DER | PEM] [-list_curves] [-name arg]\n"
	    "    [-no_seed] [-noout] [-out file] [-outform DER | PEM]\n"
	    "    [-param_enc arg] [-text]\n\n");
	options_usage(ecparam_options);
}

int
ecparam_main(int argc, char **argv)
{
	BIGNUM *ec_p = NULL, *ec_a = NULL, *ec_b = NULL, *ec_gen = NULL;
	BIGNUM *ec_order = NULL, *ec_cofactor = NULL;
	EC_GROUP *group = NULL;
	unsigned char *buffer = NULL;
	BIO *in = NULL, *out = NULL;
	int i, ret = 1;

	if (single_execution) {
		if (pledge("stdio rpath wpath cpath", NULL) == -1) {
			perror("pledge");
			exit(1);
		}
	}

	memset(&ecparam_config, 0, sizeof(ecparam_config));
	ecparam_config.asn1_flag = OPENSSL_EC_NAMED_CURVE;
	ecparam_config.form = POINT_CONVERSION_UNCOMPRESSED;
	ecparam_config.informat = FORMAT_PEM;
	ecparam_config.outformat = FORMAT_PEM;

	if (options_parse(argc, argv, ecparam_options, NULL, NULL) != 0) {
		ecparam_usage();
		goto end;
	}

	in = BIO_new(BIO_s_file());
	out = BIO_new(BIO_s_file());
	if ((in == NULL) || (out == NULL)) {
		ERR_print_errors(bio_err);
		goto end;
	}
	if (ecparam_config.infile == NULL)
		BIO_set_fp(in, stdin, BIO_NOCLOSE);
	else {
		if (BIO_read_filename(in, ecparam_config.infile) <= 0) {
			perror(ecparam_config.infile);
			goto end;
		}
	}
	if (ecparam_config.outfile == NULL) {
		BIO_set_fp(out, stdout, BIO_NOCLOSE);
	} else {
		if (BIO_write_filename(out, ecparam_config.outfile) <= 0) {
			perror(ecparam_config.outfile);
			goto end;
		}
	}

	if (ecparam_config.list_curves) {
		EC_builtin_curve *curves = NULL;
		size_t crv_len = 0;
		size_t n = 0;

		crv_len = EC_get_builtin_curves(NULL, 0);

		curves = reallocarray(NULL, crv_len, sizeof(EC_builtin_curve));
		if (curves == NULL)
			goto end;

		if (!EC_get_builtin_curves(curves, crv_len)) {
			free(curves);
			goto end;
		}
		for (n = 0; n < crv_len; n++) {
			const char *comment;
			const char *sname;
			comment = curves[n].comment;
			sname = OBJ_nid2sn(curves[n].nid);
			if (comment == NULL)
				comment = "CURVE DESCRIPTION NOT AVAILABLE";
			if (sname == NULL)
				sname = "";

			BIO_printf(out, "  %-10s: ", sname);
			BIO_printf(out, "%s\n", comment);
		}

		free(curves);
		ret = 0;
		goto end;
	}
	if (ecparam_config.curve_name != NULL) {
		int nid;

		/*
		 * workaround for the SECG curve names secp192r1 and
		 * secp256r1 (which are the same as the curves prime192v1 and
		 * prime256v1 defined in X9.62)
		 */
		if (!strcmp(ecparam_config.curve_name, "secp192r1")) {
			BIO_printf(bio_err, "using curve name prime192v1 "
			    "instead of secp192r1\n");
			nid = NID_X9_62_prime192v1;
		} else if (!strcmp(ecparam_config.curve_name, "secp256r1")) {
			BIO_printf(bio_err, "using curve name prime256v1 "
			    "instead of secp256r1\n");
			nid = NID_X9_62_prime256v1;
		} else
			nid = OBJ_sn2nid(ecparam_config.curve_name);

		if (nid == 0)
			nid = EC_curve_nist2nid(ecparam_config.curve_name);

		if (nid == 0) {
			BIO_printf(bio_err, "unknown curve name (%s)\n",
			    ecparam_config.curve_name);
			goto end;
		}
		group = EC_GROUP_new_by_curve_name(nid);
		if (group == NULL) {
			BIO_printf(bio_err, "unable to create curve (%s)\n",
			    ecparam_config.curve_name);
			goto end;
		}
		EC_GROUP_set_asn1_flag(group, ecparam_config.asn1_flag);
		EC_GROUP_set_point_conversion_form(group, ecparam_config.form);
	} else if (ecparam_config.informat == FORMAT_ASN1) {
		group = d2i_ECPKParameters_bio(in, NULL);
	} else if (ecparam_config.informat == FORMAT_PEM) {
		group = PEM_read_bio_ECPKParameters(in, NULL, NULL, NULL);
	} else {
		BIO_printf(bio_err, "bad input format specified\n");
		goto end;
	}

	if (group == NULL) {
		BIO_printf(bio_err,
		    "unable to load elliptic curve parameters\n");
		ERR_print_errors(bio_err);
		goto end;
	}
	if (ecparam_config.new_form)
		EC_GROUP_set_point_conversion_form(group, ecparam_config.form);

	if (ecparam_config.new_asn1_flag)
		EC_GROUP_set_asn1_flag(group, ecparam_config.asn1_flag);

	if (ecparam_config.no_seed)
		EC_GROUP_set_seed(group, NULL, 0);

	if (ecparam_config.text) {
		if (!ECPKParameters_print(out, group, 0))
			goto end;
	}
	if (ecparam_config.check) {
		BIO_printf(bio_err, "checking elliptic curve parameters: ");
		if (!EC_GROUP_check(group, NULL)) {
			BIO_printf(bio_err, "failed\n");
			ERR_print_errors(bio_err);
		} else
			BIO_printf(bio_err, "ok\n");

	}
	if (ecparam_config.C) {
		size_t buf_len = 0, tmp_len = 0;
		const EC_POINT *point;
		int is_prime, len = 0;
		const EC_METHOD *meth = EC_GROUP_method_of(group);

		if ((ec_p = BN_new()) == NULL || (ec_a = BN_new()) == NULL ||
		    (ec_b = BN_new()) == NULL || (ec_gen = BN_new()) == NULL ||
		    (ec_order = BN_new()) == NULL ||
		    (ec_cofactor = BN_new()) == NULL) {
			perror("malloc");
			goto end;
		}
		is_prime = (EC_METHOD_get_field_type(meth) ==
		    NID_X9_62_prime_field);

		if (is_prime) {
			if (!EC_GROUP_get_curve_GFp(group, ec_p, ec_a,
			    ec_b, NULL))
				goto end;
		} else {
			if (!EC_GROUP_get_curve_GF2m(group, ec_p, ec_a,
			    ec_b, NULL))
				goto end;
		}

		if ((point = EC_GROUP_get0_generator(group)) == NULL)
			goto end;
		if (!EC_POINT_point2bn(group, point,
			EC_GROUP_get_point_conversion_form(group), ec_gen,
			NULL))
			goto end;
		if (!EC_GROUP_get_order(group, ec_order, NULL))
			goto end;
		if (!EC_GROUP_get_cofactor(group, ec_cofactor, NULL))
			goto end;

		len = BN_num_bits(ec_order);

		if ((tmp_len = (size_t) BN_num_bytes(ec_p)) > buf_len)
			buf_len = tmp_len;
		if ((tmp_len = (size_t) BN_num_bytes(ec_a)) > buf_len)
			buf_len = tmp_len;
		if ((tmp_len = (size_t) BN_num_bytes(ec_b)) > buf_len)
			buf_len = tmp_len;
		if ((tmp_len = (size_t) BN_num_bytes(ec_gen)) > buf_len)
			buf_len = tmp_len;
		if ((tmp_len = (size_t) BN_num_bytes(ec_order)) > buf_len)
			buf_len = tmp_len;
		if ((tmp_len = (size_t) BN_num_bytes(ec_cofactor)) > buf_len)
			buf_len = tmp_len;

		buffer = malloc(buf_len);

		if (buffer == NULL) {
			perror("malloc");
			goto end;
		}
		ecparam_print_var(out, ec_p, "ec_p", len, buffer);
		ecparam_print_var(out, ec_a, "ec_a", len, buffer);
		ecparam_print_var(out, ec_b, "ec_b", len, buffer);
		ecparam_print_var(out, ec_gen, "ec_gen", len, buffer);
		ecparam_print_var(out, ec_order, "ec_order", len, buffer);
		ecparam_print_var(out, ec_cofactor, "ec_cofactor", len,
		    buffer);

		BIO_printf(out, "\n\n");

		BIO_printf(out, "EC_GROUP *get_ec_group_%d(void)\n\t{\n", len);
		BIO_printf(out, "\tint ok=0;\n");
		BIO_printf(out, "\tEC_GROUP *group = NULL;\n");
		BIO_printf(out, "\tEC_POINT *point = NULL;\n");
		BIO_printf(out, "\tBIGNUM   *tmp_1 = NULL, *tmp_2 = NULL, "
		    "*tmp_3 = NULL;\n\n");
		BIO_printf(out, "\tif ((tmp_1 = BN_bin2bn(ec_p_%d, "
		    "sizeof(ec_p_%d), NULL)) == NULL)\n\t\t"
		    "goto err;\n", len, len);
		BIO_printf(out, "\tif ((tmp_2 = BN_bin2bn(ec_a_%d, "
		    "sizeof(ec_a_%d), NULL)) == NULL)\n\t\t"
		    "goto err;\n", len, len);
		BIO_printf(out, "\tif ((tmp_3 = BN_bin2bn(ec_b_%d, "
		    "sizeof(ec_b_%d), NULL)) == NULL)\n\t\t"
		    "goto err;\n", len, len);
		if (is_prime) {
			BIO_printf(out, "\tif ((group = EC_GROUP_new_curve_"
			    "GFp(tmp_1, tmp_2, tmp_3, NULL)) == NULL)"
			    "\n\t\tgoto err;\n\n");
		} else {
			BIO_printf(out, "\tif ((group = EC_GROUP_new_curve_"
			    "GF2m(tmp_1, tmp_2, tmp_3, NULL)) == NULL)"
			    "\n\t\tgoto err;\n\n");
		}
		BIO_printf(out, "\t/* build generator */\n");
		BIO_printf(out, "\tif ((tmp_1 = BN_bin2bn(ec_gen_%d, "
		    "sizeof(ec_gen_%d), tmp_1)) == NULL)"
		    "\n\t\tgoto err;\n", len, len);
		BIO_printf(out, "\tpoint = EC_POINT_bn2point(group, tmp_1, "
		    "NULL, NULL);\n");
		BIO_printf(out, "\tif (point == NULL)\n\t\tgoto err;\n");
		BIO_printf(out, "\tif ((tmp_2 = BN_bin2bn(ec_order_%d, "
		    "sizeof(ec_order_%d), tmp_2)) == NULL)"
		    "\n\t\tgoto err;\n", len, len);
		BIO_printf(out, "\tif ((tmp_3 = BN_bin2bn(ec_cofactor_%d, "
		    "sizeof(ec_cofactor_%d), tmp_3)) == NULL)"
		    "\n\t\tgoto err;\n", len, len);
		BIO_printf(out, "\tif (!EC_GROUP_set_generator(group, point,"
		    " tmp_2, tmp_3))\n\t\tgoto err;\n");
		BIO_printf(out, "\n\tok=1;\n");
		BIO_printf(out, "err:\n");
		BIO_printf(out, "\tif (tmp_1)\n\t\tBN_free(tmp_1);\n");
		BIO_printf(out, "\tif (tmp_2)\n\t\tBN_free(tmp_2);\n");
		BIO_printf(out, "\tif (tmp_3)\n\t\tBN_free(tmp_3);\n");
		BIO_printf(out, "\tif (point)\n\t\tEC_POINT_free(point);\n");
		BIO_printf(out, "\tif (!ok)\n");
		BIO_printf(out, "\t\t{\n");
		BIO_printf(out, "\t\tEC_GROUP_free(group);\n");
		BIO_printf(out, "\t\tgroup = NULL;\n");
		BIO_printf(out, "\t\t}\n");
		BIO_printf(out, "\treturn(group);\n\t}\n");
	}
	if (!ecparam_config.noout) {
		if (ecparam_config.outformat == FORMAT_ASN1)
			i = i2d_ECPKParameters_bio(out, group);
		else if (ecparam_config.outformat == FORMAT_PEM)
			i = PEM_write_bio_ECPKParameters(out, group);
		else {
			BIO_printf(bio_err, "bad output format specified for"
			    " outfile\n");
			goto end;
		}
		if (!i) {
			BIO_printf(bio_err, "unable to write elliptic "
			    "curve parameters\n");
			ERR_print_errors(bio_err);
			goto end;
		}
	}
	if (ecparam_config.genkey) {
		EC_KEY *eckey = EC_KEY_new();

		if (eckey == NULL)
			goto end;

		if (EC_KEY_set_group(eckey, group) == 0) {
			EC_KEY_free(eckey);
			goto end;
		}

		if (!EC_KEY_generate_key(eckey)) {
			EC_KEY_free(eckey);
			goto end;
		}
		if (ecparam_config.outformat == FORMAT_ASN1)
			i = i2d_ECPrivateKey_bio(out, eckey);
		else if (ecparam_config.outformat == FORMAT_PEM)
			i = PEM_write_bio_ECPrivateKey(out, eckey, NULL,
			    NULL, 0, NULL, NULL);
		else {
			BIO_printf(bio_err, "bad output format specified "
			    "for outfile\n");
			EC_KEY_free(eckey);
			goto end;
		}
		EC_KEY_free(eckey);
	}
	ret = 0;

end:
	BN_free(ec_p);
	BN_free(ec_a);
	BN_free(ec_b);
	BN_free(ec_gen);
	BN_free(ec_order);
	BN_free(ec_cofactor);

	free(buffer);

	BIO_free(in);
	BIO_free_all(out);
	EC_GROUP_free(group);

	return (ret);
}

static int
ecparam_print_var(BIO * out, BIGNUM * in, const char *var,
    int len, unsigned char *buffer)
{
	BIO_printf(out, "static unsigned char %s_%d[] = {", var, len);
	if (BN_is_zero(in))
		BIO_printf(out, "\n\t0x00");
	else {
		int i, l;

		l = BN_bn2bin(in, buffer);
		for (i = 0; i < l - 1; i++) {
			if ((i % 12) == 0)
				BIO_printf(out, "\n\t");
			BIO_printf(out, "0x%02X,", buffer[i]);
		}
		if ((i % 12) == 0)
			BIO_printf(out, "\n\t");
		BIO_printf(out, "0x%02X", buffer[i]);
	}
	BIO_printf(out, "\n\t};\n\n");
	return 1;
}
#endif
