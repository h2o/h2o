/* $OpenBSD: dhparam.c,v 1.7 2015/10/10 22:28:51 doug Exp $ */
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
/* ====================================================================
 * Copyright (c) 1998-2000 The OpenSSL Project.  All rights reserved.
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

#include <openssl/opensslconf.h>	/* for OPENSSL_NO_DH */

#ifndef OPENSSL_NO_DH

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "apps.h"

#include <openssl/bio.h>
#include <openssl/bn.h>
#include <openssl/err.h>
#include <openssl/dh.h>
#include <openssl/pem.h>
#include <openssl/x509.h>

#include <openssl/dsa.h>

#define DEFBITS	2048

struct {
	int C;
	int check;
	int dsaparam;
	int g;
	char *infile;
	int informat;
	int noout;
	char *outfile;
	int outformat;
	int text;
} dhparam_config;

struct option dhparam_options[] = {
	{
		.name = "2",
		.desc = "Generate DH parameters with a generator value of 2 "
		    "(default)",
		.type = OPTION_VALUE,
		.opt.value = &dhparam_config.g,
		.value = 2,
	},
	{
		.name = "5",
		.desc = "Generate DH parameters with a generator value of 5",
		.type = OPTION_VALUE,
		.opt.value = &dhparam_config.g,
		.value = 5,
	},
	{
		.name = "C",
		.desc = "Convert DH parameters into C code",
		.type = OPTION_FLAG,
		.opt.flag = &dhparam_config.C,
	},
	{
		.name = "check",
		.desc = "Check the DH parameters",
		.type = OPTION_FLAG,
		.opt.flag = &dhparam_config.check,
	},
	{
		.name = "dsaparam",
		.desc = "Read or generate DSA parameters and convert to DH",
		.type = OPTION_FLAG,
		.opt.flag = &dhparam_config.dsaparam,
	},
	{
		.name = "in",
		.argname = "file",
		.desc = "Input file (default stdin)",
		.type = OPTION_ARG,
		.opt.arg = &dhparam_config.infile,
	},
	{
		.name = "inform",
		.argname = "format",
		.desc = "Input format (DER or PEM (default))",
		.type = OPTION_ARG_FORMAT,
		.opt.value = &dhparam_config.informat,
	},
	{
		.name = "noout",
		.desc = "Do not output encoded version of DH parameters",
		.type = OPTION_FLAG,
		.opt.flag = &dhparam_config.noout,
	},
	{
		.name = "out",
		.argname = "file",
		.desc = "Output file (default stdout)",
		.type = OPTION_ARG,
		.opt.arg = &dhparam_config.outfile,
	},
	{
		.name = "outform",
		.argname = "format",
		.desc = "Output format (DER or PEM (default))",
		.type = OPTION_ARG_FORMAT,
		.opt.value = &dhparam_config.outformat,
	},
	{
		.name = "text",
		.desc = "Print DH parameters in plain text",
		.type = OPTION_FLAG,
		.opt.flag = &dhparam_config.text,
	},
	{ NULL },
};

static void
dhparam_usage()
{
	fprintf(stderr,
	    "usage: dhparam [-2 | -5] [-C] [-check] [-dsaparam]\n"
	    "    [-in file] [-inform DER | PEM] [-noout] [-out file]\n"
	    "    [-outform DER | PEM] [-text] [numbits]\n\n");
	options_usage(dhparam_options);
}

static int dh_cb(int p, int n, BN_GENCB * cb);

int
dhparam_main(int argc, char **argv)
{
	BIO *in = NULL, *out = NULL;
	char *num_bits = NULL;
	DH *dh = NULL;
	int num = 0;
	int ret = 1;
	int i;

	if (single_execution) {
		if (pledge("stdio rpath wpath cpath", NULL) == -1) {
			perror("pledge");
			exit(1);
		}
	}

	memset(&dhparam_config, 0, sizeof(dhparam_config));

	dhparam_config.informat = FORMAT_PEM;
	dhparam_config.outformat = FORMAT_PEM;

	if (options_parse(argc, argv, dhparam_options, &num_bits, NULL) != 0) {
		dhparam_usage();
		return (1);
	}

	if (num_bits != NULL) {
		if(sscanf(num_bits, "%d", &num) == 0 || num <= 0) {
			BIO_printf(bio_err, "invalid number of bits: %s\n",
			    num_bits);
			return (1);
		}
	}

	if (dhparam_config.g && !num)
		num = DEFBITS;

	if (dhparam_config.dsaparam) {
		if (dhparam_config.g) {
			BIO_printf(bio_err, "generator may not be chosen for DSA parameters\n");
			goto end;
		}
	} else {
		/* DH parameters */
		if (num && !dhparam_config.g)
			dhparam_config.g = 2;
	}

	if (num) {

		BN_GENCB cb;
		BN_GENCB_set(&cb, dh_cb, bio_err);
		if (dhparam_config.dsaparam) {
			DSA *dsa = DSA_new();

			BIO_printf(bio_err, "Generating DSA parameters, %d bit long prime\n", num);
			if (!dsa || !DSA_generate_parameters_ex(dsa, num,
				NULL, 0, NULL, NULL, &cb)) {
				if (dsa)
					DSA_free(dsa);
				ERR_print_errors(bio_err);
				goto end;
			}
			dh = DSA_dup_DH(dsa);
			DSA_free(dsa);
			if (dh == NULL) {
				ERR_print_errors(bio_err);
				goto end;
			}
		} else {
			dh = DH_new();
			BIO_printf(bio_err, "Generating DH parameters, %d bit long safe prime, generator %d\n", num, dhparam_config.g);
			BIO_printf(bio_err, "This is going to take a long time\n");
			if (!dh || !DH_generate_parameters_ex(dh, num, dhparam_config.g, &cb)) {
				ERR_print_errors(bio_err);
				goto end;
			}
		}
	} else {

		in = BIO_new(BIO_s_file());
		if (in == NULL) {
			ERR_print_errors(bio_err);
			goto end;
		}
		if (dhparam_config.infile == NULL)
			BIO_set_fp(in, stdin, BIO_NOCLOSE);
		else {
			if (BIO_read_filename(in, dhparam_config.infile) <= 0) {
				perror(dhparam_config.infile);
				goto end;
			}
		}

		if (dhparam_config.informat != FORMAT_ASN1 &&
		    dhparam_config.informat != FORMAT_PEM) {
			BIO_printf(bio_err, "bad input format specified\n");
			goto end;
		}
		if (dhparam_config.dsaparam) {
			DSA *dsa;

			if (dhparam_config.informat == FORMAT_ASN1)
				dsa = d2i_DSAparams_bio(in, NULL);
			else	/* informat == FORMAT_PEM */
				dsa = PEM_read_bio_DSAparams(in, NULL, NULL, NULL);

			if (dsa == NULL) {
				BIO_printf(bio_err, "unable to load DSA parameters\n");
				ERR_print_errors(bio_err);
				goto end;
			}
			dh = DSA_dup_DH(dsa);
			DSA_free(dsa);
			if (dh == NULL) {
				ERR_print_errors(bio_err);
				goto end;
			}
		} else
		{
			if (dhparam_config.informat == FORMAT_ASN1)
				dh = d2i_DHparams_bio(in, NULL);
			else	/* informat == FORMAT_PEM */
				dh = PEM_read_bio_DHparams(in, NULL, NULL, NULL);

			if (dh == NULL) {
				BIO_printf(bio_err, "unable to load DH parameters\n");
				ERR_print_errors(bio_err);
				goto end;
			}
		}

		/* dh != NULL */
	}

	out = BIO_new(BIO_s_file());
	if (out == NULL) {
		ERR_print_errors(bio_err);
		goto end;
	}
	if (dhparam_config.outfile == NULL) {
		BIO_set_fp(out, stdout, BIO_NOCLOSE);
	} else {
		if (BIO_write_filename(out, dhparam_config.outfile) <= 0) {
			perror(dhparam_config.outfile);
			goto end;
		}
	}


	if (dhparam_config.text) {
		DHparams_print(out, dh);
	}
	if (dhparam_config.check) {
		if (!DH_check(dh, &i)) {
			ERR_print_errors(bio_err);
			goto end;
		}
		if (i & DH_CHECK_P_NOT_PRIME)
			printf("p value is not prime\n");
		if (i & DH_CHECK_P_NOT_SAFE_PRIME)
			printf("p value is not a safe prime\n");
		if (i & DH_UNABLE_TO_CHECK_GENERATOR)
			printf("unable to check the generator value\n");
		if (i & DH_NOT_SUITABLE_GENERATOR)
			printf("the g value is not a generator\n");
		if (i == 0)
			printf("DH parameters appear to be ok.\n");
	}
	if (dhparam_config.C) {
		unsigned char *data;
		int len, l, bits;

		len = BN_num_bytes(dh->p);
		bits = BN_num_bits(dh->p);
		data = malloc(len);
		if (data == NULL) {
			perror("malloc");
			goto end;
		}
		printf("#ifndef HEADER_DH_H\n"
		    "#include <openssl/dh.h>\n"
		    "#endif\n");
		printf("DH *get_dh%d()\n\t{\n", bits);

		l = BN_bn2bin(dh->p, data);
		printf("\tstatic unsigned char dh%d_p[] = {", bits);
		for (i = 0; i < l; i++) {
			if ((i % 12) == 0)
				printf("\n\t\t");
			printf("0x%02X, ", data[i]);
		}
		printf("\n\t\t};\n");

		l = BN_bn2bin(dh->g, data);
		printf("\tstatic unsigned char dh%d_g[] = {", bits);
		for (i = 0; i < l; i++) {
			if ((i % 12) == 0)
				printf("\n\t\t");
			printf("0x%02X, ", data[i]);
		}
		printf("\n\t\t};\n");

		printf("\tDH *dh;\n\n");
		printf("\tif ((dh = DH_new()) == NULL) return(NULL);\n");
		printf("\tdh->p = BN_bin2bn(dh%d_p, sizeof(dh%d_p), NULL);\n",
		    bits, bits);
		printf("\tdh->g = BN_bin2bn(dh%d_g, sizeof(dh%d_g), NULL);\n",
		    bits, bits);
		printf("\tif ((dh->p == NULL) || (dh->g == NULL))\n");
		printf("\t\t{ DH_free(dh); return(NULL); }\n");
		if (dh->length)
			printf("\tdh->length = %ld;\n", dh->length);
		printf("\treturn(dh);\n\t}\n");
		free(data);
	}
	if (!dhparam_config.noout) {
		if (dhparam_config.outformat == FORMAT_ASN1)
			i = i2d_DHparams_bio(out, dh);
		else if (dhparam_config.outformat == FORMAT_PEM)
			i = PEM_write_bio_DHparams(out, dh);
		else {
			BIO_printf(bio_err, "bad output format specified for outfile\n");
			goto end;
		}
		if (!i) {
			BIO_printf(bio_err, "unable to write DH parameters\n");
			ERR_print_errors(bio_err);
			goto end;
		}
	}
	ret = 0;

end:
	BIO_free(in);
	if (out != NULL)
		BIO_free_all(out);
	if (dh != NULL)
		DH_free(dh);

	return (ret);
}

/* dh_cb is identical to dsa_cb in apps/dsaparam.c */
static int
dh_cb(int p, int n, BN_GENCB * cb)
{
	char c = '*';

	if (p == 0)
		c = '.';
	if (p == 1)
		c = '+';
	if (p == 2)
		c = '*';
	if (p == 3)
		c = '\n';
	BIO_write(cb->arg, &c, 1);
	(void) BIO_flush(cb->arg);
	return 1;
}

#endif
