/* $OpenBSD: asn1pars.c,v 1.5 2015/10/10 22:28:51 doug Exp $ */
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

/* A nice addition from Dr Stephen Henson <steve@openssl.org> to
 * add the -strparse option which parses nested binary structures
 */

#include <stdio.h>
#include <stdlib.h>
#include <limits.h>
#include <string.h>

#include "apps.h"
#include "progs.h"

#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/x509.h>

static struct {
	char *derfile;
	int dump;
	char *genconf;
	char *genstr;
	int indent;
	char *infile;
	int informat;
	unsigned int length;
	int noout;
	int offset;
	char *oidfile;
	STACK_OF(OPENSSL_STRING) *osk;
} asn1pars_config;

static int
asn1pars_opt_dlimit(char *arg)
{
	const char *errstr;

	asn1pars_config.dump = strtonum(arg, 1, INT_MAX, &errstr);
	if (errstr) {
		fprintf(stderr, "-dlimit must be from 1 to INT_MAX: %s\n",
		    errstr);
		return (-1);
	}
	return (0);
}

static int
asn1pars_opt_length(char *arg)
{
	const char *errstr;

	asn1pars_config.length = strtonum(arg, 1, UINT_MAX, &errstr);
	if (errstr) {
		fprintf(stderr, "-length must be from 1 to UINT_MAX: %s\n",
		    errstr);
		return (-1);
	}
	return (0);
}

static int
asn1pars_opt_strparse(char *arg)
{
	if (sk_OPENSSL_STRING_push(asn1pars_config.osk, arg) == 0) {
		fprintf(stderr, "-strparse cannot add argument\n");
		return (-1);
	}
	return (0);
}

static struct option asn1pars_options[] = {
	{
		.name = "dump",
		.desc = "Dump unknown data in hex form",
		.type = OPTION_VALUE,
		.value = -1,
		.opt.value = &asn1pars_config.dump,
	},
	{
		.name = "dlimit",
		.argname = "num",
		.desc = "Dump the first num bytes of unknown data in hex form",
		.type = OPTION_ARG_FUNC,
		.opt.argfunc = asn1pars_opt_dlimit,
	},
	{
		.name = "genconf",
		.argname = "file",
		.desc = "File to generate ASN.1 structure from",
		.type = OPTION_ARG,
		.opt.arg = &asn1pars_config.genconf,
	},
	{
		.name = "genstr",
		.argname = "string",
		.desc = "String to generate ASN.1 structure from",
		.type = OPTION_ARG,
		.opt.arg = &asn1pars_config.genstr,
	},
	{
		.name = "i",
		.desc = "Indent output according to depth of structures",
		.type = OPTION_FLAG,
		.opt.flag = &asn1pars_config.indent,
	},
	{
		.name = "in",
		.argname = "file",
		.desc = "The input file (default stdin)",
		.type = OPTION_ARG,
		.opt.arg = &asn1pars_config.infile,
	},
	{
		.name = "inform",
		.argname = "fmt",
		.desc = "Input format (DER, TXT or PEM (default))",
		.type = OPTION_ARG_FORMAT,
		.opt.value = &asn1pars_config.informat,
	},
	{
		.name = "length",
		.argname = "num",
		.desc = "Number of bytes to parse (default until EOF)",
		.type = OPTION_ARG_FUNC,
		.opt.argfunc = asn1pars_opt_length,
	},
	{
		.name = "noout",
		.desc = "Do not produce any output",
		.type = OPTION_FLAG,
		.opt.flag = &asn1pars_config.noout,
	},
	{
		.name = "offset",
		.argname = "num",
		.desc = "Offset to begin parsing",
		.type = OPTION_ARG_INT,
		.opt.value = &asn1pars_config.offset,
	},
	{
		.name = "oid",
		.argname = "file",
		.desc = "File containing additional object identifiers (OIDs)",
		.type = OPTION_ARG,
		.opt.arg = &asn1pars_config.oidfile,
	},
	{
		.name = "out",
		.argname = "file",
		.desc = "Output file in DER format",
		.type = OPTION_ARG,
		.opt.arg = &asn1pars_config.derfile,
	},
	{
		.name = "strparse",
		.argname = "offset",
		.desc = "Parse the content octets of ASN.1 object starting at"
		" offset",
		.type = OPTION_ARG_FUNC,
		.opt.argfunc = asn1pars_opt_strparse,
	},
	{ NULL },
};

static void
asn1pars_usage()
{
	fprintf(stderr,
	    "usage: asn1parse [-i] [-dlimit num] [-dump] [-genconf file] "
	    "[-genstr string]\n"
	    "    [-in file] [-inform fmt] [-length num] [-noout] [-offset num] "
	    "[-oid file]\n"
	    "    [-out file] [-strparse offset]\n\n");
	options_usage(asn1pars_options);
}

static int do_generate(BIO *bio, char *genstr, char *genconf, BUF_MEM *buf);

int
asn1parse_main(int argc, char **argv)
{
	int i, j, ret = 1;
	long num, tmplen;
	BIO *in = NULL, *out = NULL, *b64 = NULL, *derout = NULL;
	char *str = NULL;
	const char *errstr = NULL;
	unsigned char *tmpbuf;
	const unsigned char *ctmpbuf;
	BUF_MEM *buf = NULL;
	ASN1_TYPE *at = NULL;

	if (single_execution) {
		if (pledge("stdio rpath wpath cpath", NULL) == -1) {
			perror("pledge");
			exit(1);
		}
	}

	memset(&asn1pars_config, 0, sizeof(asn1pars_config));

	asn1pars_config.informat = FORMAT_PEM;
	if ((asn1pars_config.osk = sk_OPENSSL_STRING_new_null()) == NULL) {
		BIO_printf(bio_err, "Memory allocation failure\n");
		goto end;
	}

	if (options_parse(argc, argv, asn1pars_options, NULL, NULL) != 0) {
		asn1pars_usage();
		return (1);
	}

	in = BIO_new(BIO_s_file());
	out = BIO_new(BIO_s_file());
	if ((in == NULL) || (out == NULL)) {
		ERR_print_errors(bio_err);
		goto end;
	}
	BIO_set_fp(out, stdout, BIO_NOCLOSE | BIO_FP_TEXT);

	if (asn1pars_config.oidfile != NULL) {
		if (BIO_read_filename(in, asn1pars_config.oidfile) <= 0) {
			BIO_printf(bio_err, "problems opening %s\n",
			    asn1pars_config.oidfile);
			ERR_print_errors(bio_err);
			goto end;
		}
		OBJ_create_objects(in);
	}
	if (asn1pars_config.infile == NULL)
		BIO_set_fp(in, stdin, BIO_NOCLOSE);
	else {
		if (BIO_read_filename(in, asn1pars_config.infile) <= 0) {
			perror(asn1pars_config.infile);
			goto end;
		}
	}

	if (asn1pars_config.derfile) {
		if (!(derout = BIO_new_file(asn1pars_config.derfile, "wb"))) {
			BIO_printf(bio_err, "problems opening %s\n",
			    asn1pars_config.derfile);
			ERR_print_errors(bio_err);
			goto end;
		}
	}
	if ((buf = BUF_MEM_new()) == NULL)
		goto end;
	if (!BUF_MEM_grow(buf, BUFSIZ * 8))
		goto end;	/* Pre-allocate :-) */

	if (asn1pars_config.genstr || asn1pars_config.genconf) {
		num = do_generate(bio_err, asn1pars_config.genstr,
		    asn1pars_config.genconf, buf);
		if (num < 0) {
			ERR_print_errors(bio_err);
			goto end;
		}
	} else {

		if (asn1pars_config.informat == FORMAT_PEM) {
			BIO *tmp;

			if ((b64 = BIO_new(BIO_f_base64())) == NULL)
				goto end;
			BIO_push(b64, in);
			tmp = in;
			in = b64;
			b64 = tmp;
		}
		num = 0;
		for (;;) {
			if (!BUF_MEM_grow(buf, (int) num + BUFSIZ))
				goto end;
			i = BIO_read(in, &(buf->data[num]), BUFSIZ);
			if (i <= 0)
				break;
			num += i;
		}
	}
	str = buf->data;

	/* If any structs to parse go through in sequence */

	if (sk_OPENSSL_STRING_num(asn1pars_config.osk)) {
		tmpbuf = (unsigned char *) str;
		tmplen = num;
		for (i = 0; i < sk_OPENSSL_STRING_num(asn1pars_config.osk);
		     i++) {
			ASN1_TYPE *atmp;
			int typ;
			j = strtonum(
			    sk_OPENSSL_STRING_value(asn1pars_config.osk, i),
			    1, INT_MAX, &errstr);
			if (errstr) {
				BIO_printf(bio_err,
				    "'%s' is an invalid number: %s\n",
				    sk_OPENSSL_STRING_value(asn1pars_config.osk,
				    i), errstr);
				continue;
			}
			tmpbuf += j;
			tmplen -= j;
			atmp = at;
			ctmpbuf = tmpbuf;
			at = d2i_ASN1_TYPE(NULL, &ctmpbuf, tmplen);
			ASN1_TYPE_free(atmp);
			if (!at) {
				BIO_printf(bio_err, "Error parsing structure\n");
				ERR_print_errors(bio_err);
				goto end;
			}
			typ = ASN1_TYPE_get(at);
			if ((typ == V_ASN1_OBJECT) ||
			    (typ == V_ASN1_NULL)) {
				BIO_printf(bio_err, "Can't parse %s type\n",
				    typ == V_ASN1_NULL ? "NULL" : "OBJECT");
				ERR_print_errors(bio_err);
				goto end;
			}
			/* hmm... this is a little evil but it works */
			tmpbuf = at->value.asn1_string->data;
			tmplen = at->value.asn1_string->length;
		}
		str = (char *) tmpbuf;
		num = tmplen;
	}
	if (asn1pars_config.offset >= num) {
		BIO_printf(bio_err, "Error: offset too large\n");
		goto end;
	}
	num -= asn1pars_config.offset;

	if ((asn1pars_config.length == 0) ||
	    ((long)asn1pars_config.length > num))
		asn1pars_config.length = (unsigned int) num;
	if (derout) {
		if (BIO_write(derout, str + asn1pars_config.offset,
		    asn1pars_config.length) != (int)asn1pars_config.length) {
			BIO_printf(bio_err, "Error writing output\n");
			ERR_print_errors(bio_err);
			goto end;
		}
	}
	if (!asn1pars_config.noout &&
	    !ASN1_parse_dump(out,
	    (unsigned char *)&(str[asn1pars_config.offset]),
	    asn1pars_config.length, asn1pars_config.indent,
	    asn1pars_config.dump)) {
		ERR_print_errors(bio_err);
		goto end;
	}
	ret = 0;
end:
	BIO_free(derout);
	BIO_free(in);
	BIO_free_all(out);
	BIO_free(b64);
	if (ret != 0)
		ERR_print_errors(bio_err);
	BUF_MEM_free(buf);
	if (at != NULL)
		ASN1_TYPE_free(at);
	sk_OPENSSL_STRING_free(asn1pars_config.osk);
	OBJ_cleanup();

	return (ret);
}

static int
do_generate(BIO * bio, char *genstr, char *genconf, BUF_MEM * buf)
{
	CONF *cnf = NULL;
	int len;
	long errline;
	unsigned char *p;
	ASN1_TYPE *atyp = NULL;

	if (genconf) {
		cnf = NCONF_new(NULL);
		if (!NCONF_load(cnf, genconf, &errline))
			goto conferr;
		if (!genstr)
			genstr = NCONF_get_string(cnf, "default", "asn1");
		if (!genstr) {
			BIO_printf(bio, "Can't find 'asn1' in '%s'\n", genconf);
			goto err;
		}
	}
	atyp = ASN1_generate_nconf(genstr, cnf);
	NCONF_free(cnf);
	cnf = NULL;

	if (!atyp)
		return -1;

	len = i2d_ASN1_TYPE(atyp, NULL);
	if (len <= 0)
		goto err;

	if (!BUF_MEM_grow(buf, len))
		goto err;

	p = (unsigned char *) buf->data;

	i2d_ASN1_TYPE(atyp, &p);

	ASN1_TYPE_free(atyp);
	return len;

conferr:

	if (errline > 0)
		BIO_printf(bio, "Error on line %ld of config file '%s'\n",
		    errline, genconf);
	else
		BIO_printf(bio, "Error loading config file '%s'\n", genconf);

err:
	NCONF_free(cnf);
	ASN1_TYPE_free(atyp);

	return -1;

}
