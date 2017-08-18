/* $OpenBSD: sess_id.c,v 1.6 2015/10/10 22:28:51 doug Exp $ */
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
#include "progs.h"

#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>

static struct {
	int cert;
	char *context;
	char *infile;
	int informat;
	int noout;
	char *outfile;
	int outformat;
	int text;
} sess_id_config;

static struct option sess_id_options[] = {
	{
		.name = "cert",
		.desc = "Output certificate if present in session",
		.type = OPTION_FLAG,
		.opt.flag = &sess_id_config.cert,
	},
	{
		.name = "context",
		.argname = "id",
		.desc = "Set the session ID context for output",
		.type = OPTION_ARG,
		.opt.arg = &sess_id_config.context,
	},
	{
		.name = "in",
		.argname = "file",
		.desc = "Input file (default stdin)",
		.type = OPTION_ARG,
		.opt.arg = &sess_id_config.infile,
	},
	{
		.name = "inform",
		.argname = "format",
		.desc = "Input format (DER or PEM (default))",
		.type = OPTION_ARG_FORMAT,
		.opt.value = &sess_id_config.informat,
	},
	{
		.name = "noout",
		.desc = "Do not output the encoded session info",
		.type = OPTION_FLAG,
		.opt.flag = &sess_id_config.noout,
	},
	{
		.name = "out",
		.argname = "file",
		.desc = "Output file (default stdout)",
		.type = OPTION_ARG,
		.opt.arg = &sess_id_config.outfile,
	},
	{
		.name = "outform",
		.argname = "format",
		.desc = "Output format (DER or PEM (default))",
		.type = OPTION_ARG_FORMAT,
		.opt.value = &sess_id_config.outformat,
	},
	{
		.name = "text",
		.desc = "Print various public or private key components in"
		    " plain text",
		.type = OPTION_FLAG,
		.opt.flag = &sess_id_config.text,
	},
	{ NULL }
};

static void
sess_id_usage(void)
{
	fprintf(stderr,
	    "usage: sess_id [-cert] [-context id] [-in file] [-inform fmt] "
	    "[-noout]\n"
	    "    [-out file] [-outform fmt] [-text]\n\n");
	options_usage(sess_id_options);
}

static SSL_SESSION *load_sess_id(char *file, int format);

int
sess_id_main(int argc, char **argv)
{
	SSL_SESSION *x = NULL;
	X509 *peer = NULL;
	int ret = 1, i;
	BIO *out = NULL;

	if (single_execution) {
		if (pledge("stdio rpath wpath cpath", NULL) == -1) {
			perror("pledge");
			exit(1);
		}
	}

	memset(&sess_id_config, 0, sizeof(sess_id_config));

	sess_id_config.informat = FORMAT_PEM;
	sess_id_config.outformat = FORMAT_PEM;

	if (options_parse(argc, argv, sess_id_options, NULL, NULL) != 0) {
		sess_id_usage();
		return (1);
	}

	x = load_sess_id(sess_id_config.infile, sess_id_config.informat);
	if (x == NULL) {
		goto end;
	}
	peer = SSL_SESSION_get0_peer(x);

	if (sess_id_config.context) {
		size_t ctx_len = strlen(sess_id_config.context);
		if (ctx_len > SSL_MAX_SID_CTX_LENGTH) {
			BIO_printf(bio_err, "Context too long\n");
			goto end;
		}
		SSL_SESSION_set1_id_context(x,
		    (unsigned char *)sess_id_config.context, ctx_len);
	}

	if (!sess_id_config.noout || sess_id_config.text) {
		out = BIO_new(BIO_s_file());
		if (out == NULL) {
			ERR_print_errors(bio_err);
			goto end;
		}
		if (sess_id_config.outfile == NULL) {
			BIO_set_fp(out, stdout, BIO_NOCLOSE);
		} else {
			if (BIO_write_filename(out, sess_id_config.outfile)
			    <= 0) {
				perror(sess_id_config.outfile);
				goto end;
			}
		}
	}
	if (sess_id_config.text) {
		SSL_SESSION_print(out, x);

		if (sess_id_config.cert) {
			if (peer == NULL)
				BIO_puts(out, "No certificate present\n");
			else
				X509_print(out, peer);
		}
	}
	if (!sess_id_config.noout && !sess_id_config.cert) {
		if (sess_id_config.outformat == FORMAT_ASN1)
			i = i2d_SSL_SESSION_bio(out, x);
		else if (sess_id_config.outformat == FORMAT_PEM)
			i = PEM_write_bio_SSL_SESSION(out, x);
		else {
			BIO_printf(bio_err,
			    "bad output format specified for outfile\n");
			goto end;
		}
		if (!i) {
			BIO_printf(bio_err, "unable to write SSL_SESSION\n");
			goto end;
		}
	} else if (!sess_id_config.noout && (peer != NULL)) {
		/* just print the certificate */
		if (sess_id_config.outformat == FORMAT_ASN1)
			i = (int) i2d_X509_bio(out, peer);
		else if (sess_id_config.outformat == FORMAT_PEM)
			i = PEM_write_bio_X509(out, peer);
		else {
			BIO_printf(bio_err,
			    "bad output format specified for outfile\n");
			goto end;
		}
		if (!i) {
			BIO_printf(bio_err, "unable to write X509\n");
			goto end;
		}
	}
	ret = 0;

end:
	BIO_free_all(out);
	SSL_SESSION_free(x);

	return (ret);
}

static SSL_SESSION *
load_sess_id(char *infile, int format)
{
	SSL_SESSION *x = NULL;
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
		x = d2i_SSL_SESSION_bio(in, NULL);
	else if (format == FORMAT_PEM)
		x = PEM_read_bio_SSL_SESSION(in, NULL, NULL, NULL);
	else {
		BIO_printf(bio_err,
		    "bad input format specified for input crl\n");
		goto end;
	}
	if (x == NULL) {
		BIO_printf(bio_err, "unable to load SSL_SESSION\n");
		ERR_print_errors(bio_err);
		goto end;
	}
end:
	BIO_free(in);
	return (x);
}
