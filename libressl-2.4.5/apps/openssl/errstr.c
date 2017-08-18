/* $OpenBSD: errstr.c,v 1.5 2015/10/10 22:28:51 doug Exp $ */
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

#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "apps.h"

#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/lhash.h>
#include <openssl/ssl.h>

struct {
	int stats;
} errstr_config;

struct option errstr_options[] = {
	{
		.name = "stats",
		.desc = "Print debugging statistics for the hash table",
		.type = OPTION_FLAG,
		.opt.flag = &errstr_config.stats,
	},
	{ NULL },
};

static void
errstr_usage()
{
	fprintf(stderr, "usage: errstr [-stats] errno ...\n");
	options_usage(errstr_options);
}

int
errstr_main(int argc, char **argv)
{
	unsigned long ulval;
	char *ularg, *ep;
	int argsused, i;
	char buf[256];
	int ret = 0;

	if (single_execution) {
		if (pledge("stdio rpath", NULL) == -1) {
			perror("pledge");
			exit(1);
		}
	}

	memset(&errstr_config, 0, sizeof(errstr_config));

	if (options_parse(argc, argv, errstr_options, NULL, &argsused) != 0) {
		errstr_usage();
		return (1);
	}

	if (errstr_config.stats) {
		BIO *out;

		if ((out = BIO_new_fp(stdout, BIO_NOCLOSE)) == NULL) {
			fprintf(stderr, "Out of memory");
			return (1);
		}

		lh_ERR_STRING_DATA_node_stats_bio(ERR_get_string_table(), out);
		lh_ERR_STRING_DATA_stats_bio(ERR_get_string_table(), out);
		lh_ERR_STRING_DATA_node_usage_stats_bio(
			    ERR_get_string_table(), out);

		BIO_free_all(out);
	}

	for (i = argsused; i < argc; i++) {
		errno = 0;
		ularg = argv[i];
		ulval = strtoul(ularg, &ep, 16);
		if (strchr(ularg, '-') != NULL ||
		    (ularg[0] == '\0' || *ep != '\0') ||
		    (errno == ERANGE && ulval == ULONG_MAX)) {
			printf("%s: bad error code\n", ularg);
			ret++;
			continue;
		}

		ERR_error_string_n(ulval, buf, sizeof(buf));
		printf("%s\n", buf);
	}

	return (ret);
}
