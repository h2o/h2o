/* $OpenBSD: version.c,v 1.7 2015/10/10 22:28:51 doug Exp $ */
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
 * Copyright (c) 1998-2001 The OpenSSL Project.  All rights reserved.
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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "apps.h"

#include <openssl/bn.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>

#ifndef OPENSSL_NO_BF
#include <openssl/blowfish.h>
#endif

#ifndef OPENSSL_NO_DES
#include <openssl/des.h>
#endif

#ifndef OPENSSL_NO_IDEA
#include <openssl/idea.h>
#endif

#ifndef OPENSSL_NO_RC4
#include <openssl/rc4.h>
#endif

static struct {
	int cflags;
	int date;
	int dir;
	int options;
	int platform;
	int version;
} version_config;

static int
version_all_opts(void)
{
	version_config.cflags = 1;
	version_config.date = 1;
	version_config.dir= 1;
	version_config.options = 1;
	version_config.platform = 1;
	version_config.version = 1;

	return (0);
}

static struct option version_options[] = {
	{
		.name = "a",
		.desc = "All information (same as setting all other flags)",
		.type = OPTION_FUNC,
		.opt.func = version_all_opts,
	},
	{
		.name = "b",
		.desc = "Date the current version of OpenSSL was built",
		.type = OPTION_FLAG,
		.opt.flag = &version_config.date,
	},
	{
		.name = "d",
		.desc = "OPENSSLDIR value",
		.type = OPTION_FLAG,
		.opt.flag = &version_config.dir,
	},
	{
		.name = "f",
		.desc = "Compilation flags",
		.type = OPTION_FLAG,
		.opt.flag = &version_config.cflags,
	},
	{
		.name = "o",
		.desc = "Option information",
		.type = OPTION_FLAG,
		.opt.flag = &version_config.options,
	},
	{
		.name = "p",
		.desc = "Platform settings",
		.type = OPTION_FLAG,
		.opt.flag = &version_config.platform,
	},
	{
		.name = "v",
		.desc = "Current OpenSSL version",
		.type = OPTION_FLAG,
		.opt.flag = &version_config.version,
	},
	{NULL},
};

static void
version_usage(void)
{
	fprintf(stderr, "usage: version [-abdfopv]\n");
	options_usage(version_options);
}

int
version_main(int argc, char **argv)
{
	if (single_execution) {
		if (pledge("stdio", NULL) == -1) {
			perror("pledge");
			exit(1);
		}
	}

	memset(&version_config, 0, sizeof(version_config));

	if (options_parse(argc, argv, version_options, NULL, NULL) != 0) {
		version_usage();
		return (1);
	}

	if (argc == 1)
		version_config.version = 1;

	if (version_config.version) {
		if (SSLeay() == SSLEAY_VERSION_NUMBER) {
			printf("%s\n", SSLeay_version(SSLEAY_VERSION));
		} else {
			printf("%s (Library: %s)\n",
			    OPENSSL_VERSION_TEXT,
			    SSLeay_version(SSLEAY_VERSION));
		}
	}
	if (version_config.date)
		printf("%s\n", SSLeay_version(SSLEAY_BUILT_ON));
	if (version_config.platform)
		printf("%s\n", SSLeay_version(SSLEAY_PLATFORM));
	if (version_config.options) {
		printf("options:  ");
		printf("%s ", BN_options());
#ifndef OPENSSL_NO_RC4
		printf("%s ", RC4_options());
#endif
#ifndef OPENSSL_NO_DES
		printf("%s ", DES_options());
#endif
#ifndef OPENSSL_NO_IDEA
		printf("%s ", idea_options());
#endif
#ifndef OPENSSL_NO_BF
		printf("%s ", BF_options());
#endif
		printf("\n");
	}
	if (version_config.cflags)
		printf("%s\n", SSLeay_version(SSLEAY_CFLAGS));
	if (version_config.dir)
		printf("%s\n", SSLeay_version(SSLEAY_DIR));

	return (0);
}
