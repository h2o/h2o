/*	$OpenBSD: verifytest.c,v 1.4 2015/09/11 12:57:24 beck Exp $	*/
/*
 * Copyright (c) 2014 Joel Sing <jsing@openbsd.org>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#include <err.h>
#include <stdio.h>
#include <stdlib.h>

#include <openssl/x509v3.h>
#include <tls.h>

extern int tls_check_name(struct tls *ctx, X509 *cert, const char *name);

struct verify_test {
	const char common_name[128];
	const char alt_name[128];
	int alt_name_len;
	int alt_name_type;
	const char name[128];
	int want;
};

struct verify_test verify_tests[] = {
	{
		.common_name = "www.openbsd.org",
		.name = "www.openbsd.org",
		.want = 0,
	},
	{
		.common_name = "www.openbsd.org",
		.name = "",
		.want = -1,
	},
	{
		.common_name = "*.openbsd.org",
		.name = "www.openbsd.org",
		.want = 0,
	},
	{
		.common_name = "www.openbsdfoundation.org",
		.name = "www.openbsd.org",
		.want = -1,
	},
	{
		.common_name = "w*.openbsd.org",
		.name = "www.openbsd.org",
		.want = -1,
	},
	{
		.common_name = "www.*.org",
		.name = "www.openbsd.org",
		.want = -1,
	},
	{
		.common_name = "www.openbsd.*",
		.name = "www.openbsd.org",
		.want = -1,
	},
	{
		.common_name = "*",
		.name = "www.openbsd.org",
		.want = -1,
	},
	{
		.common_name = "*.org",
		.name = "www.openbsd.org",
		.want = -1,
	},
	{
		.common_name = "*.org",
		.name = "openbsd.org",
		.want = -1,
	},
	{
		.common_name = "1.2.3.4",
		.name = "1.2.3.4",
		.want = 0,
	},
	{
		.common_name = "*.2.3.4",
		.name = "1.2.3.4",
		.want = -1,
	},
	{
		.common_name = "cafe::beef",
		.name = "cafe::beef",
		.want = 0,
	},
	{
		.common_name = "www.openbsd.org",
		.alt_name = "ftp.openbsd.org",
		.alt_name_len = -1,
		.alt_name_type = GEN_DNS,
		.name = "ftp.openbsd.org",
		.want = 0,
	},
	{
		.common_name = "www.openbsdfoundation.org",
		.alt_name = "*.openbsd.org",
		.alt_name_len = -1,
		.alt_name_type = GEN_DNS,
		.name = "www.openbsd.org",
		.want = 0,
	},
	{
		.common_name = "www.openbsdfoundation.org",
		.alt_name = "*.org",
		.alt_name_len = -1,
		.alt_name_type = GEN_DNS,
		.name = "www.openbsd.org",
		.want = -1,
	},
	{
		.common_name = "www.openbsd.org",
		.alt_name = "1.2.3.4",
		.alt_name_len = -1,
		.alt_name_type = GEN_DNS,
		.name = "1.2.3.4",
		.want = -1,
	},
	{
		.common_name = "www.openbsd.org",
		.alt_name = {0x1, 0x2, 0x3, 0x4},
		.alt_name_len = 4,
		.alt_name_type = GEN_IPADD,
		.name = "1.2.3.4",
		.want = 0,
	},
	{
		.common_name = "www.openbsd.org",
		.alt_name = {
			0xca, 0xfe, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xbe, 0xef,
		},
		.alt_name_len = 16,
		.alt_name_type = GEN_IPADD,
		.name = "cafe::beef",
		.want = 0,
	},
	{
		.common_name = "*.openbsd.org",
		.name = ".openbsd.org",
		.want = -1,
	},
};

#define N_VERIFY_TESTS \
    (sizeof(verify_tests) / sizeof(*verify_tests))

static int
do_verify_test(int test_no, struct verify_test *vt)
{
	STACK_OF(GENERAL_NAME) *alt_name_stack = NULL;
	ASN1_STRING *alt_name_str;
	GENERAL_NAME *alt_name;
	X509_NAME *name;
	X509 *cert;
	struct tls *tls;

	/* Build certificate structure. */
	if ((cert = X509_new()) == NULL)
		errx(1, "failed to malloc X509");
	if ((name = X509_NAME_new()) == NULL)
		errx(1, "failed to malloc X509_NAME");
	if (X509_NAME_add_entry_by_NID(name, NID_commonName, MBSTRING_ASC,
	    (unsigned char *)vt->common_name, -1, -1, 0) == 0)
		errx(1, "failed to add name entry");
	if (X509_set_subject_name(cert, name) == 0)
		errx(1, "failed to set subject name");
	X509_NAME_free(name);
	if ((tls = tls_client()) == NULL)
		errx(1, "failed to malloc tls_client");

	if (vt->alt_name_type != 0) {
		if ((alt_name_stack = sk_GENERAL_NAME_new_null()) == NULL)
			errx(1, "failed to malloc sk_GENERAL_NAME");
		if ((alt_name = GENERAL_NAME_new()) == NULL)
			errx(1, "failed to malloc GENERAL_NAME");
		alt_name->type = vt->alt_name_type;

		if ((alt_name_str = ASN1_STRING_new()) == NULL)
			errx(1, "failed to malloc alt name");
		if (ASN1_STRING_set(alt_name_str, vt->alt_name,
		    vt->alt_name_len) == 0)
			errx(1, "failed to set alt name");

		switch (alt_name->type) {
		case GEN_DNS:
			alt_name->d.dNSName = alt_name_str;
			break;

		case GEN_IPADD:
			alt_name->d.iPAddress = alt_name_str;
			break;

		default:
			errx(1, "unknown alt name type (%i)", alt_name->type);
		}
	
		if (sk_GENERAL_NAME_push(alt_name_stack, alt_name) == 0)
			errx(1, "failed to push alt_name");
		if (X509_add1_ext_i2d(cert, NID_subject_alt_name,
		    alt_name_stack, 0, 0) == 0)
			errx(1, "failed to set subject alt name");
		sk_GENERAL_NAME_pop_free(alt_name_stack, GENERAL_NAME_free);
	}

	if (tls_check_name(tls, cert, vt->name) != vt->want) {
		fprintf(stderr, "FAIL: test %i failed with common name "
		    "'%s', alt name '%s' and name '%s'\n", test_no,
		    vt->common_name, vt->alt_name, vt->name);
		return (1);
	}

	X509_free(cert);

	return (0);
}

int
main(int argc, char **argv)
{
	int failed = 0;
	size_t i;

	for (i = 0; i < N_VERIFY_TESTS; i++)
		failed += do_verify_test(i, &verify_tests[i]);

	return (failed);
}
