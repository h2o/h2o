/* $OpenBSD: passwd.c,v 1.6 2015/10/17 07:51:10 semarie Exp $ */

#if defined OPENSSL_NO_MD5
#define NO_MD5CRYPT_1
#endif

#if !defined(OPENSSL_NO_DES) || !defined(NO_MD5CRYPT_1)

#include <assert.h>
#include <string.h>

#include "apps.h"

#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/evp.h>

#ifndef OPENSSL_NO_DES
#include <openssl/des.h>
#endif

#ifndef NO_MD5CRYPT_1
#include <openssl/md5.h>
#endif

static unsigned const char cov_2char[64] = {
	/* from crypto/des/fcrypt.c */
	0x2E, 0x2F, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35,
	0x36, 0x37, 0x38, 0x39, 0x41, 0x42, 0x43, 0x44,
	0x45, 0x46, 0x47, 0x48, 0x49, 0x4A, 0x4B, 0x4C,
	0x4D, 0x4E, 0x4F, 0x50, 0x51, 0x52, 0x53, 0x54,
	0x55, 0x56, 0x57, 0x58, 0x59, 0x5A, 0x61, 0x62,
	0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69, 0x6A,
	0x6B, 0x6C, 0x6D, 0x6E, 0x6F, 0x70, 0x71, 0x72,
	0x73, 0x74, 0x75, 0x76, 0x77, 0x78, 0x79, 0x7A
};

static int
do_passwd(int passed_salt, char **salt_p, char **salt_malloc_p,
    char *passwd, BIO * out, int quiet, int table, int reverse,
    size_t pw_maxlen, int usecrypt, int use1, int useapr1);

static struct {
	char *infile;
	int in_stdin;
	int noverify;
	int quiet;
	int reverse;
	char *salt;
	int table;
	int use1;
	int useapr1;
	int usecrypt;
} passwd_config;

static struct option passwd_options[] = {
#ifndef NO_MD5CRYPT_1
	{
		.name = "1",
		.desc = "Use MD5 based BSD password algorithm 1",
		.type = OPTION_FLAG,
		.opt.flag = &passwd_config.use1,
	},
	{
		.name = "apr1",
		.desc = "Use apr1 algorithm (Apache variant of BSD algorithm)",
		.type = OPTION_FLAG,
		.opt.flag = &passwd_config.useapr1,
	},
#endif
#ifndef OPENSSL_NO_DES
	{
		.name = "crypt",
		.desc = "Use crypt algorithm (default)",
		.type = OPTION_FLAG,
		.opt.flag = &passwd_config.usecrypt,
	},
#endif
	{
		.name = "in",
		.argname = "file",
		.desc = "Read passwords from specified file",
		.type = OPTION_ARG,
		.opt.arg = &passwd_config.infile,
	},
	{
		.name = "noverify",
		.desc = "Do not verify password",
		.type = OPTION_FLAG,
		.opt.flag = &passwd_config.noverify,
	},
	{
		.name = "quiet",
		.desc = "Do not output warnings",
		.type = OPTION_FLAG,
		.opt.flag = &passwd_config.quiet,
	},
	{
		.name = "reverse",
		.desc = "Reverse table columns (requires -table)",
		.type = OPTION_FLAG,
		.opt.flag = &passwd_config.reverse,
	},
	{
		.name = "salt",
		.argname = "string",
		.desc = "Use specified salt",
		.type = OPTION_ARG,
		.opt.arg = &passwd_config.salt,
	},
	{
		.name = "stdin",
		.desc = "Read passwords from stdin",
		.type = OPTION_FLAG,
		.opt.flag = &passwd_config.in_stdin,
	},
	{
		.name = "table",
		.desc = "Output cleartext and hashed passwords (tab separated)",
		.type = OPTION_FLAG,
		.opt.flag = &passwd_config.table,
	},
	{ NULL },
};

static void
passwd_usage(void)
{
        fprintf(stderr, "usage: passwd [-1 | -apr1 | -crypt] [-in file] "
	    "[-noverify] [-quiet]\n"
	    "    [-reverse] [-salt string] [-stdin] [-table] [password]\n\n");
        options_usage(passwd_options);
}

int
passwd_main(int argc, char **argv)
{
	char *passwd = NULL, **passwds = NULL;
	char *salt_malloc = NULL, *passwd_malloc = NULL;
	size_t passwd_malloc_size = 0;
	BIO *in = NULL, *out = NULL;
	int badopt = 0;
	int passed_salt = 0;
	size_t pw_maxlen = 0;
	int argsused;
	int ret = 1;

	if (single_execution) {
		if (pledge("stdio rpath wpath cpath tty", NULL) == -1) {
			perror("pledge");
			exit(1);
		}
	}

	memset(&passwd_config, 0, sizeof(passwd_config));

	if (options_parse(argc, argv, passwd_options, NULL, &argsused) != 0) {
		passwd_usage();
		goto err;
	}

	if (argsused < argc)
		passwds = &argv[argsused];
	if (passwd_config.salt != NULL)
		passed_salt = 1;

	if (!passwd_config.usecrypt && !passwd_config.use1 &&
	    !passwd_config.useapr1)
		passwd_config.usecrypt = 1;	/* use default */
	if (passwd_config.usecrypt + passwd_config.use1 +
	    passwd_config.useapr1 > 1)
		badopt = 1;	/* conflicting options */

	/* Reject unsupported algorithms */
#ifdef OPENSSL_NO_DES
	if (passwd_config.usecrypt)
		badopt = 1;
#endif
#ifdef NO_MD5CRYPT_1
	if (passwd_config.use1 || passwd_config.useapr1)
		badopt = 1;
#endif

	if (badopt) {
		passwd_usage();
		goto err;
	}

	if ((out = BIO_new(BIO_s_file())) == NULL)
		goto err;
	BIO_set_fp(out, stdout, BIO_NOCLOSE | BIO_FP_TEXT);

	if (passwd_config.infile != NULL || passwd_config.in_stdin) {
		if ((in = BIO_new(BIO_s_file())) == NULL)
			goto err;
		if (passwd_config.infile != NULL) {
			assert(passwd_config.in_stdin == 0);
			if (BIO_read_filename(in, passwd_config.infile) <= 0)
				goto err;
		} else {
			assert(passwd_config.in_stdin);
			BIO_set_fp(in, stdin, BIO_NOCLOSE);
		}
	}
	if (passwd_config.usecrypt)
		pw_maxlen = 8;
	else if (passwd_config.use1 || passwd_config.useapr1)
		pw_maxlen = 256;/* arbitrary limit, should be enough for most
				 * passwords */

	if (passwds == NULL) {
		/* no passwords on the command line */

		passwd_malloc_size = pw_maxlen + 2;
		/* longer than necessary so that we can warn about truncation */
		passwd = passwd_malloc = malloc(passwd_malloc_size);
		if (passwd_malloc == NULL)
			goto err;
	}
	if (in == NULL && passwds == NULL) {
		/* build a null-terminated list */
		static char *passwds_static[2] = {NULL, NULL};

		passwds = passwds_static;
		if (in == NULL)
			if (EVP_read_pw_string(passwd_malloc,
			    passwd_malloc_size, "Password: ",
			    !(passed_salt || passwd_config.noverify)) != 0)
				goto err;
		passwds[0] = passwd_malloc;
	}
	if (in == NULL) {
		assert(passwds != NULL);
		assert(*passwds != NULL);

		do {	/* loop over list of passwords */
			passwd = *passwds++;
			if (!do_passwd(passed_salt, &passwd_config.salt,
			    &salt_malloc, passwd, out, passwd_config.quiet,
			    passwd_config.table, passwd_config.reverse,
			    pw_maxlen, passwd_config.usecrypt,
			    passwd_config.use1, passwd_config.useapr1))
				goto err;
		} while (*passwds != NULL);
	} else {
		int done;

		assert(passwd != NULL);
		do {
			int r = BIO_gets(in, passwd, pw_maxlen + 1);
			if (r > 0) {
				char *c = (strchr(passwd, '\n'));
				if (c != NULL)
					*c = 0;	/* truncate at newline */
				else {
					/* ignore rest of line */
					char trash[BUFSIZ];
					do
						r = BIO_gets(in, trash, sizeof trash);
					while ((r > 0) && (!strchr(trash, '\n')));
				}

				if (!do_passwd(passed_salt, &passwd_config.salt,
				    &salt_malloc, passwd, out,
				    passwd_config.quiet, passwd_config.table,
				    passwd_config.reverse, pw_maxlen,
				    passwd_config.usecrypt, passwd_config.use1,
				    passwd_config.useapr1))
					goto err;
			}
			done = (r <= 0);
		} while (!done);
	}
	ret = 0;

err:
	ERR_print_errors(bio_err);

	free(salt_malloc);
	free(passwd_malloc);

	BIO_free(in);
	BIO_free_all(out);

	return (ret);
}


#ifndef NO_MD5CRYPT_1
/* MD5-based password algorithm (should probably be available as a library
 * function; then the static buffer would not be acceptable).
 * For magic string "1", this should be compatible to the MD5-based BSD
 * password algorithm.
 * For 'magic' string "apr1", this is compatible to the MD5-based Apache
 * password algorithm.
 * (Apparently, the Apache password algorithm is identical except that the
 * 'magic' string was changed -- the laziest application of the NIH principle
 * I've ever encountered.)
 */
static char *
md5crypt(const char *passwd, const char *magic, const char *salt)
{
	static char out_buf[6 + 9 + 24 + 2];	/* "$apr1$..salt..$.......md5h
						 * ash..........\0" */
	unsigned char buf[MD5_DIGEST_LENGTH];
	char *salt_out;
	int n;
	unsigned int i;
	EVP_MD_CTX md, md2;
	size_t passwd_len, salt_len;

	passwd_len = strlen(passwd);
	out_buf[0] = '$';
	out_buf[1] = 0;
	assert(strlen(magic) <= 4);	/* "1" or "apr1" */
	strlcat(out_buf, magic, sizeof(out_buf));
	strlcat(out_buf, "$", sizeof(out_buf));
	strlcat(out_buf, salt, sizeof(out_buf));
	assert(strlen(out_buf) <= 6 + 8);	/* "$apr1$..salt.." */
	salt_out = out_buf + 2 + strlen(magic);
	salt_len = strlen(salt_out);
	assert(salt_len <= 8);

	EVP_MD_CTX_init(&md);
	EVP_DigestInit_ex(&md, EVP_md5(), NULL);
	EVP_DigestUpdate(&md, passwd, passwd_len);
	EVP_DigestUpdate(&md, "$", 1);
	EVP_DigestUpdate(&md, magic, strlen(magic));
	EVP_DigestUpdate(&md, "$", 1);
	EVP_DigestUpdate(&md, salt_out, salt_len);

	EVP_MD_CTX_init(&md2);
	EVP_DigestInit_ex(&md2, EVP_md5(), NULL);
	EVP_DigestUpdate(&md2, passwd, passwd_len);
	EVP_DigestUpdate(&md2, salt_out, salt_len);
	EVP_DigestUpdate(&md2, passwd, passwd_len);
	EVP_DigestFinal_ex(&md2, buf, NULL);

	for (i = passwd_len; i > sizeof buf; i -= sizeof buf)
		EVP_DigestUpdate(&md, buf, sizeof buf);
	EVP_DigestUpdate(&md, buf, i);

	n = passwd_len;
	while (n) {
		EVP_DigestUpdate(&md, (n & 1) ? "\0" : passwd, 1);
		n >>= 1;
	}
	EVP_DigestFinal_ex(&md, buf, NULL);

	for (i = 0; i < 1000; i++) {
		EVP_DigestInit_ex(&md2, EVP_md5(), NULL);
		EVP_DigestUpdate(&md2, (i & 1) ? (unsigned const char *) passwd : buf,
		    (i & 1) ? passwd_len : sizeof buf);
		if (i % 3)
			EVP_DigestUpdate(&md2, salt_out, salt_len);
		if (i % 7)
			EVP_DigestUpdate(&md2, passwd, passwd_len);
		EVP_DigestUpdate(&md2, (i & 1) ? buf : (unsigned const char *) passwd,
		    (i & 1) ? sizeof buf : passwd_len);
		EVP_DigestFinal_ex(&md2, buf, NULL);
	}
	EVP_MD_CTX_cleanup(&md2);

	{
		/* transform buf into output string */

		unsigned char buf_perm[sizeof buf];
		int dest, source;
		char *output;

		/* silly output permutation */
		for (dest = 0, source = 0; dest < 14; dest++, source = (source + 6) % 17)
			buf_perm[dest] = buf[source];
		buf_perm[14] = buf[5];
		buf_perm[15] = buf[11];
		assert(16 == sizeof buf_perm);

		output = salt_out + salt_len;
		assert(output == out_buf + strlen(out_buf));

		*output++ = '$';

		for (i = 0; i < 15; i += 3) {
			*output++ = cov_2char[buf_perm[i + 2] & 0x3f];
			*output++ = cov_2char[((buf_perm[i + 1] & 0xf) << 2) |
			    (buf_perm[i + 2] >> 6)];
			*output++ = cov_2char[((buf_perm[i] & 3) << 4) |
			    (buf_perm[i + 1] >> 4)];
			*output++ = cov_2char[buf_perm[i] >> 2];
		}
		assert(i == 15);
		*output++ = cov_2char[buf_perm[i] & 0x3f];
		*output++ = cov_2char[buf_perm[i] >> 6];
		*output = 0;
		assert(strlen(out_buf) < sizeof(out_buf));
	}
	EVP_MD_CTX_cleanup(&md);

	return out_buf;
}
#endif


static int
do_passwd(int passed_salt, char **salt_p, char **salt_malloc_p,
    char *passwd, BIO * out, int quiet, int table, int reverse,
    size_t pw_maxlen, int usecrypt, int use1, int useapr1)
{
	char *hash = NULL;

	assert(salt_p != NULL);
	assert(salt_malloc_p != NULL);

	/* first make sure we have a salt */
	if (!passed_salt) {
#ifndef OPENSSL_NO_DES
		if (usecrypt) {
			if (*salt_malloc_p == NULL) {
				*salt_p = *salt_malloc_p = malloc(3);
				if (*salt_malloc_p == NULL)
					goto err;
			}
			arc4random_buf(*salt_p, 2);
			(*salt_p)[0] = cov_2char[(*salt_p)[0] & 0x3f];	/* 6 bits */
			(*salt_p)[1] = cov_2char[(*salt_p)[1] & 0x3f];	/* 6 bits */
			(*salt_p)[2] = 0;
		}
#endif				/* !OPENSSL_NO_DES */

#ifndef NO_MD5CRYPT_1
		if (use1 || useapr1) {
			int i;

			if (*salt_malloc_p == NULL) {
				*salt_p = *salt_malloc_p = malloc(9);
				if (*salt_malloc_p == NULL)
					goto err;
			}
			arc4random_buf(*salt_p, 8);

			for (i = 0; i < 8; i++)
				(*salt_p)[i] = cov_2char[(*salt_p)[i] & 0x3f];	/* 6 bits */
			(*salt_p)[8] = 0;
		}
#endif				/* !NO_MD5CRYPT_1 */
	}
	assert(*salt_p != NULL);

	/* truncate password if necessary */
	if ((strlen(passwd) > pw_maxlen)) {
		if (!quiet)
			/*
			 * XXX: really we should know how to print a size_t,
			 * not cast it
			 */
			BIO_printf(bio_err, "Warning: truncating password to %u characters\n", (unsigned) pw_maxlen);
		passwd[pw_maxlen] = 0;
	}
	assert(strlen(passwd) <= pw_maxlen);

	/* now compute password hash */
#ifndef OPENSSL_NO_DES
	if (usecrypt)
		hash = DES_crypt(passwd, *salt_p);
#endif
#ifndef NO_MD5CRYPT_1
	if (use1 || useapr1)
		hash = md5crypt(passwd, (use1 ? "1" : "apr1"), *salt_p);
#endif
	assert(hash != NULL);

	if (table && !reverse)
		BIO_printf(out, "%s\t%s\n", passwd, hash);
	else if (table && reverse)
		BIO_printf(out, "%s\t%s\n", hash, passwd);
	else
		BIO_printf(out, "%s\n", hash);
	return 1;

err:
	return 0;
}
#else

int
passwd_main(int argc, char **argv)
{
	fputs("Program not available.\n", stderr)
	return (1);
}
#endif
