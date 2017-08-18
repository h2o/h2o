/* $OpenBSD: openssl.c,v 1.22 2015/12/01 01:24:47 beck Exp $ */
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
 * Copyright (c) 1998-2006 The OpenSSL Project.  All rights reserved.
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

#include <err.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>

#include "apps.h"

#include <openssl/bio.h>
#include <openssl/conf.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/lhash.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>

#include "progs.h"
#include "s_apps.h"

#define FUNC_TYPE_GENERAL       1
#define FUNC_TYPE_MD            2
#define FUNC_TYPE_CIPHER        3
#define FUNC_TYPE_PKEY          4
#define FUNC_TYPE_MD_ALG        5
#define FUNC_TYPE_CIPHER_ALG    6

int single_execution = 0;

typedef struct {
        int type;
        const char *name;
        int (*func)(int argc, char **argv);
} FUNCTION;

DECLARE_LHASH_OF(FUNCTION);

FUNCTION functions[] = {

	/* General functions. */
	{ FUNC_TYPE_GENERAL, "asn1parse", asn1parse_main },
	{ FUNC_TYPE_GENERAL, "ca", ca_main },
	{ FUNC_TYPE_GENERAL, "certhash", certhash_main },
	{ FUNC_TYPE_GENERAL, "ciphers", ciphers_main },
#ifndef OPENSSL_NO_CMS
	{ FUNC_TYPE_GENERAL, "cms", cms_main },
#endif
	{ FUNC_TYPE_GENERAL, "crl2pkcs7", crl2pkcs7_main },
	{ FUNC_TYPE_GENERAL, "crl", crl_main },
	{ FUNC_TYPE_GENERAL, "dgst", dgst_main },
	{ FUNC_TYPE_GENERAL, "enc", enc_main },
	{ FUNC_TYPE_GENERAL, "errstr", errstr_main },
	{ FUNC_TYPE_GENERAL, "genpkey", genpkey_main },
	{ FUNC_TYPE_GENERAL, "nseq", nseq_main },
#ifndef OPENSSL_NO_OCSP
	{ FUNC_TYPE_GENERAL, "ocsp", ocsp_main },
#endif
	{ FUNC_TYPE_GENERAL, "passwd", passwd_main },
	{ FUNC_TYPE_GENERAL, "pkcs7", pkcs7_main },
	{ FUNC_TYPE_GENERAL, "pkcs8", pkcs8_main },
#if !defined(OPENSSL_NO_DES) && !defined(OPENSSL_NO_SHA1)
	{ FUNC_TYPE_GENERAL, "pkcs12", pkcs12_main },
#endif
	{ FUNC_TYPE_GENERAL, "pkey", pkey_main },
	{ FUNC_TYPE_GENERAL, "pkeyparam", pkeyparam_main },
	{ FUNC_TYPE_GENERAL, "pkeyutl", pkeyutl_main },
	{ FUNC_TYPE_GENERAL, "prime", prime_main },
	{ FUNC_TYPE_GENERAL, "rand", rand_main },
	{ FUNC_TYPE_GENERAL, "req", req_main },
	{ FUNC_TYPE_GENERAL, "s_client", s_client_main },
	{ FUNC_TYPE_GENERAL, "s_server", s_server_main },
	{ FUNC_TYPE_GENERAL, "s_time", s_time_main },
	{ FUNC_TYPE_GENERAL, "sess_id", sess_id_main },
	{ FUNC_TYPE_GENERAL, "smime", smime_main },
#ifndef OPENSSL_NO_SPEED
	{ FUNC_TYPE_GENERAL, "speed", speed_main },
#endif
	{ FUNC_TYPE_GENERAL, "spkac", spkac_main },
	{ FUNC_TYPE_GENERAL, "ts", ts_main },
	{ FUNC_TYPE_GENERAL, "verify", verify_main },
	{ FUNC_TYPE_GENERAL, "version", version_main },
	{ FUNC_TYPE_GENERAL, "x509", x509_main },

#ifndef OPENSSL_NO_DH
	{ FUNC_TYPE_GENERAL, "dh", dh_main },
	{ FUNC_TYPE_GENERAL, "dhparam", dhparam_main },
	{ FUNC_TYPE_GENERAL, "gendh", gendh_main },
#endif
#ifndef OPENSSL_NO_DSA
	{ FUNC_TYPE_GENERAL, "dsa", dsa_main },
	{ FUNC_TYPE_GENERAL, "dsaparam", dsaparam_main },
	{ FUNC_TYPE_GENERAL, "gendsa", gendsa_main },
#endif
#ifndef OPENSSL_NO_EC
	{ FUNC_TYPE_GENERAL, "ec", ec_main },
	{ FUNC_TYPE_GENERAL, "ecparam", ecparam_main },
#endif
#ifndef OPENSSL_NO_RSA
	{ FUNC_TYPE_GENERAL, "genrsa", genrsa_main },
	{ FUNC_TYPE_GENERAL, "rsa", rsa_main },
	{ FUNC_TYPE_GENERAL, "rsautl", rsautl_main },
#endif

	/* Message Digests. */
#ifndef OPENSSL_NO_GOST
	{ FUNC_TYPE_MD, "gost-mac", dgst_main },
	{ FUNC_TYPE_MD, "md_gost94", dgst_main },
	{ FUNC_TYPE_MD, "streebog256", dgst_main },
	{ FUNC_TYPE_MD, "streebog512", dgst_main },
#endif
#ifndef OPENSSL_NO_MD4
	{ FUNC_TYPE_MD, "md4", dgst_main },
#endif
#ifndef OPENSSL_NO_MD5
	{ FUNC_TYPE_MD, "md5", dgst_main },
#endif
#ifndef OPENSSL_NO_RIPEMD160
	{ FUNC_TYPE_MD, "ripemd160", dgst_main },
#endif
#ifndef OPENSSL_NO_SHA1
	{ FUNC_TYPE_MD, "sha1", dgst_main },
#endif
#ifndef OPENSSL_NO_SHA224
	{ FUNC_TYPE_MD, "sha224", dgst_main },
#endif
#ifndef OPENSSL_NO_SHA256
	{ FUNC_TYPE_MD, "sha256", dgst_main },
#endif
#ifndef OPENSSL_NO_SHA384
	{ FUNC_TYPE_MD, "sha384", dgst_main },
#endif
#ifndef OPENSSL_NO_SHA512
	{ FUNC_TYPE_MD, "sha512", dgst_main },
#endif
#ifndef OPENSSL_NO_WHIRLPOOL
	{ FUNC_TYPE_MD, "whirlpool", dgst_main },
#endif

	/* Ciphers. */
	{ FUNC_TYPE_CIPHER, "base64", enc_main },
#ifndef OPENSSL_NO_AES
	{ FUNC_TYPE_CIPHER, "aes-128-cbc", enc_main },
	{ FUNC_TYPE_CIPHER, "aes-128-ecb", enc_main },
	{ FUNC_TYPE_CIPHER, "aes-192-cbc", enc_main },
	{ FUNC_TYPE_CIPHER, "aes-192-ecb", enc_main },
	{ FUNC_TYPE_CIPHER, "aes-256-cbc", enc_main },
	{ FUNC_TYPE_CIPHER, "aes-256-ecb", enc_main },
#endif
#ifndef OPENSSL_NO_BF
	{ FUNC_TYPE_CIPHER, "bf", enc_main },
	{ FUNC_TYPE_CIPHER, "bf-cbc", enc_main },
	{ FUNC_TYPE_CIPHER, "bf-ecb", enc_main },
	{ FUNC_TYPE_CIPHER, "bf-cfb", enc_main },
	{ FUNC_TYPE_CIPHER, "bf-ofb", enc_main },
#endif
#ifndef OPENSSL_NO_CAMELLIA
	{ FUNC_TYPE_CIPHER, "camellia-128-cbc", enc_main },
	{ FUNC_TYPE_CIPHER, "camellia-128-ecb", enc_main },
	{ FUNC_TYPE_CIPHER, "camellia-192-cbc", enc_main },
	{ FUNC_TYPE_CIPHER, "camellia-192-ecb", enc_main },
	{ FUNC_TYPE_CIPHER, "camellia-256-cbc", enc_main },
	{ FUNC_TYPE_CIPHER, "camellia-256-ecb", enc_main },
#endif
#ifndef OPENSSL_NO_CAST
	{ FUNC_TYPE_CIPHER, "cast", enc_main },
	{ FUNC_TYPE_CIPHER, "cast5-cbc", enc_main },
	{ FUNC_TYPE_CIPHER, "cast5-ecb", enc_main },
	{ FUNC_TYPE_CIPHER, "cast5-cfb", enc_main },
	{ FUNC_TYPE_CIPHER, "cast5-ofb", enc_main },
	{ FUNC_TYPE_CIPHER, "cast-cbc", enc_main },
#endif
#ifndef OPENSSL_NO_CHACHA
	{ FUNC_TYPE_CIPHER, "chacha", enc_main },
#endif
#ifndef OPENSSL_NO_DES
	{ FUNC_TYPE_CIPHER, "des", enc_main },
	{ FUNC_TYPE_CIPHER, "des3", enc_main },
	{ FUNC_TYPE_CIPHER, "desx", enc_main },
	{ FUNC_TYPE_CIPHER, "des-ecb", enc_main },
	{ FUNC_TYPE_CIPHER, "des-ede", enc_main },
	{ FUNC_TYPE_CIPHER, "des-ede3", enc_main },
	{ FUNC_TYPE_CIPHER, "des-cbc", enc_main },
	{ FUNC_TYPE_CIPHER, "des-ede-cbc", enc_main },
	{ FUNC_TYPE_CIPHER, "des-ede3-cbc", enc_main },
	{ FUNC_TYPE_CIPHER, "des-cfb", enc_main },
	{ FUNC_TYPE_CIPHER, "des-ede-cfb", enc_main },
	{ FUNC_TYPE_CIPHER, "des-ede3-cfb", enc_main },
	{ FUNC_TYPE_CIPHER, "des-ofb", enc_main },
	{ FUNC_TYPE_CIPHER, "des-ede-ofb", enc_main },
	{ FUNC_TYPE_CIPHER, "des-ede3-ofb", enc_main },
#endif
#ifndef OPENSSL_NO_IDEA
	{ FUNC_TYPE_CIPHER, "idea", enc_main },
	{ FUNC_TYPE_CIPHER, "idea-cbc", enc_main },
	{ FUNC_TYPE_CIPHER, "idea-ecb", enc_main },
	{ FUNC_TYPE_CIPHER, "idea-cfb", enc_main },
	{ FUNC_TYPE_CIPHER, "idea-ofb", enc_main },
#endif
#ifndef OPENSSL_NO_RC2
	{ FUNC_TYPE_CIPHER, "rc2", enc_main },
	{ FUNC_TYPE_CIPHER, "rc2-cbc", enc_main },
	{ FUNC_TYPE_CIPHER, "rc2-ecb", enc_main },
	{ FUNC_TYPE_CIPHER, "rc2-cfb", enc_main },
	{ FUNC_TYPE_CIPHER, "rc2-ofb", enc_main },
	{ FUNC_TYPE_CIPHER, "rc2-64-cbc", enc_main },
	{ FUNC_TYPE_CIPHER, "rc2-40-cbc", enc_main },
#endif
#ifndef OPENSSL_NO_RC4
	{ FUNC_TYPE_CIPHER, "rc4", enc_main },
	{ FUNC_TYPE_CIPHER, "rc4-40", enc_main },
#endif
#ifdef ZLIB
	{ FUNC_TYPE_CIPHER, "zlib", enc_main },
#endif

	{ 0, NULL, NULL }
};

static void openssl_startup(void);
static void openssl_shutdown(void);

/* The LHASH callbacks ("hash" & "cmp") have been replaced by functions with the
 * base prototypes (we cast each variable inside the function to the required
 * type of "FUNCTION*"). This removes the necessity for macro-generated wrapper
 * functions. */

static LHASH_OF(FUNCTION) *prog_init(void);
static int do_cmd(LHASH_OF(FUNCTION) *prog, int argc, char *argv[]);
static void list_pkey(BIO * out);
static void list_cipher(BIO * out);
static void list_md(BIO * out);
char *default_config_file = NULL;

CONF *config = NULL;
BIO *bio_err = NULL;

static void
lock_dbg_cb(int mode, int type, const char *file, int line)
{
	static int modes[CRYPTO_NUM_LOCKS];	/* = {0, 0, ... } */
	const char *errstr = NULL;
	int rw;

	rw = mode & (CRYPTO_READ | CRYPTO_WRITE);
	if (!((rw == CRYPTO_READ) || (rw == CRYPTO_WRITE))) {
		errstr = "invalid mode";
		goto err;
	}
	if (type < 0 || type >= CRYPTO_NUM_LOCKS) {
		errstr = "type out of bounds";
		goto err;
	}
	if (mode & CRYPTO_LOCK) {
		if (modes[type]) {
			errstr = "already locked";
			/*
			 * must not happen in a single-threaded program
			 * (would deadlock)
			 */
			goto err;
		}
		modes[type] = rw;
	} else if (mode & CRYPTO_UNLOCK) {
		if (!modes[type]) {
			errstr = "not locked";
			goto err;
		}
		if (modes[type] != rw) {
			errstr = (rw == CRYPTO_READ) ?
			    "CRYPTO_r_unlock on write lock" :
			    "CRYPTO_w_unlock on read lock";
		}
		modes[type] = 0;
	} else {
		errstr = "invalid mode";
		goto err;
	}

err:
	if (errstr) {
		/* we cannot use bio_err here */
		fprintf(stderr, "openssl (lock_dbg_cb): %s (mode=%d, type=%d) at %s:%d\n",
		    errstr, mode, type, file, line);
	}
}

static void
openssl_startup(void)
{
#ifndef _WIN32
	signal(SIGPIPE, SIG_IGN);
#endif

	OpenSSL_add_all_algorithms();
	SSL_library_init();
	SSL_load_error_strings();

	setup_ui();
}

static void
openssl_shutdown(void)
{
	CONF_modules_unload(1);
	destroy_ui();
	OBJ_cleanup();
	EVP_cleanup();
	CRYPTO_cleanup_all_ex_data();
	ERR_remove_thread_state(NULL);
	ERR_free_strings();
}

int
main(int argc, char **argv)
{
	ARGS arg;
#define PROG_NAME_SIZE	39
	char pname[PROG_NAME_SIZE + 1];
	FUNCTION f, *fp;
	const char *prompt;
	char buf[1024];
	char *to_free = NULL;
	int n, i, ret = 0;
	char *p;
	LHASH_OF(FUNCTION) * prog = NULL;
	long errline;

	arg.data = NULL;
	arg.count = 0;

	if (pledge("stdio inet dns rpath wpath cpath proc flock tty", NULL) == -1) {
		fprintf(stderr, "openssl: pledge: %s\n", strerror(errno));
		exit(1);
	}

	bio_err = BIO_new_fp(stderr, BIO_NOCLOSE);
	if (bio_err == NULL) {
		fprintf(stderr, "openssl: failed to initialise bio_err\n");
		exit(1);
	}

	if (BIO_sock_init() != 1) {
		BIO_printf(bio_err, "BIO_sock_init failed\n");
		exit(1);
	}

	CRYPTO_set_locking_callback(lock_dbg_cb);

	openssl_startup();

	/* Lets load up our environment a little */
	p = getenv("OPENSSL_CONF");
	if (p == NULL) {
		p = to_free = make_config_name();
		if (p == NULL) {
			BIO_printf(bio_err, "error making config file name\n");
			goto end;
		}
	}

	default_config_file = p;

	config = NCONF_new(NULL);
	i = NCONF_load(config, p, &errline);
	if (i == 0) {
		if (ERR_GET_REASON(ERR_peek_last_error()) ==
		    CONF_R_NO_SUCH_FILE) {
			BIO_printf(bio_err,
			    "WARNING: can't open config file: %s\n", p);
			ERR_clear_error();
			NCONF_free(config);
			config = NULL;
		} else {
			ERR_print_errors(bio_err);
			NCONF_free(config);
			exit(1);
		}
	}

	if (!load_config(bio_err, NULL)) {
		BIO_printf(bio_err, "failed to load configuration\n");
		goto end;
	}

	prog = prog_init();

	/* first check the program name */
	program_name(argv[0], pname, sizeof pname);

	f.name = pname;
	fp = lh_FUNCTION_retrieve(prog, &f);
	if (fp != NULL) {
		argv[0] = pname;

		single_execution = 1;
		ret = fp->func(argc, argv);
		goto end;
	}
	/*
	 * ok, now check that there are not arguments, if there are, run with
	 * them, shifting the ssleay off the front
	 */
	if (argc != 1) {
		argc--;
		argv++;

		single_execution = 1;
		ret = do_cmd(prog, argc, argv);
		if (ret < 0)
			ret = 0;
		goto end;
	}
	/* ok, lets enter the old 'OpenSSL>' mode */

	for (;;) {
		ret = 0;
		p = buf;
		n = sizeof buf;
		i = 0;
		for (;;) {
			p[0] = '\0';
			if (i++)
				prompt = ">";
			else
				prompt = "OpenSSL> ";
			fputs(prompt, stdout);
			fflush(stdout);
			if (!fgets(p, n, stdin))
				goto end;
			if (p[0] == '\0')
				goto end;
			i = strlen(p);
			if (i <= 1)
				break;
			if (p[i - 2] != '\\')
				break;
			i -= 2;
			p += i;
			n -= i;
		}
		if (!chopup_args(&arg, buf, &argc, &argv))
			break;

		ret = do_cmd(prog, argc, argv);
		if (ret < 0) {
			ret = 0;
			goto end;
		}
		if (ret != 0)
			BIO_printf(bio_err, "error in %s\n", argv[0]);
		(void) BIO_flush(bio_err);
	}
	BIO_printf(bio_err, "bad exit\n");
	ret = 1;

end:
	free(to_free);

	if (config != NULL) {
		NCONF_free(config);
		config = NULL;
	}
	if (prog != NULL)
		lh_FUNCTION_free(prog);
	free(arg.data);

	openssl_shutdown();

	if (bio_err != NULL) {
		BIO_free(bio_err);
		bio_err = NULL;
	}
	return (ret);
}

#define LIST_STANDARD_COMMANDS "list-standard-commands"
#define LIST_MESSAGE_DIGEST_COMMANDS "list-message-digest-commands"
#define LIST_MESSAGE_DIGEST_ALGORITHMS "list-message-digest-algorithms"
#define LIST_CIPHER_COMMANDS "list-cipher-commands"
#define LIST_CIPHER_ALGORITHMS "list-cipher-algorithms"
#define LIST_PUBLIC_KEY_ALGORITHMS "list-public-key-algorithms"


static int
do_cmd(LHASH_OF(FUNCTION) * prog, int argc, char *argv[])
{
	FUNCTION f, *fp;
	int i, ret = 1, tp, nl;

	if ((argc <= 0) || (argv[0] == NULL)) {
		ret = 0;
		goto end;
	}
	f.name = argv[0];
	fp = lh_FUNCTION_retrieve(prog, &f);
	if (fp == NULL) {
		if (EVP_get_digestbyname(argv[0])) {
			f.type = FUNC_TYPE_MD;
			f.func = dgst_main;
			fp = &f;
		} else if (EVP_get_cipherbyname(argv[0])) {
			f.type = FUNC_TYPE_CIPHER;
			f.func = enc_main;
			fp = &f;
		}
	}
	if (fp != NULL) {
		ret = fp->func(argc, argv);
	} else if ((strncmp(argv[0], "no-", 3)) == 0) {
		BIO *bio_stdout = BIO_new_fp(stdout, BIO_NOCLOSE);
		f.name = argv[0] + 3;
		ret = (lh_FUNCTION_retrieve(prog, &f) != NULL);
		if (!ret)
			BIO_printf(bio_stdout, "%s\n", argv[0]);
		else
			BIO_printf(bio_stdout, "%s\n", argv[0] + 3);
		BIO_free_all(bio_stdout);
		goto end;
	} else if ((strcmp(argv[0], "quit") == 0) ||
	    (strcmp(argv[0], "q") == 0) ||
	    (strcmp(argv[0], "exit") == 0) ||
	    (strcmp(argv[0], "bye") == 0)) {
		ret = -1;
		goto end;
	} else if ((strcmp(argv[0], LIST_STANDARD_COMMANDS) == 0) ||
	    (strcmp(argv[0], LIST_MESSAGE_DIGEST_COMMANDS) == 0) ||
	    (strcmp(argv[0], LIST_MESSAGE_DIGEST_ALGORITHMS) == 0) ||
	    (strcmp(argv[0], LIST_CIPHER_COMMANDS) == 0) ||
	    (strcmp(argv[0], LIST_CIPHER_ALGORITHMS) == 0) ||
	    (strcmp(argv[0], LIST_PUBLIC_KEY_ALGORITHMS) == 0)) {
		int list_type;
		BIO *bio_stdout;

		if (strcmp(argv[0], LIST_STANDARD_COMMANDS) == 0)
			list_type = FUNC_TYPE_GENERAL;
		else if (strcmp(argv[0], LIST_MESSAGE_DIGEST_COMMANDS) == 0)
			list_type = FUNC_TYPE_MD;
		else if (strcmp(argv[0], LIST_MESSAGE_DIGEST_ALGORITHMS) == 0)
			list_type = FUNC_TYPE_MD_ALG;
		else if (strcmp(argv[0], LIST_PUBLIC_KEY_ALGORITHMS) == 0)
			list_type = FUNC_TYPE_PKEY;
		else if (strcmp(argv[0], LIST_CIPHER_ALGORITHMS) == 0)
			list_type = FUNC_TYPE_CIPHER_ALG;
		else		/* strcmp(argv[0],LIST_CIPHER_COMMANDS) == 0 */
			list_type = FUNC_TYPE_CIPHER;
		bio_stdout = BIO_new_fp(stdout, BIO_NOCLOSE);

		if (list_type == FUNC_TYPE_PKEY)
			list_pkey(bio_stdout);
		if (list_type == FUNC_TYPE_MD_ALG)
			list_md(bio_stdout);
		if (list_type == FUNC_TYPE_CIPHER_ALG)
			list_cipher(bio_stdout);
		else {
			for (fp = functions; fp->name != NULL; fp++)
				if (fp->type == list_type)
					BIO_printf(bio_stdout, "%s\n",
					    fp->name);
		}
		BIO_free_all(bio_stdout);
		ret = 0;
		goto end;
	} else {
		BIO_printf(bio_err,
		    "openssl:Error: '%s' is an invalid command.\n",
		    argv[0]);
		BIO_printf(bio_err, "\nStandard commands");
		i = 0;
		tp = 0;
		for (fp = functions; fp->name != NULL; fp++) {
			nl = 0;
#ifdef OPENSSL_NO_CAMELLIA
			if (((i++) % 5) == 0)
#else
			if (((i++) % 4) == 0)
#endif
			{
				BIO_printf(bio_err, "\n");
				nl = 1;
			}
			if (fp->type != tp) {
				tp = fp->type;
				if (!nl)
					BIO_printf(bio_err, "\n");
				if (tp == FUNC_TYPE_MD) {
					i = 1;
					BIO_printf(bio_err,
					    "\nMessage Digest commands (see the `dgst' command for more details)\n");
				} else if (tp == FUNC_TYPE_CIPHER) {
					i = 1;
					BIO_printf(bio_err, "\nCipher commands (see the `enc' command for more details)\n");
				}
			}
#ifdef OPENSSL_NO_CAMELLIA
			BIO_printf(bio_err, "%-15s", fp->name);
#else
			BIO_printf(bio_err, "%-18s", fp->name);
#endif
		}
		BIO_printf(bio_err, "\n\n");
		ret = 0;
	}
end:
	return (ret);
}

static int
SortFnByName(const void *_f1, const void *_f2)
{
	const FUNCTION *f1 = _f1;
	const FUNCTION *f2 = _f2;

	if (f1->type != f2->type)
		return f1->type - f2->type;
	return strcmp(f1->name, f2->name);
}

static void
list_pkey(BIO * out)
{
	int i;

	for (i = 0; i < EVP_PKEY_asn1_get_count(); i++) {
		const EVP_PKEY_ASN1_METHOD *ameth;
		int pkey_id, pkey_base_id, pkey_flags;
		const char *pinfo, *pem_str;
		ameth = EVP_PKEY_asn1_get0(i);
		EVP_PKEY_asn1_get0_info(&pkey_id, &pkey_base_id, &pkey_flags,
		    &pinfo, &pem_str, ameth);
		if (pkey_flags & ASN1_PKEY_ALIAS) {
			BIO_printf(out, "Name: %s\n",
			    OBJ_nid2ln(pkey_id));
			BIO_printf(out, "\tType: Alias to %s\n",
			    OBJ_nid2ln(pkey_base_id));
		} else {
			BIO_printf(out, "Name: %s\n", pinfo);
			BIO_printf(out, "\tType: %s Algorithm\n",
			    pkey_flags & ASN1_PKEY_DYNAMIC ?
			    "External" : "Builtin");
			BIO_printf(out, "\tOID: %s\n", OBJ_nid2ln(pkey_id));
			if (pem_str == NULL)
				pem_str = "(none)";
			BIO_printf(out, "\tPEM string: %s\n", pem_str);
		}

	}
}

static void
list_cipher_fn(const EVP_CIPHER * c, const char *from, const char *to,
    void *arg)
{
	if (c)
		BIO_printf(arg, "%s\n", EVP_CIPHER_name(c));
	else {
		if (!from)
			from = "<undefined>";
		if (!to)
			to = "<undefined>";
		BIO_printf(arg, "%s => %s\n", from, to);
	}
}

static void
list_cipher(BIO * out)
{
	EVP_CIPHER_do_all_sorted(list_cipher_fn, out);
}

static void
list_md_fn(const EVP_MD * m, const char *from, const char *to, void *arg)
{
	if (m)
		BIO_printf(arg, "%s\n", EVP_MD_name(m));
	else {
		if (!from)
			from = "<undefined>";
		if (!to)
			to = "<undefined>";
		BIO_printf(arg, "%s => %s\n", from, to);
	}
}

static void
list_md(BIO * out)
{
	EVP_MD_do_all_sorted(list_md_fn, out);
}

static int
function_cmp(const FUNCTION * a, const FUNCTION * b)
{
	return strncmp(a->name, b->name, 8);
}

static IMPLEMENT_LHASH_COMP_FN(function, FUNCTION)

static unsigned long
function_hash(const FUNCTION * a)
{
	return lh_strhash(a->name);
}

static IMPLEMENT_LHASH_HASH_FN(function, FUNCTION)

static LHASH_OF(FUNCTION) *
prog_init(void)
{
	LHASH_OF(FUNCTION) * ret;
	FUNCTION *f;
	size_t i;

	/* Purely so it looks nice when the user hits ? */
	for (i = 0, f = functions; f->name != NULL; ++f, ++i)
		;
	qsort(functions, i, sizeof *functions, SortFnByName);

	if ((ret = lh_FUNCTION_new()) == NULL)
		return (NULL);

	for (f = functions; f->name != NULL; f++)
		(void) lh_FUNCTION_insert(ret, f);
	return (ret);
}
