/* $OpenBSD: s_time.c,v 1.13 2015/10/10 22:28:51 doug Exp $ */
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

/*-----------------------------------------
   s_time - SSL client connection timer program
   Written and donated by Larry Streepy <streepy@healthcare.com>
  -----------------------------------------*/

#include <sys/types.h>
#include <sys/socket.h>

#include <stdio.h>
#include <stdlib.h>
#include <limits.h>
#include <string.h>
#include <unistd.h>
#include <poll.h>

#include "apps.h"

#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>

#include "s_apps.h"

#define SSL_CONNECT_NAME	"localhost:4433"

#define BUFSIZZ 1024*10

#define MYBUFSIZ 1024*8

#undef min
#undef max
#define min(a,b) (((a) < (b)) ? (a) : (b))
#define max(a,b) (((a) > (b)) ? (a) : (b))

#define SECONDS	30
extern int verify_depth;
extern int verify_error;

static void s_time_usage(void);
static SSL *doConnection(SSL * scon);

static SSL_CTX *tm_ctx = NULL;
static const SSL_METHOD *s_time_meth = NULL;
static long bytes_read = 0;

struct {
	int bugs;
	char *CAfile;
	char *CApath;
	char *certfile;
	char *cipher;
	char *host;
	char *keyfile;
	int maxtime;
	int nbio;
	int no_shutdown;
	int perform;
	int verify;
	int verify_depth;
	char *www_path;
} s_time_config;

struct option s_time_options[] = {
	{
		.name = "bugs",
		.desc = "Enable workarounds for known SSL/TLS bugs",
		.type = OPTION_FLAG,
		.opt.flag = &s_time_config.bugs,
	},
	{
		.name = "CAfile",
		.argname = "file",
		.desc = "File containing trusted certificates in PEM format",
		.type = OPTION_ARG,
		.opt.arg = &s_time_config.CAfile,
	},
	{
		.name = "CApath",
		.argname = "path",
		.desc = "Directory containing trusted certificates",
		.type = OPTION_ARG,
		.opt.arg = &s_time_config.CApath,
	},
	{
		.name = "cert",
		.argname = "file",
		.desc = "Client certificate to use, if one is requested",
		.type = OPTION_ARG,
		.opt.arg = &s_time_config.certfile,
	},
	{
		.name = "cipher",
		.argname = "list",
		.desc = "List of cipher suites to send to the server",
		.type = OPTION_ARG,
		.opt.arg = &s_time_config.cipher,
	},
	{
		.name = "connect",
		.argname = "host:port",
		.desc = "Host and port to connect to (default "
		    SSL_CONNECT_NAME ")",
		.type = OPTION_ARG,
		.opt.arg = &s_time_config.host,
	},
	{
		.name = "key",
		.argname = "file",
		.desc = "Client private key to use, if one is required",
		.type = OPTION_ARG,
		.opt.arg = &s_time_config.keyfile,
	},
	{
		.name = "nbio",
		.desc = "Use non-blocking I/O",
		.type = OPTION_FLAG,
		.opt.flag = &s_time_config.nbio,
	},
	{
		.name = "new",
		.desc = "Use a new session ID for each connection",
		.type = OPTION_VALUE,
		.opt.value = &s_time_config.perform,
		.value = 1,
	},
	{
		.name = "no_shutdown",
		.desc = "Shut down the connection without notifying the server",
		.type = OPTION_FLAG,
		.opt.flag = &s_time_config.no_shutdown,
	},
	{
		.name = "reuse",
		.desc = "Reuse the same session ID for each connection",
		.type = OPTION_VALUE,
		.opt.value = &s_time_config.perform,
		.value = 2,
	},
	{
		.name = "time",
		.argname = "seconds",
		.desc = "Duration to perform timing tests for (default 30)",
		.type = OPTION_ARG_INT,
		.opt.value = &s_time_config.maxtime,
	},
	{
		.name = "verify",
		.argname = "depth",
		.desc = "Enable peer certificate verification with given depth",
		.type = OPTION_ARG_INT,
		.opt.value = &s_time_config.verify_depth,
	},
	{
		.name = "www",
		.argname = "page",
		.desc = "Page to GET from the server (default none)",
		.type = OPTION_ARG,
		.opt.arg = &s_time_config.www_path,
	},
	{ NULL },
};

static void
s_time_usage(void)
{
	fprintf(stderr,
	    "usage: s_time "
	    "[-bugs] [-CAfile file] [-CApath directory] [-cert file]\n"
	    "    [-cipher cipherlist] [-connect host:port] [-key keyfile]\n"
	    "    [-nbio] [-new] [-no_shutdown] [-reuse] [-time seconds]\n"
	    "    [-verify depth] [-www page]\n\n");
	options_usage(s_time_options);
}

/***********************************************************************
 * TIME - time functions
 */
#define START	0
#define STOP	1

static double
tm_Time_F(int s)
{
	return app_tminterval(s, 1);
}

/***********************************************************************
 * MAIN - main processing area for client
 *			real name depends on MONOLITH
 */
int
s_time_main(int argc, char **argv)
{
	double totalTime = 0.0;
	int nConn = 0;
	SSL *scon = NULL;
	long finishtime = 0;
	int ret = 1, i;
	char buf[1024 * 8];
	int ver;

	if (single_execution) {
		if (pledge("stdio inet rpath", NULL) == -1) {
			perror("pledge");
			exit(1);
		}
	}

	s_time_meth = SSLv23_client_method();

	verify_depth = 0;

	memset(&s_time_config, 0, sizeof(s_time_config));

	s_time_config.host = SSL_CONNECT_NAME;
	s_time_config.maxtime = SECONDS;
	s_time_config.perform = 3;
	s_time_config.verify = SSL_VERIFY_NONE;
	s_time_config.verify_depth = -1;

	if (options_parse(argc, argv, s_time_options, NULL, NULL) != 0) {
		s_time_usage();
		goto end;
	}

	if (s_time_config.verify_depth >= 0) {
		s_time_config.verify = SSL_VERIFY_PEER | SSL_VERIFY_CLIENT_ONCE;
		verify_depth = s_time_config.verify_depth;
		BIO_printf(bio_err, "verify depth is %d\n", verify_depth);
	}

	if (s_time_config.www_path != NULL &&
	    strlen(s_time_config.www_path) > MYBUFSIZ - 100) {
		BIO_printf(bio_err, "-www option too long\n");
		goto end;
	}

	if ((tm_ctx = SSL_CTX_new(s_time_meth)) == NULL)
		return (1);

	SSL_CTX_set_quiet_shutdown(tm_ctx, 1);

	if (s_time_config.bugs)
		SSL_CTX_set_options(tm_ctx, SSL_OP_ALL);

	if (s_time_config.cipher != NULL) {
		if (!SSL_CTX_set_cipher_list(tm_ctx, s_time_config.cipher)) {
			BIO_printf(bio_err, "error setting cipher list\n");
			ERR_print_errors(bio_err);
			goto end;
		}
	}

	SSL_CTX_set_verify(tm_ctx, s_time_config.verify, NULL);

	if (!set_cert_stuff(tm_ctx, s_time_config.certfile,
	    s_time_config.keyfile))
		goto end;

	if ((!SSL_CTX_load_verify_locations(tm_ctx, s_time_config.CAfile,
	    s_time_config.CApath)) ||
	    (!SSL_CTX_set_default_verify_paths(tm_ctx))) {
		/*
		 * BIO_printf(bio_err,"error setting default verify
		 * locations\n");
		 */
		ERR_print_errors(bio_err);
		/* goto end; */
	}

	if (!(s_time_config.perform & 1))
		goto next;
	printf("Collecting connection statistics for %d seconds\n",
	    s_time_config.maxtime);

	/* Loop and time how long it takes to make connections */

	bytes_read = 0;
	finishtime = (long) time(NULL) + s_time_config.maxtime;
	tm_Time_F(START);
	for (;;) {
		if (finishtime < (long) time(NULL))
			break;
		if ((scon = doConnection(NULL)) == NULL)
			goto end;

		if (s_time_config.www_path != NULL) {
			int retval = snprintf(buf, sizeof buf,
			    "GET %s HTTP/1.0\r\n\r\n", s_time_config.www_path);
			if ((size_t)retval >= sizeof buf) {
				fprintf(stderr, "URL too long\n");
				goto end;
			}
			SSL_write(scon, buf, strlen(buf));
			while ((i = SSL_read(scon, buf, sizeof(buf))) > 0)
				bytes_read += i;
		}
		if (s_time_config.no_shutdown)
			SSL_set_shutdown(scon, SSL_SENT_SHUTDOWN |
			    SSL_RECEIVED_SHUTDOWN);
		else
			SSL_shutdown(scon);
		shutdown(SSL_get_fd(scon), SHUT_RDWR);
		close(SSL_get_fd(scon));

		nConn += 1;
		if (SSL_session_reused(scon))
			ver = 'r';
		else {
			ver = SSL_version(scon);
			if (ver == TLS1_VERSION)
				ver = 't';
			else if (ver == SSL3_VERSION)
				ver = '3';
			else if (ver == SSL2_VERSION)
				ver = '2';
			else
				ver = '*';
		}
		fputc(ver, stdout);
		fflush(stdout);

		SSL_free(scon);
		scon = NULL;
	}
	totalTime += tm_Time_F(STOP);	/* Add the time for this iteration */

	i = (int) ((long) time(NULL) - finishtime + s_time_config.maxtime);
	printf("\n\n%d connections in %.2fs; %.2f connections/user sec, bytes read %ld\n", nConn, totalTime, ((double) nConn / totalTime), bytes_read);
	printf("%d connections in %ld real seconds, %ld bytes read per connection\n", nConn, (long) time(NULL) - finishtime + s_time_config.maxtime, bytes_read / nConn);

	/*
	 * Now loop and time connections using the same session id over and
	 * over
	 */

next:
	if (!(s_time_config.perform & 2))
		goto end;
	printf("\n\nNow timing with session id reuse.\n");

	/* Get an SSL object so we can reuse the session id */
	if ((scon = doConnection(NULL)) == NULL) {
		fprintf(stderr, "Unable to get connection\n");
		goto end;
	}
	if (s_time_config.www_path != NULL) {
		int retval = snprintf(buf, sizeof buf,
		    "GET %s HTTP/1.0\r\n\r\n", s_time_config.www_path);
		if ((size_t)retval >= sizeof buf) {
			fprintf(stderr, "URL too long\n");
			goto end;
		}
		SSL_write(scon, buf, strlen(buf));
		while (SSL_read(scon, buf, sizeof(buf)) > 0);
	}
	if (s_time_config.no_shutdown)
		SSL_set_shutdown(scon, SSL_SENT_SHUTDOWN |
		    SSL_RECEIVED_SHUTDOWN);
	else
		SSL_shutdown(scon);
	shutdown(SSL_get_fd(scon), SHUT_RDWR);
	close(SSL_get_fd(scon));

	nConn = 0;
	totalTime = 0.0;

	finishtime = (long) time(NULL) + s_time_config.maxtime;

	printf("starting\n");
	bytes_read = 0;
	tm_Time_F(START);

	for (;;) {
		if (finishtime < (long) time(NULL))
			break;
		if ((doConnection(scon)) == NULL)
			goto end;

		if (s_time_config.www_path) {
			int retval = snprintf(buf, sizeof buf,
			    "GET %s HTTP/1.0\r\n\r\n", s_time_config.www_path);
			if ((size_t)retval >= sizeof buf) {
				fprintf(stderr, "URL too long\n");
				goto end;
			}
			SSL_write(scon, buf, strlen(buf));
			while ((i = SSL_read(scon, buf, sizeof(buf))) > 0)
				bytes_read += i;
		}
		if (s_time_config.no_shutdown)
			SSL_set_shutdown(scon, SSL_SENT_SHUTDOWN |
			    SSL_RECEIVED_SHUTDOWN);
		else
			SSL_shutdown(scon);
		shutdown(SSL_get_fd(scon), SHUT_RDWR);
		close(SSL_get_fd(scon));

		nConn += 1;
		if (SSL_session_reused(scon))
			ver = 'r';
		else {
			ver = SSL_version(scon);
			if (ver == TLS1_VERSION)
				ver = 't';
			else if (ver == SSL3_VERSION)
				ver = '3';
			else if (ver == SSL2_VERSION)
				ver = '2';
			else
				ver = '*';
		}
		fputc(ver, stdout);
		fflush(stdout);
	}
	totalTime += tm_Time_F(STOP);	/* Add the time for this iteration */


	printf("\n\n%d connections in %.2fs; %.2f connections/user sec, bytes read %ld\n", nConn, totalTime, ((double) nConn / totalTime), bytes_read);
	printf("%d connections in %ld real seconds, %ld bytes read per connection\n", nConn, (long) time(NULL) - finishtime + s_time_config.maxtime, bytes_read / nConn);

	ret = 0;
end:
	if (scon != NULL)
		SSL_free(scon);

	if (tm_ctx != NULL) {
		SSL_CTX_free(tm_ctx);
		tm_ctx = NULL;
	}

	return (ret);
}

/***********************************************************************
 * doConnection - make a connection
 * Args:
 *		scon	= earlier ssl connection for session id, or NULL
 * Returns:
 *		SSL *	= the connection pointer.
 */
static SSL *
doConnection(SSL * scon)
{
	struct pollfd pfd[1];
	SSL *serverCon;
	BIO *conn;
	long verify_error;
	int i;

	if ((conn = BIO_new(BIO_s_connect())) == NULL)
		return (NULL);

/*	BIO_set_conn_port(conn,port);*/
	BIO_set_conn_hostname(conn, s_time_config.host);

	if (scon == NULL)
		serverCon = SSL_new(tm_ctx);
	else {
		serverCon = scon;
		SSL_set_connect_state(serverCon);
	}

	SSL_set_bio(serverCon, conn, conn);

	/* ok, lets connect */
	for (;;) {
		i = SSL_connect(serverCon);
		if (BIO_sock_should_retry(i)) {
			BIO_printf(bio_err, "DELAY\n");

			i = SSL_get_fd(serverCon);
			pfd[0].fd = i;
			pfd[0].events = POLLIN;
			poll(pfd, 1, -1);
			continue;
		}
		break;
	}
	if (i <= 0) {
		BIO_printf(bio_err, "ERROR\n");
		verify_error = SSL_get_verify_result(serverCon);
		if (verify_error != X509_V_OK)
			BIO_printf(bio_err, "verify error:%s\n",
			    X509_verify_cert_error_string(verify_error));
		else
			ERR_print_errors(bio_err);
		if (scon == NULL)
			SSL_free(serverCon);
		return NULL;
	}
	return serverCon;
}
