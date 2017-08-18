/* $OpenBSD: s_server.c,v 1.23 2015/12/01 12:04:51 jca Exp $ */
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
/* ====================================================================
 * Copyright 2002 Sun Microsystems, Inc. ALL RIGHTS RESERVED.
 * ECC cipher suite support in OpenSSL originally developed by
 * SUN MICROSYSTEMS, INC., and contributed to the OpenSSL project.
 */
/* ====================================================================
 * Copyright 2005 Nokia. All rights reserved.
 *
 * The portions of the attached software ("Contribution") is developed by
 * Nokia Corporation and is licensed pursuant to the OpenSSL open source
 * license.
 *
 * The Contribution, originally written by Mika Kousa and Pasi Eronen of
 * Nokia Corporation, consists of the "PSK" (Pre-Shared Key) ciphersuites
 * support (see RFC 4279) to OpenSSL.
 *
 * No patent licenses or other rights except those expressly stated in
 * the OpenSSL open source license shall be deemed granted or received
 * expressly, by implication, estoppel, or otherwise.
 *
 * No assurances are provided by Nokia that the Contribution does not
 * infringe the patent or other intellectual property rights of any third
 * party or that the license provides you with all the necessary rights
 * to make use of the Contribution.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" WITHOUT WARRANTY OF ANY KIND. IN
 * ADDITION TO THE DISCLAIMERS INCLUDED IN THE LICENSE, NOKIA
 * SPECIFICALLY DISCLAIMS ANY LIABILITY FOR CLAIMS BROUGHT BY YOU OR ANY
 * OTHER ENTITY BASED ON INFRINGEMENT OF INTELLECTUAL PROPERTY RIGHTS OR
 * OTHERWISE.
 */

/* Until the key-gen callbacks are modified to use newer prototypes, we allow
 * deprecated functions for openssl-internal code */
#ifdef OPENSSL_NO_DEPRECATED
#undef OPENSSL_NO_DEPRECATED
#endif

#include <sys/types.h>
#include <sys/socket.h>

#include <assert.h>
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <limits.h>
#include <string.h>
#include <unistd.h>
#include <poll.h>

#include "apps.h"

#include <openssl/bn.h>
#include <openssl/err.h>
#include <openssl/lhash.h>
#include <openssl/ocsp.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>

#ifndef OPENSSL_NO_DH
#include <openssl/dh.h>
#endif

#include <openssl/rsa.h>

#include "s_apps.h"
#include "timeouts.h"

static int sv_body(char *hostname, int s, unsigned char *context);
static int www_body(char *hostname, int s, unsigned char *context);
static void close_accept_socket(void);
static void sv_usage(void);
static int init_ssl_connection(SSL * s);
static void print_stats(BIO * bp, SSL_CTX * ctx);
static int
generate_session_id(const SSL * ssl, unsigned char *id,
    unsigned int *id_len);
#ifndef OPENSSL_NO_DH
static DH *load_dh_param(const char *dhfile);
#endif

static void s_server_init(void);

/* static int load_CA(SSL_CTX *ctx, char *file);*/

#define BUFSIZZ	16*1024
static int bufsize = BUFSIZZ;
static int accept_socket = -1;

#define TEST_CERT	"server.pem"
#define TEST_CERT2	"server2.pem"

static char *cipher = NULL;
static int s_server_verify = SSL_VERIFY_NONE;
static int s_server_session_id_context = 1;	/* anything will do */
static const char *s_cert_file = TEST_CERT, *s_key_file = NULL;
static const char *s_cert_file2 = TEST_CERT2, *s_key_file2 = NULL;
static char *s_dcert_file = NULL, *s_dkey_file = NULL;
static int s_nbio = 0;
static int s_nbio_test = 0;
int s_crlf = 0;
static SSL_CTX *ctx = NULL;
static SSL_CTX *ctx2 = NULL;
static int www = 0;

static BIO *bio_s_out = NULL;
static int s_debug = 0;
static int s_tlsextdebug = 0;
static int s_tlsextstatus = 0;
static int cert_status_cb(SSL * s, void *arg);
static int s_msg = 0;
static int s_quiet = 0;

static char *keymatexportlabel = NULL;
static int keymatexportlen = 20;

static const char *session_id_prefix = NULL;

static int enable_timeouts = 0;
static long socket_mtu;
#ifndef OPENSSL_NO_DTLS1
static int cert_chain = 0;
#endif




static void
s_server_init(void)
{
	accept_socket = -1;
	cipher = NULL;
	s_server_verify = SSL_VERIFY_NONE;
	s_dcert_file = NULL;
	s_dkey_file = NULL;
	s_cert_file = TEST_CERT;
	s_key_file = NULL;
	s_cert_file2 = TEST_CERT2;
	s_key_file2 = NULL;
	ctx2 = NULL;
	s_nbio = 0;
	s_nbio_test = 0;
	ctx = NULL;
	www = 0;

	bio_s_out = NULL;
	s_debug = 0;
	s_msg = 0;
	s_quiet = 0;
}

static void
sv_usage(void)
{
	BIO_printf(bio_err, "usage: s_server [args ...]\n");
	BIO_printf(bio_err, "\n");
	BIO_printf(bio_err, " -accept arg   - port to accept on (default is %d)\n", PORT);
	BIO_printf(bio_err, " -context arg  - set session ID context\n");
	BIO_printf(bio_err, " -verify arg   - turn on peer certificate verification\n");
	BIO_printf(bio_err, " -Verify arg   - turn on peer certificate verification, must have a cert.\n");
	BIO_printf(bio_err, " -cert arg     - certificate file to use\n");
	BIO_printf(bio_err, "                 (default is %s)\n", TEST_CERT);
	BIO_printf(bio_err, " -crl_check    - check the peer certificate has not been revoked by its CA.\n" \
	    "                 The CRL(s) are appended to the certificate file\n");
	BIO_printf(bio_err, " -crl_check_all - check the peer certificate has not been revoked by its CA\n" \
	    "                 or any other CRL in the CA chain. CRL(s) are appended to the\n" \
	    "                 the certificate file.\n");
	BIO_printf(bio_err, " -certform arg - certificate format (PEM or DER) PEM default\n");
	BIO_printf(bio_err, " -key arg      - Private Key file to use, in cert file if\n");
	BIO_printf(bio_err, "                 not specified (default is %s)\n", TEST_CERT);
	BIO_printf(bio_err, " -keyform arg  - key format (PEM or DER) PEM default\n");
	BIO_printf(bio_err, " -pass arg     - private key file pass phrase source\n");
	BIO_printf(bio_err, " -dcert arg    - second certificate file to use (usually for DSA)\n");
	BIO_printf(bio_err, " -dcertform x  - second certificate format (PEM or DER) PEM default\n");
	BIO_printf(bio_err, " -dkey arg     - second private key file to use (usually for DSA)\n");
	BIO_printf(bio_err, " -dkeyform arg - second key format (PEM or DER) PEM default\n");
	BIO_printf(bio_err, " -dpass arg    - second private key file pass phrase source\n");
	BIO_printf(bio_err, " -dhparam arg  - DH parameter file to use, in cert file if not specified\n");
	BIO_printf(bio_err, "                 or a default set of parameters is used\n");
	BIO_printf(bio_err, " -named_curve arg  - Elliptic curve name to use for ephemeral ECDH keys.\n" \
	    "                 Use \"openssl ecparam -list_curves\" for all names\n" \
	    "                 (default is nistp256).\n");
	BIO_printf(bio_err, " -nbio         - Run with non-blocking IO\n");
	BIO_printf(bio_err, " -nbio_test    - test with the non-blocking test bio\n");
	BIO_printf(bio_err, " -crlf         - convert LF from terminal into CRLF\n");
	BIO_printf(bio_err, " -debug        - Print more output\n");
	BIO_printf(bio_err, " -msg          - Show protocol messages\n");
	BIO_printf(bio_err, " -state        - Print the SSL states\n");
	BIO_printf(bio_err, " -CApath arg   - PEM format directory of CA's\n");
	BIO_printf(bio_err, " -CAfile arg   - PEM format file of CA's\n");
	BIO_printf(bio_err, " -nocert       - Don't use any certificates (Anon-DH)\n");
	BIO_printf(bio_err, " -cipher arg   - play with 'openssl ciphers' to see what goes here\n");
	BIO_printf(bio_err, " -serverpref   - Use server's cipher preferences\n");
	BIO_printf(bio_err, " -quiet        - Inhibit printing of session and certificate information\n");
	BIO_printf(bio_err, " -tls1_2       - Just talk TLSv1.2\n");
	BIO_printf(bio_err, " -tls1_1       - Just talk TLSv1.1\n");
	BIO_printf(bio_err, " -tls1         - Just talk TLSv1\n");
	BIO_printf(bio_err, " -dtls1        - Just talk DTLSv1\n");
	BIO_printf(bio_err, " -timeout      - Enable timeouts\n");
	BIO_printf(bio_err, " -mtu          - Set link layer MTU\n");
	BIO_printf(bio_err, " -chain        - Read a certificate chain\n");
	BIO_printf(bio_err, " -no_ssl2      - Just disable SSLv2\n");
	BIO_printf(bio_err, " -no_ssl3      - Just disable SSLv3\n");
	BIO_printf(bio_err, " -no_tls1      - Just disable TLSv1\n");
	BIO_printf(bio_err, " -no_tls1_1    - Just disable TLSv1.1\n");
	BIO_printf(bio_err, " -no_tls1_2    - Just disable TLSv1.2\n");
#ifndef OPENSSL_NO_DH
	BIO_printf(bio_err, " -no_dhe       - Disable ephemeral DH\n");
#endif
	BIO_printf(bio_err, " -no_ecdhe     - Disable ephemeral ECDH\n");
	BIO_printf(bio_err, " -bugs         - Turn on SSL bug compatibility\n");
	BIO_printf(bio_err, " -www          - Respond to a 'GET /' with a status page\n");
	BIO_printf(bio_err, " -WWW          - Respond to a 'GET /<path> HTTP/1.0' with file ./<path>\n");
	BIO_printf(bio_err, " -HTTP         - Respond to a 'GET /<path> HTTP/1.0' with file ./<path>\n");
	BIO_printf(bio_err, "                 with the assumption it contains a complete HTTP response.\n");
	BIO_printf(bio_err, " -id_prefix arg - Generate SSL/TLS session IDs prefixed by 'arg'\n");
	BIO_printf(bio_err, " -servername host - servername for HostName TLS extension\n");
	BIO_printf(bio_err, " -servername_fatal - on mismatch send fatal alert (default warning alert)\n");
	BIO_printf(bio_err, " -cert2 arg    - certificate file to use for servername\n");
	BIO_printf(bio_err, "                 (default is %s)\n", TEST_CERT2);
	BIO_printf(bio_err, " -key2 arg     - Private Key file to use for servername, in cert file if\n");
	BIO_printf(bio_err, "                 not specified (default is %s)\n", TEST_CERT2);
	BIO_printf(bio_err, " -tlsextdebug  - hex dump of all TLS extensions received\n");
	BIO_printf(bio_err, " -no_ticket    - disable use of RFC4507bis session tickets\n");
	BIO_printf(bio_err, " -nextprotoneg arg - set the advertised protocols for the NPN extension (comma-separated list)\n");
	BIO_printf(bio_err," -alpn arg  - set the advertised protocols for the ALPN extension (comma-separated list)\n");
#ifndef OPENSSL_NO_SRTP
	BIO_printf(bio_err, " -use_srtp profiles - Offer SRTP key management with a colon-separated profile list\n");
#endif
	BIO_printf(bio_err, " -keymatexport label   - Export keying material using label\n");
	BIO_printf(bio_err, " -keymatexportlen len  - Export len bytes of keying material (default 20)\n");
}

static int local_argc = 0;
static char **local_argv;


/* This is a context that we pass to callbacks */
typedef struct tlsextctx_st {
	char *servername;
	BIO *biodebug;
	int extension_error;
} tlsextctx;


static int
ssl_servername_cb(SSL * s, int *ad, void *arg)
{
	tlsextctx *p = (tlsextctx *) arg;
	const char *servername = SSL_get_servername(s, TLSEXT_NAMETYPE_host_name);
	if (servername && p->biodebug)
		BIO_printf(p->biodebug, "Hostname in TLS extension: \"%s\"\n", servername);

	if (!p->servername)
		return SSL_TLSEXT_ERR_NOACK;

	if (servername) {
		if (strcmp(servername, p->servername))
			return p->extension_error;
		if (ctx2) {
			BIO_printf(p->biodebug, "Switching server context.\n");
			SSL_set_SSL_CTX(s, ctx2);
		}
	}
	return SSL_TLSEXT_ERR_OK;
}

/* Structure passed to cert status callback */

typedef struct tlsextstatusctx_st {
	/* Default responder to use */
	char *host, *path, *port;
	int use_ssl;
	int timeout;
	BIO *err;
	int verbose;
} tlsextstatusctx;

static tlsextstatusctx tlscstatp = {NULL, NULL, NULL, 0, -1, NULL, 0};

/* Certificate Status callback. This is called when a client includes a
 * certificate status request extension.
 *
 * This is a simplified version. It examines certificates each time and
 * makes one OCSP responder query for each request.
 *
 * A full version would store details such as the OCSP certificate IDs and
 * minimise the number of OCSP responses by caching them until they were
 * considered "expired".
 */

static int
cert_status_cb(SSL * s, void *arg)
{
	tlsextstatusctx *srctx = arg;
	BIO *err = srctx->err;
	char *host, *port, *path;
	int use_ssl;
	unsigned char *rspder = NULL;
	int rspderlen;
	STACK_OF(OPENSSL_STRING) * aia = NULL;
	X509 *x = NULL;
	X509_STORE_CTX inctx;
	X509_OBJECT obj;
	OCSP_REQUEST *req = NULL;
	OCSP_RESPONSE *resp = NULL;
	OCSP_CERTID *id = NULL;
	STACK_OF(X509_EXTENSION) * exts;
	int ret = SSL_TLSEXT_ERR_NOACK;
	int i;

	if (srctx->verbose)
		BIO_puts(err, "cert_status: callback called\n");
	/* Build up OCSP query from server certificate */
	x = SSL_get_certificate(s);
	aia = X509_get1_ocsp(x);
	if (aia) {
		if (!OCSP_parse_url(sk_OPENSSL_STRING_value(aia, 0),
			&host, &port, &path, &use_ssl)) {
			BIO_puts(err, "cert_status: can't parse AIA URL\n");
			goto err;
		}
		if (srctx->verbose)
			BIO_printf(err, "cert_status: AIA URL: %s\n",
			    sk_OPENSSL_STRING_value(aia, 0));
	} else {
		if (!srctx->host) {
			BIO_puts(srctx->err, "cert_status: no AIA and no default responder URL\n");
			goto done;
		}
		host = srctx->host;
		path = srctx->path;
		port = srctx->port;
		use_ssl = srctx->use_ssl;
	}

	if (!X509_STORE_CTX_init(&inctx,
		SSL_CTX_get_cert_store(SSL_get_SSL_CTX(s)),
		NULL, NULL))
		goto err;
	if (X509_STORE_get_by_subject(&inctx, X509_LU_X509,
		X509_get_issuer_name(x), &obj) <= 0) {
		BIO_puts(err, "cert_status: Can't retrieve issuer certificate.\n");
		X509_STORE_CTX_cleanup(&inctx);
		goto done;
	}
	req = OCSP_REQUEST_new();
	if (!req)
		goto err;
	id = OCSP_cert_to_id(NULL, x, obj.data.x509);
	X509_free(obj.data.x509);
	X509_STORE_CTX_cleanup(&inctx);
	if (!id)
		goto err;
	if (!OCSP_request_add0_id(req, id))
		goto err;
	id = NULL;
	/* Add any extensions to the request */
	SSL_get_tlsext_status_exts(s, &exts);
	for (i = 0; i < sk_X509_EXTENSION_num(exts); i++) {
		X509_EXTENSION *ext = sk_X509_EXTENSION_value(exts, i);
		if (!OCSP_REQUEST_add_ext(req, ext, -1))
			goto err;
	}
	resp = process_responder(err, req, host, path, port, use_ssl, NULL,
	    srctx->timeout);
	if (!resp) {
		BIO_puts(err, "cert_status: error querying responder\n");
		goto done;
	}
	rspderlen = i2d_OCSP_RESPONSE(resp, &rspder);
	if (rspderlen <= 0)
		goto err;
	SSL_set_tlsext_status_ocsp_resp(s, rspder, rspderlen);
	if (srctx->verbose) {
		BIO_puts(err, "cert_status: ocsp response sent:\n");
		OCSP_RESPONSE_print(err, resp, 2);
	}
	ret = SSL_TLSEXT_ERR_OK;
done:
	if (ret != SSL_TLSEXT_ERR_OK)
		ERR_print_errors(err);
	if (aia) {
		free(host);
		free(path);
		free(port);
		X509_email_free(aia);
	}
	if (id)
		OCSP_CERTID_free(id);
	if (req)
		OCSP_REQUEST_free(req);
	if (resp)
		OCSP_RESPONSE_free(resp);
	return ret;
err:
	ret = SSL_TLSEXT_ERR_ALERT_FATAL;
	goto done;
}

/* This is the context that we pass to next_proto_cb */
typedef struct tlsextnextprotoctx_st {
	unsigned char *data;
	unsigned int len;
} tlsextnextprotoctx;

static int
next_proto_cb(SSL * s, const unsigned char **data, unsigned int *len, void *arg)
{
	tlsextnextprotoctx *next_proto = arg;

	*data = next_proto->data;
	*len = next_proto->len;

	return SSL_TLSEXT_ERR_OK;
}


/* This the context that we pass to alpn_cb */
typedef struct tlsextalpnctx_st {
	unsigned char *data;
	unsigned short len;
} tlsextalpnctx;

static int
alpn_cb(SSL *s, const unsigned char **out, unsigned char *outlen,
    const unsigned char *in, unsigned int inlen, void *arg)
{
	tlsextalpnctx *alpn_ctx = arg;

	if (!s_quiet) {
		/* We can assume that in is syntactically valid. */
		unsigned i;

		BIO_printf(bio_s_out,
		    "ALPN protocols advertised by the client: ");
		for (i = 0; i < inlen; ) {
			if (i)
				BIO_write(bio_s_out, ", ", 2);
			BIO_write(bio_s_out, &in[i + 1], in[i]);
			i += in[i] + 1;
		}
		BIO_write(bio_s_out, "\n", 1);
	}

	if (SSL_select_next_proto((unsigned char**)out, outlen, alpn_ctx->data,
	    alpn_ctx->len, in, inlen) != OPENSSL_NPN_NEGOTIATED)
		return (SSL_TLSEXT_ERR_NOACK);

	if (!s_quiet) {
		BIO_printf(bio_s_out, "ALPN protocols selected: ");
		BIO_write(bio_s_out, *out, *outlen);
		BIO_write(bio_s_out, "\n", 1);
	}

	return (SSL_TLSEXT_ERR_OK);
}

#ifndef OPENSSL_NO_SRTP
static char *srtp_profiles = NULL;
#endif

int
s_server_main(int argc, char *argv[])
{
	X509_VERIFY_PARAM *vpm = NULL;
	int badarg = 0;
	short port = PORT;
	char *CApath = NULL, *CAfile = NULL;
	unsigned char *context = NULL;
	char *dhfile = NULL;
	char *named_curve = NULL;
	int badop = 0, bugs = 0;
	int ret = 1;
	int off = 0;
	int no_dhe = 0, no_ecdhe = 0, nocert = 0;
	int state = 0;
	const SSL_METHOD *meth = NULL;
	int socket_type = SOCK_STREAM;
	int s_cert_format = FORMAT_PEM, s_key_format = FORMAT_PEM;
	char *passarg = NULL, *pass = NULL;
	char *dpassarg = NULL, *dpass = NULL;
	int s_dcert_format = FORMAT_PEM, s_dkey_format = FORMAT_PEM;
	X509 *s_cert = NULL, *s_dcert = NULL;
	EVP_PKEY *s_key = NULL, *s_dkey = NULL;
	int no_cache = 0;
	const char *errstr = NULL;
	EVP_PKEY *s_key2 = NULL;
	X509 *s_cert2 = NULL;
	tlsextctx tlsextcbp = {NULL, NULL, SSL_TLSEXT_ERR_ALERT_WARNING};
	const char *next_proto_neg_in = NULL;
	tlsextnextprotoctx next_proto = { NULL, 0 };
	const char *alpn_in = NULL;
	tlsextalpnctx alpn_ctx = { NULL, 0 };

	if (single_execution) {
		if (pledge("stdio inet dns rpath tty", NULL) == -1) {
			perror("pledge");
			exit(1);
		}
	}

	meth = SSLv23_server_method();

	local_argc = argc;
	local_argv = argv;

	s_server_init();

	verify_depth = 0;
	s_nbio = 0;
	s_nbio_test = 0;

	argc--;
	argv++;

	while (argc >= 1) {
		if ((strcmp(*argv, "-port") == 0) ||
		    (strcmp(*argv, "-accept") == 0)) {
			if (--argc < 1)
				goto bad;
			if (!extract_port(*(++argv), &port))
				goto bad;
		} else if (strcmp(*argv, "-verify") == 0) {
			s_server_verify = SSL_VERIFY_PEER | SSL_VERIFY_CLIENT_ONCE;
			if (--argc < 1)
				goto bad;
			verify_depth = strtonum(*(++argv), 0, INT_MAX, &errstr);
			if (errstr)
				goto bad;
			BIO_printf(bio_err, "verify depth is %d\n", verify_depth);
		} else if (strcmp(*argv, "-Verify") == 0) {
			s_server_verify = SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT |
			    SSL_VERIFY_CLIENT_ONCE;
			if (--argc < 1)
				goto bad;
			verify_depth = strtonum(*(++argv), 0, INT_MAX, &errstr);
			if (errstr)
				goto bad;
			BIO_printf(bio_err, "verify depth is %d, must return a certificate\n", verify_depth);
		} else if (strcmp(*argv, "-context") == 0) {
			if (--argc < 1)
				goto bad;
			context = (unsigned char *) *(++argv);
		} else if (strcmp(*argv, "-cert") == 0) {
			if (--argc < 1)
				goto bad;
			s_cert_file = *(++argv);
		} else if (strcmp(*argv, "-certform") == 0) {
			if (--argc < 1)
				goto bad;
			s_cert_format = str2fmt(*(++argv));
		} else if (strcmp(*argv, "-key") == 0) {
			if (--argc < 1)
				goto bad;
			s_key_file = *(++argv);
		} else if (strcmp(*argv, "-keyform") == 0) {
			if (--argc < 1)
				goto bad;
			s_key_format = str2fmt(*(++argv));
		} else if (strcmp(*argv, "-pass") == 0) {
			if (--argc < 1)
				goto bad;
			passarg = *(++argv);
		} else if (strcmp(*argv, "-dhparam") == 0) {
			if (--argc < 1)
				goto bad;
			dhfile = *(++argv);
		}
		else if (strcmp(*argv, "-named_curve") == 0) {
			if (--argc < 1)
				goto bad;
			named_curve = *(++argv);
		}
		else if (strcmp(*argv, "-dcertform") == 0) {
			if (--argc < 1)
				goto bad;
			s_dcert_format = str2fmt(*(++argv));
		} else if (strcmp(*argv, "-dcert") == 0) {
			if (--argc < 1)
				goto bad;
			s_dcert_file = *(++argv);
		} else if (strcmp(*argv, "-dkeyform") == 0) {
			if (--argc < 1)
				goto bad;
			s_dkey_format = str2fmt(*(++argv));
		} else if (strcmp(*argv, "-dpass") == 0) {
			if (--argc < 1)
				goto bad;
			dpassarg = *(++argv);
		} else if (strcmp(*argv, "-dkey") == 0) {
			if (--argc < 1)
				goto bad;
			s_dkey_file = *(++argv);
		} else if (strcmp(*argv, "-nocert") == 0) {
			nocert = 1;
		} else if (strcmp(*argv, "-CApath") == 0) {
			if (--argc < 1)
				goto bad;
			CApath = *(++argv);
		} else if (strcmp(*argv, "-no_cache") == 0)
			no_cache = 1;
		else if (args_verify(&argv, &argc, &badarg, bio_err, &vpm)) {
			if (badarg)
				goto bad;
			continue;
		} else if (strcmp(*argv, "-verify_return_error") == 0)
			verify_return_error = 1;
		else if (strcmp(*argv, "-serverpref") == 0) {
			off |= SSL_OP_CIPHER_SERVER_PREFERENCE;
		} else if (strcmp(*argv, "-legacy_renegotiation") == 0)
			; /* no-op */
		else if (strcmp(*argv, "-cipher") == 0) {
			if (--argc < 1)
				goto bad;
			cipher = *(++argv);
		} else if (strcmp(*argv, "-CAfile") == 0) {
			if (--argc < 1)
				goto bad;
			CAfile = *(++argv);
		}
		else if (strcmp(*argv, "-nbio") == 0) {
			s_nbio = 1;
		}
		else if (strcmp(*argv, "-nbio_test") == 0) {
			s_nbio = 1;
			s_nbio_test = 1;
		} else if (strcmp(*argv, "-debug") == 0) {
			s_debug = 1;
		}
		else if (strcmp(*argv, "-tlsextdebug") == 0)
			s_tlsextdebug = 1;
		else if (strcmp(*argv, "-status") == 0)
			s_tlsextstatus = 1;
		else if (strcmp(*argv, "-status_verbose") == 0) {
			s_tlsextstatus = 1;
			tlscstatp.verbose = 1;
		} else if (!strcmp(*argv, "-status_timeout")) {
			s_tlsextstatus = 1;
			if (--argc < 1)
				goto bad;
			tlscstatp.timeout = strtonum(*(++argv), 0, INT_MAX, &errstr);
			if (errstr)
				goto bad;
		} else if (!strcmp(*argv, "-status_url")) {
			s_tlsextstatus = 1;
			if (--argc < 1)
				goto bad;
			if (!OCSP_parse_url(*(++argv),
				&tlscstatp.host,
				&tlscstatp.port,
				&tlscstatp.path,
				&tlscstatp.use_ssl)) {
				BIO_printf(bio_err, "Error parsing URL\n");
				goto bad;
			}
		}
		else if (strcmp(*argv, "-msg") == 0) {
			s_msg = 1;
		} else if (strcmp(*argv, "-state") == 0) {
			state = 1;
		} else if (strcmp(*argv, "-crlf") == 0) {
			s_crlf = 1;
		} else if (strcmp(*argv, "-quiet") == 0) {
			s_quiet = 1;
		} else if (strcmp(*argv, "-bugs") == 0) {
			bugs = 1;
		} else if (strcmp(*argv, "-no_tmp_rsa") == 0) {
			/* No-op. */
		} else if (strcmp(*argv, "-no_dhe") == 0) {
			no_dhe = 1;
		} else if (strcmp(*argv, "-no_ecdhe") == 0) {
			no_ecdhe = 1;
		} else if (strcmp(*argv, "-www") == 0) {
			www = 1;
		} else if (strcmp(*argv, "-WWW") == 0) {
			www = 2;
		} else if (strcmp(*argv, "-HTTP") == 0) {
			www = 3;
		} else if (strcmp(*argv, "-no_ssl2") == 0) {
			off |= SSL_OP_NO_SSLv2;
		} else if (strcmp(*argv, "-no_ssl3") == 0) {
			off |= SSL_OP_NO_SSLv3;
		} else if (strcmp(*argv, "-no_tls1") == 0) {
			off |= SSL_OP_NO_TLSv1;
		} else if (strcmp(*argv, "-no_tls1_1") == 0) {
			off |= SSL_OP_NO_TLSv1_1;
		} else if (strcmp(*argv, "-no_tls1_2") == 0) {
			off |= SSL_OP_NO_TLSv1_2;
		} else if (strcmp(*argv, "-no_comp") == 0) {
			off |= SSL_OP_NO_COMPRESSION;
		} else if (strcmp(*argv, "-no_ticket") == 0) {
			off |= SSL_OP_NO_TICKET;
		} else if (strcmp(*argv, "-tls1") == 0) {
			meth = TLSv1_server_method();
		} else if (strcmp(*argv, "-tls1_1") == 0) {
			meth = TLSv1_1_server_method();
		} else if (strcmp(*argv, "-tls1_2") == 0) {
			meth = TLSv1_2_server_method();
		}
#ifndef OPENSSL_NO_DTLS1
		else if (strcmp(*argv, "-dtls1") == 0) {
			meth = DTLSv1_server_method();
			socket_type = SOCK_DGRAM;
		} else if (strcmp(*argv, "-timeout") == 0)
			enable_timeouts = 1;
		else if (strcmp(*argv, "-mtu") == 0) {
			if (--argc < 1)
				goto bad;
			socket_mtu = strtonum(*(++argv), 0, LONG_MAX, &errstr);
			if (errstr)
				goto bad;
		} else if (strcmp(*argv, "-chain") == 0)
			cert_chain = 1;
#endif
		else if (strcmp(*argv, "-id_prefix") == 0) {
			if (--argc < 1)
				goto bad;
			session_id_prefix = *(++argv);
		}
		else if (strcmp(*argv, "-servername") == 0) {
			if (--argc < 1)
				goto bad;
			tlsextcbp.servername = *(++argv);
		} else if (strcmp(*argv, "-servername_fatal") == 0) {
			tlsextcbp.extension_error = SSL_TLSEXT_ERR_ALERT_FATAL;
		} else if (strcmp(*argv, "-cert2") == 0) {
			if (--argc < 1)
				goto bad;
			s_cert_file2 = *(++argv);
		} else if (strcmp(*argv, "-key2") == 0) {
			if (--argc < 1)
				goto bad;
			s_key_file2 = *(++argv);
		}
		else if (strcmp(*argv, "-nextprotoneg") == 0) {
			if (--argc < 1)
				goto bad;
			next_proto_neg_in = *(++argv);
		}
		else if	(strcmp(*argv,"-alpn") == 0) {
			if (--argc < 1)
				goto bad;
			alpn_in = *(++argv);
		}
#ifndef OPENSSL_NO_SRTP
		else if (strcmp(*argv, "-use_srtp") == 0) {
			if (--argc < 1)
				goto bad;
			srtp_profiles = *(++argv);
		}
#endif
		else if (strcmp(*argv, "-keymatexport") == 0) {
			if (--argc < 1)
				goto bad;
			keymatexportlabel = *(++argv);
		} else if (strcmp(*argv, "-keymatexportlen") == 0) {
			if (--argc < 1)
				goto bad;
			keymatexportlen = strtonum(*(++argv), 1, INT_MAX, &errstr);
			if (errstr)
				goto bad;
		} else {
			BIO_printf(bio_err, "unknown option %s\n", *argv);
			badop = 1;
			break;
		}
		argc--;
		argv++;
	}
	if (badop) {
bad:
		if (errstr)
			BIO_printf(bio_err, "invalid argument %s: %s\n",
			    *argv, errstr);
		else
			sv_usage();
		goto end;
	}

	if (!app_passwd(bio_err, passarg, dpassarg, &pass, &dpass)) {
		BIO_printf(bio_err, "Error getting password\n");
		goto end;
	}
	if (s_key_file == NULL)
		s_key_file = s_cert_file;
	if (s_key_file2 == NULL)
		s_key_file2 = s_cert_file2;

	if (nocert == 0) {
		s_key = load_key(bio_err, s_key_file, s_key_format, 0, pass,
		    "server certificate private key file");
		if (!s_key) {
			ERR_print_errors(bio_err);
			goto end;
		}
		s_cert = load_cert(bio_err, s_cert_file, s_cert_format,
		    NULL, "server certificate file");

		if (!s_cert) {
			ERR_print_errors(bio_err);
			goto end;
		}
		if (tlsextcbp.servername) {
			s_key2 = load_key(bio_err, s_key_file2, s_key_format, 0, pass,
			    "second server certificate private key file");
			if (!s_key2) {
				ERR_print_errors(bio_err);
				goto end;
			}
			s_cert2 = load_cert(bio_err, s_cert_file2, s_cert_format,
			    NULL, "second server certificate file");

			if (!s_cert2) {
				ERR_print_errors(bio_err);
				goto end;
			}
		}
	}
	if (next_proto_neg_in) {
		unsigned short len;
		next_proto.data = next_protos_parse(&len, next_proto_neg_in);
		if (next_proto.data == NULL)
			goto end;
		next_proto.len = len;
	} else {
		next_proto.data = NULL;
	}
	alpn_ctx.data = NULL;
	if (alpn_in) {
		unsigned short len;
		alpn_ctx.data = next_protos_parse(&len, alpn_in);
		if (alpn_ctx.data == NULL)
			goto end;
		alpn_ctx.len = len;
	}

	if (s_dcert_file) {

		if (s_dkey_file == NULL)
			s_dkey_file = s_dcert_file;

		s_dkey = load_key(bio_err, s_dkey_file, s_dkey_format,
		    0, dpass, "second certificate private key file");
		if (!s_dkey) {
			ERR_print_errors(bio_err);
			goto end;
		}
		s_dcert = load_cert(bio_err, s_dcert_file, s_dcert_format,
		    NULL, "second server certificate file");

		if (!s_dcert) {
			ERR_print_errors(bio_err);
			goto end;
		}
	}
	if (bio_s_out == NULL) {
		if (s_quiet && !s_debug && !s_msg) {
			bio_s_out = BIO_new(BIO_s_null());
		} else {
			if (bio_s_out == NULL)
				bio_s_out = BIO_new_fp(stdout, BIO_NOCLOSE);
		}
	}
	if (nocert) {
		s_cert_file = NULL;
		s_key_file = NULL;
		s_dcert_file = NULL;
		s_dkey_file = NULL;
		s_cert_file2 = NULL;
		s_key_file2 = NULL;
	}
	ctx = SSL_CTX_new(meth);
	if (ctx == NULL) {
		ERR_print_errors(bio_err);
		goto end;
	}
	if (session_id_prefix) {
		if (strlen(session_id_prefix) >= 32)
			BIO_printf(bio_err,
			    "warning: id_prefix is too long, only one new session will be possible\n");
		else if (strlen(session_id_prefix) >= 16)
			BIO_printf(bio_err,
			    "warning: id_prefix is too long if you use SSLv2\n");
		if (!SSL_CTX_set_generate_session_id(ctx, generate_session_id)) {
			BIO_printf(bio_err, "error setting 'id_prefix'\n");
			ERR_print_errors(bio_err);
			goto end;
		}
		BIO_printf(bio_err, "id_prefix '%s' set.\n", session_id_prefix);
	}
	SSL_CTX_set_quiet_shutdown(ctx, 1);
	if (bugs)
		SSL_CTX_set_options(ctx, SSL_OP_ALL);
	SSL_CTX_set_options(ctx, off);
	/*
	 * DTLS: partial reads end up discarding unread UDP bytes :-( Setting
	 * read ahead solves this problem.
	 */
	if (socket_type == SOCK_DGRAM)
		SSL_CTX_set_read_ahead(ctx, 1);

	if (state)
		SSL_CTX_set_info_callback(ctx, apps_ssl_info_callback);
	if (no_cache)
		SSL_CTX_set_session_cache_mode(ctx, SSL_SESS_CACHE_OFF);
	else
		SSL_CTX_sess_set_cache_size(ctx, 128);

#ifndef OPENSSL_NO_SRTP
	if (srtp_profiles != NULL)
		SSL_CTX_set_tlsext_use_srtp(ctx, srtp_profiles);
#endif


	if ((!SSL_CTX_load_verify_locations(ctx, CAfile, CApath)) ||
	    (!SSL_CTX_set_default_verify_paths(ctx))) {
		/* BIO_printf(bio_err,"X509_load_verify_locations\n"); */
		ERR_print_errors(bio_err);
		/* goto end; */
	}
	if (vpm)
		SSL_CTX_set1_param(ctx, vpm);

	if (s_cert2) {
		ctx2 = SSL_CTX_new(meth);
		if (ctx2 == NULL) {
			ERR_print_errors(bio_err);
			goto end;
		}
	}
	if (ctx2) {
		BIO_printf(bio_s_out, "Setting secondary ctx parameters\n");

		if (session_id_prefix) {
			if (strlen(session_id_prefix) >= 32)
				BIO_printf(bio_err,
				    "warning: id_prefix is too long, only one new session will be possible\n");
			else if (strlen(session_id_prefix) >= 16)
				BIO_printf(bio_err,
				    "warning: id_prefix is too long if you use SSLv2\n");
			if (!SSL_CTX_set_generate_session_id(ctx2, generate_session_id)) {
				BIO_printf(bio_err, "error setting 'id_prefix'\n");
				ERR_print_errors(bio_err);
				goto end;
			}
			BIO_printf(bio_err, "id_prefix '%s' set.\n", session_id_prefix);
		}
		SSL_CTX_set_quiet_shutdown(ctx2, 1);
		if (bugs)
			SSL_CTX_set_options(ctx2, SSL_OP_ALL);
		SSL_CTX_set_options(ctx2, off);
		/*
		 * DTLS: partial reads end up discarding unread UDP bytes :-(
		 * Setting read ahead solves this problem.
		 */
		if (socket_type == SOCK_DGRAM)
			SSL_CTX_set_read_ahead(ctx2, 1);

		if (state)
			SSL_CTX_set_info_callback(ctx2, apps_ssl_info_callback);

		if (no_cache)
			SSL_CTX_set_session_cache_mode(ctx2, SSL_SESS_CACHE_OFF);
		else
			SSL_CTX_sess_set_cache_size(ctx2, 128);

		if ((!SSL_CTX_load_verify_locations(ctx2, CAfile, CApath)) ||
		    (!SSL_CTX_set_default_verify_paths(ctx2))) {
			ERR_print_errors(bio_err);
		}
		if (vpm)
			SSL_CTX_set1_param(ctx2, vpm);
	}
	if (next_proto.data)
		SSL_CTX_set_next_protos_advertised_cb(ctx, next_proto_cb, &next_proto);
	if (alpn_ctx.data)
		SSL_CTX_set_alpn_select_cb(ctx, alpn_cb, &alpn_ctx);

#ifndef OPENSSL_NO_DH
	if (!no_dhe) {
		DH *dh = NULL;

		if (dhfile)
			dh = load_dh_param(dhfile);
		else if (s_cert_file)
			dh = load_dh_param(s_cert_file);

		if (dh != NULL)
			BIO_printf(bio_s_out, "Setting temp DH parameters\n");
		else
			BIO_printf(bio_s_out, "Using auto DH parameters\n");
		(void) BIO_flush(bio_s_out);

		if (dh == NULL)
			SSL_CTX_set_dh_auto(ctx, 1);
		else if (!SSL_CTX_set_tmp_dh(ctx, dh)) {
			BIO_printf(bio_err,
			    "Error setting temp DH parameters\n");
			ERR_print_errors(bio_err);
			DH_free(dh);
			goto end;
		}

		if (ctx2) {
			if (!dhfile) {
				DH *dh2 = NULL;

				if (s_cert_file2 != NULL)
					dh2 = load_dh_param(s_cert_file2);
				if (dh2 != NULL) {
					BIO_printf(bio_s_out, "Setting temp DH parameters\n");
					(void) BIO_flush(bio_s_out);

					DH_free(dh);
					dh = dh2;
				}
			}
			if (dh == NULL)
				SSL_CTX_set_dh_auto(ctx2, 1);
			else if (!SSL_CTX_set_tmp_dh(ctx2, dh)) {
				BIO_printf(bio_err,
				    "Error setting temp DH parameters\n");
				ERR_print_errors(bio_err);
				DH_free(dh);
				goto end;
			}
		}
		DH_free(dh);
	}
#endif

	if (!no_ecdhe) {
		EC_KEY *ecdh = NULL;

		if (named_curve) {
			int nid = OBJ_sn2nid(named_curve);

			if (nid == 0) {
				BIO_printf(bio_err, "unknown curve name (%s)\n",
				    named_curve);
				goto end;
			}
			ecdh = EC_KEY_new_by_curve_name(nid);
			if (ecdh == NULL) {
				BIO_printf(bio_err, "unable to create curve (%s)\n",
				    named_curve);
				goto end;
			}
		}
		if (ecdh != NULL) {
			BIO_printf(bio_s_out, "Setting temp ECDH parameters\n");
		} else {
			BIO_printf(bio_s_out, "Using default temp ECDH parameters\n");
			ecdh = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
			if (ecdh == NULL) {
				BIO_printf(bio_err, "unable to create curve (nistp256)\n");
				goto end;
			}
		}
		(void) BIO_flush(bio_s_out);

		SSL_CTX_set_tmp_ecdh(ctx, ecdh);
		if (ctx2)
			SSL_CTX_set_tmp_ecdh(ctx2, ecdh);
		EC_KEY_free(ecdh);
	}

	if (!set_cert_key_stuff(ctx, s_cert, s_key))
		goto end;
	if (ctx2 && !set_cert_key_stuff(ctx2, s_cert2, s_key2))
		goto end;
	if (s_dcert != NULL) {
		if (!set_cert_key_stuff(ctx, s_dcert, s_dkey))
			goto end;
	}

	if (cipher != NULL) {
		if (!SSL_CTX_set_cipher_list(ctx, cipher)) {
			BIO_printf(bio_err, "error setting cipher list\n");
			ERR_print_errors(bio_err);
			goto end;
		}
		if (ctx2 && !SSL_CTX_set_cipher_list(ctx2, cipher)) {
			BIO_printf(bio_err, "error setting cipher list\n");
			ERR_print_errors(bio_err);
			goto end;
		}
	}
	SSL_CTX_set_verify(ctx, s_server_verify, verify_callback);
	SSL_CTX_set_session_id_context(ctx, (void *) &s_server_session_id_context,
	    sizeof s_server_session_id_context);

	/* Set DTLS cookie generation and verification callbacks */
	SSL_CTX_set_cookie_generate_cb(ctx, generate_cookie_callback);
	SSL_CTX_set_cookie_verify_cb(ctx, verify_cookie_callback);

	if (ctx2) {
		SSL_CTX_set_verify(ctx2, s_server_verify, verify_callback);
		SSL_CTX_set_session_id_context(ctx2, (void *) &s_server_session_id_context,
		    sizeof s_server_session_id_context);

		tlsextcbp.biodebug = bio_s_out;
		SSL_CTX_set_tlsext_servername_callback(ctx2, ssl_servername_cb);
		SSL_CTX_set_tlsext_servername_arg(ctx2, &tlsextcbp);
		SSL_CTX_set_tlsext_servername_callback(ctx, ssl_servername_cb);
		SSL_CTX_set_tlsext_servername_arg(ctx, &tlsextcbp);
	}

	if (CAfile != NULL) {
		SSL_CTX_set_client_CA_list(ctx, SSL_load_client_CA_file(CAfile));
		if (ctx2)
			SSL_CTX_set_client_CA_list(ctx2, SSL_load_client_CA_file(CAfile));
	}
	BIO_printf(bio_s_out, "ACCEPT\n");
	(void) BIO_flush(bio_s_out);
	if (www)
		do_server(port, socket_type, &accept_socket, www_body, context);
	else
		do_server(port, socket_type, &accept_socket, sv_body, context);
	print_stats(bio_s_out, ctx);
	ret = 0;
end:
	if (ctx != NULL)
		SSL_CTX_free(ctx);
	if (s_cert)
		X509_free(s_cert);
	if (s_dcert)
		X509_free(s_dcert);
	if (s_key)
		EVP_PKEY_free(s_key);
	if (s_dkey)
		EVP_PKEY_free(s_dkey);
	free(pass);
	free(dpass);
	if (vpm)
		X509_VERIFY_PARAM_free(vpm);
	free(tlscstatp.host);
	free(tlscstatp.port);
	free(tlscstatp.path);
	if (ctx2 != NULL)
		SSL_CTX_free(ctx2);
	if (s_cert2)
		X509_free(s_cert2);
	if (s_key2)
		EVP_PKEY_free(s_key2);
	free(next_proto.data);
	free(alpn_ctx.data);
	if (bio_s_out != NULL) {
		BIO_free(bio_s_out);
		bio_s_out = NULL;
	}

	return (ret);
}

static void
print_stats(BIO * bio, SSL_CTX * ssl_ctx)
{
	BIO_printf(bio, "%4ld items in the session cache\n",
	    SSL_CTX_sess_number(ssl_ctx));
	BIO_printf(bio, "%4ld client connects (SSL_connect())\n",
	    SSL_CTX_sess_connect(ssl_ctx));
	BIO_printf(bio, "%4ld client renegotiates (SSL_connect())\n",
	    SSL_CTX_sess_connect_renegotiate(ssl_ctx));
	BIO_printf(bio, "%4ld client connects that finished\n",
	    SSL_CTX_sess_connect_good(ssl_ctx));
	BIO_printf(bio, "%4ld server accepts (SSL_accept())\n",
	    SSL_CTX_sess_accept(ssl_ctx));
	BIO_printf(bio, "%4ld server renegotiates (SSL_accept())\n",
	    SSL_CTX_sess_accept_renegotiate(ssl_ctx));
	BIO_printf(bio, "%4ld server accepts that finished\n",
	    SSL_CTX_sess_accept_good(ssl_ctx));
	BIO_printf(bio, "%4ld session cache hits\n", SSL_CTX_sess_hits(ssl_ctx));
	BIO_printf(bio, "%4ld session cache misses\n", SSL_CTX_sess_misses(ssl_ctx));
	BIO_printf(bio, "%4ld session cache timeouts\n", SSL_CTX_sess_timeouts(ssl_ctx));
	BIO_printf(bio, "%4ld callback cache hits\n", SSL_CTX_sess_cb_hits(ssl_ctx));
	BIO_printf(bio, "%4ld cache full overflows (%ld allowed)\n",
	    SSL_CTX_sess_cache_full(ssl_ctx),
	    SSL_CTX_sess_get_cache_size(ssl_ctx));
}

static int
sv_body(char *hostname, int s, unsigned char *context)
{
	char *buf = NULL;
	int ret = 1;
	int k, i;
	unsigned long l;
	SSL *con = NULL;
	BIO *sbio;
	struct timeval timeout;

	if ((buf = malloc(bufsize)) == NULL) {
		BIO_printf(bio_err, "out of memory\n");
		goto err;
	}
	if (s_nbio) {
		if (!s_quiet)
			BIO_printf(bio_err, "turning on non blocking io\n");
		if (!BIO_socket_nbio(s, 1))
			ERR_print_errors(bio_err);
	}

	if (con == NULL) {
		con = SSL_new(ctx);
		if (s_tlsextdebug) {
			SSL_set_tlsext_debug_callback(con, tlsext_cb);
			SSL_set_tlsext_debug_arg(con, bio_s_out);
		}
		if (s_tlsextstatus) {
			SSL_CTX_set_tlsext_status_cb(ctx, cert_status_cb);
			tlscstatp.err = bio_err;
			SSL_CTX_set_tlsext_status_arg(ctx, &tlscstatp);
		}
		if (context)
			SSL_set_session_id_context(con, context,
			    strlen((char *) context));
	}
	SSL_clear(con);

	if (SSL_version(con) == DTLS1_VERSION) {

		sbio = BIO_new_dgram(s, BIO_NOCLOSE);

		if (enable_timeouts) {
			timeout.tv_sec = 0;
			timeout.tv_usec = DGRAM_RCV_TIMEOUT;
			BIO_ctrl(sbio, BIO_CTRL_DGRAM_SET_RECV_TIMEOUT, 0, &timeout);

			timeout.tv_sec = 0;
			timeout.tv_usec = DGRAM_SND_TIMEOUT;
			BIO_ctrl(sbio, BIO_CTRL_DGRAM_SET_SEND_TIMEOUT, 0, &timeout);
		}
		if (socket_mtu > 28) {
			SSL_set_options(con, SSL_OP_NO_QUERY_MTU);
			SSL_set_mtu(con, socket_mtu - 28);
		} else
			/* want to do MTU discovery */
			BIO_ctrl(sbio, BIO_CTRL_DGRAM_MTU_DISCOVER, 0, NULL);

		/* turn on cookie exchange */
		SSL_set_options(con, SSL_OP_COOKIE_EXCHANGE);
	} else
		sbio = BIO_new_socket(s, BIO_NOCLOSE);

	if (s_nbio_test) {
		BIO *test;

		test = BIO_new(BIO_f_nbio_test());
		sbio = BIO_push(test, sbio);
	}

	SSL_set_bio(con, sbio, sbio);
	SSL_set_accept_state(con);
	/* SSL_set_fd(con,s); */

	if (s_debug) {
		SSL_set_debug(con, 1);
		BIO_set_callback(SSL_get_rbio(con), bio_dump_callback);
		BIO_set_callback_arg(SSL_get_rbio(con), (char *) bio_s_out);
	}
	if (s_msg) {
		SSL_set_msg_callback(con, msg_cb);
		SSL_set_msg_callback_arg(con, bio_s_out);
	}
	if (s_tlsextdebug) {
		SSL_set_tlsext_debug_callback(con, tlsext_cb);
		SSL_set_tlsext_debug_arg(con, bio_s_out);
	}

	for (;;) {
		int read_from_terminal;
		int read_from_sslcon;
		struct pollfd pfd[2];
		int ptimeout;

		read_from_terminal = 0;
		read_from_sslcon = SSL_pending(con);

		if (!read_from_sslcon) {
			pfd[0].fd = fileno(stdin);
			pfd[0].events = POLLIN;
			pfd[1].fd = s;
			pfd[1].events = POLLIN;

			if ((SSL_version(con) == DTLS1_VERSION) &&
			    DTLSv1_get_timeout(con, &timeout))
				ptimeout = timeout.tv_sec * 1000 +
				    timeout.tv_usec / 1000;
			else
				ptimeout = -1;

			i = poll(pfd, 2, ptimeout);

			if ((SSL_version(con) == DTLS1_VERSION) && DTLSv1_handle_timeout(con) > 0) {
				BIO_printf(bio_err, "TIMEOUT occured\n");
			}
			if (i <= 0)
				continue;
			if (pfd[0].revents) {
				if ((pfd[0].revents & (POLLERR|POLLNVAL)))
					continue;
				read_from_terminal = 1;
			}
			if (pfd[1].revents) {
				if ((pfd[1].revents & (POLLERR|POLLNVAL)))
					continue;
				read_from_sslcon = 1;
			}
		}
		if (read_from_terminal) {
			if (s_crlf) {
				int j, lf_num;

				i = read(fileno(stdin), buf, bufsize / 2);
				lf_num = 0;
				/* both loops are skipped when i <= 0 */
				for (j = 0; j < i; j++)
					if (buf[j] == '\n')
						lf_num++;
				for (j = i - 1; j >= 0; j--) {
					buf[j + lf_num] = buf[j];
					if (buf[j] == '\n') {
						lf_num--;
						i++;
						buf[j + lf_num] = '\r';
					}
				}
				assert(lf_num == 0);
			} else
				i = read(fileno(stdin), buf, bufsize);
			if (!s_quiet) {
				if ((i <= 0) || (buf[0] == 'Q')) {
					BIO_printf(bio_s_out, "DONE\n");
					shutdown(s, SHUT_RD);
					close(s);
					close_accept_socket();
					ret = -11;
					goto err;
				}
				if ((i <= 0) || (buf[0] == 'q')) {
					BIO_printf(bio_s_out, "DONE\n");
					if (SSL_version(con) != DTLS1_VERSION) {
						shutdown(s, SHUT_RD);
						close(s);
					}
					/*
					 * close_accept_socket(); ret= -11;
					 */
					goto err;
				}
				if ((buf[0] == 'r') &&
				    ((buf[1] == '\n') || (buf[1] == '\r'))) {
					SSL_renegotiate(con);
					i = SSL_do_handshake(con);
					printf("SSL_do_handshake -> %d\n", i);
					i = 0;	/* 13; */
					continue;
					/*
					 * RE-NEGOTIATE\n");
					 */
				}
				if ((buf[0] == 'R') &&
				    ((buf[1] == '\n') || (buf[1] == '\r'))) {
					SSL_set_verify(con,
					    SSL_VERIFY_PEER | SSL_VERIFY_CLIENT_ONCE, NULL);
					SSL_renegotiate(con);
					i = SSL_do_handshake(con);
					printf("SSL_do_handshake -> %d\n", i);
					i = 0;	/* 13; */
					continue;
					/*
					 * RE-NEGOTIATE asking for client
					 * cert\n");
					 */
				}
				if (buf[0] == 'P') {
					static const char *str = "Lets print some clear text\n";
					BIO_write(SSL_get_wbio(con), str, strlen(str));
				}
				if (buf[0] == 'S') {
					print_stats(bio_s_out, SSL_get_SSL_CTX(con));
				}
			}
			l = k = 0;
			for (;;) {
				/* should do a select for the write */
#ifdef RENEG
				{
					static count = 0;
					if (++count == 100) {
						count = 0;
						SSL_renegotiate(con);
					}
				}
#endif
				k = SSL_write(con, &(buf[l]), (unsigned int) i);
				switch (SSL_get_error(con, k)) {
				case SSL_ERROR_NONE:
					break;
				case SSL_ERROR_WANT_WRITE:
				case SSL_ERROR_WANT_READ:
				case SSL_ERROR_WANT_X509_LOOKUP:
					BIO_printf(bio_s_out, "Write BLOCK\n");
					break;
				case SSL_ERROR_SYSCALL:
				case SSL_ERROR_SSL:
					BIO_printf(bio_s_out, "ERROR\n");
					ERR_print_errors(bio_err);
					ret = 1;
					goto err;
					/* break; */
				case SSL_ERROR_ZERO_RETURN:
					BIO_printf(bio_s_out, "DONE\n");
					ret = 1;
					goto err;
				}
				l += k;
				i -= k;
				if (i <= 0)
					break;
			}
		}
		if (read_from_sslcon) {
			if (!SSL_is_init_finished(con)) {
				i = init_ssl_connection(con);

				if (i < 0) {
					ret = 0;
					goto err;
				} else if (i == 0) {
					ret = 1;
					goto err;
				}
			} else {
		again:
				i = SSL_read(con, (char *) buf, bufsize);
				switch (SSL_get_error(con, i)) {
				case SSL_ERROR_NONE: {
						int len, n;
						for (len = 0; len < i;) {
							do {
								n = write(fileno(stdout), buf + len, i - len);
							} while (n == -1 && errno == EINTR);

							if (n < 0) {
								BIO_printf(bio_s_out, "ERROR\n");
								goto err;
							}
							len += n;
						}
					}
					if (SSL_pending(con))
						goto again;
					break;
				case SSL_ERROR_WANT_WRITE:
				case SSL_ERROR_WANT_READ:
					BIO_printf(bio_s_out, "Read BLOCK\n");
					break;
				case SSL_ERROR_SYSCALL:
				case SSL_ERROR_SSL:
					BIO_printf(bio_s_out, "ERROR\n");
					ERR_print_errors(bio_err);
					ret = 1;
					goto err;
				case SSL_ERROR_ZERO_RETURN:
					BIO_printf(bio_s_out, "DONE\n");
					ret = 1;
					goto err;
				}
			}
		}
	}
err:
	if (con != NULL) {
		BIO_printf(bio_s_out, "shutting down SSL\n");
		SSL_set_shutdown(con, SSL_SENT_SHUTDOWN | SSL_RECEIVED_SHUTDOWN);
		SSL_free(con);
	}
	BIO_printf(bio_s_out, "CONNECTION CLOSED\n");
	if (buf != NULL) {
		explicit_bzero(buf, bufsize);
		free(buf);
	}
	if (ret >= 0)
		BIO_printf(bio_s_out, "ACCEPT\n");
	return (ret);
}

static void
close_accept_socket(void)
{
	BIO_printf(bio_err, "shutdown accept socket\n");
	if (accept_socket >= 0) {
		shutdown(accept_socket, SHUT_RDWR);
		close(accept_socket);
	}
}

static int
init_ssl_connection(SSL * con)
{
	int i;
	const char *str;
	X509 *peer;
	long verify_error;
	char buf[BUFSIZ];
	const unsigned char *next_proto_neg;
	unsigned next_proto_neg_len;
	unsigned char *exportedkeymat;

	i = SSL_accept(con);
	if (i <= 0) {
		if (BIO_sock_should_retry(i)) {
			BIO_printf(bio_s_out, "DELAY\n");
			return (1);
		}
		BIO_printf(bio_err, "ERROR\n");
		verify_error = SSL_get_verify_result(con);
		if (verify_error != X509_V_OK) {
			BIO_printf(bio_err, "verify error:%s\n",
			    X509_verify_cert_error_string(verify_error));
		} else
			ERR_print_errors(bio_err);
		return (0);
	}
	PEM_write_bio_SSL_SESSION(bio_s_out, SSL_get_session(con));

	peer = SSL_get_peer_certificate(con);
	if (peer != NULL) {
		BIO_printf(bio_s_out, "Client certificate\n");
		PEM_write_bio_X509(bio_s_out, peer);
		X509_NAME_oneline(X509_get_subject_name(peer), buf, sizeof buf);
		BIO_printf(bio_s_out, "subject=%s\n", buf);
		X509_NAME_oneline(X509_get_issuer_name(peer), buf, sizeof buf);
		BIO_printf(bio_s_out, "issuer=%s\n", buf);
		X509_free(peer);
	}
	if (SSL_get_shared_ciphers(con, buf, sizeof buf) != NULL)
		BIO_printf(bio_s_out, "Shared ciphers:%s\n", buf);
	str = SSL_CIPHER_get_name(SSL_get_current_cipher(con));
	BIO_printf(bio_s_out, "CIPHER is %s\n", (str != NULL) ? str : "(NONE)");

	SSL_get0_next_proto_negotiated(con, &next_proto_neg, &next_proto_neg_len);
	if (next_proto_neg) {
		BIO_printf(bio_s_out, "NEXTPROTO is ");
		BIO_write(bio_s_out, next_proto_neg, next_proto_neg_len);
		BIO_printf(bio_s_out, "\n");
	}
#ifndef OPENSSL_NO_SRTP
	{
		SRTP_PROTECTION_PROFILE *srtp_profile
		= SSL_get_selected_srtp_profile(con);

		if (srtp_profile)
			BIO_printf(bio_s_out, "SRTP Extension negotiated, profile=%s\n",
			    srtp_profile->name);
	}
#endif
	if (SSL_cache_hit(con))
		BIO_printf(bio_s_out, "Reused session-id\n");
	BIO_printf(bio_s_out, "Secure Renegotiation IS%s supported\n",
	    SSL_get_secure_renegotiation_support(con) ? "" : " NOT");
	if (keymatexportlabel != NULL) {
		BIO_printf(bio_s_out, "Keying material exporter:\n");
		BIO_printf(bio_s_out, "    Label: '%s'\n", keymatexportlabel);
		BIO_printf(bio_s_out, "    Length: %i bytes\n",
		    keymatexportlen);
		exportedkeymat = malloc(keymatexportlen);
		if (exportedkeymat != NULL) {
			if (!SSL_export_keying_material(con, exportedkeymat,
				keymatexportlen,
				keymatexportlabel,
				strlen(keymatexportlabel),
				NULL, 0, 0)) {
				BIO_printf(bio_s_out, "    Error\n");
			} else {
				BIO_printf(bio_s_out, "    Keying material: ");
				for (i = 0; i < keymatexportlen; i++)
					BIO_printf(bio_s_out, "%02X",
					    exportedkeymat[i]);
				BIO_printf(bio_s_out, "\n");
			}
			free(exportedkeymat);
		}
	}
	return (1);
}

#ifndef OPENSSL_NO_DH
static DH *
load_dh_param(const char *dhfile)
{
	DH *ret = NULL;
	BIO *bio;

	if ((bio = BIO_new_file(dhfile, "r")) == NULL)
		goto err;
	ret = PEM_read_bio_DHparams(bio, NULL, NULL, NULL);
err:
	BIO_free(bio);
	return (ret);
}
#endif

static int
www_body(char *hostname, int s, unsigned char *context)
{
	char *buf = NULL;
	int ret = 1;
	int i, j, k, dot;
	SSL *con;
	const SSL_CIPHER *c;
	BIO *io, *ssl_bio, *sbio;

	buf = malloc(bufsize);
	if (buf == NULL)
		return (0);
	io = BIO_new(BIO_f_buffer());
	ssl_bio = BIO_new(BIO_f_ssl());
	if ((io == NULL) || (ssl_bio == NULL))
		goto err;

	if (s_nbio) {
		if (!s_quiet)
			BIO_printf(bio_err, "turning on non blocking io\n");
		if (!BIO_socket_nbio(s, 1))
			ERR_print_errors(bio_err);
	}

	/* lets make the output buffer a reasonable size */
	if (!BIO_set_write_buffer_size(io, bufsize))
		goto err;

	if ((con = SSL_new(ctx)) == NULL)
		goto err;
	if (s_tlsextdebug) {
		SSL_set_tlsext_debug_callback(con, tlsext_cb);
		SSL_set_tlsext_debug_arg(con, bio_s_out);
	}
	if (context)
		SSL_set_session_id_context(con, context,
		    strlen((char *) context));

	sbio = BIO_new_socket(s, BIO_NOCLOSE);
	if (s_nbio_test) {
		BIO *test;

		test = BIO_new(BIO_f_nbio_test());
		sbio = BIO_push(test, sbio);
	}
	SSL_set_bio(con, sbio, sbio);
	SSL_set_accept_state(con);

	/* SSL_set_fd(con,s); */
	BIO_set_ssl(ssl_bio, con, BIO_CLOSE);
	BIO_push(io, ssl_bio);

	if (s_debug) {
		SSL_set_debug(con, 1);
		BIO_set_callback(SSL_get_rbio(con), bio_dump_callback);
		BIO_set_callback_arg(SSL_get_rbio(con), (char *) bio_s_out);
	}
	if (s_msg) {
		SSL_set_msg_callback(con, msg_cb);
		SSL_set_msg_callback_arg(con, bio_s_out);
	}
	for (;;) {
		i = BIO_gets(io, buf, bufsize - 1);
		if (i < 0) {	/* error */
			if (!BIO_should_retry(io)) {
				if (!s_quiet)
					ERR_print_errors(bio_err);
				goto err;
			} else {
				BIO_printf(bio_s_out, "read R BLOCK\n");
				sleep(1);
				continue;
			}
		} else if (i == 0) {	/* end of input */
			ret = 1;
			goto end;
		}
		/* else we have data */
		if (((www == 1) && (strncmp("GET ", buf, 4) == 0)) ||
		    ((www == 2) && (strncmp("GET /stats ", buf, 11) == 0))) {
			char *p;
			X509 *peer;
			STACK_OF(SSL_CIPHER) * sk;
			static const char *space = "                          ";

			BIO_puts(io, "HTTP/1.0 200 ok\r\nContent-type: text/html\r\n\r\n");
			BIO_puts(io, "<HTML><BODY BGCOLOR=\"#ffffff\">\n");
			BIO_puts(io, "<pre>\n");
/*			BIO_puts(io,SSLeay_version(SSLEAY_VERSION));*/
			BIO_puts(io, "\n");
			for (i = 0; i < local_argc; i++) {
				BIO_puts(io, local_argv[i]);
				BIO_write(io, " ", 1);
			}
			BIO_puts(io, "\n");

			BIO_printf(io,
			    "Secure Renegotiation IS%s supported\n",
			    SSL_get_secure_renegotiation_support(con) ?
			    "" : " NOT");

			/*
			 * The following is evil and should not really be
			 * done
			 */
			BIO_printf(io, "Ciphers supported in s_server binary\n");
			sk = SSL_get_ciphers(con);
			j = sk_SSL_CIPHER_num(sk);
			for (i = 0; i < j; i++) {
				c = sk_SSL_CIPHER_value(sk, i);
				BIO_printf(io, "%-11s:%-25s",
				    SSL_CIPHER_get_version(c),
				    SSL_CIPHER_get_name(c));
				if ((((i + 1) % 2) == 0) && (i + 1 != j))
					BIO_puts(io, "\n");
			}
			BIO_puts(io, "\n");
			p = SSL_get_shared_ciphers(con, buf, bufsize);
			if (p != NULL) {
				BIO_printf(io, "---\nCiphers common between both SSL end points:\n");
				j = i = 0;
				while (*p) {
					if (*p == ':') {
						BIO_write(io, space, 26 - j);
						i++;
						j = 0;
						BIO_write(io, ((i % 3) ? " " : "\n"), 1);
					} else {
						BIO_write(io, p, 1);
						j++;
					}
					p++;
				}
				BIO_puts(io, "\n");
			}
			BIO_printf(io, (SSL_cache_hit(con)
				? "---\nReused, "
				: "---\nNew, "));
			c = SSL_get_current_cipher(con);
			BIO_printf(io, "%s, Cipher is %s\n",
			    SSL_CIPHER_get_version(c),
			    SSL_CIPHER_get_name(c));
			SSL_SESSION_print(io, SSL_get_session(con));
			BIO_printf(io, "---\n");
			print_stats(io, SSL_get_SSL_CTX(con));
			BIO_printf(io, "---\n");
			peer = SSL_get_peer_certificate(con);
			if (peer != NULL) {
				BIO_printf(io, "Client certificate\n");
				X509_print(io, peer);
				PEM_write_bio_X509(io, peer);
			} else
				BIO_puts(io, "no client certificate available\n");
			BIO_puts(io, "</BODY></HTML>\r\n\r\n");
			break;
		} else if ((www == 2 || www == 3)
		    && (strncmp("GET /", buf, 5) == 0)) {
			BIO *file;
			char *p, *e;
			static const char *text = "HTTP/1.0 200 ok\r\nContent-type: text/plain\r\n\r\n";

			/* skip the '/' */
			p = &(buf[5]);

			dot = 1;
			for (e = p; *e != '\0'; e++) {
				if (e[0] == ' ')
					break;

				switch (dot) {
				case 1:
					dot = (e[0] == '.') ? 2 : 0;
					break;
				case 2:
					dot = (e[0] == '.') ? 3 : 0;
					break;
				case 3:
					dot = (e[0] == '/') ? -1 : 0;
					break;
				}
				if (dot == 0)
					dot = (e[0] == '/') ? 1 : 0;
			}
			dot = (dot == 3) || (dot == -1);	/* filename contains
								 * ".." component */

			if (*e == '\0') {
				BIO_puts(io, text);
				BIO_printf(io, "'%s' is an invalid file name\r\n", p);
				break;
			}
			*e = '\0';

			if (dot) {
				BIO_puts(io, text);
				BIO_printf(io, "'%s' contains '..' reference\r\n", p);
				break;
			}
			if (*p == '/') {
				BIO_puts(io, text);
				BIO_printf(io, "'%s' is an invalid path\r\n", p);
				break;
			}
			/* if a directory, do the index thang */
			if (app_isdir(p) > 0) {
				BIO_puts(io, text);
				BIO_printf(io, "'%s' is a directory\r\n", p);
				break;
			}
			if ((file = BIO_new_file(p, "r")) == NULL) {
				BIO_puts(io, text);
				BIO_printf(io, "Error opening '%s'\r\n", p);
				ERR_print_errors(io);
				break;
			}
			if (!s_quiet)
				BIO_printf(bio_err, "FILE:%s\n", p);

			if (www == 2) {
				i = strlen(p);
				if (((i > 5) && (strcmp(&(p[i - 5]), ".html") == 0)) ||
				    ((i > 4) && (strcmp(&(p[i - 4]), ".php") == 0)) ||
				    ((i > 4) && (strcmp(&(p[i - 4]), ".htm") == 0)))
					BIO_puts(io, "HTTP/1.0 200 ok\r\nContent-type: text/html\r\n\r\n");
				else
					BIO_puts(io, "HTTP/1.0 200 ok\r\nContent-type: text/plain\r\n\r\n");
			}
			/* send the file */
			for (;;) {
				i = BIO_read(file, buf, bufsize);
				if (i <= 0)
					break;

#ifdef RENEG
				total_bytes += i;
				fprintf(stderr, "%d\n", i);
				if (total_bytes > 3 * 1024) {
					total_bytes = 0;
					fprintf(stderr, "RENEGOTIATE\n");
					SSL_renegotiate(con);
				}
#endif

				for (j = 0; j < i;) {
#ifdef RENEG
					{
						static count = 0;
						if (++count == 13) {
							SSL_renegotiate(con);
						}
					}
#endif
					k = BIO_write(io, &(buf[j]), i - j);
					if (k <= 0) {
						if (!BIO_should_retry(io))
							goto write_error;
						else {
							BIO_printf(bio_s_out, "rwrite W BLOCK\n");
						}
					} else {
						j += k;
					}
				}
			}
	write_error:
			BIO_free(file);
			break;
		}
	}

	for (;;) {
		i = (int) BIO_flush(io);
		if (i <= 0) {
			if (!BIO_should_retry(io))
				break;
		} else
			break;
	}
end:
	/* make sure we re-use sessions */
	SSL_set_shutdown(con, SSL_SENT_SHUTDOWN | SSL_RECEIVED_SHUTDOWN);

err:

	if (ret >= 0)
		BIO_printf(bio_s_out, "ACCEPT\n");

	free(buf);
	if (io != NULL)
		BIO_free_all(io);
/*	if (ssl_bio != NULL) BIO_free(ssl_bio);*/
	return (ret);
}

#define MAX_SESSION_ID_ATTEMPTS 10
static int
generate_session_id(const SSL * ssl, unsigned char *id,
    unsigned int *id_len)
{
	unsigned int count = 0;
	do {
		arc4random_buf(id, *id_len);
		/*
		 * Prefix the session_id with the required prefix. NB: If our
		 * prefix is too long, clip it - but there will be worse
		 * effects anyway, eg. the server could only possibly create
		 * 1 session ID (ie. the prefix!) so all future session
		 * negotiations will fail due to conflicts.
		 */
		memcpy(id, session_id_prefix,
		    (strlen(session_id_prefix) < *id_len) ?
		    strlen(session_id_prefix) : *id_len);
	}
	while (SSL_has_matching_session_id(ssl, id, *id_len) &&
	    (++count < MAX_SESSION_ID_ATTEMPTS));
	if (count >= MAX_SESSION_ID_ATTEMPTS)
		return 0;
	return 1;
}
