/* $OpenBSD: ssl_asn1.c,v 1.40 2014/12/14 15:30:50 jsing Exp $ */
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

#include "ssl_locl.h"

#include <openssl/objects.h>
#include <openssl/x509.h>

/* XXX - these are here to avoid including asn1_mac.h */
int asn1_GetSequence(ASN1_const_CTX *c, long *length);
void asn1_add_error(const unsigned char *address, int offset);

typedef struct ssl_session_asn1_st {
	ASN1_INTEGER version;
	ASN1_INTEGER ssl_version;
	ASN1_OCTET_STRING cipher;
	ASN1_OCTET_STRING master_key;
	ASN1_OCTET_STRING session_id;
	ASN1_OCTET_STRING session_id_context;
	ASN1_INTEGER time;
	ASN1_INTEGER timeout;
	ASN1_INTEGER verify_result;
	ASN1_OCTET_STRING tlsext_hostname;
	ASN1_INTEGER tlsext_tick_lifetime;
	ASN1_OCTET_STRING tlsext_tick;
} SSL_SESSION_ASN1;

int
i2d_SSL_SESSION(SSL_SESSION *in, unsigned char **pp)
{
#define LSIZE2 (sizeof(long)*2)
	int v1 = 0, v2 = 0, v3 = 0, v4 = 0, v5 = 0, v6 = 0, v9 = 0, v10 = 0;
	unsigned char buf[4], ibuf1[LSIZE2], ibuf2[LSIZE2];
	unsigned char ibuf3[LSIZE2], ibuf4[LSIZE2], ibuf5[LSIZE2];
	unsigned char ibuf6[LSIZE2];
	SSL_SESSION_ASN1 a;
	unsigned char *p;
	int len = 0, ret;
	long l;

	if ((in == NULL) || ((in->cipher == NULL) && (in->cipher_id == 0)))
		return (0);

	/*
	 * Note that I cheat in the following 2 assignments.
	 * I know that if the ASN1_INTEGER passed to ASN1_INTEGER_set
	 * is > sizeof(long)+1, the buffer will not be re-malloc()ed.
	 * This is a bit evil but makes things simple, no dynamic allocation
	 * to clean up :-)
	 */
	a.version.length = LSIZE2;
	a.version.type = V_ASN1_INTEGER;
	a.version.data = ibuf1;
	ASN1_INTEGER_set(&(a.version), SSL_SESSION_ASN1_VERSION);
	len += i2d_ASN1_INTEGER(&(a.version), NULL);

	a.ssl_version.length = LSIZE2;
	a.ssl_version.type = V_ASN1_INTEGER;
	a.ssl_version.data = ibuf2;
	ASN1_INTEGER_set(&(a.ssl_version), in->ssl_version);
	len += i2d_ASN1_INTEGER(&(a.ssl_version), NULL);

	a.cipher.length = 2;
	a.cipher.type = V_ASN1_OCTET_STRING;
	l = (in->cipher == NULL) ? in->cipher_id : in->cipher->id;
	buf[0] = ((unsigned char)(l >> 8L)) & 0xff;
	buf[1] = ((unsigned char)(l)) & 0xff;
	a.cipher.data = buf;
	len += i2d_ASN1_OCTET_STRING(&(a.cipher), NULL);

	a.master_key.length = in->master_key_length;
	a.master_key.type = V_ASN1_OCTET_STRING;
	a.master_key.data = in->master_key;
	len += i2d_ASN1_OCTET_STRING(&(a.master_key), NULL);

	a.session_id.length = in->session_id_length;
	a.session_id.type = V_ASN1_OCTET_STRING;
	a.session_id.data = in->session_id;
	len += i2d_ASN1_OCTET_STRING(&(a.session_id), NULL);

	if (in->time != 0L) {
		a.time.length = LSIZE2;
		a.time.type = V_ASN1_INTEGER;
		a.time.data = ibuf3;
		ASN1_INTEGER_set(&(a.time), in->time);	/* XXX 2038 */
		v1 = i2d_ASN1_INTEGER(&(a.time), NULL);
		len += ASN1_object_size(1, v1, 1);
	}

	if (in->timeout != 0L) {
		a.timeout.length = LSIZE2;
		a.timeout.type = V_ASN1_INTEGER;
		a.timeout.data = ibuf4;
		ASN1_INTEGER_set(&(a.timeout), in->timeout);
		v2 = i2d_ASN1_INTEGER(&(a.timeout), NULL);
		len += ASN1_object_size(1, v2, 2);
	}

	if (in->peer != NULL) {
		v3 = i2d_X509(in->peer, NULL);
		len += ASN1_object_size(1, v3, 3);
	}

	a.session_id_context.length = in->sid_ctx_length;
	a.session_id_context.type = V_ASN1_OCTET_STRING;
	a.session_id_context.data = in->sid_ctx;
	v4 = i2d_ASN1_OCTET_STRING(&(a.session_id_context), NULL);
	len += ASN1_object_size(1, v4, 4);

	if (in->verify_result != X509_V_OK) {
		a.verify_result.length = LSIZE2;
		a.verify_result.type = V_ASN1_INTEGER;
		a.verify_result.data = ibuf5;
		ASN1_INTEGER_set(&a.verify_result, in->verify_result);
		v5 = i2d_ASN1_INTEGER(&(a.verify_result), NULL);
		len += ASN1_object_size(1, v5, 5);
	}

	if (in->tlsext_hostname) {
		a.tlsext_hostname.length = strlen(in->tlsext_hostname);
		a.tlsext_hostname.type = V_ASN1_OCTET_STRING;
		a.tlsext_hostname.data = (unsigned char *)in->tlsext_hostname;
		v6 = i2d_ASN1_OCTET_STRING(&(a.tlsext_hostname), NULL);
		len += ASN1_object_size(1, v6, 6);
	}

	/* 7 - PSK identity hint. */
	/* 8 - PSK identity. */

	if (in->tlsext_tick_lifetime_hint > 0) {
		a.tlsext_tick_lifetime.length = LSIZE2;
		a.tlsext_tick_lifetime.type = V_ASN1_INTEGER;
		a.tlsext_tick_lifetime.data = ibuf6;
		ASN1_INTEGER_set(&a.tlsext_tick_lifetime,
		    in->tlsext_tick_lifetime_hint);
		v9 = i2d_ASN1_INTEGER(&(a.tlsext_tick_lifetime), NULL);
		len += ASN1_object_size(1, v9, 9);
	}

	if (in->tlsext_tick) {
		a.tlsext_tick.length = in->tlsext_ticklen;
		a.tlsext_tick.type = V_ASN1_OCTET_STRING;
		a.tlsext_tick.data = (unsigned char *)in->tlsext_tick;
		v10 = i2d_ASN1_OCTET_STRING(&(a.tlsext_tick), NULL);
		len += ASN1_object_size(1, v10, 10);
	}

	/* 11 - Compression method. */
	/* 12 - SRP username. */

	/* If given a NULL pointer, return the length only. */
	ret = (ASN1_object_size(1, len, V_ASN1_SEQUENCE));
	if (pp == NULL)
		return (ret);

	/* Burp out the ASN1. */
	p = *pp;
	ASN1_put_object(&p, 1, len, V_ASN1_SEQUENCE, V_ASN1_UNIVERSAL);
	i2d_ASN1_INTEGER(&(a.version), &p);
	i2d_ASN1_INTEGER(&(a.ssl_version), &p);
	i2d_ASN1_OCTET_STRING(&(a.cipher), &p);
	i2d_ASN1_OCTET_STRING(&(a.session_id), &p);
	i2d_ASN1_OCTET_STRING(&(a.master_key), &p);
	if (in->time != 0L) {
		ASN1_put_object(&p, 1, v1, 1, V_ASN1_CONTEXT_SPECIFIC);
		i2d_ASN1_INTEGER(&(a.time), &p);
	}
	if (in->timeout != 0L) {
		ASN1_put_object(&p, 1, v2, 2, V_ASN1_CONTEXT_SPECIFIC);
		i2d_ASN1_INTEGER(&(a.timeout), &p);
	}
	if (in->peer != NULL) {
		ASN1_put_object(&p, 1, v3, 3, V_ASN1_CONTEXT_SPECIFIC);
		i2d_X509(in->peer, &p);
	}
	ASN1_put_object(&p, 1, v4, 4, V_ASN1_CONTEXT_SPECIFIC);
	i2d_ASN1_OCTET_STRING(&(a.session_id_context), &p);
	if (in->verify_result != X509_V_OK) {
		ASN1_put_object(&p, 1, v5, 5, V_ASN1_CONTEXT_SPECIFIC);
		i2d_ASN1_INTEGER(&(a.verify_result), &p);
	}
	if (in->tlsext_hostname) {
		ASN1_put_object(&p, 1, v6, 6, V_ASN1_CONTEXT_SPECIFIC);
		i2d_ASN1_OCTET_STRING(&(a.tlsext_hostname), &p);
	}
	/* 7 - PSK identity hint. */
	/* 8 - PSK identity. */
	if (in->tlsext_tick_lifetime_hint > 0) {
		ASN1_put_object(&p, 1, v9, 9, V_ASN1_CONTEXT_SPECIFIC);
		i2d_ASN1_INTEGER(&(a.tlsext_tick_lifetime), &p);
	}
	if (in->tlsext_tick) {
		ASN1_put_object(&p, 1, v10, 10, V_ASN1_CONTEXT_SPECIFIC);
		i2d_ASN1_OCTET_STRING(&(a.tlsext_tick), &p);
	}
	/* 11 - Compression method. */
	/* 12 - SRP username. */

	*pp = p;
	return (ret);
}

SSL_SESSION *
d2i_SSL_SESSION(SSL_SESSION **a, const unsigned char **pp, long length)
{
	SSL_SESSION *ret = NULL;
	ASN1_const_CTX c;
	ASN1_INTEGER ai, *aip;
	ASN1_OCTET_STRING os, *osp;
	int ssl_version = 0, i;
	int Tinf, Ttag, Tclass;
	long Tlen;
	long id;

	c.pp = pp;
	c.p = *pp;
	c.q = *pp;
	c.max = (length == 0) ? 0 : (c.p + length);
	c.slen = length;

	if (a == NULL || *a == NULL) {
		if ((ret = SSL_SESSION_new()) == NULL) {
			SSLerr(SSL_F_D2I_SSL_SESSION, ERR_R_NESTED_ASN1_ERROR);
			goto err;
		}
	} else
		ret = *a;

	aip = &ai;
	osp = &os;

	if (!asn1_GetSequence(&c, &length)) {
		SSLerr(SSL_F_D2I_SSL_SESSION, ERR_R_NESTED_ASN1_ERROR);
		goto err;
	}

	ai.data = NULL;
	ai.length = 0;
	c.q = c.p;
	if (d2i_ASN1_INTEGER(&aip, &c.p, c.slen) == NULL) {
		SSLerr(SSL_F_D2I_SSL_SESSION, ERR_R_NESTED_ASN1_ERROR);
		goto err;
	}
	c.slen -= (c.p - c.q);

	if (ai.data != NULL) {
		free(ai.data);
		ai.data = NULL;
		ai.length = 0;
	}

	/* we don't care about the version right now :-) */
	c.q = c.p;
	if (d2i_ASN1_INTEGER(&aip, &c.p, c.slen) == NULL) {
		SSLerr(SSL_F_D2I_SSL_SESSION, ERR_R_NESTED_ASN1_ERROR);
		goto err;
	}
	c.slen -= (c.p - c.q);
	ssl_version = (int)ASN1_INTEGER_get(aip);
	ret->ssl_version = ssl_version;
	if (ai.data != NULL) {
		free(ai.data);
		ai.data = NULL;
		ai.length = 0;
	}

	os.data = NULL;
	os.length = 0;
	c.q = c.p;
	if (d2i_ASN1_OCTET_STRING(&osp, &c.p, c.slen) == NULL) {
		SSLerr(SSL_F_D2I_SSL_SESSION, ERR_R_NESTED_ASN1_ERROR);
		goto err;
	}
	c.slen -= (c.p - c.q);
	if ((ssl_version >> 8) >= SSL3_VERSION_MAJOR) {
		if (os.length != 2) {
			SSLerr(SSL_F_D2I_SSL_SESSION,
			    SSL_R_CIPHER_CODE_WRONG_LENGTH);
			goto err;
		}
		id = 0x03000000L | ((unsigned long)os.data[0]<<8L) |
		    (unsigned long)os.data[1];
	} else {
		SSLerr(SSL_F_D2I_SSL_SESSION, SSL_R_UNKNOWN_SSL_VERSION);
		goto err;
	}

	ret->cipher = NULL;
	ret->cipher_id = id;

	c.q = c.p;
	if (d2i_ASN1_OCTET_STRING(&osp, &c.p, c.slen) == NULL) {
		SSLerr(SSL_F_D2I_SSL_SESSION, ERR_R_NESTED_ASN1_ERROR);
		goto err;
	}
	c.slen -= (c.p - c.q);

	i = SSL3_MAX_SSL_SESSION_ID_LENGTH;
	if (os.length > i)
		os.length = i;
	if (os.length > (int)sizeof(ret->session_id)) /* can't happen */
		os.length = sizeof(ret->session_id);

	ret->session_id_length = os.length;
	OPENSSL_assert(os.length <= (int)sizeof(ret->session_id));
	memcpy(ret->session_id, os.data, os.length);

	c.q = c.p;
	if (d2i_ASN1_OCTET_STRING(&osp, &c.p, c.slen) == NULL) {
		SSLerr(SSL_F_D2I_SSL_SESSION, ERR_R_NESTED_ASN1_ERROR);
		goto err;
	}
	c.slen -= (c.p - c.q);
	if (os.length > SSL_MAX_MASTER_KEY_LENGTH)
		ret->master_key_length = SSL_MAX_MASTER_KEY_LENGTH;
	else
		ret->master_key_length = os.length;
	memcpy(ret->master_key, os.data, ret->master_key_length);

	os.length = 0;

	/* 1 - Time (INTEGER). */
	/* XXX 2038 */
	ai.length = 0;
	if (c.slen != 0L &&
	    *c.p == (V_ASN1_CONSTRUCTED | V_ASN1_CONTEXT_SPECIFIC | 1)) {
		c.q = c.p;
		Tinf = ASN1_get_object(&c.p, &Tlen, &Ttag, &Tclass, c.slen);
		if (Tinf & 0x80) {
			SSLerr(SSL_F_D2I_SSL_SESSION,
			    ERR_R_BAD_ASN1_OBJECT_HEADER);
			goto err;
		}
		if (Tinf == (V_ASN1_CONSTRUCTED + 1))
			Tlen = c.slen - (c.p - c.q) - 2;
		if (d2i_ASN1_INTEGER(&aip, &c.p, Tlen) == NULL) {
			SSLerr(SSL_F_D2I_SSL_SESSION, ERR_R_NESTED_ASN1_ERROR);
			goto err;
		}
		if (Tinf == (V_ASN1_CONSTRUCTED + 1)) {
			Tlen = c.slen - (c.p - c.q);
			if(!ASN1_const_check_infinite_end(&c.p, Tlen)) {
				SSLerr(SSL_F_D2I_SSL_SESSION,
				    ERR_R_MISSING_ASN1_EOS);
				goto err;
			}
		}
		c.slen -= (c.p - c.q);
	}
	if (ai.data != NULL) {
		ret->time = ASN1_INTEGER_get(aip);
		free(ai.data);
		ai.data = NULL;
		ai.length = 0;
	} else
		ret->time = time(NULL);

	/* 2 - Timeout (INTEGER). */
	ai.length = 0;
	if (c.slen != 0L &&
	    *c.p == (V_ASN1_CONSTRUCTED | V_ASN1_CONTEXT_SPECIFIC | 2)) {
		c.q = c.p;
		Tinf = ASN1_get_object(&c.p, &Tlen, &Ttag, &Tclass, c.slen);
		if (Tinf & 0x80) {
			SSLerr(SSL_F_D2I_SSL_SESSION,
			    ERR_R_BAD_ASN1_OBJECT_HEADER);
			goto err;
		}
		if (Tinf == (V_ASN1_CONSTRUCTED + 1))
			Tlen = c.slen - (c.p - c.q) - 2;
		if (d2i_ASN1_INTEGER(&aip, &c.p, Tlen) == NULL) {
			SSLerr(SSL_F_D2I_SSL_SESSION, ERR_R_NESTED_ASN1_ERROR);
			goto err;
		}
		if (Tinf == (V_ASN1_CONSTRUCTED + 1)) {
			Tlen = c.slen - (c.p - c.q);
			if(!ASN1_const_check_infinite_end(&c.p, Tlen)) {
				SSLerr(SSL_F_D2I_SSL_SESSION,
				    ERR_R_MISSING_ASN1_EOS);
				goto err;
			}
		}
		c.slen -= (c.p - c.q);
	}
	if (ai.data != NULL) {
		ret->timeout = ASN1_INTEGER_get(aip);
		free(ai.data);
		ai.data = NULL;
		ai.length = 0;
	} else
		ret->timeout = 3;

	/* 3 - Peer (X509). */
	X509_free(ret->peer);
	ret->peer = NULL;

	if (c.slen != 0L &&
	    *c.p == (V_ASN1_CONSTRUCTED | V_ASN1_CONTEXT_SPECIFIC | 3)) {
		c.q = c.p;
		Tinf = ASN1_get_object(&c.p, &Tlen, &Ttag, &Tclass, c.slen);
		if (Tinf & 0x80) {
			SSLerr(SSL_F_D2I_SSL_SESSION,
			    ERR_R_BAD_ASN1_OBJECT_HEADER);
			goto err;
		}
		if (Tinf == (V_ASN1_CONSTRUCTED + 1))
			Tlen = c.slen - (c.p - c.q) - 2;
		if (d2i_X509(&ret->peer, &c.p, Tlen) == NULL) {
			SSLerr(SSL_F_D2I_SSL_SESSION, ERR_R_NESTED_ASN1_ERROR);
			goto err;
		}
		if (Tinf == (V_ASN1_CONSTRUCTED + 1)) {
			Tlen = c.slen - (c.p - c.q);
			if(!ASN1_const_check_infinite_end(&c.p, Tlen)) {
				SSLerr(SSL_F_D2I_SSL_SESSION,
				    ERR_R_MISSING_ASN1_EOS);
				goto err;
			}
		}
		c.slen -= (c.p - c.q);
	}

	/* 4 - Session ID (OCTET STRING). */
	os.length = 0;
	free(os.data);
	os.data = NULL;
	if (c.slen != 0L &&
	    *c.p == (V_ASN1_CONSTRUCTED | V_ASN1_CONTEXT_SPECIFIC | 4)) {
		c.q = c.p;
		Tinf = ASN1_get_object(&c.p, &Tlen, &Ttag, &Tclass, c.slen);
		if (Tinf & 0x80) {
			SSLerr(SSL_F_D2I_SSL_SESSION,
			    ERR_R_BAD_ASN1_OBJECT_HEADER);
			goto err;
		}
		if (Tinf == (V_ASN1_CONSTRUCTED + 1))
			Tlen = c.slen - (c.p - c.q) - 2;
		if (d2i_ASN1_OCTET_STRING(&osp, &c.p, Tlen) == NULL) {
			SSLerr(SSL_F_D2I_SSL_SESSION, ERR_R_NESTED_ASN1_ERROR);
			goto err;
		}
		if (Tinf == (V_ASN1_CONSTRUCTED + 1)) {
			Tlen = c.slen - (c.p - c.q);
			if(!ASN1_const_check_infinite_end(&c.p, Tlen)) {
				SSLerr(SSL_F_D2I_SSL_SESSION,
				    ERR_R_MISSING_ASN1_EOS);
				goto err;
			}
		}
		c.slen -= (c.p - c.q);
	}
	if (os.data != NULL) {
		if (os.length > SSL_MAX_SID_CTX_LENGTH) {
			SSLerr(SSL_F_D2I_SSL_SESSION, SSL_R_BAD_LENGTH);
			goto err;
		} else {
			ret->sid_ctx_length = os.length;
			memcpy(ret->sid_ctx, os.data, os.length);
		}
		free(os.data);
		os.data = NULL;
		os.length = 0;
	} else
		ret->sid_ctx_length = 0;

	/* 5 - Verify_result. */
	ai.length = 0;
	if (c.slen != 0L &&
	    *c.p == (V_ASN1_CONSTRUCTED | V_ASN1_CONTEXT_SPECIFIC | 5)) {
		c.q = c.p;
		Tinf = ASN1_get_object(&c.p, &Tlen, &Ttag, &Tclass, c.slen);
		if (Tinf & 0x80) {
			SSLerr(SSL_F_D2I_SSL_SESSION,
			    ERR_R_BAD_ASN1_OBJECT_HEADER);
			goto err;
		}
		if (Tinf == (V_ASN1_CONSTRUCTED + 1))
			Tlen = c.slen - (c.p - c.q) - 2;
		if (d2i_ASN1_INTEGER(&aip, &c.p, Tlen) == NULL) {
			SSLerr(SSL_F_D2I_SSL_SESSION, ERR_R_NESTED_ASN1_ERROR);
			goto err;
		}
		if (Tinf == (V_ASN1_CONSTRUCTED + 1)) {
			Tlen = c.slen - (c.p - c.q);
			if(!ASN1_const_check_infinite_end(&c.p, Tlen)) {
				SSLerr(SSL_F_D2I_SSL_SESSION,
				    ERR_R_MISSING_ASN1_EOS);
				goto err;
			}
		}
		c.slen -= (c.p - c.q);
	}
	if (ai.data != NULL) {
		ret->verify_result = ASN1_INTEGER_get(aip);
		free(ai.data);
		ai.data = NULL;
		ai.length = 0;
	} else
		ret->verify_result = X509_V_OK;

	/* 6 - HostName (OCTET STRING). */
	os.length = 0;
	os.data = NULL;
	if (c.slen != 0L &&
	    *c.p == (V_ASN1_CONSTRUCTED | V_ASN1_CONTEXT_SPECIFIC | 6)) {
		c.q = c.p;
		Tinf = ASN1_get_object(&c.p, &Tlen, &Ttag, &Tclass, c.slen);
		if (Tinf & 0x80) {
			SSLerr(SSL_F_D2I_SSL_SESSION,
			    ERR_R_BAD_ASN1_OBJECT_HEADER);
			goto err;
		}
		if (Tinf == (V_ASN1_CONSTRUCTED + 1))
			Tlen = c.slen - (c.p - c.q) - 2;
		if (d2i_ASN1_OCTET_STRING(&osp, &c.p, Tlen) == NULL) {
			SSLerr(SSL_F_D2I_SSL_SESSION, ERR_R_NESTED_ASN1_ERROR);
			goto err;
		}
		if (Tinf == (V_ASN1_CONSTRUCTED + 1)) {
			Tlen = c.slen - (c.p - c.q);
			if(!ASN1_const_check_infinite_end(&c.p, Tlen)) {
				SSLerr(SSL_F_D2I_SSL_SESSION,
				    ERR_R_MISSING_ASN1_EOS);
				goto err;
			}
		}
		c.slen -= (c.p - c.q);
	}
	if (os.data) {
		ret->tlsext_hostname = strndup((char *)os.data, os.length);
		free(os.data);
		os.data = NULL;
		os.length = 0;
	} else
		ret->tlsext_hostname = NULL;

	/* 7 - PSK identity hint (OCTET STRING). */
	/* 8 - PSK identity (OCTET STRING). */

	/* 9 - Ticket lifetime. */
	ai.length = 0;
	if (c.slen != 0L &&
	    *c.p == (V_ASN1_CONSTRUCTED | V_ASN1_CONTEXT_SPECIFIC | 9)) {
		c.q = c.p;
		Tinf = ASN1_get_object(&c.p, &Tlen, &Ttag, &Tclass, c.slen);
		if (Tinf & 0x80) {
			SSLerr(SSL_F_D2I_SSL_SESSION,
			    ERR_R_BAD_ASN1_OBJECT_HEADER);
			goto err;
		}
		if (Tinf == (V_ASN1_CONSTRUCTED + 1))
			Tlen = c.slen - (c.p - c.q) - 2;
		if (d2i_ASN1_INTEGER(&aip, &c.p, Tlen) == NULL) {
			SSLerr(SSL_F_D2I_SSL_SESSION, ERR_R_NESTED_ASN1_ERROR);
			goto err;
		}
		if (Tinf == (V_ASN1_CONSTRUCTED + 1)) {
			Tlen = c.slen - (c.p - c.q);
			if(!ASN1_const_check_infinite_end(&c.p, Tlen)) {
				SSLerr(SSL_F_D2I_SSL_SESSION,
				    ERR_R_MISSING_ASN1_EOS);
				goto err;
			}
		}
		c.slen -= (c.p - c.q);
	}
	if (ai.data != NULL) {
		ret->tlsext_tick_lifetime_hint = ASN1_INTEGER_get(aip);
		free(ai.data);
		ai.data = NULL;
		ai.length = 0;
	} else if (ret->tlsext_ticklen && ret->session_id_length)
		ret->tlsext_tick_lifetime_hint = -1;
	else
		ret->tlsext_tick_lifetime_hint = 0;
	os.length = 0;
	os.data = NULL;

	/* 10 - Ticket (OCTET STRING). */
	if (c.slen != 0L &&
	    *c.p == (V_ASN1_CONSTRUCTED | V_ASN1_CONTEXT_SPECIFIC | 10)) {
		c.q = c.p;
		Tinf = ASN1_get_object(&c.p, &Tlen, &Ttag, &Tclass, c.slen);
		if (Tinf & 0x80) {
			SSLerr(SSL_F_D2I_SSL_SESSION,
			    ERR_R_BAD_ASN1_OBJECT_HEADER);
			goto err;
		}
		if (Tinf == (V_ASN1_CONSTRUCTED + 1))
			Tlen = c.slen - (c.p - c.q) - 2;
		if (d2i_ASN1_OCTET_STRING(&osp, &c.p, Tlen) == NULL) {
			SSLerr(SSL_F_D2I_SSL_SESSION, ERR_R_NESTED_ASN1_ERROR);
			goto err;
		}
		if (Tinf == (V_ASN1_CONSTRUCTED + 1)) {
			Tlen = c.slen - (c.p - c.q);
			if(!ASN1_const_check_infinite_end(&c.p, Tlen)) {
				SSLerr(SSL_F_D2I_SSL_SESSION,
				    ERR_R_MISSING_ASN1_EOS);
				goto err;
			}
		}
		c.slen -= (c.p - c.q);
	}
	if (os.data) {
		ret->tlsext_tick = os.data;
		ret->tlsext_ticklen = os.length;
		os.data = NULL;
		os.length = 0;
	} else
		ret->tlsext_tick = NULL;

	/* 11 - Compression method (OCTET STRING). */
	/* 12 - SRP username (OCTET STRING). */

	if (!asn1_const_Finish(&c)) {
		SSLerr(SSL_F_D2I_SSL_SESSION, ERR_R_NESTED_ASN1_ERROR);
		goto err;
	}

	*pp = c.p;
	if (a != NULL)
		*a = ret;

	return (ret);

err:
	ERR_asprintf_error_data("offset=%d", (int)(c.q - *pp));
	if (ret != NULL && (a == NULL || *a != ret))
		SSL_SESSION_free(ret);

	return (NULL);
}
