/* $OpenBSD: t1_lib.c,v 1.91 2016/10/02 21:05:44 guenther Exp $ */
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
 * Copyright (c) 1998-2007 The OpenSSL Project.  All rights reserved.
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

#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/objects.h>
#include <openssl/ocsp.h>

#include "ssl_locl.h"
#include "bytestring.h"

static int tls_decrypt_ticket(SSL *s, const unsigned char *tick, int ticklen,
    const unsigned char *sess_id, int sesslen,
    SSL_SESSION **psess);

SSL3_ENC_METHOD TLSv1_enc_data = {
	.enc = tls1_enc,
	.mac = tls1_mac,
	.setup_key_block = tls1_setup_key_block,
	.generate_master_secret = tls1_generate_master_secret,
	.change_cipher_state = tls1_change_cipher_state,
	.final_finish_mac = tls1_final_finish_mac,
	.finish_mac_length = TLS1_FINISH_MAC_LENGTH,
	.cert_verify_mac = tls1_cert_verify_mac,
	.client_finished_label = TLS_MD_CLIENT_FINISH_CONST,
	.client_finished_label_len = TLS_MD_CLIENT_FINISH_CONST_SIZE,
	.server_finished_label = TLS_MD_SERVER_FINISH_CONST,
	.server_finished_label_len = TLS_MD_SERVER_FINISH_CONST_SIZE,
	.alert_value = tls1_alert_code,
	.export_keying_material = tls1_export_keying_material,
	.enc_flags = 0,
};

SSL3_ENC_METHOD TLSv1_1_enc_data = {
	.enc = tls1_enc,
	.mac = tls1_mac,
	.setup_key_block = tls1_setup_key_block,
	.generate_master_secret = tls1_generate_master_secret,
	.change_cipher_state = tls1_change_cipher_state,
	.final_finish_mac = tls1_final_finish_mac,
	.finish_mac_length = TLS1_FINISH_MAC_LENGTH,
	.cert_verify_mac = tls1_cert_verify_mac,
	.client_finished_label = TLS_MD_CLIENT_FINISH_CONST,
	.client_finished_label_len = TLS_MD_CLIENT_FINISH_CONST_SIZE,
	.server_finished_label = TLS_MD_SERVER_FINISH_CONST,
	.server_finished_label_len = TLS_MD_SERVER_FINISH_CONST_SIZE,
	.alert_value = tls1_alert_code,
	.export_keying_material = tls1_export_keying_material,
	.enc_flags = SSL_ENC_FLAG_EXPLICIT_IV,
};

SSL3_ENC_METHOD TLSv1_2_enc_data = {
	.enc = tls1_enc,
	.mac = tls1_mac,
	.setup_key_block = tls1_setup_key_block,
	.generate_master_secret = tls1_generate_master_secret,
	.change_cipher_state = tls1_change_cipher_state,
	.final_finish_mac = tls1_final_finish_mac,
	.finish_mac_length = TLS1_FINISH_MAC_LENGTH,
	.cert_verify_mac = tls1_cert_verify_mac,
	.client_finished_label = TLS_MD_CLIENT_FINISH_CONST,
	.client_finished_label_len = TLS_MD_CLIENT_FINISH_CONST_SIZE,
	.server_finished_label = TLS_MD_SERVER_FINISH_CONST,
	.server_finished_label_len = TLS_MD_SERVER_FINISH_CONST_SIZE,
	.alert_value = tls1_alert_code,
	.export_keying_material = tls1_export_keying_material,
	.enc_flags = SSL_ENC_FLAG_EXPLICIT_IV|SSL_ENC_FLAG_SIGALGS|
	    SSL_ENC_FLAG_SHA256_PRF|SSL_ENC_FLAG_TLS1_2_CIPHERS,
};

long
tls1_default_timeout(void)
{
	/* 2 hours, the 24 hours mentioned in the TLSv1 spec
	 * is way too long for http, the cache would over fill */
	return (60 * 60 * 2);
}

int
tls1_new(SSL *s)
{
	if (!ssl3_new(s))
		return (0);
	s->method->ssl_clear(s);
	return (1);
}

void
tls1_free(SSL *s)
{
	if (s == NULL)
		return;

	free(s->tlsext_session_ticket);
	ssl3_free(s);
}

void
tls1_clear(SSL *s)
{
	ssl3_clear(s);
	s->version = s->method->version;
}


static int nid_list[] = {
	NID_sect163k1,		/* sect163k1 (1) */
	NID_sect163r1,		/* sect163r1 (2) */
	NID_sect163r2,		/* sect163r2 (3) */
	NID_sect193r1,		/* sect193r1 (4) */
	NID_sect193r2,		/* sect193r2 (5) */
	NID_sect233k1,		/* sect233k1 (6) */
	NID_sect233r1,		/* sect233r1 (7) */
	NID_sect239k1,		/* sect239k1 (8) */
	NID_sect283k1,		/* sect283k1 (9) */
	NID_sect283r1,		/* sect283r1 (10) */
	NID_sect409k1,		/* sect409k1 (11) */
	NID_sect409r1,		/* sect409r1 (12) */
	NID_sect571k1,		/* sect571k1 (13) */
	NID_sect571r1,		/* sect571r1 (14) */
	NID_secp160k1,		/* secp160k1 (15) */
	NID_secp160r1,		/* secp160r1 (16) */
	NID_secp160r2,		/* secp160r2 (17) */
	NID_secp192k1,		/* secp192k1 (18) */
	NID_X9_62_prime192v1,	/* secp192r1 (19) */
	NID_secp224k1,		/* secp224k1 (20) */
	NID_secp224r1,		/* secp224r1 (21) */
	NID_secp256k1,		/* secp256k1 (22) */
	NID_X9_62_prime256v1,	/* secp256r1 (23) */
	NID_secp384r1,		/* secp384r1 (24) */
	NID_secp521r1,		/* secp521r1 (25) */
	NID_brainpoolP256r1,	/* brainpoolP256r1 (26) */
	NID_brainpoolP384r1,	/* brainpoolP384r1 (27) */
	NID_brainpoolP512r1	/* brainpoolP512r1 (28) */
};

static const uint8_t ecformats_default[] = {
	TLSEXT_ECPOINTFORMAT_uncompressed,
	TLSEXT_ECPOINTFORMAT_ansiX962_compressed_prime,
	TLSEXT_ECPOINTFORMAT_ansiX962_compressed_char2
};

static const uint16_t eccurves_default[] = {
	14,			/* sect571r1 (14) */
	13,			/* sect571k1 (13) */
	25,			/* secp521r1 (25) */
	28,			/* brainpool512r1 (28) */
	11,			/* sect409k1 (11) */
	12,			/* sect409r1 (12) */
	27,			/* brainpoolP384r1 (27) */
	24,			/* secp384r1 (24) */
	9,			/* sect283k1 (9) */
	10,			/* sect283r1 (10) */
	26,			/* brainpoolP256r1 (26) */
	22,			/* secp256k1 (22) */
	23,			/* secp256r1 (23) */
	8,			/* sect239k1 (8) */
	6,			/* sect233k1 (6) */
	7,			/* sect233r1 (7) */
	20,			/* secp224k1 (20) */
	21,			/* secp224r1 (21) */
	4,			/* sect193r1 (4) */
	5,			/* sect193r2 (5) */
	18,			/* secp192k1 (18) */
	19,			/* secp192r1 (19) */
	1,			/* sect163k1 (1) */
	2,			/* sect163r1 (2) */
	3,			/* sect163r2 (3) */
	15,			/* secp160k1 (15) */
	16,			/* secp160r1 (16) */
	17,			/* secp160r2 (17) */
};

int
tls1_ec_curve_id2nid(uint16_t curve_id)
{
	/* ECC curves from draft-ietf-tls-ecc-12.txt (Oct. 17, 2005) */
	if ((curve_id < 1) ||
	    ((unsigned int)curve_id > sizeof(nid_list) / sizeof(nid_list[0])))
		return 0;
	return nid_list[curve_id - 1];
}

uint16_t
tls1_ec_nid2curve_id(int nid)
{
	/* ECC curves from draft-ietf-tls-ecc-12.txt (Oct. 17, 2005) */
	switch (nid) {
	case NID_sect163k1: /* sect163k1 (1) */
		return 1;
	case NID_sect163r1: /* sect163r1 (2) */
		return 2;
	case NID_sect163r2: /* sect163r2 (3) */
		return 3;
	case NID_sect193r1: /* sect193r1 (4) */
		return 4;
	case NID_sect193r2: /* sect193r2 (5) */
		return 5;
	case NID_sect233k1: /* sect233k1 (6) */
		return 6;
	case NID_sect233r1: /* sect233r1 (7) */
		return 7;
	case NID_sect239k1: /* sect239k1 (8) */
		return 8;
	case NID_sect283k1: /* sect283k1 (9) */
		return 9;
	case NID_sect283r1: /* sect283r1 (10) */
		return 10;
	case NID_sect409k1: /* sect409k1 (11) */
		return 11;
	case NID_sect409r1: /* sect409r1 (12) */
		return 12;
	case NID_sect571k1: /* sect571k1 (13) */
		return 13;
	case NID_sect571r1: /* sect571r1 (14) */
		return 14;
	case NID_secp160k1: /* secp160k1 (15) */
		return 15;
	case NID_secp160r1: /* secp160r1 (16) */
		return 16;
	case NID_secp160r2: /* secp160r2 (17) */
		return 17;
	case NID_secp192k1: /* secp192k1 (18) */
		return 18;
	case NID_X9_62_prime192v1: /* secp192r1 (19) */
		return 19;
	case NID_secp224k1: /* secp224k1 (20) */
		return 20;
	case NID_secp224r1: /* secp224r1 (21) */
		return 21;
	case NID_secp256k1: /* secp256k1 (22) */
		return 22;
	case NID_X9_62_prime256v1: /* secp256r1 (23) */
		return 23;
	case NID_secp384r1: /* secp384r1 (24) */
		return 24;
	case NID_secp521r1: /* secp521r1 (25) */
		return 25;
	case NID_brainpoolP256r1: /* brainpoolP256r1 (26) */
		return 26;
	case NID_brainpoolP384r1: /* brainpoolP384r1 (27) */
		return 27;
	case NID_brainpoolP512r1: /* brainpoolP512r1 (28) */
		return 28;
	default:
		return 0;
	}
}

/*
 * Return the appropriate format list. If client_formats is non-zero, return
 * the client/session formats. Otherwise return the custom format list if one
 * exists, or the default formats if a custom list has not been specified.
 */
static void
tls1_get_formatlist(SSL *s, int client_formats, const uint8_t **pformats,
    size_t *pformatslen)
{
	if (client_formats != 0) {
		*pformats = s->session->tlsext_ecpointformatlist;
		*pformatslen = s->session->tlsext_ecpointformatlist_length;
		return;
	}

	*pformats = s->tlsext_ecpointformatlist;
	*pformatslen = s->tlsext_ecpointformatlist_length;
	if (*pformats == NULL) {
		*pformats = ecformats_default;
		*pformatslen = sizeof(ecformats_default);
	}
}

/*
 * Return the appropriate curve list. If client_curves is non-zero, return
 * the client/session curves. Otherwise return the custom curve list if one
 * exists, or the default curves if a custom list has not been specified.
 */
static void
tls1_get_curvelist(SSL *s, int client_curves, const uint16_t **pcurves,
    size_t *pcurveslen)
{
	if (client_curves != 0) {
		*pcurves = s->session->tlsext_ellipticcurvelist;
		*pcurveslen = s->session->tlsext_ellipticcurvelist_length;
		return;
	}

	*pcurves = s->tlsext_ellipticcurvelist;
	*pcurveslen = s->tlsext_ellipticcurvelist_length;
	if (*pcurves == NULL) {
		*pcurves = eccurves_default;
		*pcurveslen = sizeof(eccurves_default) / 2;
	}
}

/* Check that a curve is one of our preferences. */
int
tls1_check_curve(SSL *s, const unsigned char *p, size_t len)
{
	CBS cbs;
	const uint16_t *curves;
	size_t curveslen, i;
	uint8_t type;
	uint16_t cid;

	CBS_init(&cbs, p, len);

	/* Only named curves are supported. */
	if (CBS_len(&cbs) != 3 ||
	    !CBS_get_u8(&cbs, &type) ||
	    type != NAMED_CURVE_TYPE ||
	    !CBS_get_u16(&cbs, &cid))
		return (0);

	tls1_get_curvelist(s, 0, &curves, &curveslen);

	for (i = 0; i < curveslen; i++) {
		if (curves[i] == cid)
			return (1);
	}
	return (0);
}

int
tls1_get_shared_curve(SSL *s)
{
	size_t preflen, supplen, i, j;
	const uint16_t *pref, *supp;
	unsigned long server_pref;

	/* Cannot do anything on the client side. */
	if (s->server == 0)
		return (NID_undef);

	/* Return first preference shared curve. */
	server_pref = (s->options & SSL_OP_CIPHER_SERVER_PREFERENCE);
	tls1_get_curvelist(s, (server_pref == 0), &pref, &preflen);
	tls1_get_curvelist(s, (server_pref != 0), &supp, &supplen);

	for (i = 0; i < preflen; i++) {
		for (j = 0; j < supplen; j++) {
			if (pref[i] == supp[j])
				return (tls1_ec_curve_id2nid(pref[i]));
		}
	}
	return (NID_undef);
}

/* For an EC key set TLS ID and required compression based on parameters. */
static int
tls1_set_ec_id(uint16_t *curve_id, uint8_t *comp_id, EC_KEY *ec)
{
	const EC_GROUP *grp;
	const EC_METHOD *meth;
	int is_prime = 0;
	int nid, id;

	if (ec == NULL)
		return (0);

	/* Determine if it is a prime field. */
	if ((grp = EC_KEY_get0_group(ec)) == NULL)
		return (0);
	if ((meth = EC_GROUP_method_of(grp)) == NULL)
		return (0);
	if (EC_METHOD_get_field_type(meth) == NID_X9_62_prime_field)
		is_prime = 1;

	/* Determine curve ID. */
	nid = EC_GROUP_get_curve_name(grp);
	id = tls1_ec_nid2curve_id(nid);

	/* If we have an ID set it, otherwise set arbitrary explicit curve. */
	if (id != 0)
		*curve_id = id;
	else
		*curve_id = is_prime ? 0xff01 : 0xff02;

	/* Specify the compression identifier. */
	if (comp_id != NULL) {
		if (EC_KEY_get0_public_key(ec) == NULL)
			return (0);

		if (EC_KEY_get_conv_form(ec) == POINT_CONVERSION_COMPRESSED) {
			*comp_id = is_prime ?
			    TLSEXT_ECPOINTFORMAT_ansiX962_compressed_prime :
			    TLSEXT_ECPOINTFORMAT_ansiX962_compressed_char2;
		} else {
			*comp_id = TLSEXT_ECPOINTFORMAT_uncompressed;
		}
	}
	return (1);
}

/* Check that an EC key is compatible with extensions. */
static int
tls1_check_ec_key(SSL *s, const uint16_t *curve_id, const uint8_t *comp_id)
{
	size_t curveslen, formatslen, i;
	const uint16_t *curves;
	const uint8_t *formats;

	/*
	 * Check point formats extension if present, otherwise everything
	 * is supported (see RFC4492).
	 */
	tls1_get_formatlist(s, 1, &formats, &formatslen);
	if (comp_id != NULL && formats != NULL) {
		for (i = 0; i < formatslen; i++) {
			if (formats[i] == *comp_id)
				break;
		}
		if (i == formatslen)
			return (0);
	}

	/*
	 * Check curve list if present, otherwise everything is supported.
	 */
	tls1_get_curvelist(s, 1, &curves, &curveslen);
	if (curve_id != NULL && curves != NULL) {
		for (i = 0; i < curveslen; i++) {
			if (curves[i] == *curve_id)
				break;
		}
		if (i == curveslen)
			return (0);
	}

	return (1);
}

/* Check EC server key is compatible with client extensions. */
int
tls1_check_ec_server_key(SSL *s)
{
	CERT_PKEY *cpk = s->cert->pkeys + SSL_PKEY_ECC;
	uint16_t curve_id;
	uint8_t comp_id;
	EVP_PKEY *pkey;
	int rv;

	if (cpk->x509 == NULL || cpk->privatekey == NULL)
		return (0);
	if ((pkey = X509_get_pubkey(cpk->x509)) == NULL)
		return (0);
	rv = tls1_set_ec_id(&curve_id, &comp_id, pkey->pkey.ec);
	EVP_PKEY_free(pkey);
	if (rv != 1)
		return (0);

	return tls1_check_ec_key(s, &curve_id, &comp_id);
}

/* Check EC temporary key is compatible with client extensions. */
int
tls1_check_ec_tmp_key(SSL *s)
{
	EC_KEY *ec = s->cert->ecdh_tmp;
	uint16_t curve_id;

	if (s->cert->ecdh_tmp_auto != 0) {
		/* Need a shared curve. */
		if (tls1_get_shared_curve(s) != NID_undef)
			return (1);
		return (0);
	}

	if (ec == NULL) {
		if (s->cert->ecdh_tmp_cb != NULL)
			return (1);
		return (0);
	}
	if (tls1_set_ec_id(&curve_id, NULL, ec) != 1)
		return (0);

	return tls1_check_ec_key(s, &curve_id, NULL);
}

/*
 * List of supported signature algorithms and hashes. Should make this
 * customisable at some point, for now include everything we support.
 */

static unsigned char tls12_sigalgs[] = {
	TLSEXT_hash_sha512, TLSEXT_signature_rsa,
	TLSEXT_hash_sha512, TLSEXT_signature_dsa,
	TLSEXT_hash_sha512, TLSEXT_signature_ecdsa,
#ifndef OPENSSL_NO_GOST
	TLSEXT_hash_streebog_512, TLSEXT_signature_gostr12_512,
#endif

	TLSEXT_hash_sha384, TLSEXT_signature_rsa,
	TLSEXT_hash_sha384, TLSEXT_signature_dsa,
	TLSEXT_hash_sha384, TLSEXT_signature_ecdsa,

	TLSEXT_hash_sha256, TLSEXT_signature_rsa,
	TLSEXT_hash_sha256, TLSEXT_signature_dsa,
	TLSEXT_hash_sha256, TLSEXT_signature_ecdsa,

#ifndef OPENSSL_NO_GOST
	TLSEXT_hash_streebog_256, TLSEXT_signature_gostr12_256,
	TLSEXT_hash_gost94, TLSEXT_signature_gostr01,
#endif

	TLSEXT_hash_sha224, TLSEXT_signature_rsa,
	TLSEXT_hash_sha224, TLSEXT_signature_dsa,
	TLSEXT_hash_sha224, TLSEXT_signature_ecdsa,

	TLSEXT_hash_sha1, TLSEXT_signature_rsa,
	TLSEXT_hash_sha1, TLSEXT_signature_dsa,
	TLSEXT_hash_sha1, TLSEXT_signature_ecdsa,
};

int
tls12_get_req_sig_algs(SSL *s, unsigned char *p)
{
	size_t slen = sizeof(tls12_sigalgs);

	if (p)
		memcpy(p, tls12_sigalgs, slen);
	return (int)slen;
}

unsigned char *
ssl_add_clienthello_tlsext(SSL *s, unsigned char *p, unsigned char *limit)
{
	int extdatalen = 0;
	unsigned char *ret = p;
	int using_ecc = 0;

	/* See if we support any ECC ciphersuites. */
	if (s->version != DTLS1_VERSION && s->version >= TLS1_VERSION) {
		STACK_OF(SSL_CIPHER) *cipher_stack = SSL_get_ciphers(s);
		unsigned long alg_k, alg_a;
		int i;

		for (i = 0; i < sk_SSL_CIPHER_num(cipher_stack); i++) {
			SSL_CIPHER *c = sk_SSL_CIPHER_value(cipher_stack, i);

			alg_k = c->algorithm_mkey;
			alg_a = c->algorithm_auth;

			if ((alg_k & (SSL_kECDHE|SSL_kECDHr|SSL_kECDHe) ||
			    (alg_a & SSL_aECDSA))) {
				using_ecc = 1;
				break;
			}
		}
	}

	ret += 2;

	if (ret >= limit)
		return NULL; /* this really never occurs, but ... */

	if (s->tlsext_hostname != NULL) {
		/* Add TLS extension servername to the Client Hello message */
		size_t size_str, lenmax;

		/* check for enough space.
		   4 for the servername type and extension length
		   2 for servernamelist length
		   1 for the hostname type
		   2 for hostname length
		   + hostname length
		*/

		if ((size_t)(limit - ret) < 9)
			return NULL;

		lenmax = limit - ret - 9;
		if ((size_str = strlen(s->tlsext_hostname)) > lenmax)
			return NULL;

		/* extension type and length */
		s2n(TLSEXT_TYPE_server_name, ret);

		s2n(size_str + 5, ret);

		/* length of servername list */
		s2n(size_str + 3, ret);

		/* hostname type, length and hostname */
		*(ret++) = (unsigned char) TLSEXT_NAMETYPE_host_name;
		s2n(size_str, ret);
		memcpy(ret, s->tlsext_hostname, size_str);
		ret += size_str;
	}

	/* Add RI if renegotiating */
	if (s->renegotiate) {
		int el;

		if (!ssl_add_clienthello_renegotiate_ext(s, 0, &el, 0)) {
			SSLerr(SSL_F_SSL_ADD_CLIENTHELLO_TLSEXT,
			    ERR_R_INTERNAL_ERROR);
			return NULL;
		}

		if ((size_t)(limit - ret) < 4 + el)
			return NULL;

		s2n(TLSEXT_TYPE_renegotiate, ret);
		s2n(el, ret);

		if (!ssl_add_clienthello_renegotiate_ext(s, ret, &el, el)) {
			SSLerr(SSL_F_SSL_ADD_CLIENTHELLO_TLSEXT,
			    ERR_R_INTERNAL_ERROR);
			return NULL;
		}

		ret += el;
	}

	if (using_ecc) {
		size_t curveslen, formatslen, lenmax;
		const uint16_t *curves;
		const uint8_t *formats;
		int i;

		/*
		 * Add TLS extension ECPointFormats to the ClientHello message.
		 */
		tls1_get_formatlist(s, 0, &formats, &formatslen);

		if ((size_t)(limit - ret) < 5)
			return NULL;

		lenmax = limit - ret - 5;
		if (formatslen > lenmax)
			return NULL;
		if (formatslen > 255) {
			SSLerr(SSL_F_SSL_ADD_CLIENTHELLO_TLSEXT,
			    ERR_R_INTERNAL_ERROR);
			return NULL;
		}

		s2n(TLSEXT_TYPE_ec_point_formats, ret);
		s2n(formatslen + 1, ret);
		*(ret++) = (unsigned char)formatslen;
		memcpy(ret, formats, formatslen);
		ret += formatslen;

		/*
		 * Add TLS extension EllipticCurves to the ClientHello message.
		 */
		tls1_get_curvelist(s, 0, &curves, &curveslen);

		if ((size_t)(limit - ret) < 6)
			return NULL;

		lenmax = limit - ret - 6;
		if (curveslen > lenmax)
			return NULL;
		if (curveslen > 65532) {
			SSLerr(SSL_F_SSL_ADD_CLIENTHELLO_TLSEXT,
			    ERR_R_INTERNAL_ERROR);
			return NULL;
		}

		s2n(TLSEXT_TYPE_elliptic_curves, ret);
		s2n((curveslen * 2) + 2, ret);

		/* NB: draft-ietf-tls-ecc-12.txt uses a one-byte prefix for
		 * elliptic_curve_list, but the examples use two bytes.
		 * https://www1.ietf.org/mail-archive/web/tls/current/msg00538.html
		 * resolves this to two bytes.
		 */
		s2n(curveslen * 2, ret);
		for (i = 0; i < curveslen; i++)
			s2n(curves[i], ret);
	}

	if (!(SSL_get_options(s) & SSL_OP_NO_TICKET)) {
		int ticklen;
		if (!s->new_session && s->session && s->session->tlsext_tick)
			ticklen = s->session->tlsext_ticklen;
		else if (s->session && s->tlsext_session_ticket &&
		    s->tlsext_session_ticket->data) {
			ticklen = s->tlsext_session_ticket->length;
			s->session->tlsext_tick = malloc(ticklen);
			if (!s->session->tlsext_tick)
				return NULL;
			memcpy(s->session->tlsext_tick,
			    s->tlsext_session_ticket->data, ticklen);
			s->session->tlsext_ticklen = ticklen;
		} else
			ticklen = 0;
		if (ticklen == 0 && s->tlsext_session_ticket &&
		    s->tlsext_session_ticket->data == NULL)
			goto skip_ext;
		/* Check for enough room 2 for extension type, 2 for len
 		 * rest for ticket
  		 */
		if ((size_t)(limit - ret) < 4 + ticklen)
			return NULL;
		s2n(TLSEXT_TYPE_session_ticket, ret);

		s2n(ticklen, ret);
		if (ticklen) {
			memcpy(ret, s->session->tlsext_tick, ticklen);
			ret += ticklen;
		}
	}
skip_ext:

	if (TLS1_get_client_version(s) >= TLS1_2_VERSION) {
		if ((size_t)(limit - ret) < sizeof(tls12_sigalgs) + 6)
			return NULL;

		s2n(TLSEXT_TYPE_signature_algorithms, ret);
		s2n(sizeof(tls12_sigalgs) + 2, ret);
		s2n(sizeof(tls12_sigalgs), ret);
		memcpy(ret, tls12_sigalgs, sizeof(tls12_sigalgs));
		ret += sizeof(tls12_sigalgs);
	}

	if (s->tlsext_status_type == TLSEXT_STATUSTYPE_ocsp &&
	    s->version != DTLS1_VERSION) {
		int i;
		long extlen, idlen, itmp;
		OCSP_RESPID *id;

		idlen = 0;
		for (i = 0; i < sk_OCSP_RESPID_num(s->tlsext_ocsp_ids); i++) {
			id = sk_OCSP_RESPID_value(s->tlsext_ocsp_ids, i);
			itmp = i2d_OCSP_RESPID(id, NULL);
			if (itmp <= 0)
				return NULL;
			idlen += itmp + 2;
		}

		if (s->tlsext_ocsp_exts) {
			extlen = i2d_X509_EXTENSIONS(s->tlsext_ocsp_exts, NULL);
			if (extlen < 0)
				return NULL;
		} else
			extlen = 0;

		if ((size_t)(limit - ret) < 7 + extlen + idlen)
			return NULL;
		s2n(TLSEXT_TYPE_status_request, ret);
		if (extlen + idlen > 0xFFF0)
			return NULL;
		s2n(extlen + idlen + 5, ret);
		*(ret++) = TLSEXT_STATUSTYPE_ocsp;
		s2n(idlen, ret);
		for (i = 0; i < sk_OCSP_RESPID_num(s->tlsext_ocsp_ids); i++) {
			/* save position of id len */
			unsigned char *q = ret;
			id = sk_OCSP_RESPID_value(s->tlsext_ocsp_ids, i);
			/* skip over id len */
			ret += 2;
			itmp = i2d_OCSP_RESPID(id, &ret);
			/* write id len */
			s2n(itmp, q);
		}
		s2n(extlen, ret);
		if (extlen > 0)
			i2d_X509_EXTENSIONS(s->tlsext_ocsp_exts, &ret);
	}

	if (s->ctx->next_proto_select_cb && !s->s3->tmp.finish_md_len) {
		/* The client advertises an emtpy extension to indicate its
		 * support for Next Protocol Negotiation */
		if ((size_t)(limit - ret) < 4)
			return NULL;
		s2n(TLSEXT_TYPE_next_proto_neg, ret);
		s2n(0, ret);
	}

	if (s->alpn_client_proto_list != NULL &&
	    s->s3->tmp.finish_md_len == 0) {
		if ((size_t)(limit - ret) < 6 + s->alpn_client_proto_list_len)
			return (NULL);
		s2n(TLSEXT_TYPE_application_layer_protocol_negotiation, ret);
		s2n(2 + s->alpn_client_proto_list_len, ret);
		s2n(s->alpn_client_proto_list_len, ret);
		memcpy(ret, s->alpn_client_proto_list,
		    s->alpn_client_proto_list_len);
		ret += s->alpn_client_proto_list_len;
	}

#ifndef OPENSSL_NO_SRTP
	if (SSL_IS_DTLS(s) && SSL_get_srtp_profiles(s)) {
		int el;

		ssl_add_clienthello_use_srtp_ext(s, 0, &el, 0);

		if ((size_t)(limit - ret) < 4 + el)
			return NULL;

		s2n(TLSEXT_TYPE_use_srtp, ret);
		s2n(el, ret);

		if (ssl_add_clienthello_use_srtp_ext(s, ret, &el, el)) {
			SSLerr(SSL_F_SSL_ADD_CLIENTHELLO_TLSEXT,
			    ERR_R_INTERNAL_ERROR);
			return NULL;
		}
		ret += el;
	}
#endif

	/*
	 * Add padding to workaround bugs in F5 terminators.
	 * See https://tools.ietf.org/html/draft-agl-tls-padding-03
	 *
	 * Note that this seems to trigger issues with IronPort SMTP
	 * appliances.
	 *
	 * NB: because this code works out the length of all existing
	 * extensions it MUST always appear last.
	 */
	if (s->options & SSL_OP_TLSEXT_PADDING) {
		int hlen = ret - (unsigned char *)s->init_buf->data;

		/*
		 * The code in s23_clnt.c to build ClientHello messages
		 * includes the 5-byte record header in the buffer, while the
		 * code in s3_clnt.c does not.
		 */
		if (s->state == SSL23_ST_CW_CLNT_HELLO_A)
			hlen -= 5;
		if (hlen > 0xff && hlen < 0x200) {
			hlen = 0x200 - hlen;
			if (hlen >= 4)
				hlen -= 4;
			else
				hlen = 0;

			s2n(TLSEXT_TYPE_padding, ret);
			s2n(hlen, ret);
			memset(ret, 0, hlen);
			ret += hlen;
		}
	}

	if ((extdatalen = ret - p - 2) == 0)
		return p;

	s2n(extdatalen, p);
	return ret;
}

unsigned char *
ssl_add_serverhello_tlsext(SSL *s, unsigned char *p, unsigned char *limit)
{
	int using_ecc, extdatalen = 0;
	unsigned long alg_a, alg_k;
	unsigned char *ret = p;
	int next_proto_neg_seen;

	alg_a = s->s3->tmp.new_cipher->algorithm_auth;
	alg_k = s->s3->tmp.new_cipher->algorithm_mkey;
	using_ecc = (alg_k & (SSL_kECDHE|SSL_kECDHr|SSL_kECDHe) ||
	    alg_a & SSL_aECDSA) &&
	    s->session->tlsext_ecpointformatlist != NULL;

	ret += 2;
	if (ret >= limit)
		return NULL; /* this really never occurs, but ... */

	if (!s->hit && s->servername_done == 1 &&
	    s->session->tlsext_hostname != NULL) {
		if ((size_t)(limit - ret) < 4)
			return NULL;

		s2n(TLSEXT_TYPE_server_name, ret);
		s2n(0, ret);
	}

	if (s->s3->send_connection_binding) {
		int el;

		if (!ssl_add_serverhello_renegotiate_ext(s, 0, &el, 0)) {
			SSLerr(SSL_F_SSL_ADD_SERVERHELLO_TLSEXT,
			    ERR_R_INTERNAL_ERROR);
			return NULL;
		}

		if ((size_t)(limit - ret) < 4 + el)
			return NULL;

		s2n(TLSEXT_TYPE_renegotiate, ret);
		s2n(el, ret);

		if (!ssl_add_serverhello_renegotiate_ext(s, ret, &el, el)) {
			SSLerr(SSL_F_SSL_ADD_SERVERHELLO_TLSEXT,
			    ERR_R_INTERNAL_ERROR);
			return NULL;
		}

		ret += el;
	}

	if (using_ecc && s->version != DTLS1_VERSION) {
		const unsigned char *formats;
		size_t formatslen, lenmax;

		/*
		 * Add TLS extension ECPointFormats to the ServerHello message.
		 */
		tls1_get_formatlist(s, 0, &formats, &formatslen);

		if ((size_t)(limit - ret) < 5)
			return NULL;

		lenmax = limit - ret - 5;
		if (formatslen > lenmax)
			return NULL;
		if (formatslen > 255) {
			SSLerr(SSL_F_SSL_ADD_SERVERHELLO_TLSEXT,
			    ERR_R_INTERNAL_ERROR);
			return NULL;
		}

		s2n(TLSEXT_TYPE_ec_point_formats, ret);
		s2n(formatslen + 1, ret);
		*(ret++) = (unsigned char)formatslen;
		memcpy(ret, formats, formatslen);
		ret += formatslen;
	}

	/*
	 * Currently the server should not respond with a SupportedCurves
	 * extension.
	 */

	if (s->tlsext_ticket_expected &&
	    !(SSL_get_options(s) & SSL_OP_NO_TICKET)) {
		if ((size_t)(limit - ret) < 4)
			return NULL;

		s2n(TLSEXT_TYPE_session_ticket, ret);
		s2n(0, ret);
	}

	if (s->tlsext_status_expected) {
		if ((size_t)(limit - ret) < 4)
			return NULL;

		s2n(TLSEXT_TYPE_status_request, ret);
		s2n(0, ret);
	}

#ifndef OPENSSL_NO_SRTP
	if (SSL_IS_DTLS(s) && s->srtp_profile) {
		int el;

		ssl_add_serverhello_use_srtp_ext(s, 0, &el, 0);

		if ((size_t)(limit - ret) < 4 + el)
			return NULL;

		s2n(TLSEXT_TYPE_use_srtp, ret);
		s2n(el, ret);

		if (ssl_add_serverhello_use_srtp_ext(s, ret, &el, el)) {
			SSLerr(SSL_F_SSL_ADD_SERVERHELLO_TLSEXT,
			    ERR_R_INTERNAL_ERROR);
			return NULL;
		}
		ret += el;
	}
#endif

	if (((s->s3->tmp.new_cipher->id & 0xFFFF) == 0x80 ||
	    (s->s3->tmp.new_cipher->id & 0xFFFF) == 0x81) &&
	    (SSL_get_options(s) & SSL_OP_CRYPTOPRO_TLSEXT_BUG)) {
		static const unsigned char cryptopro_ext[36] = {
			0xfd, 0xe8, /*65000*/
			0x00, 0x20, /*32 bytes length*/
			0x30, 0x1e, 0x30, 0x08, 0x06, 0x06, 0x2a, 0x85,
			0x03, 0x02, 0x02, 0x09, 0x30, 0x08, 0x06, 0x06,
			0x2a, 0x85, 0x03, 0x02, 0x02, 0x16, 0x30, 0x08,
			0x06, 0x06, 0x2a, 0x85, 0x03, 0x02, 0x02, 0x17
		};
		if ((size_t)(limit - ret) < sizeof(cryptopro_ext))
			return NULL;
		memcpy(ret, cryptopro_ext, sizeof(cryptopro_ext));
		ret += sizeof(cryptopro_ext);
	}

	next_proto_neg_seen = s->s3->next_proto_neg_seen;
	s->s3->next_proto_neg_seen = 0;
	if (next_proto_neg_seen && s->ctx->next_protos_advertised_cb) {
		const unsigned char *npa;
		unsigned int npalen;
		int r;

		r = s->ctx->next_protos_advertised_cb(s, &npa, &npalen,
		    s->ctx->next_protos_advertised_cb_arg);
		if (r == SSL_TLSEXT_ERR_OK) {
			if ((size_t)(limit - ret) < 4 + npalen)
				return NULL;
			s2n(TLSEXT_TYPE_next_proto_neg, ret);
			s2n(npalen, ret);
			memcpy(ret, npa, npalen);
			ret += npalen;
			s->s3->next_proto_neg_seen = 1;
		}
	}

	if (s->s3->alpn_selected != NULL) {
		const unsigned char *selected = s->s3->alpn_selected;
		unsigned int len = s->s3->alpn_selected_len;

		if ((long)(limit - ret - 4 - 2 - 1 - len) < 0)
			return (NULL);
		s2n(TLSEXT_TYPE_application_layer_protocol_negotiation, ret);
		s2n(3 + len, ret);
		s2n(1 + len, ret);
		*ret++ = len;
		memcpy(ret, selected, len);
		ret += len;
	}

	if ((extdatalen = ret - p - 2) == 0)
		return p;

	s2n(extdatalen, p);
	return ret;
}

/*
 * tls1_alpn_handle_client_hello is called to process the ALPN extension in a
 * ClientHello.
 *   data: the contents of the extension, not including the type and length.
 *   data_len: the number of bytes in data.
 *   al: a pointer to the alert value to send in the event of a non-zero
 *       return.
 *   returns: 1 on success.
 */
static int
tls1_alpn_handle_client_hello(SSL *s, const unsigned char *data,
    unsigned int data_len, int *al)
{
	CBS cbs, proto_name_list, alpn;
	const unsigned char *selected;
	unsigned char selected_len;
	int r;

	if (s->ctx->alpn_select_cb == NULL)
		return (1);

	if (data_len < 2)
		goto parse_error;

	CBS_init(&cbs, data, data_len);

	/*
	 * data should contain a uint16 length followed by a series of 8-bit,
	 * length-prefixed strings.
	 */
	if (!CBS_get_u16_length_prefixed(&cbs, &alpn) ||
	    CBS_len(&alpn) < 2 ||
	    CBS_len(&cbs) != 0)
		goto parse_error;

	/* Validate data before sending to callback. */
	CBS_dup(&alpn, &proto_name_list);
	while (CBS_len(&proto_name_list) > 0) {
		CBS proto_name;

		if (!CBS_get_u8_length_prefixed(&proto_name_list, &proto_name) ||
		    CBS_len(&proto_name) == 0)
			goto parse_error;
	}

	r = s->ctx->alpn_select_cb(s, &selected, &selected_len,
	    CBS_data(&alpn), CBS_len(&alpn), s->ctx->alpn_select_cb_arg);
	if (r == SSL_TLSEXT_ERR_OK) {
		free(s->s3->alpn_selected);
		if ((s->s3->alpn_selected = malloc(selected_len)) == NULL) {
			*al = SSL_AD_INTERNAL_ERROR;
			return (-1);
		}
		memcpy(s->s3->alpn_selected, selected, selected_len);
		s->s3->alpn_selected_len = selected_len;
	}

	return (1);

parse_error:
	*al = SSL_AD_DECODE_ERROR;
	return (0);
}

int
ssl_parse_clienthello_tlsext(SSL *s, unsigned char **p, unsigned char *d,
    int n, int *al)
{
	unsigned short type;
	unsigned short size;
	unsigned short len;
	unsigned char *data = *p;
	int renegotiate_seen = 0;
	int sigalg_seen = 0;

	s->servername_done = 0;
	s->tlsext_status_type = -1;
	s->s3->next_proto_neg_seen = 0;
	free(s->s3->alpn_selected);
	s->s3->alpn_selected = NULL;

	if (data >= (d + n - 2))
		goto ri_check;
	n2s(data, len);

	if (data > (d + n - len))
		goto ri_check;

	while (data <= (d + n - 4)) {
		n2s(data, type);
		n2s(data, size);

		if (data + size > (d + n))
			goto ri_check;
		if (s->tlsext_debug_cb)
			s->tlsext_debug_cb(s, 0, type, data, size,
			    s->tlsext_debug_arg);
/* The servername extension is treated as follows:

   - Only the hostname type is supported with a maximum length of 255.
   - The servername is rejected if too long or if it contains zeros,
     in which case an fatal alert is generated.
   - The servername field is maintained together with the session cache.
   - When a session is resumed, the servername call back invoked in order
     to allow the application to position itself to the right context.
   - The servername is acknowledged if it is new for a session or when
     it is identical to a previously used for the same session.
     Applications can control the behaviour.  They can at any time
     set a 'desirable' servername for a new SSL object. This can be the
     case for example with HTTPS when a Host: header field is received and
     a renegotiation is requested. In this case, a possible servername
     presented in the new client hello is only acknowledged if it matches
     the value of the Host: field.
   - Applications must  use SSL_OP_NO_SESSION_RESUMPTION_ON_RENEGOTIATION
     if they provide for changing an explicit servername context for the session,
     i.e. when the session has been established with a servername extension.
   - On session reconnect, the servername extension may be absent.

*/

		if (type == TLSEXT_TYPE_server_name) {
			unsigned char *sdata;
			int servname_type;
			int dsize;

			if (size < 2) {
				*al = SSL_AD_DECODE_ERROR;
				return 0;
			}
			n2s(data, dsize);

			size -= 2;
			if (dsize > size) {
				*al = SSL_AD_DECODE_ERROR;
				return 0;
			}

			sdata = data;
			while (dsize > 3) {
				servname_type = *(sdata++);

				n2s(sdata, len);
				dsize -= 3;

				if (len > dsize) {
					*al = SSL_AD_DECODE_ERROR;
					return 0;
				}
				if (s->servername_done == 0)
					switch (servname_type) {
					case TLSEXT_NAMETYPE_host_name:
						if (!s->hit) {
							if (s->session->tlsext_hostname) {
								*al = SSL_AD_DECODE_ERROR;
								return 0;
							}
							if (len > TLSEXT_MAXLEN_host_name) {
								*al = TLS1_AD_UNRECOGNIZED_NAME;
								return 0;
							}
							if ((s->session->tlsext_hostname =
							    malloc(len + 1)) == NULL) {
								*al = TLS1_AD_INTERNAL_ERROR;
								return 0;
							}
							memcpy(s->session->tlsext_hostname, sdata, len);
							s->session->tlsext_hostname[len] = '\0';
							if (strlen(s->session->tlsext_hostname) != len) {
								free(s->session->tlsext_hostname);
								s->session->tlsext_hostname = NULL;
								*al = TLS1_AD_UNRECOGNIZED_NAME;
								return 0;
							}
							s->servername_done = 1;


						} else {
							s->servername_done = s->session->tlsext_hostname &&
							    strlen(s->session->tlsext_hostname) == len &&
							    strncmp(s->session->tlsext_hostname, (char *)sdata, len) == 0;
						}
						break;

					default:
						break;
					}

				dsize -= len;
			}
			if (dsize != 0) {
				*al = SSL_AD_DECODE_ERROR;
				return 0;
			}

		}

		else if (type == TLSEXT_TYPE_ec_point_formats &&
		    s->version != DTLS1_VERSION) {
			unsigned char *sdata = data;
			size_t formatslen;
			uint8_t *formats;

			if (size < 1) {
				*al = TLS1_AD_DECODE_ERROR;
				return 0;
			}
			formatslen = *(sdata++);
			if (formatslen != size - 1) {
				*al = TLS1_AD_DECODE_ERROR;
				return 0;
			}

			if (!s->hit) {
				free(s->session->tlsext_ecpointformatlist);
				s->session->tlsext_ecpointformatlist = NULL;
				s->session->tlsext_ecpointformatlist_length = 0;

				if ((formats = reallocarray(NULL, formatslen,
				    sizeof(uint8_t))) == NULL) {
					*al = TLS1_AD_INTERNAL_ERROR;
					return 0;
				}
				memcpy(formats, sdata, formatslen);
				s->session->tlsext_ecpointformatlist = formats;
				s->session->tlsext_ecpointformatlist_length =
				    formatslen;
			}
		} else if (type == TLSEXT_TYPE_elliptic_curves &&
		    s->version != DTLS1_VERSION) {
			unsigned char *sdata = data;
			size_t curveslen, i;
			uint16_t *curves;

			if (size < 2) {
				*al = TLS1_AD_DECODE_ERROR;
				return 0;
			}
			n2s(sdata, curveslen);
			if (curveslen != size - 2 || curveslen % 2 != 0) {
				*al = TLS1_AD_DECODE_ERROR;
				return 0;
			}
			curveslen /= 2;

			if (!s->hit) {
				if (s->session->tlsext_ellipticcurvelist) {
					*al = TLS1_AD_DECODE_ERROR;
					return 0;
				}
				s->session->tlsext_ellipticcurvelist_length = 0;
				if ((curves = reallocarray(NULL, curveslen,
				    sizeof(uint16_t))) == NULL) {
					*al = TLS1_AD_INTERNAL_ERROR;
					return 0;
				}
				for (i = 0; i < curveslen; i++)
					n2s(sdata, curves[i]);
				s->session->tlsext_ellipticcurvelist = curves;
				s->session->tlsext_ellipticcurvelist_length = curveslen;
			}
		}
		else if (type == TLSEXT_TYPE_session_ticket) {
			if (s->tls_session_ticket_ext_cb &&
			    !s->tls_session_ticket_ext_cb(s, data, size, s->tls_session_ticket_ext_cb_arg)) {
				*al = TLS1_AD_INTERNAL_ERROR;
				return 0;
			}
		} else if (type == TLSEXT_TYPE_renegotiate) {
			if (!ssl_parse_clienthello_renegotiate_ext(s, data, size, al))
				return 0;
			renegotiate_seen = 1;
		} else if (type == TLSEXT_TYPE_signature_algorithms) {
			int dsize;
			if (sigalg_seen || size < 2) {
				*al = SSL_AD_DECODE_ERROR;
				return 0;
			}
			sigalg_seen = 1;
			n2s(data, dsize);
			size -= 2;
			if (dsize != size || dsize & 1) {
				*al = SSL_AD_DECODE_ERROR;
				return 0;
			}
			if (!tls1_process_sigalgs(s, data, dsize)) {
				*al = SSL_AD_DECODE_ERROR;
				return 0;
			}
		} else if (type == TLSEXT_TYPE_status_request &&
		    s->version != DTLS1_VERSION) {

			if (size < 5) {
				*al = SSL_AD_DECODE_ERROR;
				return 0;
			}

			s->tlsext_status_type = *data++;
			size--;
			if (s->tlsext_status_type == TLSEXT_STATUSTYPE_ocsp) {
				const unsigned char *sdata;
				int dsize;
				/* Read in responder_id_list */
				n2s(data, dsize);
				size -= 2;
				if (dsize > size) {
					*al = SSL_AD_DECODE_ERROR;
					return 0;
				}

				/*
				 * We remove any OCSP_RESPIDs from a
				 * previous handshake to prevent
				 * unbounded memory growth.
				 */
				sk_OCSP_RESPID_pop_free(s->tlsext_ocsp_ids,
				    OCSP_RESPID_free);
				s->tlsext_ocsp_ids = NULL;
				if (dsize > 0) {
					s->tlsext_ocsp_ids =
					    sk_OCSP_RESPID_new_null();
					if (s->tlsext_ocsp_ids == NULL) {
						*al = SSL_AD_INTERNAL_ERROR;
						return 0;
					}
				}

				while (dsize > 0) {
					OCSP_RESPID *id;
					int idsize;
					if (dsize < 4) {
						*al = SSL_AD_DECODE_ERROR;
						return 0;
					}
					n2s(data, idsize);
					dsize -= 2 + idsize;
					size -= 2 + idsize;
					if (dsize < 0) {
						*al = SSL_AD_DECODE_ERROR;
						return 0;
					}
					sdata = data;
					data += idsize;
					id = d2i_OCSP_RESPID(NULL,
					    &sdata, idsize);
					if (!id) {
						*al = SSL_AD_DECODE_ERROR;
						return 0;
					}
					if (data != sdata) {
						OCSP_RESPID_free(id);
						*al = SSL_AD_DECODE_ERROR;
						return 0;
					}
					if (!sk_OCSP_RESPID_push(
					    s->tlsext_ocsp_ids, id)) {
						OCSP_RESPID_free(id);
						*al = SSL_AD_INTERNAL_ERROR;
						return 0;
					}
				}

				/* Read in request_extensions */
				if (size < 2) {
					*al = SSL_AD_DECODE_ERROR;
					return 0;
				}
				n2s(data, dsize);
				size -= 2;
				if (dsize != size) {
					*al = SSL_AD_DECODE_ERROR;
					return 0;
				}
				sdata = data;
				if (dsize > 0) {
					if (s->tlsext_ocsp_exts) {
						sk_X509_EXTENSION_pop_free(s->tlsext_ocsp_exts,
						    X509_EXTENSION_free);
					}

					s->tlsext_ocsp_exts =
					    d2i_X509_EXTENSIONS(NULL,
					    &sdata, dsize);
					if (!s->tlsext_ocsp_exts ||
						    (data + dsize != sdata)) {
						*al = SSL_AD_DECODE_ERROR;
						return 0;
					}
				}
			} else {
				/* We don't know what to do with any other type
 			 	* so ignore it.
 			 	*/
				s->tlsext_status_type = -1;
			}
		}
		else if (type == TLSEXT_TYPE_next_proto_neg &&
		    s->s3->tmp.finish_md_len == 0 &&
		    s->s3->alpn_selected == NULL) {
			/* We shouldn't accept this extension on a
			 * renegotiation.
			 *
			 * s->new_session will be set on renegotiation, but we
			 * probably shouldn't rely that it couldn't be set on
			 * the initial renegotation too in certain cases (when
			 * there's some other reason to disallow resuming an
			 * earlier session -- the current code won't be doing
			 * anything like that, but this might change).

			 * A valid sign that there's been a previous handshake
			 * in this connection is if s->s3->tmp.finish_md_len >
			 * 0.  (We are talking about a check that will happen
			 * in the Hello protocol round, well before a new
			 * Finished message could have been computed.) */
			s->s3->next_proto_neg_seen = 1;
		}
		else if (type ==
		    TLSEXT_TYPE_application_layer_protocol_negotiation &&
		    s->ctx->alpn_select_cb != NULL &&
		    s->s3->tmp.finish_md_len == 0) {
			if (tls1_alpn_handle_client_hello(s, data,
			    size, al) != 1)
				return (0);
			/* ALPN takes precedence over NPN. */
			s->s3->next_proto_neg_seen = 0;
		}

		/* session ticket processed earlier */
#ifndef OPENSSL_NO_SRTP
		else if (SSL_IS_DTLS(s) && type == TLSEXT_TYPE_use_srtp) {
			if (ssl_parse_clienthello_use_srtp_ext(s, data, size, al))
				return 0;
		}
#endif

		data += size;
	}

	*p = data;

ri_check:

	/* Need RI if renegotiating */

	if (!renegotiate_seen && s->renegotiate) {
		*al = SSL_AD_HANDSHAKE_FAILURE;
		SSLerr(SSL_F_SSL_PARSE_CLIENTHELLO_TLSEXT,
		    SSL_R_UNSAFE_LEGACY_RENEGOTIATION_DISABLED);
		return 0;
	}

	return 1;
}

/*
 * ssl_next_proto_validate validates a Next Protocol Negotiation block. No
 * elements of zero length are allowed and the set of elements must exactly fill
 * the length of the block.
 */
static char
ssl_next_proto_validate(const unsigned char *d, unsigned int len)
{
	CBS npn, value;

	CBS_init(&npn, d, len);
	while (CBS_len(&npn) > 0) {
		if (!CBS_get_u8_length_prefixed(&npn, &value) ||
		    CBS_len(&value) == 0)
			return 0;
	}
	return 1;
}

int
ssl_parse_serverhello_tlsext(SSL *s, unsigned char **p, unsigned char *d,
    int n, int *al)
{
	unsigned short length;
	unsigned short type;
	unsigned short size;
	unsigned char *data = *p;
	int tlsext_servername = 0;
	int renegotiate_seen = 0;

	s->s3->next_proto_neg_seen = 0;
	free(s->s3->alpn_selected);
	s->s3->alpn_selected = NULL;

	if (data >= (d + n - 2))
		goto ri_check;

	n2s(data, length);
	if (data + length != d + n) {
		*al = SSL_AD_DECODE_ERROR;
		return 0;
	}

	while (data <= (d + n - 4)) {
		n2s(data, type);
		n2s(data, size);

		if (data + size > (d + n))
			goto ri_check;

		if (s->tlsext_debug_cb)
			s->tlsext_debug_cb(s, 1, type, data, size,
			    s->tlsext_debug_arg);

		if (type == TLSEXT_TYPE_server_name) {
			if (s->tlsext_hostname == NULL || size > 0) {
				*al = TLS1_AD_UNRECOGNIZED_NAME;
				return 0;
			}
			tlsext_servername = 1;

		}
		else if (type == TLSEXT_TYPE_ec_point_formats &&
		    s->version != DTLS1_VERSION) {
			unsigned char *sdata = data;
			size_t formatslen;
			uint8_t *formats;

			if (size < 1) {
				*al = TLS1_AD_DECODE_ERROR;
				return 0;
			}
			formatslen = *(sdata++);
			if (formatslen != size - 1) {
				*al = TLS1_AD_DECODE_ERROR;
				return 0;
			}

			if (!s->hit) {
				free(s->session->tlsext_ecpointformatlist);
				s->session->tlsext_ecpointformatlist = NULL;
				s->session->tlsext_ecpointformatlist_length = 0;

				if ((formats = reallocarray(NULL, formatslen,
				    sizeof(uint8_t))) == NULL) {
					*al = TLS1_AD_INTERNAL_ERROR;
					return 0;
				}
				memcpy(formats, sdata, formatslen);
				s->session->tlsext_ecpointformatlist = formats;
				s->session->tlsext_ecpointformatlist_length =
				    formatslen;
			}
		}
		else if (type == TLSEXT_TYPE_session_ticket) {
			if (s->tls_session_ticket_ext_cb &&
			    !s->tls_session_ticket_ext_cb(s, data, size, s->tls_session_ticket_ext_cb_arg)) {
				*al = TLS1_AD_INTERNAL_ERROR;
				return 0;
			}
			if ((SSL_get_options(s) & SSL_OP_NO_TICKET) || (size > 0)) {
				*al = TLS1_AD_UNSUPPORTED_EXTENSION;
				return 0;
			}
			s->tlsext_ticket_expected = 1;
		}
		else if (type == TLSEXT_TYPE_status_request &&
		    s->version != DTLS1_VERSION) {
			/* MUST be empty and only sent if we've requested
			 * a status request message.
			 */
			if ((s->tlsext_status_type == -1) || (size > 0)) {
				*al = TLS1_AD_UNSUPPORTED_EXTENSION;
				return 0;
			}
			/* Set flag to expect CertificateStatus message */
			s->tlsext_status_expected = 1;
		}
		else if (type == TLSEXT_TYPE_next_proto_neg &&
		    s->s3->tmp.finish_md_len == 0) {
			unsigned char *selected;
			unsigned char selected_len;

			/* We must have requested it. */
			if (s->ctx->next_proto_select_cb == NULL) {
				*al = TLS1_AD_UNSUPPORTED_EXTENSION;
				return 0;
			}
			/* The data must be valid */
			if (!ssl_next_proto_validate(data, size)) {
				*al = TLS1_AD_DECODE_ERROR;
				return 0;
			}
			if (s->ctx->next_proto_select_cb(s, &selected, &selected_len, data, size, s->ctx->next_proto_select_cb_arg) != SSL_TLSEXT_ERR_OK) {
				*al = TLS1_AD_INTERNAL_ERROR;
				return 0;
			}
			s->next_proto_negotiated = malloc(selected_len);
			if (!s->next_proto_negotiated) {
				*al = TLS1_AD_INTERNAL_ERROR;
				return 0;
			}
			memcpy(s->next_proto_negotiated, selected, selected_len);
			s->next_proto_negotiated_len = selected_len;
			s->s3->next_proto_neg_seen = 1;
		}
		else if (type ==
		    TLSEXT_TYPE_application_layer_protocol_negotiation) {
			unsigned int len;

			/* We must have requested it. */
			if (s->alpn_client_proto_list == NULL) {
				*al = TLS1_AD_UNSUPPORTED_EXTENSION;
				return 0;
			}
			if (size < 4) {
				*al = TLS1_AD_DECODE_ERROR;
				return (0);
			}

			/* The extension data consists of:
			 *   uint16 list_length
			 *   uint8 proto_length;
			 *   uint8 proto[proto_length]; */
			len = ((unsigned int)data[0]) << 8 |
			    ((unsigned int)data[1]);
			if (len != (unsigned int)size - 2) {
				*al = TLS1_AD_DECODE_ERROR;
				return (0);
			}
			len = data[2];
			if (len != (unsigned int)size - 3) {
				*al = TLS1_AD_DECODE_ERROR;
				return (0);
			}
			free(s->s3->alpn_selected);
			s->s3->alpn_selected = malloc(len);
			if (s->s3->alpn_selected == NULL) {
				*al = TLS1_AD_INTERNAL_ERROR;
				return (0);
			}
			memcpy(s->s3->alpn_selected, data + 3, len);
			s->s3->alpn_selected_len = len;

		} else if (type == TLSEXT_TYPE_renegotiate) {
			if (!ssl_parse_serverhello_renegotiate_ext(s, data, size, al))
				return 0;
			renegotiate_seen = 1;
		}
#ifndef OPENSSL_NO_SRTP
		else if (SSL_IS_DTLS(s) && type == TLSEXT_TYPE_use_srtp) {
			if (ssl_parse_serverhello_use_srtp_ext(s, data,
			    size, al))
				return 0;
		}
#endif

		data += size;

	}

	if (data != d + n) {
		*al = SSL_AD_DECODE_ERROR;
		return 0;
	}

	if (!s->hit && tlsext_servername == 1) {
		if (s->tlsext_hostname) {
			if (s->session->tlsext_hostname == NULL) {
				s->session->tlsext_hostname =
				    strdup(s->tlsext_hostname);

				if (!s->session->tlsext_hostname) {
					*al = SSL_AD_UNRECOGNIZED_NAME;
					return 0;
				}
			} else {
				*al = SSL_AD_DECODE_ERROR;
				return 0;
			}
		}
	}

	*p = data;

ri_check:

	/* Determine if we need to see RI. Strictly speaking if we want to
	 * avoid an attack we should *always* see RI even on initial server
	 * hello because the client doesn't see any renegotiation during an
	 * attack. However this would mean we could not connect to any server
	 * which doesn't support RI so for the immediate future tolerate RI
	 * absence on initial connect only.
	 */
	if (!renegotiate_seen && !(s->options & SSL_OP_LEGACY_SERVER_CONNECT)) {
		*al = SSL_AD_HANDSHAKE_FAILURE;
		SSLerr(SSL_F_SSL_PARSE_SERVERHELLO_TLSEXT,
		    SSL_R_UNSAFE_LEGACY_RENEGOTIATION_DISABLED);
		return 0;
	}

	return 1;
}

int
ssl_check_clienthello_tlsext_early(SSL *s)
{
	int ret = SSL_TLSEXT_ERR_NOACK;
	int al = SSL_AD_UNRECOGNIZED_NAME;

	/* The handling of the ECPointFormats extension is done elsewhere, namely in
	 * ssl3_choose_cipher in s3_lib.c.
	 */
	/* The handling of the EllipticCurves extension is done elsewhere, namely in
	 * ssl3_choose_cipher in s3_lib.c.
	 */

	if (s->ctx != NULL && s->ctx->tlsext_servername_callback != 0)
		ret = s->ctx->tlsext_servername_callback(s, &al, s->ctx->tlsext_servername_arg);
	else if (s->initial_ctx != NULL && s->initial_ctx->tlsext_servername_callback != 0)
		ret = s->initial_ctx->tlsext_servername_callback(s, &al, s->initial_ctx->tlsext_servername_arg);

	switch (ret) {
	case SSL_TLSEXT_ERR_ALERT_FATAL:
		ssl3_send_alert(s, SSL3_AL_FATAL, al);
		return -1;
	case SSL_TLSEXT_ERR_ALERT_WARNING:
		ssl3_send_alert(s, SSL3_AL_WARNING, al);
		return 1;
	case SSL_TLSEXT_ERR_NOACK:
		s->servername_done = 0;
	default:
		return 1;
	}
}

int
ssl_check_clienthello_tlsext_late(SSL *s)
{
	int ret = SSL_TLSEXT_ERR_OK;
	int al = 0;	/* XXX gcc3 */

	/* If status request then ask callback what to do.
 	 * Note: this must be called after servername callbacks in case
 	 * the certificate has changed, and must be called after the cipher
	 * has been chosen because this may influence which certificate is sent
 	 */
	if ((s->tlsext_status_type != -1) &&
	    s->ctx && s->ctx->tlsext_status_cb) {
		int r;
		CERT_PKEY *certpkey;
		certpkey = ssl_get_server_send_pkey(s);
		/* If no certificate can't return certificate status */
		if (certpkey == NULL) {
			s->tlsext_status_expected = 0;
			return 1;
		}
		/* Set current certificate to one we will use so
		 * SSL_get_certificate et al can pick it up.
		 */
		s->cert->key = certpkey;
		r = s->ctx->tlsext_status_cb(s, s->ctx->tlsext_status_arg);
		switch (r) {
			/* We don't want to send a status request response */
		case SSL_TLSEXT_ERR_NOACK:
			s->tlsext_status_expected = 0;
			break;
			/* status request response should be sent */
		case SSL_TLSEXT_ERR_OK:
			if (s->tlsext_ocsp_resp)
				s->tlsext_status_expected = 1;
			else
				s->tlsext_status_expected = 0;
			break;
			/* something bad happened */
		case SSL_TLSEXT_ERR_ALERT_FATAL:
			ret = SSL_TLSEXT_ERR_ALERT_FATAL;
			al = SSL_AD_INTERNAL_ERROR;
			goto err;
		}
	} else
		s->tlsext_status_expected = 0;

err:
	switch (ret) {
	case SSL_TLSEXT_ERR_ALERT_FATAL:
		ssl3_send_alert(s, SSL3_AL_FATAL, al);
		return -1;
	case SSL_TLSEXT_ERR_ALERT_WARNING:
		ssl3_send_alert(s, SSL3_AL_WARNING, al);
		return 1;
	default:
		return 1;
	}
}

int
ssl_check_serverhello_tlsext(SSL *s)
{
	int ret = SSL_TLSEXT_ERR_NOACK;
	int al = SSL_AD_UNRECOGNIZED_NAME;

	/* If we are client and using an elliptic curve cryptography cipher
	 * suite, then if server returns an EC point formats lists extension
	 * it must contain uncompressed.
	 */
	unsigned long alg_k = s->s3->tmp.new_cipher->algorithm_mkey;
	unsigned long alg_a = s->s3->tmp.new_cipher->algorithm_auth;
	if ((s->tlsext_ecpointformatlist != NULL) &&
	    (s->tlsext_ecpointformatlist_length > 0) &&
	    (s->session->tlsext_ecpointformatlist != NULL) &&
	    (s->session->tlsext_ecpointformatlist_length > 0) &&
	    ((alg_k & (SSL_kECDHE|SSL_kECDHr|SSL_kECDHe)) || (alg_a & SSL_aECDSA))) {
		/* we are using an ECC cipher */
		size_t i;
		unsigned char *list;
		int found_uncompressed = 0;
		list = s->session->tlsext_ecpointformatlist;
		for (i = 0; i < s->session->tlsext_ecpointformatlist_length; i++) {
			if (*(list++) == TLSEXT_ECPOINTFORMAT_uncompressed) {
				found_uncompressed = 1;
				break;
			}
		}
		if (!found_uncompressed) {
			SSLerr(SSL_F_SSL_CHECK_SERVERHELLO_TLSEXT, SSL_R_TLS_INVALID_ECPOINTFORMAT_LIST);
			return -1;
		}
	}
	ret = SSL_TLSEXT_ERR_OK;

	if (s->ctx != NULL && s->ctx->tlsext_servername_callback != 0)
		ret = s->ctx->tlsext_servername_callback(s, &al, s->ctx->tlsext_servername_arg);
	else if (s->initial_ctx != NULL && s->initial_ctx->tlsext_servername_callback != 0)
		ret = s->initial_ctx->tlsext_servername_callback(s, &al, s->initial_ctx->tlsext_servername_arg);

	/* If we've requested certificate status and we wont get one
 	 * tell the callback
 	 */
	if ((s->tlsext_status_type != -1) && !(s->tlsext_status_expected) &&
	    s->ctx && s->ctx->tlsext_status_cb) {
		int r;
		/* Set resp to NULL, resplen to -1 so callback knows
 		 * there is no response.
 		 */
		free(s->tlsext_ocsp_resp);
		s->tlsext_ocsp_resp = NULL;
		s->tlsext_ocsp_resplen = -1;
		r = s->ctx->tlsext_status_cb(s, s->ctx->tlsext_status_arg);
		if (r == 0) {
			al = SSL_AD_BAD_CERTIFICATE_STATUS_RESPONSE;
			ret = SSL_TLSEXT_ERR_ALERT_FATAL;
		}
		if (r < 0) {
			al = SSL_AD_INTERNAL_ERROR;
			ret = SSL_TLSEXT_ERR_ALERT_FATAL;
		}
	}

	switch (ret) {
	case SSL_TLSEXT_ERR_ALERT_FATAL:
		ssl3_send_alert(s, SSL3_AL_FATAL, al);

		return -1;
	case SSL_TLSEXT_ERR_ALERT_WARNING:
		ssl3_send_alert(s, SSL3_AL_WARNING, al);

		return 1;
	case SSL_TLSEXT_ERR_NOACK:
		s->servername_done = 0;
	default:
		return 1;
	}
}

/* Since the server cache lookup is done early on in the processing of the
 * ClientHello, and other operations depend on the result, we need to handle
 * any TLS session ticket extension at the same time.
 *
 *   session_id: points at the session ID in the ClientHello. This code will
 *       read past the end of this in order to parse out the session ticket
 *       extension, if any.
 *   len: the length of the session ID.
 *   limit: a pointer to the first byte after the ClientHello.
 *   ret: (output) on return, if a ticket was decrypted, then this is set to
 *       point to the resulting session.
 *
 * If s->tls_session_secret_cb is set then we are expecting a pre-shared key
 * ciphersuite, in which case we have no use for session tickets and one will
 * never be decrypted, nor will s->tlsext_ticket_expected be set to 1.
 *
 * Returns:
 *   -1: fatal error, either from parsing or decrypting the ticket.
 *    0: no ticket was found (or was ignored, based on settings).
 *    1: a zero length extension was found, indicating that the client supports
 *       session tickets but doesn't currently have one to offer.
 *    2: either s->tls_session_secret_cb was set, or a ticket was offered but
 *       couldn't be decrypted because of a non-fatal error.
 *    3: a ticket was successfully decrypted and *ret was set.
 *
 * Side effects:
 *   Sets s->tlsext_ticket_expected to 1 if the server will have to issue
 *   a new session ticket to the client because the client indicated support
 *   (and s->tls_session_secret_cb is NULL) but the client either doesn't have
 *   a session ticket or we couldn't use the one it gave us, or if
 *   s->ctx->tlsext_ticket_key_cb asked to renew the client's ticket.
 *   Otherwise, s->tlsext_ticket_expected is set to 0.
 */
int
tls1_process_ticket(SSL *s, const unsigned char *session, int session_len,
    const unsigned char *limit, SSL_SESSION **ret)
{
	/* Point after session ID in client hello */
	CBS session_id, cookie, cipher_list, compress_algo, extensions;

	*ret = NULL;
	s->tlsext_ticket_expected = 0;

	/* If tickets disabled behave as if no ticket present
	 * to permit stateful resumption.
	 */
	if (SSL_get_options(s) & SSL_OP_NO_TICKET)
		return 0;
	if (!limit)
		return 0;

	if (limit < session)
		return -1;

	CBS_init(&session_id, session, limit - session);

	/* Skip past the session id */
	if (!CBS_skip(&session_id, session_len))
		return -1;

	/* Skip past DTLS cookie */
	if (SSL_IS_DTLS(s)) {
		if (!CBS_get_u8_length_prefixed(&session_id, &cookie))
			return -1;
	}

	/* Skip past cipher list */
	if (!CBS_get_u16_length_prefixed(&session_id, &cipher_list))
		return -1;

	/* Skip past compression algorithm list */
	if (!CBS_get_u8_length_prefixed(&session_id, &compress_algo))
		return -1;

	/* Now at start of extensions */
	if (CBS_len(&session_id) == 0)
		return 0;
	if (!CBS_get_u16_length_prefixed(&session_id, &extensions))
		return -1;

	while (CBS_len(&extensions) > 0) {
		CBS ext_data;
		uint16_t ext_type;

		if (!CBS_get_u16(&extensions, &ext_type) ||
		    !CBS_get_u16_length_prefixed(&extensions, &ext_data))
			return -1;

		if (ext_type == TLSEXT_TYPE_session_ticket) {
			int r;
			if (CBS_len(&ext_data) == 0) {
				/* The client will accept a ticket but doesn't
				 * currently have one. */
				s->tlsext_ticket_expected = 1;
				return 1;
			}
			if (s->tls_session_secret_cb) {
				/* Indicate that the ticket couldn't be
				 * decrypted rather than generating the session
				 * from ticket now, trigger abbreviated
				 * handshake based on external mechanism to
				 * calculate the master secret later. */
				return 2;
			}

			r = tls_decrypt_ticket(s, CBS_data(&ext_data),
			    CBS_len(&ext_data), session, session_len, ret);

			switch (r) {
			case 2: /* ticket couldn't be decrypted */
				s->tlsext_ticket_expected = 1;
				return 2;
			case 3: /* ticket was decrypted */
				return r;
			case 4: /* ticket decrypted but need to renew */
				s->tlsext_ticket_expected = 1;
				return 3;
			default: /* fatal error */
				return -1;
			}
		}
	}
	return 0;
}

/* tls_decrypt_ticket attempts to decrypt a session ticket.
 *
 *   etick: points to the body of the session ticket extension.
 *   eticklen: the length of the session tickets extenion.
 *   sess_id: points at the session ID.
 *   sesslen: the length of the session ID.
 *   psess: (output) on return, if a ticket was decrypted, then this is set to
 *       point to the resulting session.
 *
 * Returns:
 *   -1: fatal error, either from parsing or decrypting the ticket.
 *    2: the ticket couldn't be decrypted.
 *    3: a ticket was successfully decrypted and *psess was set.
 *    4: same as 3, but the ticket needs to be renewed.
 */
static int
tls_decrypt_ticket(SSL *s, const unsigned char *etick, int eticklen,
    const unsigned char *sess_id, int sesslen, SSL_SESSION **psess)
{
	SSL_SESSION *sess;
	unsigned char *sdec;
	const unsigned char *p;
	int slen, mlen, renew_ticket = 0;
	unsigned char tick_hmac[EVP_MAX_MD_SIZE];
	HMAC_CTX hctx;
	EVP_CIPHER_CTX ctx;
	SSL_CTX *tctx = s->initial_ctx;

	/*
	 * The API guarantees EVP_MAX_IV_LENGTH bytes of space for
	 * the iv to tlsext_ticket_key_cb().  Since the total space
	 * required for a session cookie is never less than this,
	 * this check isn't too strict.  The exact check comes later.
	 */
	if (eticklen < 16 + EVP_MAX_IV_LENGTH)
		return 2;

	/* Initialize session ticket encryption and HMAC contexts */
	HMAC_CTX_init(&hctx);
	EVP_CIPHER_CTX_init(&ctx);
	if (tctx->tlsext_ticket_key_cb) {
		unsigned char *nctick = (unsigned char *)etick;
		int rv = tctx->tlsext_ticket_key_cb(s, nctick, nctick + 16,
		    &ctx, &hctx, 0);
		if (rv < 0) {
			HMAC_CTX_cleanup(&hctx);
			EVP_CIPHER_CTX_cleanup(&ctx);
			return -1;
		}
		if (rv == 0) {
			HMAC_CTX_cleanup(&hctx);
			EVP_CIPHER_CTX_cleanup(&ctx);
			return 2;
		}
		if (rv == 2)
			renew_ticket = 1;
	} else {
		/* Check key name matches */
		if (timingsafe_memcmp(etick, tctx->tlsext_tick_key_name, 16))
			return 2;
		HMAC_Init_ex(&hctx, tctx->tlsext_tick_hmac_key, 16,
		    tlsext_tick_md(), NULL);
		EVP_DecryptInit_ex(&ctx, EVP_aes_128_cbc(), NULL,
		    tctx->tlsext_tick_aes_key, etick + 16);
	}

	/*
	 * Attempt to process session ticket, first conduct sanity and
	 * integrity checks on ticket.
	 */
	mlen = HMAC_size(&hctx);
	if (mlen < 0) {
		HMAC_CTX_cleanup(&hctx);
		EVP_CIPHER_CTX_cleanup(&ctx);
		return -1;
	}

	/* Sanity check ticket length: must exceed keyname + IV + HMAC */
	if (eticklen <= 16 + EVP_CIPHER_CTX_iv_length(&ctx) + mlen) {
		HMAC_CTX_cleanup(&hctx);
		EVP_CIPHER_CTX_cleanup(&ctx);
		return 2;
	}
	eticklen -= mlen;

	/* Check HMAC of encrypted ticket */
	if (HMAC_Update(&hctx, etick, eticklen) <= 0 ||
	    HMAC_Final(&hctx, tick_hmac, NULL) <= 0) {
		HMAC_CTX_cleanup(&hctx);
		EVP_CIPHER_CTX_cleanup(&ctx);
		return -1;
	}

	HMAC_CTX_cleanup(&hctx);
	if (timingsafe_memcmp(tick_hmac, etick + eticklen, mlen)) {
		EVP_CIPHER_CTX_cleanup(&ctx);
		return 2;
	}

	/* Attempt to decrypt session data */
	/* Move p after IV to start of encrypted ticket, update length */
	p = etick + 16 + EVP_CIPHER_CTX_iv_length(&ctx);
	eticklen -= 16 + EVP_CIPHER_CTX_iv_length(&ctx);
	sdec = malloc(eticklen);
	if (sdec == NULL ||
	    EVP_DecryptUpdate(&ctx, sdec, &slen, p, eticklen) <= 0) {
		free(sdec);
		EVP_CIPHER_CTX_cleanup(&ctx);
		return -1;
	}
	if (EVP_DecryptFinal_ex(&ctx, sdec + slen, &mlen) <= 0) {
		free(sdec);
		EVP_CIPHER_CTX_cleanup(&ctx);
		return 2;
	}
	slen += mlen;
	EVP_CIPHER_CTX_cleanup(&ctx);
	p = sdec;

	sess = d2i_SSL_SESSION(NULL, &p, slen);
	free(sdec);
	if (sess) {
		/* The session ID, if non-empty, is used by some clients to
		 * detect that the ticket has been accepted. So we copy it to
		 * the session structure. If it is empty set length to zero
		 * as required by standard.
		 */
		if (sesslen)
			memcpy(sess->session_id, sess_id, sesslen);
		sess->session_id_length = sesslen;
		*psess = sess;
		if (renew_ticket)
			return 4;
		else
			return 3;
	}
	ERR_clear_error();
	/* For session parse failure, indicate that we need to send a new
	 * ticket. */
	return 2;
}

/* Tables to translate from NIDs to TLS v1.2 ids */

typedef struct {
	int nid;
	int id;
} tls12_lookup;

static tls12_lookup tls12_md[] = {
	{NID_md5, TLSEXT_hash_md5},
	{NID_sha1, TLSEXT_hash_sha1},
	{NID_sha224, TLSEXT_hash_sha224},
	{NID_sha256, TLSEXT_hash_sha256},
	{NID_sha384, TLSEXT_hash_sha384},
	{NID_sha512, TLSEXT_hash_sha512},
	{NID_id_GostR3411_94, TLSEXT_hash_gost94},
	{NID_id_tc26_gost3411_2012_256, TLSEXT_hash_streebog_256},
	{NID_id_tc26_gost3411_2012_512, TLSEXT_hash_streebog_512}
};

static tls12_lookup tls12_sig[] = {
	{EVP_PKEY_RSA, TLSEXT_signature_rsa},
	{EVP_PKEY_DSA, TLSEXT_signature_dsa},
	{EVP_PKEY_EC, TLSEXT_signature_ecdsa},
	{EVP_PKEY_GOSTR01, TLSEXT_signature_gostr01},
};

static int
tls12_find_id(int nid, tls12_lookup *table, size_t tlen)
{
	size_t i;
	for (i = 0; i < tlen; i++) {
		if (table[i].nid == nid)
			return table[i].id;
	}
	return -1;
}

int
tls12_get_sigandhash(unsigned char *p, const EVP_PKEY *pk, const EVP_MD *md)
{
	int sig_id, md_id;
	if (!md)
		return 0;
	md_id = tls12_find_id(EVP_MD_type(md), tls12_md,
	    sizeof(tls12_md) / sizeof(tls12_lookup));
	if (md_id == -1)
		return 0;
	sig_id = tls12_get_sigid(pk);
	if (sig_id == -1)
		return 0;
	p[0] = (unsigned char)md_id;
	p[1] = (unsigned char)sig_id;
	return 1;
}

int
tls12_get_sigid(const EVP_PKEY *pk)
{
	return tls12_find_id(pk->type, tls12_sig,
	    sizeof(tls12_sig) / sizeof(tls12_lookup));
}

const EVP_MD *
tls12_get_hash(unsigned char hash_alg)
{
	switch (hash_alg) {
	case TLSEXT_hash_sha1:
		return EVP_sha1();
	case TLSEXT_hash_sha224:
		return EVP_sha224();
	case TLSEXT_hash_sha256:
		return EVP_sha256();
	case TLSEXT_hash_sha384:
		return EVP_sha384();
	case TLSEXT_hash_sha512:
		return EVP_sha512();
#ifndef OPENSSL_NO_GOST
	case TLSEXT_hash_gost94:
		return EVP_gostr341194();
	case TLSEXT_hash_streebog_256:
		return EVP_streebog256();
	case TLSEXT_hash_streebog_512:
		return EVP_streebog512();
#endif
	default:
		return NULL;
	}
}

/* Set preferred digest for each key type */

int
tls1_process_sigalgs(SSL *s, const unsigned char *data, int dsize)
{
	int idx;
	const EVP_MD *md;
	CERT *c = s->cert;
	CBS cbs;

	/* Extension ignored for inappropriate versions */
	if (!SSL_USE_SIGALGS(s))
		return 1;

	/* Should never happen */
	if (!c || dsize < 0)
		return 0;

	CBS_init(&cbs, data, dsize);

	c->pkeys[SSL_PKEY_DSA_SIGN].digest = NULL;
	c->pkeys[SSL_PKEY_RSA_SIGN].digest = NULL;
	c->pkeys[SSL_PKEY_RSA_ENC].digest = NULL;
	c->pkeys[SSL_PKEY_ECC].digest = NULL;
	c->pkeys[SSL_PKEY_GOST01].digest = NULL;

	while (CBS_len(&cbs) > 0) {
		uint8_t hash_alg, sig_alg;

		if (!CBS_get_u8(&cbs, &hash_alg) ||
		    !CBS_get_u8(&cbs, &sig_alg)) {
			/* Should never happen */
			return 0;
		}

		switch (sig_alg) {
		case TLSEXT_signature_rsa:
			idx = SSL_PKEY_RSA_SIGN;
			break;
		case TLSEXT_signature_dsa:
			idx = SSL_PKEY_DSA_SIGN;
			break;
		case TLSEXT_signature_ecdsa:
			idx = SSL_PKEY_ECC;
			break;
		case TLSEXT_signature_gostr01:
		case TLSEXT_signature_gostr12_256:
		case TLSEXT_signature_gostr12_512:
			idx = SSL_PKEY_GOST01;
			break;
		default:
			continue;
		}

		if (c->pkeys[idx].digest == NULL) {
			md = tls12_get_hash(hash_alg);
			if (md) {
				c->pkeys[idx].digest = md;
				if (idx == SSL_PKEY_RSA_SIGN)
					c->pkeys[SSL_PKEY_RSA_ENC].digest = md;
			}
		}

	}

	/* Set any remaining keys to default values. NOTE: if alg is not
	 * supported it stays as NULL.
	 */
	if (!c->pkeys[SSL_PKEY_DSA_SIGN].digest)
		c->pkeys[SSL_PKEY_DSA_SIGN].digest = EVP_sha1();
	if (!c->pkeys[SSL_PKEY_RSA_SIGN].digest) {
		c->pkeys[SSL_PKEY_RSA_SIGN].digest = EVP_sha1();
		c->pkeys[SSL_PKEY_RSA_ENC].digest = EVP_sha1();
	}
	if (!c->pkeys[SSL_PKEY_ECC].digest)
		c->pkeys[SSL_PKEY_ECC].digest = EVP_sha1();
#ifndef OPENSSL_NO_GOST
	if (!c->pkeys[SSL_PKEY_GOST01].digest)
		c->pkeys[SSL_PKEY_GOST01].digest = EVP_gostr341194();
#endif
	return 1;
}
