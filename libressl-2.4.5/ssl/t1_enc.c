/* $OpenBSD: t1_enc.c,v 1.84 2016/03/06 14:52:15 beck Exp $ */
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

#include <stdio.h>

#include "ssl_locl.h"

#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/md5.h>

void
tls1_cleanup_key_block(SSL *s)
{
	if (s->s3->tmp.key_block != NULL) {
		explicit_bzero(s->s3->tmp.key_block,
		    s->s3->tmp.key_block_length);
		free(s->s3->tmp.key_block);
		s->s3->tmp.key_block = NULL;
	}
	s->s3->tmp.key_block_length = 0;
}

int
tls1_init_finished_mac(SSL *s)
{
	BIO_free(s->s3->handshake_buffer);
	tls1_free_digest_list(s);

	s->s3->handshake_buffer = BIO_new(BIO_s_mem());
	if (s->s3->handshake_buffer == NULL)
		return (0);

	(void)BIO_set_close(s->s3->handshake_buffer, BIO_CLOSE);

	return (1);
}

void
tls1_free_digest_list(SSL *s)
{
	int i;

	if (s == NULL)
		return;

	if (s->s3->handshake_dgst == NULL)
		return;
	for (i = 0; i < SSL_MAX_DIGEST; i++) {
		if (s->s3->handshake_dgst[i])
			EVP_MD_CTX_destroy(s->s3->handshake_dgst[i]);
	}
	free(s->s3->handshake_dgst);
	s->s3->handshake_dgst = NULL;
}

void
tls1_finish_mac(SSL *s, const unsigned char *buf, int len)
{
	if (s->s3->handshake_buffer &&
	    !(s->s3->flags & TLS1_FLAGS_KEEP_HANDSHAKE)) {
		BIO_write(s->s3->handshake_buffer, (void *)buf, len);
	} else {
		int i;
		for (i = 0; i < SSL_MAX_DIGEST; i++) {
			if (s->s3->handshake_dgst[i]!= NULL)
				EVP_DigestUpdate(s->s3->handshake_dgst[i], buf, len);
		}
	}
}

int
tls1_digest_cached_records(SSL *s)
{
	int i;
	long mask;
	const EVP_MD *md;
	long hdatalen;
	void *hdata;

	tls1_free_digest_list(s);

	s->s3->handshake_dgst = calloc(SSL_MAX_DIGEST, sizeof(EVP_MD_CTX *));
	if (s->s3->handshake_dgst == NULL) {
		SSLerr(SSL_F_SSL3_DIGEST_CACHED_RECORDS, ERR_R_MALLOC_FAILURE);
		return 0;
	}
	hdatalen = BIO_get_mem_data(s->s3->handshake_buffer, &hdata);
	if (hdatalen <= 0) {
		SSLerr(SSL_F_SSL3_DIGEST_CACHED_RECORDS,
		    SSL_R_BAD_HANDSHAKE_LENGTH);
		return 0;
	}

	/* Loop through bits of the algorithm2 field and create MD contexts. */
	for (i = 0; ssl_get_handshake_digest(i, &mask, &md); i++) {
		if ((mask & ssl_get_algorithm2(s)) && md) {
			s->s3->handshake_dgst[i] = EVP_MD_CTX_create();
			if (s->s3->handshake_dgst[i] == NULL) {
				SSLerr(SSL_F_SSL3_DIGEST_CACHED_RECORDS,
				    ERR_R_MALLOC_FAILURE);
				return 0;
			}
			if (!EVP_DigestInit_ex(s->s3->handshake_dgst[i],
			    md, NULL)) {
				EVP_MD_CTX_destroy(s->s3->handshake_dgst[i]);
				return 0;
			}
			if (!EVP_DigestUpdate(s->s3->handshake_dgst[i], hdata,
			    hdatalen))
				return 0;
		}
	}

	if (!(s->s3->flags & TLS1_FLAGS_KEEP_HANDSHAKE)) {
		BIO_free(s->s3->handshake_buffer);
		s->s3->handshake_buffer = NULL;
	}

	return 1;
}

void
tls1_record_sequence_increment(unsigned char *seq)
{
	int i;

	for (i = SSL3_SEQUENCE_SIZE - 1; i >= 0; i--) {
		if (++seq[i] != 0)
			break;
	}
}

/* seed1 through seed5 are virtually concatenated */
static int
tls1_P_hash(const EVP_MD *md, const unsigned char *sec, int sec_len,
    const void *seed1, int seed1_len, const void *seed2, int seed2_len,
    const void *seed3, int seed3_len, const void *seed4, int seed4_len,
    const void *seed5, int seed5_len, unsigned char *out, int olen)
{
	int chunk;
	size_t j;
	EVP_MD_CTX ctx, ctx_tmp;
	EVP_PKEY *mac_key;
	unsigned char A1[EVP_MAX_MD_SIZE];
	size_t A1_len;
	int ret = 0;

	chunk = EVP_MD_size(md);
	OPENSSL_assert(chunk >= 0);

	EVP_MD_CTX_init(&ctx);
	EVP_MD_CTX_init(&ctx_tmp);
	mac_key = EVP_PKEY_new_mac_key(EVP_PKEY_HMAC, NULL, sec, sec_len);
	if (!mac_key)
		goto err;
	if (!EVP_DigestSignInit(&ctx, NULL, md, NULL, mac_key))
		goto err;
	if (!EVP_DigestSignInit(&ctx_tmp, NULL, md, NULL, mac_key))
		goto err;
	if (seed1 && !EVP_DigestSignUpdate(&ctx, seed1, seed1_len))
		goto err;
	if (seed2 && !EVP_DigestSignUpdate(&ctx, seed2, seed2_len))
		goto err;
	if (seed3 && !EVP_DigestSignUpdate(&ctx, seed3, seed3_len))
		goto err;
	if (seed4 && !EVP_DigestSignUpdate(&ctx, seed4, seed4_len))
		goto err;
	if (seed5 && !EVP_DigestSignUpdate(&ctx, seed5, seed5_len))
		goto err;
	if (!EVP_DigestSignFinal(&ctx, A1, &A1_len))
		goto err;

	for (;;) {
		/* Reinit mac contexts */
		if (!EVP_DigestSignInit(&ctx, NULL, md, NULL, mac_key))
			goto err;
		if (!EVP_DigestSignInit(&ctx_tmp, NULL, md, NULL, mac_key))
			goto err;
		if (!EVP_DigestSignUpdate(&ctx, A1, A1_len))
			goto err;
		if (!EVP_DigestSignUpdate(&ctx_tmp, A1, A1_len))
			goto err;
		if (seed1 && !EVP_DigestSignUpdate(&ctx, seed1, seed1_len))
			goto err;
		if (seed2 && !EVP_DigestSignUpdate(&ctx, seed2, seed2_len))
			goto err;
		if (seed3 && !EVP_DigestSignUpdate(&ctx, seed3, seed3_len))
			goto err;
		if (seed4 && !EVP_DigestSignUpdate(&ctx, seed4, seed4_len))
			goto err;
		if (seed5 && !EVP_DigestSignUpdate(&ctx, seed5, seed5_len))
			goto err;

		if (olen > chunk) {
			if (!EVP_DigestSignFinal(&ctx, out, &j))
				goto err;
			out += j;
			olen -= j;
			/* calc the next A1 value */
			if (!EVP_DigestSignFinal(&ctx_tmp, A1, &A1_len))
				goto err;
		} else {
			/* last one */
			if (!EVP_DigestSignFinal(&ctx, A1, &A1_len))
				goto err;
			memcpy(out, A1, olen);
			break;
		}
	}
	ret = 1;

err:
	EVP_PKEY_free(mac_key);
	EVP_MD_CTX_cleanup(&ctx);
	EVP_MD_CTX_cleanup(&ctx_tmp);
	explicit_bzero(A1, sizeof(A1));
	return ret;
}

/* seed1 through seed5 are virtually concatenated */
static int
tls1_PRF(long digest_mask, const void *seed1, int seed1_len, const void *seed2,
    int seed2_len, const void *seed3, int seed3_len, const void *seed4,
    int seed4_len, const void *seed5, int seed5_len, const unsigned char *sec,
    int slen, unsigned char *out1, unsigned char *out2, int olen)
{
	int len, i, idx, count;
	const unsigned char *S1;
	long m;
	const EVP_MD *md;
	int ret = 0;

	/* Count number of digests and partition sec evenly */
	count = 0;
	for (idx = 0; ssl_get_handshake_digest(idx, &m, &md); idx++) {
		if ((m << TLS1_PRF_DGST_SHIFT) & digest_mask)
			count++;
	}
	if (count == 0) {
		SSLerr(SSL_F_TLS1_PRF,
		    SSL_R_SSL_HANDSHAKE_FAILURE);
		goto err;
	}
	len = slen / count;
	if (count == 1)
		slen = 0;
	S1 = sec;
	memset(out1, 0, olen);
	for (idx = 0; ssl_get_handshake_digest(idx, &m, &md); idx++) {
		if ((m << TLS1_PRF_DGST_SHIFT) & digest_mask) {
			if (!md) {
				SSLerr(SSL_F_TLS1_PRF,
				    SSL_R_UNSUPPORTED_DIGEST_TYPE);
				goto err;
			}
			if (!tls1_P_hash(md , S1, len + (slen&1), seed1,
			    seed1_len, seed2, seed2_len, seed3, seed3_len,
			    seed4, seed4_len, seed5, seed5_len, out2, olen))
				goto err;
			S1 += len;
			for (i = 0; i < olen; i++) {
				out1[i] ^= out2[i];
			}
		}
	}
	ret = 1;

err:
	return ret;
}

static int
tls1_generate_key_block(SSL *s, unsigned char *km, unsigned char *tmp, int num)
{
	int ret;

	ret = tls1_PRF(ssl_get_algorithm2(s),
	    TLS_MD_KEY_EXPANSION_CONST, TLS_MD_KEY_EXPANSION_CONST_SIZE,
	    s->s3->server_random, SSL3_RANDOM_SIZE,
	    s->s3->client_random, SSL3_RANDOM_SIZE,
	    NULL, 0, NULL, 0,
	    s->session->master_key, s->session->master_key_length,
	    km, tmp, num);
	return ret;
}

/*
 * tls1_aead_ctx_init allocates aead_ctx, if needed. It returns 1 on success
 * and 0 on failure.
 */
static int
tls1_aead_ctx_init(SSL_AEAD_CTX **aead_ctx)
{
	if (*aead_ctx != NULL) {
		EVP_AEAD_CTX_cleanup(&(*aead_ctx)->ctx);
		return (1);
	}

	*aead_ctx = malloc(sizeof(SSL_AEAD_CTX));
	if (*aead_ctx == NULL) {
		SSLerr(SSL_F_TLS1_AEAD_CTX_INIT, ERR_R_MALLOC_FAILURE);
		return (0);
	}

	return (1);
}

static int
tls1_change_cipher_state_aead(SSL *s, char is_read, const unsigned char *key,
    unsigned key_len, const unsigned char *iv, unsigned iv_len)
{
	const EVP_AEAD *aead = s->s3->tmp.new_aead;
	SSL_AEAD_CTX *aead_ctx;

	if (is_read) {
		if (!tls1_aead_ctx_init(&s->aead_read_ctx))
			return 0;
		aead_ctx = s->aead_read_ctx;
	} else {
		if (!tls1_aead_ctx_init(&s->aead_write_ctx))
			return 0;
		aead_ctx = s->aead_write_ctx;
	}

	if (!EVP_AEAD_CTX_init(&aead_ctx->ctx, aead, key, key_len,
	    EVP_AEAD_DEFAULT_TAG_LENGTH, NULL))
		return (0);
	if (iv_len > sizeof(aead_ctx->fixed_nonce)) {
		SSLerr(SSL_F_TLS1_CHANGE_CIPHER_STATE_AEAD,
		    ERR_R_INTERNAL_ERROR);
		return (0);
	}
	memcpy(aead_ctx->fixed_nonce, iv, iv_len);
	aead_ctx->fixed_nonce_len = iv_len;
	aead_ctx->variable_nonce_len = 8;  /* always the case, currently. */
	aead_ctx->variable_nonce_in_record =
	    (s->s3->tmp.new_cipher->algorithm2 &
	    SSL_CIPHER_ALGORITHM2_VARIABLE_NONCE_IN_RECORD) != 0;
	aead_ctx->xor_fixed_nonce =
	    s->s3->tmp.new_cipher->algorithm_enc == SSL_CHACHA20POLY1305;
	aead_ctx->tag_len = EVP_AEAD_max_overhead(aead);

	if (aead_ctx->xor_fixed_nonce) {
		if (aead_ctx->fixed_nonce_len != EVP_AEAD_nonce_length(aead) ||
		    aead_ctx->variable_nonce_len > EVP_AEAD_nonce_length(aead)) {
			SSLerr(SSL_F_TLS1_CHANGE_CIPHER_STATE_AEAD,
			    ERR_R_INTERNAL_ERROR);
			return (0);
		}
	} else {
		if (aead_ctx->variable_nonce_len + aead_ctx->fixed_nonce_len !=
		    EVP_AEAD_nonce_length(aead)) {
			SSLerr(SSL_F_TLS1_CHANGE_CIPHER_STATE_AEAD,
			    ERR_R_INTERNAL_ERROR);
			return (0);
		}
	}

	return (1);
}

/*
 * tls1_change_cipher_state_cipher performs the work needed to switch cipher
 * states when using EVP_CIPHER. The argument is_read is true iff this function
 * is being called due to reading, as opposed to writing, a ChangeCipherSpec
 * message. In order to support export ciphersuites, use_client_keys indicates
 * whether the key material provided is in the "client write" direction.
 */
static int
tls1_change_cipher_state_cipher(SSL *s, char is_read, char use_client_keys,
    const unsigned char *mac_secret, unsigned int mac_secret_size,
    const unsigned char *key, unsigned int key_len, const unsigned char *iv,
    unsigned int iv_len)
{
	EVP_CIPHER_CTX *cipher_ctx;
	const EVP_CIPHER *cipher;
	EVP_MD_CTX *mac_ctx;
	const EVP_MD *mac;
	int mac_type;

	cipher = s->s3->tmp.new_sym_enc;
	mac = s->s3->tmp.new_hash;
	mac_type = s->s3->tmp.new_mac_pkey_type;

	if (is_read) {
		if (s->s3->tmp.new_cipher->algorithm2 & TLS1_STREAM_MAC)
			s->mac_flags |= SSL_MAC_FLAG_READ_MAC_STREAM;
		else
			s->mac_flags &= ~SSL_MAC_FLAG_READ_MAC_STREAM;

		EVP_CIPHER_CTX_free(s->enc_read_ctx);
		s->enc_read_ctx = NULL;
		EVP_MD_CTX_destroy(s->read_hash);
		s->read_hash = NULL;

		if ((cipher_ctx = EVP_CIPHER_CTX_new()) == NULL)
			goto err;
		s->enc_read_ctx = cipher_ctx;
		if ((mac_ctx = EVP_MD_CTX_create()) == NULL)
			goto err;
		s->read_hash = mac_ctx;
	} else {
		if (s->s3->tmp.new_cipher->algorithm2 & TLS1_STREAM_MAC)
			s->mac_flags |= SSL_MAC_FLAG_WRITE_MAC_STREAM;
		else
			s->mac_flags &= ~SSL_MAC_FLAG_WRITE_MAC_STREAM;

		/*
		 * DTLS fragments retain a pointer to the compression, cipher
		 * and hash contexts, so that it can restore state in order
		 * to perform retransmissions. As such, we cannot free write
		 * contexts that are used for DTLS - these are instead freed
		 * by DTLS when its frees a ChangeCipherSpec fragment.
		 */
		if (!SSL_IS_DTLS(s)) {
			EVP_CIPHER_CTX_free(s->enc_write_ctx);
			s->enc_write_ctx = NULL;
			EVP_MD_CTX_destroy(s->write_hash);
			s->write_hash = NULL;
		}
		if ((cipher_ctx = EVP_CIPHER_CTX_new()) == NULL)
			goto err;
		s->enc_write_ctx = cipher_ctx;
		if ((mac_ctx = EVP_MD_CTX_create()) == NULL)
			goto err;
		s->write_hash = mac_ctx;
	}

	if (EVP_CIPHER_mode(cipher) == EVP_CIPH_GCM_MODE) {
		EVP_CipherInit_ex(cipher_ctx, cipher, NULL, key, NULL,
		    !is_read);
		EVP_CIPHER_CTX_ctrl(cipher_ctx, EVP_CTRL_GCM_SET_IV_FIXED,
		    iv_len, (unsigned char *)iv);
	} else
		EVP_CipherInit_ex(cipher_ctx, cipher, NULL, key, iv, !is_read);

	if (!(EVP_CIPHER_flags(cipher) & EVP_CIPH_FLAG_AEAD_CIPHER)) {
		EVP_PKEY *mac_key = EVP_PKEY_new_mac_key(mac_type, NULL,
		    mac_secret, mac_secret_size);
		if (mac_key == NULL)
			goto err;
		EVP_DigestSignInit(mac_ctx, NULL, mac, NULL, mac_key);
		EVP_PKEY_free(mac_key);
	} else if (mac_secret_size > 0) {
		/* Needed for "composite" AEADs, such as RC4-HMAC-MD5 */
		EVP_CIPHER_CTX_ctrl(cipher_ctx, EVP_CTRL_AEAD_SET_MAC_KEY,
		    mac_secret_size, (unsigned char *)mac_secret);
	}

	if (s->s3->tmp.new_cipher->algorithm_enc == SSL_eGOST2814789CNT) {
		int nid;
		if (s->s3->tmp.new_cipher->algorithm2 & SSL_HANDSHAKE_MAC_GOST94)
			nid = NID_id_Gost28147_89_CryptoPro_A_ParamSet;
		else
			nid = NID_id_tc26_gost_28147_param_Z;

		EVP_CIPHER_CTX_ctrl(cipher_ctx, EVP_CTRL_GOST_SET_SBOX, nid, 0);
		if (s->s3->tmp.new_cipher->algorithm_mac == SSL_GOST89MAC)
			EVP_MD_CTX_ctrl(mac_ctx, EVP_MD_CTRL_GOST_SET_SBOX, nid, 0);
	}

	return (1);

err:
	SSLerr(SSL_F_TLS1_CHANGE_CIPHER_STATE_CIPHER, ERR_R_MALLOC_FAILURE);
	return (0);
}

int
tls1_change_cipher_state(SSL *s, int which)
{
	const unsigned char *client_write_mac_secret, *server_write_mac_secret;
	const unsigned char *client_write_key, *server_write_key;
	const unsigned char *client_write_iv, *server_write_iv;
	const unsigned char *mac_secret, *key, *iv;
	int mac_secret_size, key_len, iv_len;
	unsigned char *key_block, *seq;
	const EVP_CIPHER *cipher;
	const EVP_AEAD *aead;
	char is_read, use_client_keys;


	cipher = s->s3->tmp.new_sym_enc;
	aead = s->s3->tmp.new_aead;

	/*
	 * is_read is true if we have just read a ChangeCipherSpec message,
	 * that is we need to update the read cipherspec. Otherwise we have
	 * just written one.
	 */
	is_read = (which & SSL3_CC_READ) != 0;

	/*
	 * use_client_keys is true if we wish to use the keys for the "client
	 * write" direction. This is the case if we're a client sending a
	 * ChangeCipherSpec, or a server reading a client's ChangeCipherSpec.
	 */
	use_client_keys = ((which == SSL3_CHANGE_CIPHER_CLIENT_WRITE) ||
	    (which == SSL3_CHANGE_CIPHER_SERVER_READ));


	/*
	 * Reset sequence number to zero - for DTLS this is handled in
	 * dtls1_reset_seq_numbers().
	 */
	if (!SSL_IS_DTLS(s)) {
		seq = is_read ? s->s3->read_sequence : s->s3->write_sequence;
		memset(seq, 0, SSL3_SEQUENCE_SIZE);
	}

	if (aead != NULL) {
		key_len = EVP_AEAD_key_length(aead);
		iv_len = SSL_CIPHER_AEAD_FIXED_NONCE_LEN(s->s3->tmp.new_cipher);
	} else {
		key_len = EVP_CIPHER_key_length(cipher);
		iv_len = EVP_CIPHER_iv_length(cipher);

		/* If GCM mode only part of IV comes from PRF. */
		if (EVP_CIPHER_mode(cipher) == EVP_CIPH_GCM_MODE)
			iv_len = EVP_GCM_TLS_FIXED_IV_LEN;
	}

	mac_secret_size = s->s3->tmp.new_mac_secret_size;

	key_block = s->s3->tmp.key_block;
	client_write_mac_secret = key_block;
	key_block += mac_secret_size;
	server_write_mac_secret = key_block;
	key_block += mac_secret_size;
	client_write_key = key_block;
	key_block += key_len;
	server_write_key = key_block;
	key_block += key_len;
	client_write_iv = key_block;
	key_block += iv_len;
	server_write_iv = key_block;
	key_block += iv_len;

	if (use_client_keys) {
		mac_secret = client_write_mac_secret;
		key = client_write_key;
		iv = client_write_iv;
	} else {
		mac_secret = server_write_mac_secret;
		key = server_write_key;
		iv = server_write_iv;
	}

	if (key_block - s->s3->tmp.key_block != s->s3->tmp.key_block_length) {
		SSLerr(SSL_F_TLS1_CHANGE_CIPHER_STATE, ERR_R_INTERNAL_ERROR);
		goto err2;
	}

	if (is_read) {
		memcpy(s->s3->read_mac_secret, mac_secret, mac_secret_size);
		s->s3->read_mac_secret_size = mac_secret_size;
	} else {
		memcpy(s->s3->write_mac_secret, mac_secret, mac_secret_size);
		s->s3->write_mac_secret_size = mac_secret_size;
	}

	if (aead != NULL) {
		return tls1_change_cipher_state_aead(s, is_read, key, key_len,
		    iv, iv_len);
	}

	return tls1_change_cipher_state_cipher(s, is_read, use_client_keys,
	    mac_secret, mac_secret_size, key, key_len, iv, iv_len);

err2:
	return (0);
}

int
tls1_setup_key_block(SSL *s)
{
	unsigned char *key_block, *tmp_block = NULL;
	int mac_type = NID_undef, mac_secret_size = 0;
	int key_block_len, key_len, iv_len;
	const EVP_CIPHER *cipher = NULL;
	const EVP_AEAD *aead = NULL;
	const EVP_MD *mac = NULL;
	int ret = 0;

	if (s->s3->tmp.key_block_length != 0)
		return (1);

	if (s->session->cipher &&
	    (s->session->cipher->algorithm2 & SSL_CIPHER_ALGORITHM2_AEAD)) {
		if (!ssl_cipher_get_evp_aead(s->session, &aead)) {
			SSLerr(SSL_F_TLS1_SETUP_KEY_BLOCK,
			    SSL_R_CIPHER_OR_HASH_UNAVAILABLE);
			return (0);
		}
		key_len = EVP_AEAD_key_length(aead);
		iv_len = SSL_CIPHER_AEAD_FIXED_NONCE_LEN(s->session->cipher);
	} else {
		if (!ssl_cipher_get_evp(s->session, &cipher, &mac, &mac_type,
		    &mac_secret_size)) {
			SSLerr(SSL_F_TLS1_SETUP_KEY_BLOCK,
			    SSL_R_CIPHER_OR_HASH_UNAVAILABLE);
			return (0);
		}
		key_len = EVP_CIPHER_key_length(cipher);
		iv_len = EVP_CIPHER_iv_length(cipher);

		/* If GCM mode only part of IV comes from PRF. */
		if (EVP_CIPHER_mode(cipher) == EVP_CIPH_GCM_MODE)
			iv_len = EVP_GCM_TLS_FIXED_IV_LEN;
	}

	s->s3->tmp.new_aead = aead;
	s->s3->tmp.new_sym_enc = cipher;
	s->s3->tmp.new_hash = mac;
	s->s3->tmp.new_mac_pkey_type = mac_type;
	s->s3->tmp.new_mac_secret_size = mac_secret_size;

	tls1_cleanup_key_block(s);

	if ((key_block = reallocarray(NULL, mac_secret_size + key_len + iv_len,
	    2)) == NULL) {
		SSLerr(SSL_F_TLS1_SETUP_KEY_BLOCK, ERR_R_MALLOC_FAILURE);
		goto err;
	}
	key_block_len = (mac_secret_size + key_len + iv_len) * 2;

	s->s3->tmp.key_block_length = key_block_len;
	s->s3->tmp.key_block = key_block;

	if ((tmp_block = malloc(key_block_len)) == NULL) {
		SSLerr(SSL_F_TLS1_SETUP_KEY_BLOCK, ERR_R_MALLOC_FAILURE);
		goto err;
	}

	if (!tls1_generate_key_block(s, key_block, tmp_block, key_block_len))
		goto err;

	if (!(s->options & SSL_OP_DONT_INSERT_EMPTY_FRAGMENTS) &&
	    s->method->version <= TLS1_VERSION) {
		/*
		 * Enable vulnerability countermeasure for CBC ciphers with
		 * known-IV problem (http://www.openssl.org/~bodo/tls-cbc.txt)
		 */
		s->s3->need_empty_fragments = 1;

		if (s->session->cipher != NULL) {
			if (s->session->cipher->algorithm_enc == SSL_eNULL)
				s->s3->need_empty_fragments = 0;

#ifndef OPENSSL_NO_RC4
			if (s->session->cipher->algorithm_enc == SSL_RC4)
				s->s3->need_empty_fragments = 0;
#endif
		}
	}

	ret = 1;

err:
	if (tmp_block) {
		explicit_bzero(tmp_block, key_block_len);
		free(tmp_block);
	}
	return (ret);
}

/* tls1_enc encrypts/decrypts the record in |s->wrec| / |s->rrec|, respectively.
 *
 * Returns:
 *   0: (in non-constant time) if the record is publically invalid (i.e. too
 *       short etc).
 *   1: if the record's padding is valid / the encryption was successful.
 *   -1: if the record's padding/AEAD-authenticator is invalid or, if sending,
 *       an internal error occured.
 */
int
tls1_enc(SSL *s, int send)
{
	const SSL_AEAD_CTX *aead;
	const EVP_CIPHER *enc;
	EVP_CIPHER_CTX *ds;
	SSL3_RECORD *rec;
	unsigned char *seq;
	unsigned long l;
	int bs, i, j, k, pad = 0, ret, mac_size = 0;

	if (send) {
		aead = s->aead_write_ctx;
		rec = &s->s3->wrec;
		seq = s->s3->write_sequence;
	} else {
		aead = s->aead_read_ctx;
		rec = &s->s3->rrec;
		seq = s->s3->read_sequence;
	}

	if (aead) {
		unsigned char ad[13], *in, *out, nonce[16];
		size_t out_len, pad_len = 0;
		unsigned int nonce_used;

		if (SSL_IS_DTLS(s)) {
			dtls1_build_sequence_number(ad, seq,
			    send ? s->d1->w_epoch : s->d1->r_epoch);
		} else {
			memcpy(ad, seq, SSL3_SEQUENCE_SIZE);
			tls1_record_sequence_increment(seq);
		}

		ad[8] = rec->type;
		ad[9] = (unsigned char)(s->version >> 8);
		ad[10] = (unsigned char)(s->version);

		if (aead->variable_nonce_len > 8 ||
		    aead->variable_nonce_len > sizeof(nonce))
			return -1;

		if (aead->xor_fixed_nonce) {
			if (aead->fixed_nonce_len > sizeof(nonce) ||
			    aead->variable_nonce_len > aead->fixed_nonce_len)
				return -1;  /* Should never happen. */
			pad_len = aead->fixed_nonce_len - aead->variable_nonce_len;
		} else {
			if (aead->fixed_nonce_len +
			    aead->variable_nonce_len > sizeof(nonce))
				return -1;  /* Should never happen. */
		}

		if (send) {
			size_t len = rec->length;
			size_t eivlen = 0;
			in = rec->input;
			out = rec->data;

			if (aead->xor_fixed_nonce) {
				/*
				 * The sequence number is left zero
				 * padded, then xored with the fixed
				 * nonce.
				 */
				memset(nonce, 0, pad_len);
				memcpy(nonce + pad_len, ad,
				    aead->variable_nonce_len);
				for (i = 0; i < aead->fixed_nonce_len; i++)
					nonce[i] ^= aead->fixed_nonce[i];
				nonce_used = aead->fixed_nonce_len;
			} else {
				/*
				 * When sending we use the sequence number as
				 * the variable part of the nonce.
				 */
				memcpy(nonce, aead->fixed_nonce,
				    aead->fixed_nonce_len);
				nonce_used = aead->fixed_nonce_len;
				memcpy(nonce + nonce_used, ad,
				    aead->variable_nonce_len);
				nonce_used += aead->variable_nonce_len;
			}

			/*
			 * In do_ssl3_write, rec->input is moved forward by
			 * variable_nonce_len in order to leave space for the
			 * variable nonce. Thus we can copy the sequence number
			 * bytes into place without overwriting any of the
			 * plaintext.
			 */
			if (aead->variable_nonce_in_record) {
				memcpy(out, ad, aead->variable_nonce_len);
				len -= aead->variable_nonce_len;
				eivlen = aead->variable_nonce_len;
			}

			ad[11] = len >> 8;
			ad[12] = len & 0xff;

			if (!EVP_AEAD_CTX_seal(&aead->ctx,
			    out + eivlen, &out_len, len + aead->tag_len, nonce,
			    nonce_used, in + eivlen, len, ad, sizeof(ad)))
				return -1;
			if (aead->variable_nonce_in_record)
				out_len += aead->variable_nonce_len;
		} else {
			/* receive */
			size_t len = rec->length;

			if (rec->data != rec->input)
				return -1;  /* internal error - should never happen. */
			out = in = rec->input;

			if (len < aead->variable_nonce_len)
				return 0;

			if (aead->xor_fixed_nonce) {
				/*
				 * The sequence number is left zero
				 * padded, then xored with the fixed
				 * nonce.
				 */
				memset(nonce, 0, pad_len);
				memcpy(nonce + pad_len, ad,
				    aead->variable_nonce_len);
				for (i = 0; i < aead->fixed_nonce_len; i++)
					nonce[i] ^= aead->fixed_nonce[i];
				nonce_used = aead->fixed_nonce_len;
			} else {
				memcpy(nonce, aead->fixed_nonce,
				    aead->fixed_nonce_len);
				nonce_used = aead->fixed_nonce_len;

				memcpy(nonce + nonce_used,
				    aead->variable_nonce_in_record ? in : ad,
				    aead->variable_nonce_len);
				nonce_used += aead->variable_nonce_len;
			}

			if (aead->variable_nonce_in_record) {
				in += aead->variable_nonce_len;
				len -= aead->variable_nonce_len;
				out += aead->variable_nonce_len;
			}

			if (len < aead->tag_len)
				return 0;
			len -= aead->tag_len;

			ad[11] = len >> 8;
			ad[12] = len & 0xff;

			if (!EVP_AEAD_CTX_open(&aead->ctx, out, &out_len, len,
			    nonce, nonce_used, in, len + aead->tag_len, ad,
			    sizeof(ad)))
				return -1;

			rec->data = rec->input = out;
		}

		rec->length = out_len;

		return 1;
	}

	if (send) {
		if (EVP_MD_CTX_md(s->write_hash)) {
			int n = EVP_MD_CTX_size(s->write_hash);
			OPENSSL_assert(n >= 0);
		}
		ds = s->enc_write_ctx;
		if (s->enc_write_ctx == NULL)
			enc = NULL;
		else {
			int ivlen = 0;
			enc = EVP_CIPHER_CTX_cipher(s->enc_write_ctx);
			if (SSL_USE_EXPLICIT_IV(s) &&
			    EVP_CIPHER_mode(enc) == EVP_CIPH_CBC_MODE)
				ivlen = EVP_CIPHER_iv_length(enc);
			if (ivlen > 1) {
				if (rec->data != rec->input) {
#ifdef DEBUG
					/* we can't write into the input stream:
					 * Can this ever happen?? (steve)
					 */
					fprintf(stderr,
					    "%s:%d: rec->data != rec->input\n",
					    __FILE__, __LINE__);
#endif
				} else
					arc4random_buf(rec->input, ivlen);
			}
		}
	} else {
		if (EVP_MD_CTX_md(s->read_hash)) {
			int n = EVP_MD_CTX_size(s->read_hash);
			OPENSSL_assert(n >= 0);
		}
		ds = s->enc_read_ctx;
		if (s->enc_read_ctx == NULL)
			enc = NULL;
		else
			enc = EVP_CIPHER_CTX_cipher(s->enc_read_ctx);
	}

	if ((s->session == NULL) || (ds == NULL) || (enc == NULL)) {
		memmove(rec->data, rec->input, rec->length);
		rec->input = rec->data;
		ret = 1;
	} else {
		l = rec->length;
		bs = EVP_CIPHER_block_size(ds->cipher);

		if (EVP_CIPHER_flags(ds->cipher) & EVP_CIPH_FLAG_AEAD_CIPHER) {
			unsigned char buf[13];

			if (SSL_IS_DTLS(s)) {
				dtls1_build_sequence_number(buf, seq,
				    send ? s->d1->w_epoch : s->d1->r_epoch);
			} else {
				memcpy(buf, seq, SSL3_SEQUENCE_SIZE);
				tls1_record_sequence_increment(seq);
			}

			buf[8] = rec->type;
			buf[9] = (unsigned char)(s->version >> 8);
			buf[10] = (unsigned char)(s->version);
			buf[11] = rec->length >> 8;
			buf[12] = rec->length & 0xff;
			pad = EVP_CIPHER_CTX_ctrl(ds, EVP_CTRL_AEAD_TLS1_AAD, 13, buf);
			if (send) {
				l += pad;
				rec->length += pad;
			}
		} else if ((bs != 1) && send) {
			i = bs - ((int)l % bs);

			/* Add weird padding of upto 256 bytes */

			/* we need to add 'i' padding bytes of value j */
			j = i - 1;
			for (k = (int)l; k < (int)(l + i); k++)
				rec->input[k] = j;
			l += i;
			rec->length += i;
		}

		if (!send) {
			if (l == 0 || l % bs != 0)
				return 0;
		}

		i = EVP_Cipher(ds, rec->data, rec->input, l);
		if ((EVP_CIPHER_flags(ds->cipher) &
		    EVP_CIPH_FLAG_CUSTOM_CIPHER) ? (i < 0) : (i == 0))
			return -1;	/* AEAD can fail to verify MAC */
		if (EVP_CIPHER_mode(enc) == EVP_CIPH_GCM_MODE && !send) {
			rec->data += EVP_GCM_TLS_EXPLICIT_IV_LEN;
			rec->input += EVP_GCM_TLS_EXPLICIT_IV_LEN;
			rec->length -= EVP_GCM_TLS_EXPLICIT_IV_LEN;
		}

		ret = 1;
		if (EVP_MD_CTX_md(s->read_hash) != NULL)
			mac_size = EVP_MD_CTX_size(s->read_hash);
		if ((bs != 1) && !send)
			ret = tls1_cbc_remove_padding(s, rec, bs, mac_size);
		if (pad && !send)
			rec->length -= pad;
	}
	return ret;
}

int
tls1_cert_verify_mac(SSL *s, int md_nid, unsigned char *out)
{
	EVP_MD_CTX ctx, *d = NULL;
	unsigned int ret;
	int i;

	if (s->s3->handshake_buffer)
		if (!tls1_digest_cached_records(s))
			return 0;

	for (i = 0; i < SSL_MAX_DIGEST; i++) {
		if (s->s3->handshake_dgst[i] &&
		    EVP_MD_CTX_type(s->s3->handshake_dgst[i]) == md_nid) {
			d = s->s3->handshake_dgst[i];
			break;
		}
	}
	if (d == NULL) {
		SSLerr(SSL_F_TLS1_CERT_VERIFY_MAC, SSL_R_NO_REQUIRED_DIGEST);
		return 0;
	}

	EVP_MD_CTX_init(&ctx);
	if (!EVP_MD_CTX_copy_ex(&ctx, d))
		return 0;
	EVP_DigestFinal_ex(&ctx, out, &ret);
	EVP_MD_CTX_cleanup(&ctx);

	return ((int)ret);
}

int
tls1_final_finish_mac(SSL *s, const char *str, int slen, unsigned char *out)
{
	unsigned int i;
	EVP_MD_CTX ctx;
	unsigned char buf[2*EVP_MAX_MD_SIZE];
	unsigned char *q, buf2[12];
	int idx;
	long mask;
	int err = 0;
	const EVP_MD *md;

	q = buf;

	if (s->s3->handshake_buffer)
		if (!tls1_digest_cached_records(s))
			return 0;

	EVP_MD_CTX_init(&ctx);

	for (idx = 0; ssl_get_handshake_digest(idx, &mask, &md); idx++) {
		if (ssl_get_algorithm2(s) & mask) {
			int hashsize = EVP_MD_size(md);
			EVP_MD_CTX *hdgst = s->s3->handshake_dgst[idx];
			if (!hdgst || hashsize < 0 ||
			    hashsize > (int)(sizeof buf - (size_t)(q - buf))) {
				/* internal error: 'buf' is too small for this cipersuite! */
				err = 1;
			} else {
				if (!EVP_MD_CTX_copy_ex(&ctx, hdgst) ||
				    !EVP_DigestFinal_ex(&ctx, q, &i) ||
				    (i != (unsigned int)hashsize))
					err = 1;
				q += hashsize;
			}
		}
	}

	if (!tls1_PRF(ssl_get_algorithm2(s), str, slen, buf, (int)(q - buf),
	    NULL, 0, NULL, 0, NULL, 0,
	    s->session->master_key, s->session->master_key_length,
	    out, buf2, sizeof buf2))
		err = 1;
	EVP_MD_CTX_cleanup(&ctx);

	if (err)
		return 0;
	else
		return sizeof buf2;
}

int
tls1_mac(SSL *ssl, unsigned char *md, int send)
{
	SSL3_RECORD *rec;
	unsigned char *seq;
	EVP_MD_CTX *hash;
	size_t md_size, orig_len;
	EVP_MD_CTX hmac, *mac_ctx;
	unsigned char header[13];
	int stream_mac = (send ?
	    (ssl->mac_flags & SSL_MAC_FLAG_WRITE_MAC_STREAM) :
	    (ssl->mac_flags & SSL_MAC_FLAG_READ_MAC_STREAM));
	int t;

	if (send) {
		rec = &(ssl->s3->wrec);
		seq = &(ssl->s3->write_sequence[0]);
		hash = ssl->write_hash;
	} else {
		rec = &(ssl->s3->rrec);
		seq = &(ssl->s3->read_sequence[0]);
		hash = ssl->read_hash;
	}

	t = EVP_MD_CTX_size(hash);
	OPENSSL_assert(t >= 0);
	md_size = t;

	/* I should fix this up TLS TLS TLS TLS TLS XXXXXXXX */
	if (stream_mac) {
		mac_ctx = hash;
	} else {
		if (!EVP_MD_CTX_copy(&hmac, hash))
			return -1;
		mac_ctx = &hmac;
	}

	if (SSL_IS_DTLS(ssl))
		dtls1_build_sequence_number(header, seq,
		    send ? ssl->d1->w_epoch : ssl->d1->r_epoch);
	else
		memcpy(header, seq, SSL3_SEQUENCE_SIZE);

	/* kludge: tls1_cbc_remove_padding passes padding length in rec->type */
	orig_len = rec->length + md_size + ((unsigned int)rec->type >> 8);
	rec->type &= 0xff;

	header[8] = rec->type;
	header[9] = (unsigned char)(ssl->version >> 8);
	header[10] = (unsigned char)(ssl->version);
	header[11] = (rec->length) >> 8;
	header[12] = (rec->length) & 0xff;

	if (!send &&
	    EVP_CIPHER_CTX_mode(ssl->enc_read_ctx) == EVP_CIPH_CBC_MODE &&
	    ssl3_cbc_record_digest_supported(mac_ctx)) {
		/* This is a CBC-encrypted record. We must avoid leaking any
		 * timing-side channel information about how many blocks of
		 * data we are hashing because that gives an attacker a
		 * timing-oracle. */
		if (!ssl3_cbc_digest_record(mac_ctx,
		    md, &md_size, header, rec->input,
		    rec->length + md_size, orig_len,
		    ssl->s3->read_mac_secret,
		    ssl->s3->read_mac_secret_size,
		    0 /* not SSLv3 */))
			return -1;
	} else {
		EVP_DigestSignUpdate(mac_ctx, header, sizeof(header));
		EVP_DigestSignUpdate(mac_ctx, rec->input, rec->length);
		t = EVP_DigestSignFinal(mac_ctx, md, &md_size);
		OPENSSL_assert(t > 0);
	}

	if (!stream_mac)
		EVP_MD_CTX_cleanup(&hmac);

	if (!SSL_IS_DTLS(ssl))
		tls1_record_sequence_increment(seq);

	return (md_size);
}

int
tls1_generate_master_secret(SSL *s, unsigned char *out, unsigned char *p,
    int len)
{
	unsigned char buff[SSL_MAX_MASTER_KEY_LENGTH];

	tls1_PRF(ssl_get_algorithm2(s),
	    TLS_MD_MASTER_SECRET_CONST, TLS_MD_MASTER_SECRET_CONST_SIZE,
	    s->s3->client_random, SSL3_RANDOM_SIZE, NULL, 0,
	    s->s3->server_random, SSL3_RANDOM_SIZE, NULL, 0,
	    p, len, s->session->master_key, buff, sizeof buff);

	return (SSL3_MASTER_SECRET_SIZE);
}

int
tls1_export_keying_material(SSL *s, unsigned char *out, size_t olen,
    const char *label, size_t llen, const unsigned char *context,
    size_t contextlen, int use_context)
{
	unsigned char *buff;
	unsigned char *val = NULL;
	size_t vallen, currentvalpos;
	int rv;

	buff = malloc(olen);
	if (buff == NULL)
		goto err2;

	/* construct PRF arguments
	 * we construct the PRF argument ourself rather than passing separate
	 * values into the TLS PRF to ensure that the concatenation of values
	 * does not create a prohibited label.
	 */
	vallen = llen + SSL3_RANDOM_SIZE * 2;
	if (use_context) {
		vallen += 2 + contextlen;
	}

	val = malloc(vallen);
	if (val == NULL)
		goto err2;
	currentvalpos = 0;
	memcpy(val + currentvalpos, (unsigned char *) label, llen);
	currentvalpos += llen;
	memcpy(val + currentvalpos, s->s3->client_random, SSL3_RANDOM_SIZE);
	currentvalpos += SSL3_RANDOM_SIZE;
	memcpy(val + currentvalpos, s->s3->server_random, SSL3_RANDOM_SIZE);
	currentvalpos += SSL3_RANDOM_SIZE;

	if (use_context) {
		val[currentvalpos] = (contextlen >> 8) & 0xff;
		currentvalpos++;
		val[currentvalpos] = contextlen & 0xff;
		currentvalpos++;
		if ((contextlen > 0) || (context != NULL)) {
			memcpy(val + currentvalpos, context, contextlen);
		}
	}

	/* disallow prohibited labels
	 * note that SSL3_RANDOM_SIZE > max(prohibited label len) =
	 * 15, so size of val > max(prohibited label len) = 15 and the
	 * comparisons won't have buffer overflow
	 */
	if (memcmp(val, TLS_MD_CLIENT_FINISH_CONST,
	    TLS_MD_CLIENT_FINISH_CONST_SIZE) == 0)
		goto err1;
	if (memcmp(val, TLS_MD_SERVER_FINISH_CONST,
	    TLS_MD_SERVER_FINISH_CONST_SIZE) == 0)
		goto err1;
	if (memcmp(val, TLS_MD_MASTER_SECRET_CONST,
	    TLS_MD_MASTER_SECRET_CONST_SIZE) == 0)
		goto err1;
	if (memcmp(val, TLS_MD_KEY_EXPANSION_CONST,
	    TLS_MD_KEY_EXPANSION_CONST_SIZE) == 0)
		goto err1;

	rv = tls1_PRF(ssl_get_algorithm2(s),
	    val, vallen, NULL, 0, NULL, 0, NULL, 0, NULL, 0,
	    s->session->master_key, s->session->master_key_length,
	    out, buff, olen);

	goto ret;
err1:
	SSLerr(SSL_F_TLS1_EXPORT_KEYING_MATERIAL,
	    SSL_R_TLS_ILLEGAL_EXPORTER_LABEL);
	rv = 0;
	goto ret;
err2:
	SSLerr(SSL_F_TLS1_EXPORT_KEYING_MATERIAL, ERR_R_MALLOC_FAILURE);
	rv = 0;
ret:
	free(buff);
	free(val);

	return (rv);
}

int
tls1_alert_code(int code)
{
	switch (code) {
	case SSL_AD_CLOSE_NOTIFY:
		return (SSL3_AD_CLOSE_NOTIFY);
	case SSL_AD_UNEXPECTED_MESSAGE:
		return (SSL3_AD_UNEXPECTED_MESSAGE);
	case SSL_AD_BAD_RECORD_MAC:
		return (SSL3_AD_BAD_RECORD_MAC);
	case SSL_AD_DECRYPTION_FAILED:
		return (TLS1_AD_DECRYPTION_FAILED);
	case SSL_AD_RECORD_OVERFLOW:
		return (TLS1_AD_RECORD_OVERFLOW);
	case SSL_AD_DECOMPRESSION_FAILURE:
		return (SSL3_AD_DECOMPRESSION_FAILURE);
	case SSL_AD_HANDSHAKE_FAILURE:
		return (SSL3_AD_HANDSHAKE_FAILURE);
	case SSL_AD_NO_CERTIFICATE:
		return (-1);
	case SSL_AD_BAD_CERTIFICATE:
		return (SSL3_AD_BAD_CERTIFICATE);
	case SSL_AD_UNSUPPORTED_CERTIFICATE:
		return (SSL3_AD_UNSUPPORTED_CERTIFICATE);
	case SSL_AD_CERTIFICATE_REVOKED:
		return (SSL3_AD_CERTIFICATE_REVOKED);
	case SSL_AD_CERTIFICATE_EXPIRED:
		return (SSL3_AD_CERTIFICATE_EXPIRED);
	case SSL_AD_CERTIFICATE_UNKNOWN:
		return (SSL3_AD_CERTIFICATE_UNKNOWN);
	case SSL_AD_ILLEGAL_PARAMETER:
		return (SSL3_AD_ILLEGAL_PARAMETER);
	case SSL_AD_UNKNOWN_CA:
		return (TLS1_AD_UNKNOWN_CA);
	case SSL_AD_ACCESS_DENIED:
		return (TLS1_AD_ACCESS_DENIED);
	case SSL_AD_DECODE_ERROR:
		return (TLS1_AD_DECODE_ERROR);
	case SSL_AD_DECRYPT_ERROR:
		return (TLS1_AD_DECRYPT_ERROR);
	case SSL_AD_EXPORT_RESTRICTION:
		return (TLS1_AD_EXPORT_RESTRICTION);
	case SSL_AD_PROTOCOL_VERSION:
		return (TLS1_AD_PROTOCOL_VERSION);
	case SSL_AD_INSUFFICIENT_SECURITY:
		return (TLS1_AD_INSUFFICIENT_SECURITY);
	case SSL_AD_INTERNAL_ERROR:
		return (TLS1_AD_INTERNAL_ERROR);
	case SSL_AD_INAPPROPRIATE_FALLBACK:
		return(TLS1_AD_INAPPROPRIATE_FALLBACK);
	case SSL_AD_USER_CANCELLED:
		return (TLS1_AD_USER_CANCELLED);
	case SSL_AD_NO_RENEGOTIATION:
		return (TLS1_AD_NO_RENEGOTIATION);
	case SSL_AD_UNSUPPORTED_EXTENSION:
		return (TLS1_AD_UNSUPPORTED_EXTENSION);
	case SSL_AD_CERTIFICATE_UNOBTAINABLE:
		return (TLS1_AD_CERTIFICATE_UNOBTAINABLE);
	case SSL_AD_UNRECOGNIZED_NAME:
		return (TLS1_AD_UNRECOGNIZED_NAME);
	case SSL_AD_BAD_CERTIFICATE_STATUS_RESPONSE:
		return (TLS1_AD_BAD_CERTIFICATE_STATUS_RESPONSE);
	case SSL_AD_BAD_CERTIFICATE_HASH_VALUE:
		return (TLS1_AD_BAD_CERTIFICATE_HASH_VALUE);
	case SSL_AD_UNKNOWN_PSK_IDENTITY:
		return (TLS1_AD_UNKNOWN_PSK_IDENTITY);
	default:
		return (-1);
	}
}
