/* picotlsvs: test program for the TLS 1.3 library. */
#include <stdio.h>
#include <stdarg.h>
#include <openssl/pem.h>
#include "../picotls/wincompat.h"
#include "../../include/picotls.h"
#include "../../include/picotls/openssl.h"
#include "../../include/picotls/minicrypto.h"
#include "../../include/picotls/asn1.h"
#include "../../include/picotls/pembase64.h"

void log_printf(void * ctx, const char * format, ...)
{
	va_list argptr;
	va_start(argptr, format);
	vfprintf(stderr, format, argptr);
}

ptls_minicrypto_log_ctx_t log_ctx = { NULL, log_printf };

int ptls_export_secret(ptls_t *tls, void *output, size_t outlen, const char *label, ptls_iovec_t context_value, int is_early);

/*
 * Testing the Base64 and ASN1 verifiers.
 * Start by loading the private key object, then do a mini fuzz test.
 * The goal is to verify that the decoding returns something correct,
 * even in presence of errors.
 */

size_t ptls_minicrypto_asn1_decode_private_key(
	ptls_asn1_pkcs8_private_key_t * pkey,
	int * decode_error, ptls_minicrypto_log_ctx_t * log_ctx);

int openPemTest(char const * filename)
{
	ptls_iovec_t buf = { 0 };
	size_t count = 1;
	size_t fuzz_index = 0;
	uint8_t original_byte = 0;
	uint8_t fuzz_byte = 0xAA;
	size_t byte_index = 0;
	int decode_error;

	int ret = ptls_load_pem_objects(filename, "PRIVATE KEY", &buf, 1, &count);


	if (ret == 0)
	{
		for (fuzz_index = 0; ret == 0 && fuzz_index < buf.len; fuzz_index++)
		{
			ptls_asn1_pkcs8_private_key_t pkey = { {0} };
			original_byte = buf.base[fuzz_index];
			decode_error = 0;
			buf.base[fuzz_index] ^= fuzz_byte;

			pkey.vec.base = buf.base;
			pkey.vec.len = buf.len;

			byte_index = ptls_minicrypto_asn1_decode_private_key(
				&pkey, &decode_error, NULL);

			if (decode_error != 0)
			{
				if (decode_error == 1)
				{
					ret = -1;
				}
			}

			buf.base[fuzz_index] = original_byte;
		}
	}

	if (buf.base != NULL)
	{
		free(buf.base);
	}

	return ret;
}

/*
 * Using the open ssl library to load the test certificate
 */

X509* openPemFile(char* filename)
{

    X509* cert = X509_new();
    BIO* bio_cert = BIO_new_file(filename, "rb");
    PEM_read_bio_X509(bio_cert, &cert, NULL, NULL);
    return cert;
}

int get_certificates(char * pem_fname, ptls_iovec_t ** list, int * nb_certs)
{
    int ret = 0;
    size_t count = 0;
    X509 *cert;
    static ptls_iovec_t certs[16];

    *nb_certs = 0;
    *list = NULL;

    cert = openPemFile(pem_fname);

    if (cert == NULL)
    {
        fprintf(stderr, "Could not read cert in %s\n", pem_fname);
        ret = -1;
    }
    else
    {
        ptls_iovec_t *dst = certs + count++;
        dst->len = i2d_X509(cert, &dst->base);
    }
    
    *nb_certs = (int) count;
    *list = certs;

    return ret;
}

void SetSignCertificate(char * keypem, ptls_context_t * ctx)
{
    static ptls_openssl_sign_certificate_t signer;

    EVP_PKEY *pkey = EVP_PKEY_new();
    BIO* bio_key = BIO_new_file(keypem, "rb");
    PEM_read_bio_PrivateKey(bio_key, &pkey, NULL, NULL);
    ptls_openssl_init_sign_certificate(&signer, pkey);
    EVP_PKEY_free(pkey);
    ctx->sign_certificate = &signer.super;
}

int handshake_init(ptls_t * tls, ptls_buffer_t * sendbuf, ptls_handshake_properties_t * ph_prop)
{
    size_t inlen = 0, roff = 0;

    ptls_buffer_init(sendbuf, "", 0);
    int ret = ptls_handshake(tls, sendbuf, NULL, NULL, ph_prop);

    return ret;
}


int handshake_progress(ptls_t * tls, ptls_buffer_t * sendbuf, ptls_buffer_t * recvbuf, ptls_handshake_properties_t * ph_prop)
{
    size_t inlen = 0, roff = 0;
    int ret = 0;

    ptls_buffer_init(sendbuf, "", 0);

    /* Provide the data */
    while (roff < recvbuf->off && (ret == 0 || ret == PTLS_ERROR_IN_PROGRESS))
    {
        inlen = recvbuf->off - roff;
        ret = ptls_handshake(tls, sendbuf, recvbuf->base + roff, &inlen, ph_prop);
        roff += inlen;
    }

    if (roff < recvbuf->off)
    {
        // Could not consume all the data. This is bad.
        fprintf(stderr, "Could only process %d bytes out of %d\n", (int) roff, (int) recvbuf->off);
    }
    ptls_buffer_dispose(recvbuf);

    return ret;
}

/*
 Verify the secret extraction functionality
 at the end of the handshake.
 */

int extract_1rtt_secret( 
    ptls_t *tls, const char *label, 
    ptls_cipher_suite_t ** cipher,
    uint8_t * secret, size_t secret_max)
{
    int ret = 0;
    *cipher = ptls_get_cipher(tls);

    if (*cipher == NULL)
    {
        ret = -1;
    }
    else if ((*cipher)->hash->digest_size > secret_max)
    {
        ret = -1;
    }
    else
    {
        ret = ptls_export_secret(tls, secret, (*cipher)->hash->digest_size,
            label, ptls_iovec_init(NULL, 0), 1);
    }

    return 0;
}

int verify_1rtt_secret_extraction(ptls_t *tls_client, ptls_t *tls_server)
{
    int ret = 0;
    ptls_cipher_suite_t * cipher_client;
    ptls_cipher_suite_t * cipher_server;
    uint8_t secret_client[64];
    uint8_t secret_server[64];
    char const * label = "This is just a test";

    ret = extract_1rtt_secret(tls_client, label, &cipher_client, 
        secret_client, sizeof(secret_client));

    if (ret != 0)
    {
        fprintf(stderr, "Cannot extract client 1RTT secret, ret=%d\n", ret);
    }
    else
    {
        ret = extract_1rtt_secret(tls_server, label, &cipher_server,
            secret_server, sizeof(secret_server));
        if (ret != 0)
        {
            fprintf(stderr, "Cannot extract client 1RTT secret, ret=%d\n", ret);
        }
    }

    if (ret == 0)
    {
        if (strcmp(cipher_client->aead->name, cipher_server->aead->name) != 0)
        {
            fprintf(stderr, "AEAD differ, client:%s, server:%s\n",
                cipher_client->aead->name, cipher_server->aead->name);
            ret = -1;
        }
        else if (cipher_client->hash->digest_size != cipher_server->hash->digest_size)
        {
            fprintf(stderr, "Key length differ, client:%d, server:%d\n",
                (int) cipher_client->hash->digest_size, (int) cipher_server->hash->digest_size);
            ret = -1;
        }
        else if (memcmp(secret_client, secret_server, cipher_client->hash->digest_size) != 0)
        {
            fprintf(stderr, "Key of client and server differ!\n");
            ret = -1;
        }
    }

    return ret;
}

int openssl_init_test_client(ptls_context_t *ctx_client)
{
	int ret = 0;
	static ptls_openssl_verify_certificate_t verifier;

	/* Initialize the client context */
	memset(ctx_client, 0, sizeof(ptls_context_t));
	ctx_client->random_bytes = ptls_openssl_random_bytes;
    ctx_client->get_time = &ptls_get_time;
	ctx_client->key_exchanges = ptls_openssl_key_exchanges;
	ctx_client->cipher_suites = ptls_openssl_cipher_suites;
	ptls_openssl_init_verify_certificate(&verifier, NULL);
	ctx_client->verify_certificate = &verifier.super;

	return ret;
}

int openssl_init_test_server(ptls_context_t *ctx_server, char * key_file, char * cert_file)
{
	int ret = 0;
	/* Initialize the server context */
	memset(ctx_server, 0, sizeof(ptls_context_t));
	ctx_server->random_bytes = ptls_openssl_random_bytes;
    ctx_server->get_time = &ptls_get_time;
	ctx_server->key_exchanges = ptls_openssl_key_exchanges;
	ctx_server->cipher_suites = ptls_openssl_cipher_suites;

	ret = ptls_load_certificates(ctx_server, cert_file);
	if (ret != 0)
	{
		fprintf(stderr, "Could not read the server certificates\n");
	}
	else
	{
		SetSignCertificate(key_file, ctx_server);
	}

	return ret;
}

int minicrypto_init_test_client(ptls_context_t *ctx_client)
{
	int ret = 0;
	// static ptls_openssl_verify_certificate_t verifier;

	/* Initialize the client context */
	memset(ctx_client, 0, sizeof(ptls_context_t));
	ctx_client->random_bytes = ptls_minicrypto_random_bytes;
    ctx_client->get_time = &ptls_get_time;
	ctx_client->key_exchanges = ptls_minicrypto_key_exchanges;
	ctx_client->cipher_suites = ptls_minicrypto_cipher_suites;
	// ptls_openssl_init_verify_certificate(&verifier, NULL);
	ctx_client->verify_certificate = NULL; // &verifier.super;

	return ret;
}

int minicrypto_init_test_server(ptls_context_t *ctx_server, char * key_file, char * cert_file)
{
	int ret = 0;

	/* Initialize the server context */
	memset(ctx_server, 0, sizeof(ptls_context_t));
	ctx_server->random_bytes = ptls_minicrypto_random_bytes;
    ctx_server->get_time = &ptls_get_time;
	ctx_server->key_exchanges = ptls_minicrypto_key_exchanges;
	ctx_server->cipher_suites = ptls_minicrypto_cipher_suites;

	ret = ptls_load_certificates(ctx_server, cert_file);

	if (ret != 0)
	{
		fprintf(stderr, "Could not read the server certificates\n");
	}
	else
	{
		ret = ptls_minicrypto_load_private_key(ctx_server, key_file);
	}

	return ret;
}

#define PICOTLS_VS_TEST_EXTENSION 1234
static uint8_t testExtensionClient[] = { 1, 2, 3 };
static uint8_t testExtensionServer[] = { 1, 2, 3, 4, 5, 6, 7, 8 };
char const test_sni[] = "picotls.example.com";
char const test_alpn[] = "picotls";
static const ptls_iovec_t proposed_alpn[] = {
	{ (uint8_t *) "grease", 6},
	{ (uint8_t *)test_alpn, sizeof(test_alpn) -1 }
};


struct st_picotls_vs_test_context_t
{
	int client_mode;
	size_t received_extension_length;
	uint8_t received_extension[16];
	ptls_raw_extension_t ext[2];

	ptls_handshake_properties_t handshake_properties;

};

int collect_test_extension(ptls_t *tls, struct st_ptls_handshake_properties_t *properties, uint16_t type)
{
	return type == PICOTLS_VS_TEST_EXTENSION;
}

void set_test_extensions(ptls_raw_extension_t ext[2], uint8_t * data, size_t len)
{
	ext[0].type = PICOTLS_VS_TEST_EXTENSION;
	ext[0].data.base = data;
	ext[0].data.len = len;
	ext[1].type = 0xFFFF;
	ext[1].data.base = NULL;
	ext[1].data.len = 0;
}

int collected_test_extensions(ptls_t *tls, ptls_handshake_properties_t *properties, 
	ptls_raw_extension_t *slots)
{
	struct st_picotls_vs_test_context_t * ctx = (struct st_picotls_vs_test_context_t *)
		((char *)properties - offsetof(struct st_picotls_vs_test_context_t, handshake_properties));

	if (slots[0].type == PICOTLS_VS_TEST_EXTENSION && slots[1].type == 0xFFFF)
	{
		ctx->received_extension_length = slots[0].data.len;
		memcpy(ctx->received_extension, slots[0].data.base,
			(slots[0].data.len < sizeof(ctx->received_extension)) ?
			slots[0].data.len : sizeof(ctx->received_extension));

		if (ctx->client_mode == 0)
		{
			properties->additional_extensions = ctx->ext;
			set_test_extensions(ctx->ext, testExtensionServer, sizeof(testExtensionServer));
		}
	}

	return 0;
}

int client_hello_call_back(ptls_on_client_hello_t * on_hello_cb_ctx,
	ptls_t *tls, ptls_iovec_t server_name, const ptls_iovec_t *negotiated_protocols,
	size_t num_negotiated_protocols, const uint16_t *signature_algorithms, size_t num_signature_algorithms)
{
	for (size_t i = 0; i < num_negotiated_protocols; i++)
	{
		if (negotiated_protocols[i].len == sizeof(test_alpn) - 1 &&
			memcmp(negotiated_protocols[i].base, test_alpn, sizeof(test_alpn) - 1) == 0)
		{
			ptls_set_negotiated_protocol(tls, test_alpn, sizeof(test_alpn) - 1);
			break;
		}
	}
	return 0;
}

void set_handshake_context(struct st_picotls_vs_test_context_t * ctx, int client_mode)
{
	memset(ctx, 0, sizeof(struct st_picotls_vs_test_context_t));
	
	if ((ctx->client_mode = client_mode) != 0)
	{
		ctx->handshake_properties.client.negotiated_protocols.list = proposed_alpn;
		ctx->handshake_properties.client.negotiated_protocols.count =
			sizeof(proposed_alpn) / sizeof(ptls_iovec_t);

		ctx->handshake_properties.additional_extensions = ctx->ext;
		set_test_extensions(ctx->ext, testExtensionClient, sizeof(testExtensionClient));
	}

	ctx->handshake_properties.collect_extension = collect_test_extension;
	ctx->handshake_properties.collected_extensions = collected_test_extensions;
}

int verify_handshake_extension(struct st_picotls_vs_test_context_t * app_ctx_client,
	struct st_picotls_vs_test_context_t *app_ctx_server)
{
	int ret = 0;

	if (app_ctx_server->received_extension_length == 0)
	{
		fprintf(stderr, "Server did not receive the client extension.\n");
		ret = -1;
	}
	else if (app_ctx_server->received_extension_length != sizeof(testExtensionClient) ||
		memcmp(app_ctx_server->received_extension, testExtensionClient, sizeof(testExtensionClient)))
	{
		fprintf(stderr, "Server did not correctly receive the client extension.\n");
		ret = -1;
	}
	else if (app_ctx_client->received_extension_length == 0)
	{
		fprintf(stderr, "Client did not receive the server extension.\n");
		ret = -1;
	}
	else if (app_ctx_client->received_extension_length != sizeof(testExtensionServer) ||
		memcmp(app_ctx_client->received_extension, testExtensionServer, sizeof(testExtensionServer)))
	{
		fprintf(stderr, "Client did not correctly receive the server extension.\n");
		ret = -1;
	}

	return ret;
}

int ptls_memory_loopback_test(int openssl_client, int openssl_server, char * key_file, char * cert_file)
{
	ptls_context_t ctx_client, ctx_server;
	ptls_t *tls_client = NULL, *tls_server = NULL;
	int ret = 0;
	ptls_buffer_t client_buf, server_buf;
	struct st_picotls_vs_test_context_t app_ctx_client, app_ctx_server;
	ptls_on_client_hello_t client_hello_cb;


	/* init the contexts */
	if (ret == 0 && openssl_client)
	{
		ret = openssl_init_test_client(&ctx_client);
	}
	else
	{
		ret = minicrypto_init_test_client(&ctx_client);
	}

	if (ret == 0 && openssl_server)
	{
		ret = openssl_init_test_server(&ctx_server, key_file, cert_file);
	}
	else
	{
		ret = minicrypto_init_test_server(&ctx_server, key_file, cert_file);
	}

	/* Create the connections */
	if (ret == 0)
	{
		tls_client = ptls_new(&ctx_client, 0);
		tls_server = ptls_new(&ctx_server, 1);

		if (tls_server == NULL || tls_client == NULL)
		{
			fprintf(stderr, "Could not create the TLS connection objects\n");
			ret = -1;
		}
	}

	/* Perform the handshake */
	if (ret == 0)
	{
		int nb_rounds = 0;

		set_handshake_context(&app_ctx_client, 1);
		set_handshake_context(&app_ctx_server, 0);

		client_hello_cb.cb = client_hello_call_back;
		ctx_server.on_client_hello = &client_hello_cb;

		ptls_set_server_name(tls_client, test_sni, sizeof(test_sni) - 1);

		ret = handshake_init(tls_client, &client_buf,
			&app_ctx_client.handshake_properties);
		printf("First message from client, ret = %d, %d bytes.\n", ret, (int) client_buf.off);

		while ((ret == 0 || ret == PTLS_ERROR_IN_PROGRESS) && client_buf.off > 0 && nb_rounds < 12)
		{
			nb_rounds++;

			ret = handshake_progress(tls_server, &server_buf, &client_buf,
				&app_ctx_server.handshake_properties);
			app_ctx_server.handshake_properties.additional_extensions = NULL;

			printf("Message from server, ret = %d, %d bytes.\n", ret, (int) server_buf.off);

			if ((ret == 0 || ret == PTLS_ERROR_IN_PROGRESS) && server_buf.off > 0)
			{
				app_ctx_client.handshake_properties.additional_extensions = NULL;

				ret = handshake_progress(tls_client, &client_buf, &server_buf, 
					&app_ctx_client.handshake_properties);

				printf("Message from client, ret = %d, %d bytes.\n", ret, (int) client_buf.off);
			}
		}

		printf("Exit handshake after %d rounds, ret = %d.\n", nb_rounds, ret);

		if (ret == 0)
		{
			ret = verify_1rtt_secret_extraction(tls_client, tls_server);

			if (ret == 0)
			{
				printf("Key extracted and matches!\n");
			}
		}

		if (ret == 0)
		{
			ret = verify_handshake_extension(&app_ctx_client, &app_ctx_server);

			if (ret == 0)
			{
				printf("Extensions received and match!\n");
			}
		}

		if (ret == 0)
		{
			const char * sni_received = ptls_get_server_name(tls_server);

			if (sni_received == NULL)
			{
				fprintf(stderr, "Server did not receive the SNI set by the client\n");
				ret = -1;
			}
			else if (strcmp(sni_received, test_sni) != 0)
			{
				fprintf(stderr, "Server receives SNI: <%s>, does not match <%s>\n",
					sni_received, test_sni);
				ret = -1;
			}
		}

		if (ret == 0)
		{
			const char * alpn_received = ptls_get_negotiated_protocol(tls_server);

			if (alpn_received == NULL)
			{
				fprintf(stderr, "Server did not negotiate ALPN\n");
				ret = -1;
			}
			else if (strcmp(alpn_received, test_alpn) != 0)
			{
				fprintf(stderr, "Server receives ALPN: <%s>, does not match <%s>\n",
					alpn_received, test_alpn);
				ret = -1;
			}
		}

		if (ret == 0)
		{
			printf("SNI and ALPN match.\n");
		}
	}

	if (tls_client != NULL)
	{
		ptls_free(tls_client);
	}

	if (tls_server != NULL)
	{
		ptls_free(tls_server);
	}

	if (openssl_server == 0 && ctx_server.sign_certificate != NULL)
	{
		free(ctx_server.sign_certificate);
	}

	return ret;
}

static char const * test_keys[] = {
	"key.pem",
	"ec_key.pem",
	"key-test-1.pem",
	"key-test-2.pem",
	"key-test-4.pem"
};

static const size_t nb_test_keys = sizeof(test_keys) / sizeof(char const *);

int main()
{
	int ret = 0;

#if 1
	/* TODO: move to ASN.1 unit test*/

	for (size_t i = 0; ret == 0 && i < nb_test_keys; i++)
	{
		ret = openPemTest(test_keys[i]);
	}
#endif

	if (ret == 0)
	{
		printf("\nStarting the RSA test with OpenSSL\n");
		ret = ptls_memory_loopback_test(1, 1, "key.pem", "cert.pem");
	}

	if (ret == 0)
	{
		printf("\nStarting the P256R1 test with OpenSSL\n");
		ret = ptls_memory_loopback_test(1, 1, "ec_key.pem", "ec_cert.pem");
	}

	if (ret == 0)
	{
		printf("\nStarting the P256R1 test with OpenSSL server and Minicrypto client\n");
		ret = ptls_memory_loopback_test(0, 1, "ec_key.pem", "ec_cert.pem");
	}

	if (ret == 0)
	{
		printf("\nStarting the P256R1 test with Minicrypto\n");
		ret = ptls_memory_loopback_test(0, 0, "ec_key.pem", "ec_cert.pem");
	}

	if (ret == 0)
	{
		printf("\nStarting the P256R1 test with Minicrypto server and OpenSSL client\n");
		ret = ptls_memory_loopback_test(1, 0, "ec_key.pem", "ec_cert.pem");
	}

    return ret;
}

