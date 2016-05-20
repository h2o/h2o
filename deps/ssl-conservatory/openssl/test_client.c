/*
 * Sample HTTPS client to demonstrate how to do certificate validation using 
 * OpenSSL.
 * This client will securely connect to www.isecpartners.com:443 and print the 
 * server's response to an HTTP GET request.
 *
 * Please read "everything-you-wanted-to-know-about-openssl.pdf" before
 * attempting to use this code. This whitepaper describes how the code works, 
 * how it should be used, and what its limitations are.
 *
 * Author:  Alban Diquet
 * License: See LICENSE
 *
 */

#include <stdio.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/rand.h>

#include "openssl_hostname_validation.h"


// Sample SSL client for https://www.isecpartners.com
#define TARGET_HOST "www.isecpartners.com"
#define TARGET_PORT "443"

// CA certificate that signed www.isecpartners.com's certificate
#define TRUSTED_CA_PATHNAME "DigiCertHighAssuranceEVRootCA.pem"



#define TARGET_SERVER TARGET_HOST":"TARGET_PORT
// 'High' cipher suites minus Anonymous DH and Camellia
#define SECURE_CIPHER_LIST "RC4-SHA:HIGH:!ADH:!AECDH:!CAMELLIA"

/* Sends an HTTP GET and prints the server's response */
static void send_http_get_and_print(BIO * sbio) { 
		int len;
		char tmpbuf[1024];
		BIO * out = BIO_new_fp(stdout, BIO_NOCLOSE);

		BIO_puts(sbio, "GET / HTTP/1.0\n\n");
		for(;;) {
			len = BIO_read(sbio, tmpbuf, 1024);
			if(len <= 0) break;
		BIO_write(out, tmpbuf, len);
		}
		BIO_free(out);
}


int main(int argc, char *argv[]) {
	BIO *sbio;
	SSL_CTX *ssl_ctx;
	SSL *ssl;
	X509 *server_cert;

	// Initialize OpenSSL
	SSL_library_init();
	SSL_load_error_strings();

 	// Check OpenSSL PRNG
	if(RAND_status() != 1) {
		fprintf(stderr, "OpenSSL PRNG not seeded with enough data.");
		goto error_1;
	}

	ssl_ctx = SSL_CTX_new(TLSv1_client_method());
	
	// Enable certificate validation
	SSL_CTX_set_verify(ssl_ctx, SSL_VERIFY_PEER, NULL);
	// Configure the CA trust store to be used
	if (SSL_CTX_load_verify_locations(ssl_ctx, TRUSTED_CA_PATHNAME, NULL) != 1) {
		fprintf(stderr, "Couldn't load certificate trust store.\n");
		goto error_2;
	}

	// Only support secure cipher suites
	if (SSL_CTX_set_cipher_list(ssl_ctx, SECURE_CIPHER_LIST) != 1)
		goto error_2;

	// Create the SSL connection
	sbio = BIO_new_ssl_connect(ssl_ctx);
	BIO_get_ssl(sbio, &ssl); 
	if(!ssl) {
	  fprintf(stderr, "Can't locate SSL pointer\n");
		goto error_3;
	}

	// Do the SSL handshake
	BIO_set_conn_hostname(sbio, TARGET_SERVER);
	if(SSL_do_handshake(ssl) <= 0) {
		// SSL Handshake failed
		long verify_err = SSL_get_verify_result(ssl);
		if (verify_err != X509_V_OK) { 
			// It failed because the certificate chain validation failed
			fprintf(stderr, "Certificate chain validation failed: %s\n", X509_verify_cert_error_string(verify_err));
		}
		else {
			// It failed for another reason
			ERR_print_errors_fp(stderr);
		}
		goto error_3;
	}

	// Recover the server's certificate
	server_cert =  SSL_get_peer_certificate(ssl);
	if (server_cert == NULL) {
		// The handshake was successful although the server did not provide a certificate
		// Most likely using an insecure anonymous cipher suite... get out!
		goto error_4;
	}

	// Validate the hostname
	if (validate_hostname(TARGET_HOST, server_cert) != MatchFound) {
		fprintf(stderr, "Hostname validation failed.\n");
		goto error_5;
	}

	// Hostname validation succeeded; we can start sending data
	send_http_get_and_print(sbio);


error_5:
	X509_free(server_cert);

error_4:
	BIO_ssl_shutdown(sbio);

error_3:
	BIO_free_all(sbio);

error_2:
	SSL_CTX_free(ssl_ctx);

error_1: // OpenSSL cleanup
    EVP_cleanup();
    ERR_free_strings();

	return 0;
}
