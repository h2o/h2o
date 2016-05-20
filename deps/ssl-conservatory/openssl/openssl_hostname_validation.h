/*
 * Helper functions to perform basic hostname validation using OpenSSL.
 *
 * Please read "everything-you-wanted-to-know-about-openssl.pdf" before
 * attempting to use this code. This whitepaper describes how the code works, 
 * how it should be used, and what its limitations are.
 *
 * Author:  Alban Diquet
 * License: See LICENSE
 *
 */
#ifndef openssl_hostname_validation_h
#define openssl_hostname_validation_h

#ifndef OPENSSL_HOSTNAME_VALIDATION_LINKAGE
#define OPENSSL_HOSTNAME_VALIDATION_LINKAGE extern
#endif

typedef enum {
	MatchFound,
	MatchNotFound,
	NoSANPresent,
	MalformedCertificate,
	Error
} HostnameValidationResult;

/**
* Validates the server's identity by looking for the expected hostname in the
* server's certificate. As described in RFC 6125, it first tries to find a match
* in the Subject Alternative Name extension. If the extension is not present in
* the certificate, it checks the Common Name instead.
*
* Returns MatchFound if a match was found.
* Returns MatchNotFound if no matches were found.
* Returns MalformedCertificate if any of the hostnames had a NUL character embedded in it.
* Returns Error if there was an error.
*/
OPENSSL_HOSTNAME_VALIDATION_LINKAGE HostnameValidationResult validate_hostname(const char *hostname, const X509 *server_cert);

#endif
