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
 

#include <strings.h>
#include <openssl/x509v3.h>
#include <openssl/ssl.h>

#include "openssl_hostname_validation.h"


#define HOSTNAME_MAX_SIZE 255

static int lowercase(int ch) {
	if ('A' <= ch && ch <= 'Z')
		return ch - 'A' + 'a';
	return ch;
}

static int memeq_ncase(const char *x, const char *y, size_t l) {
	if (l == 0)
		return 1;
	do {
		if (lowercase(*x++) != lowercase(*y++))
			return 0;
	} while (--l != 0);
	return 1;
}

static int has_nul(const char *s, size_t l) {
	if (l == 0)
		return 0;
	do {
		if (*s++ == '\0')
			return 1;
	} while (--l != 0);
	return 0;
}

static HostnameValidationResult validate_name(const char *hostname, ASN1_STRING *certname_asn1) {
#if (OPENSSL_VERSION_NUMBER >= 0x10100000L) && !defined(LIBRESSL_VERSION_NUMBER)
	char *certname_s = (char *) ASN1_STRING_get0_data(certname_asn1);
#else
	char *certname_s = (char *) ASN1_STRING_data(certname_asn1);
#endif
	int certname_len = ASN1_STRING_length(certname_asn1), hostname_len = strlen(hostname);

	// Make sure there isn't an embedded NUL character in the DNS name
	if (has_nul(certname_s, certname_len)) {
		return MalformedCertificate;
	}
	// remove last '.' from hostname
	if (hostname_len != 0 && hostname[hostname_len - 1] == '.')
		--hostname_len;
	// skip the first segment if wildcard
	if (certname_len > 2 && certname_s[0] == '*' && certname_s[1] == '.') {
		if (hostname_len != 0) {
			do {
				--hostname_len;
				if (*hostname++ == '.')
					break;
			} while (hostname_len != 0);
		}
		certname_s += 2;
		certname_len -= 2;
	}
	// Compare expected hostname with the DNS name
	if (certname_len != hostname_len) {
		return MatchNotFound;
	}
	return memeq_ncase(hostname, certname_s, hostname_len) ? MatchFound : MatchNotFound;
}

/**
* Tries to find a match for hostname in the certificate's Common Name field.
*
* Returns MatchFound if a match was found.
* Returns MatchNotFound if no matches were found.
* Returns MalformedCertificate if the Common Name had a NUL character embedded in it.
* Returns Error if the Common Name could not be extracted.
*/
static HostnameValidationResult matches_common_name(const char *hostname, const X509 *server_cert) {
	int common_name_loc = -1;
	X509_NAME_ENTRY *common_name_entry = NULL;
	ASN1_STRING *common_name_asn1 = NULL;

	// Find the position of the CN field in the Subject field of the certificate
	common_name_loc = X509_NAME_get_index_by_NID(X509_get_subject_name((X509 *) server_cert), NID_commonName, -1);
	if (common_name_loc < 0) {
		return Error;
	}

	// Extract the CN field
	common_name_entry = X509_NAME_get_entry(X509_get_subject_name((X509 *) server_cert), common_name_loc);
	if (common_name_entry == NULL) {
		return Error;
	}
	common_name_asn1 = X509_NAME_ENTRY_get_data(common_name_entry);
	if (common_name_asn1 == NULL) {
		return Error;
	}

	// validate the names
	return validate_name(hostname, common_name_asn1);
}


/**
* Tries to find a match for hostname in the certificate's Subject Alternative Name extension.
*
* Returns MatchFound if a match was found.
* Returns MatchNotFound if no matches were found.
* Returns MalformedCertificate if any of the hostnames had a NUL character embedded in it.
* Returns NoSANPresent if the SAN extension was not present in the certificate.
*/
static HostnameValidationResult matches_subject_alternative_name(const char *hostname, const X509 *server_cert) {
	HostnameValidationResult result = MatchNotFound;
	int i;
	int san_names_nb = -1;
	STACK_OF(GENERAL_NAME) *san_names = NULL;

	// Try to extract the names within the SAN extension from the certificate
	san_names = X509_get_ext_d2i((X509 *) server_cert, NID_subject_alt_name, NULL, NULL);
	if (san_names == NULL) {
		return NoSANPresent;
	}
	san_names_nb = sk_GENERAL_NAME_num(san_names);

	// Check each name within the extension
	for (i=0; i<san_names_nb; i++) {
		const GENERAL_NAME *current_name = sk_GENERAL_NAME_value(san_names, i);

		if (current_name->type == GEN_DNS) {
			// Current name is a DNS name, let's check it
			result = validate_name(hostname, current_name->d.dNSName);
			if (result != MatchNotFound) {
				break;
			}
		}
	}
	sk_GENERAL_NAME_pop_free(san_names, GENERAL_NAME_free);

	return result;
}


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
HostnameValidationResult validate_hostname(const char *hostname, const X509 *server_cert) {
	HostnameValidationResult result;

	if((hostname == NULL) || (server_cert == NULL))
		return Error;

	// First try the Subject Alternative Names extension
	result = matches_subject_alternative_name(hostname, server_cert);
	if (result == NoSANPresent) {
		// Extension was not found: try the Common Name
		result = matches_common_name(hostname, server_cert);
	}

	return result;
}
