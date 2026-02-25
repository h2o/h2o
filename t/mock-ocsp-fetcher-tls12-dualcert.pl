#!/usr/bin/env perl
# Mock OCSP fetcher for TLS 1.2 dual cert OCSP stapling tests
# Reads certificate chain from stdin, outputs distinct signature based on cert type

use strict;
use warnings;
use File::Temp qw(tempfile);

# Read certificate chain from stdin
my $cert_chain = do { local $/; <STDIN> };

# Write cert to temp file for inspection
my ($fh, $tempfn) = tempfile(UNLINK => 1);
print $fh $cert_chain;
close $fh;

# Use openssl to determine the public key algorithm
my $algo = `openssl x509 -in $tempfn -noout -text 2>/dev/null | grep "Public Key Algorithm"`;
chomp $algo;

my $cert_type;
if ($algo =~ /id-ecPublicKey/i || $algo =~ /prime256v1/i || $algo =~ /EC/i) {
    $cert_type = 'ecdsa';
} elsif ($algo =~ /rsaEncryption/i || $algo =~ /RSA/i) {
    $cert_type = 'rsa';
} else {
    $cert_type = 'unknown';
}

# Output distinct, identifiable OCSP response
if ($cert_type eq 'ecdsa') {
    print "FAKE_OCSP_ECDSA_RESP_TLS12_DUALCERT";
} elsif ($cert_type eq 'rsa') {
    print "FAKE_OCSP_RSA_RESP_TLS12_DUALCERT";
} else {
    print "FAKE_OCSP_UNKNOWN_RESP_TLS12_DUALCERT";
}

exit 0;