#!/bin/sh
#	$OpenBSD: testrsa.sh,v 1.1 2014/08/26 17:50:07 jsing Exp $


#Test RSA certificate generation of openssl

if [ -d ../apps/openssl ]; then
	cmd=../apps/openssl/openssl
	if [ -e ../apps/openssl/openssl.exe ]; then
		cmd=../apps/openssl/openssl.exe
	fi
else
	cmd=../apps/openssl
	if [ -e ../apps/openssl.exe ]; then
		cmd=../apps/openssl.exe
	fi
fi

if [ -z $srcdir ]; then
	srcdir=.
fi

# Generate RSA private key
$cmd genrsa -out rsakey.pem
if [ $? != 0 ]; then
        exit 1;
fi


# Generate an RSA certificate
$cmd req -config $srcdir/openssl.cnf -key rsakey.pem -new -x509 -days 365 -out rsacert.pem
if [ $? != 0 ]; then
        exit 1;
fi


# Now check the certificate
$cmd x509 -text -in rsacert.pem
if [ $? != 0 ]; then
        exit 1;
fi

rm -f rsacert.pem rsakey.pem

exit 0
