#!/bin/sh
#	$OpenBSD: testdsa.sh,v 1.1 2014/08/26 17:50:07 jsing Exp $


#Test DSA certificate generation of openssl

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

# Generate DSA paramter set
$cmd dsaparam 512 -out dsa512.pem
if [ $? != 0 ]; then
        exit 1;
fi


# Denerate a DSA certificate
$cmd req -config $srcdir/openssl.cnf -x509 -newkey dsa:dsa512.pem -out testdsa.pem -keyout testdsa.key
if [ $? != 0 ]; then
        exit 1;
fi


# Now check the certificate
$cmd x509 -text -in testdsa.pem
if [ $? != 0 ]; then
        exit 1;
fi

rm testdsa.key dsa512.pem testdsa.pem

exit 0
