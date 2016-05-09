The SSL Conservatory: OpenSSL Certificate Validation
====================================================

This sample code demonstrates how to perform certificate validation when using
the OpenSSL library to connect to an SSL/TLS server. It was tested on Windows
7, OS X and Linux.


Read The Whitepaper
-------------------

Before using this code, please read the white paper "Everything you've always
wanted to know about certificate validation with OpenSSL (but were afraid to
ask)" available at ./everything-you-wanted-to-know-about-openssl.pdf.


OS-Specific Instructions
------------------------

### Linux

The code was compiled and tested on Ubuntu 11.04.

You will have to install the libssl and libcrypto development libraries and
header files. In most Linux distros they are part of the "libssl-dev" package.


### OS X

The code was compiled and tested on OS X Mountain Lion.

OS X comes the OpenSSL development libraries pre-installed. However, libssl has
been modified by Apple to automatically use the system's trust store when
validating certificate chains; this behavior cannot be changed. Therefore,
specifying a trust store using SSL_CTX_load_verify_locations() will always be
ignored on OS X.

Additionally, compiling the code on OS X will generate a lot of "is
deprecated" warnings because Apple is migrating from OpenSSL to the Common
Crypto framework.


### Windows

The code was compiled using minGW and tested on Windows 7.

You will have to install minGW as well as the OpenSSL development libraries.
The OpenSSL project provides a link to pre-compiled libraries for Windows at
the following URL: http://www.openssl.org/related/binaries.html

If you used those binaries, here are additional instructions to compile the
sample code. First add the OpenSSL headers and libraries to MinGW:

    Copy <OpenSSL_Folder>/include/ to <MinGW_Folder>/include/
    Copy <OpenSSL_Folder>/libeay32.dll to <MinGW_Folder>/lib/libeay32.dll
    Copy <OpenSSL_Folder>/libssl32.dll to <MinGW_Folder>/lib/libssl32.dll

Then compile the test_client: 

    make -f Makefile_mingw

