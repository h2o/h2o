

Compiling PicoTLS with Visual Studio 2017

The source contains a Visual Studio 2017 solution (picotls/picotlsvs/picotlsvs.sln)
which itself contains 10 projects, including:

* picotls-core, building the core library
* picotls-openssl, the library for the open-ssl backend
* picotls-minicrypto, the library for the minicrypto backend
* picotls-minicrypto-deps, the dependencies for the minicrypto backend
* picotls-bcrypt, implementation of some crypto functions using Windows' bcrypt library
* picotls-fusion, for the AES fusion code

* A test project, testopenssl.exe, which will run on a console and
  execute the OpenSSL tests;

* And, an example project, picotlsvs.exe, which will perform a TLS exchange
  in memory, and demonstrate how to use PicoTLS in windows.

The example code has a dependency on OpenSSL. When building the 32 bit
projects (WIN32) it expects to find:

* OpenSSL header files under $(OPENSSLDIR)\include

* OpenSSL library libcrypto.lib under $(OPENSSLDIR)

When building the 64 bits projects (X64), it expects to find:

* OpenSSL header files under $(OPENSSL64DIR)\include

* OpenSSL library libcrypto.lib under $(OPENSSL64DIR)

You will need also to copy libcrypto.dll to the library that contains your
executable, or to otherwise register that library. Be sure to copy the 32 bit 
library or 64 bit library, depending on which type of project you build.

The integration tests with Appveyor check four configurarions: "X86 Debug",
"X86 Release", "X64 Debug" and "X64 Release".

Feel free to provide feedback and contribute.
