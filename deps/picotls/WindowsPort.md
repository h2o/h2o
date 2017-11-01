Compiling PicoTLS with Visual Studio 2017

The source contains a Visual Studio 2017 solution (picotls/picotlsvs/picotlsvs.sln)
which itself contains 5 projects:

* Three libraries, picotls.lib and its dependencies cifra.lib and uecc.lib;

* A test project, testopenssl.exe, which will run on a console and
  execute the OpenSSL tests;

* And, an example project, picotlsvs.exe, which will perform a TLS exchange
  in memory, and demonstrate how to use PicoTLS in windows.

The code has a dependency on OpenSSL. It expect to find:

* OpenSSL header files under $(OPENSSLDIR)\include

* OpenSSL library libcrypto.lib under $(OPENSSLDIR)

You will need also to copy libcrypto.dll to the library that contains your
executable, or to otherwise register that library.

Only two configurations are tested: "X86 Debug" and "X86 Release".
Feel free to provide feedback and contribute.
