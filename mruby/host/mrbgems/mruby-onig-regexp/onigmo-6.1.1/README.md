[![Build Status](https://travis-ci.org/k-takata/Onigmo.svg?branch=master)](https://travis-ci.org/k-takata/Onigmo)
[![Build status](https://ci.appveyor.com/api/projects/status/kndb924qaw1hq72i/branch/master?svg=true)](https://ci.appveyor.com/project/k-takata/onigmo/branch/master)
[![Coverage Status](https://coveralls.io/repos/k-takata/Onigmo/badge.svg?branch=master&service=github)](https://coveralls.io/github/k-takata/Onigmo?branch=master)
[![Coverity Scan Build Status](https://scan.coverity.com/projects/2778/badge.svg)](https://scan.coverity.com/projects/k-takata-onigmo)

Onigmo (Oniguruma-mod)
======================

https://github.com/k-takata/Onigmo

Onigmo is a regular expressions library forked from [Oniguruma](https://github.com/kkos/oniguruma).
It focuses to support new expressions like `\K`, `\R`, `(?(cond)yes|no)`
and etc. which are supported in Perl 5.10+.

Since Onigmo is used as the default regexp library of Ruby 2.0 or later,
many patches are backported from Ruby 2.x.

See also the Wiki page:
https://github.com/k-takata/Onigmo/wiki


License
-------

  BSD license.


Install
-------

### Case 1: Unix and Cygwin platform

   1. `./configure`
   2. `make`
   3. `make install`

   * test

        make test

   * uninstall

        make uninstall

   * configuration check

        onigmo-config --cflags
        onigmo-config --libs
        onigmo-config --prefix
        onigmo-config --exec-prefix


### Case 2: Windows 64/32bit platform (Visual C++)

   Execute `build_nmake.cmd`.
   `build_x64` or `build_x86` will be used as a working/output directory.

      onigmo_s.lib:  static link library
      onigmo.lib:    import library for dynamic link
      onigmo.dll:    dynamic link library

   * test (ASCII/Shift_JIS/EUC-JP/Unicode)

      Execute `build_nmake.cmd test`.
      Python (with the same bitness of Onigmo) is needed to run the tests.


### Case 3: Windows 64/32bit platform (MinGW)

   Execute `mingw32-make -f win32/Makefile.mingw`.
   `build_x86-64`, `build_i686` and etc. will be used as a working/output
   directory.

      libonigmo.a:     static link library
      libonigmo.dll.a: import library for dynamic link
      onigmo.dll:      dynamic link library

   * test (ASCII/Shift_JIS/EUC-JP/Unicode)

      Execute `mingw32-make -f win32/Makefile.mingw test`.
      Python (with the same bitness of Onigmo) is needed to run the tests.

   * If you use MinGW on MSYS2, you can also use `./configure` and `make`
     like Unix. In this case, DLL name will have API version number. E.g.:

        libonigmo-6.dll


Regular Expressions
-------------------

  See [doc/RE](doc/RE) or [doc/RE.ja](doc/RE.ja) for Japanese.


Usage
-----

  Include onigmo.h in your program. (Onigmo API)
  See [doc/API](doc/API) for Onigmo API.

  If you want to disable `UChar` type (== `unsigned char`) definition
  in onigmo.h, define `ONIG_ESCAPE_UCHAR_COLLISION` and then
  include onigmo.h.

  If you want to disable `regex_t` type definition in onigmo.h,
  define `ONIG_ESCAPE_REGEX_T_COLLISION` and then include onigmo.h.

  Example of the compiling/linking command line in Unix or Cygwin,
  (prefix == /usr/local case)

    cc sample.c -L/usr/local/lib -lonigmo


  If you want to use static link library (onigmo_s.lib) in Win32,
  add option `-DONIG_EXTERN=extern` to C compiler.



Sample Programs
---------------

|File                  |Description                               |
|:---------------------|:-----------------------------------------|
|sample/simple.c       |example of the minimum (Onigmo API)       |
|sample/names.c        |example of the named group callback.      |
|sample/encode.c       |example of some encodings.                |
|sample/listcap.c      |example of the capture history.           |
|sample/posix.c        |POSIX API sample.                         |
|sample/sql.c          |example of the variable meta characters.  |


Test Programs

|File               |Description                            |
|:------------------|:--------------------------------------|
|sample/syntax.c    |Perl, Java and ASIS syntax test.       |
|sample/crnl.c      |CRNL test                              |



Source Files
------------

|File                |Description                                            |
|:-------------------|:------------------------------------------------------|
|onigmo.h            |Onigmo API header file (public)                        |
|onigmo-config.in    |configuration check program template                   |
|onigmo.py           |Onigmo module for Python                               |
|regenc.h            |character encodings framework header file              |
|regint.h            |internal definitions                                   |
|regparse.h          |internal definitions for regparse.c and regcomp.c      |
|regcomp.c           |compiling and optimization functions                   |
|regenc.c            |character encodings framework                          |
|regerror.c          |error message function                                 |
|regext.c            |extended API functions (deluxe version API)            |
|regexec.c           |search and match functions                             |
|regparse.c          |parsing functions.                                     |
|regsyntax.c         |pattern syntax functions and built-in syntax definition|
|regtrav.c           |capture history tree data traverse functions           |
|regversion.c        |version info function                                  |
|st.h                |hash table functions header file                       |
|st.c                |hash table functions                                   |
|onigmognu.h         |GNU regex API header file (public)                     |
|reggnu.c            |GNU regex API functions                                |
|onigmoposix.h       |POSIX API header file (public)                         |
|regposerr.c         |POSIX error message function                           |
|regposix.c          |POSIX API functions                                    |
|enc/mktable.c       |character type table generator                         |
|enc/ascii.c         |ASCII-8BIT encoding                                    |
|enc/jis/            |JIS properties data                                    |
|enc/euc_jp.c        |EUC-JP encoding                                        |
|enc/euc_tw.c        |EUC-TW encoding                                        |
|enc/euc_kr.c        |EUC-KR, EUC-CN encoding                                |
|enc/shift_jis.c     |Shift_JIS encoding                                     |
|enc/windows_31j.c   |Windows-31J (CP932) encoding                           |
|enc/big5.c          |Big5      encoding                                     |
|enc/gb18030.c       |GB18030   encoding                                     |
|enc/gbk.c           |GBK       encoding                                     |
|enc/koi8_r.c        |KOI8-R    encoding                                     |
|enc/koi8_u.c        |KOI8-U    encoding                                     |
|enc/iso_8859.h      |common definition of ISO-8859 encoding                 |
|enc/iso_8859_1.c    |ISO-8859-1 (Latin-1)                                   |
|enc/iso_8859_2.c    |ISO-8859-2 (Latin-2)                                   |
|enc/iso_8859_3.c    |ISO-8859-3 (Latin-3)                                   |
|enc/iso_8859_4.c    |ISO-8859-4 (Latin-4)                                   |
|enc/iso_8859_5.c    |ISO-8859-5 (Cyrillic)                                  |
|enc/iso_8859_6.c    |ISO-8859-6 (Arabic)                                    |
|enc/iso_8859_7.c    |ISO-8859-7 (Greek)                                     |
|enc/iso_8859_8.c    |ISO-8859-8 (Hebrew)                                    |
|enc/iso_8859_9.c    |ISO-8859-9 (Latin-5 or Turkish)                        |
|enc/iso_8859_10.c   |ISO-8859-10 (Latin-6 or Nordic)                        |
|enc/iso_8859_11.c   |ISO-8859-11 (Thai)                                     |
|enc/iso_8859_13.c   |ISO-8859-13 (Latin-7 or Baltic Rim)                    |
|enc/iso_8859_14.c   |ISO-8859-14 (Latin-8 or Celtic)                        |
|enc/iso_8859_15.c   |ISO-8859-15 (Latin-9 or West European with Euro)       |
|enc/iso_8859_16.c   |ISO-8859-16 (Latin-10)                                 |
|enc/utf_8.c         |UTF-8    encoding                                      |
|enc/utf_16be.c      |UTF-16BE encoding                                      |
|enc/utf_16le.c      |UTF-16LE encoding                                      |
|enc/utf_32be.c      |UTF-32BE encoding                                      |
|enc/utf_32le.c      |UTF-32LE encoding                                      |
|enc/unicode.c       |common codes of Unicode encoding                       |
|enc/unicode/        |Unicode case folding data and properties data          |
|enc/windows_1250.c  |Windows-1250 (CP1250) encoding (Central/Eastern Europe)|
|enc/windows_1251.c  |Windows-1251 (CP1251) encoding (Cyrillic)              |
|enc/windows_1252.c  |Windows-1252 (CP1252) encoding (Latin)                 |
|enc/windows_1253.c  |Windows-1253 (CP1253) encoding (Greek)                 |
|enc/windows_1254.c  |Windows-1254 (CP1254) encoding (Turkish)               |
|enc/windows_1257.c  |Windows-1257 (CP1257) encoding (Baltic Rim)            |
|enc/cp949.c         |CP949 encoding          (only used in Ruby)            |
|enc/emacs_mule.c    |Emacs internal encoding (only used in Ruby)            |
|enc/gb2312.c        |GB2312 encoding         (only used in Ruby)            |
|enc/us_ascii.c      |US-ASCII encoding       (only used in Ruby)            |
|win32/Makefile      |Makefile for Win32 (VC++)                              |
|win32/Makefile.mingw|Makefile for Win32 (MinGW)                             |
|win32/config.h      |config.h for Win32                                     |
|win32/onigmo.rc     |resource file for Win32                                |
