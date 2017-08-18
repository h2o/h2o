include $(top_srcdir)/Makefile.am.common

AM_CPPFLAGS += -I $(top_srcdir)/crypto/modes
AM_CPPFLAGS += -I $(top_srcdir)/crypto/asn1
AM_CPPFLAGS += -I $(top_srcdir)/ssl
AM_CPPFLAGS += -I $(top_srcdir)/apps/openssl
AM_CPPFLAGS += -I $(top_srcdir)/apps/openssl/compat

LDADD = $(PLATFORM_LDADD) $(PROG_LDADD)
LDADD += $(abs_top_builddir)/ssl/libssl.la
LDADD += $(abs_top_builddir)/crypto/libcrypto.la
LDADD += $(abs_top_builddir)/tls/libtls.la

TEST_LOG_DRIVER = env AM_TAP_AWK='$(AWK)' $(SHELL) $(top_srcdir)/tap-driver.sh

TESTS =
check_PROGRAMS =
EXTRA_DIST = CMakeLists.txt
DISTCLEANFILES = pidwraptest.txt

# aeadtest
TESTS += aeadtest.sh
check_PROGRAMS += aeadtest
aeadtest_SOURCES = aeadtest.c
EXTRA_DIST += aeadtest.sh
EXTRA_DIST += aeadtests.txt

# aes_wrap
TESTS += aes_wrap
check_PROGRAMS += aes_wrap
aes_wrap_SOURCES = aes_wrap.c

# arc4randomforktest
# Windows/mingw does not have fork, but Cygwin does.
if !HOST_WIN
TESTS += arc4randomforktest.sh
check_PROGRAMS += arc4randomforktest
arc4randomforktest_SOURCES = arc4randomforktest.c
endif
EXTRA_DIST += arc4randomforktest.sh

# asn1test
TESTS += asn1test
check_PROGRAMS += asn1test
asn1test_SOURCES = asn1test.c

# asn1time
TESTS += asn1time
check_PROGRAMS += asn1time
asn1time_SOURCES = asn1time.c

# base64test
TESTS += base64test
check_PROGRAMS += base64test
base64test_SOURCES = base64test.c

# bftest
TESTS += bftest
check_PROGRAMS += bftest
bftest_SOURCES = bftest.c

# biotest
# the BIO tests rely on resolver results that are OS and environment-specific
if ENABLE_EXTRATESTS
TESTS += biotest
check_PROGRAMS += biotest
biotest_SOURCES = biotest.c
endif

# bntest
TESTS += bntest
check_PROGRAMS += bntest
bntest_SOURCES = bntest.c

# bytestringtest
TESTS += bytestringtest
check_PROGRAMS += bytestringtest
bytestringtest_SOURCES = bytestringtest.c

# casttest
TESTS += casttest
check_PROGRAMS += casttest
casttest_SOURCES = casttest.c

# chachatest
TESTS += chachatest
check_PROGRAMS += chachatest
chachatest_SOURCES = chachatest.c

# cipher_list
TESTS += cipher_list
check_PROGRAMS += cipher_list
cipher_list_SOURCES = cipher_list.c
noinst_HEADERS = tests.h

# cipherstest
TESTS += cipherstest
check_PROGRAMS += cipherstest
cipherstest_SOURCES = cipherstest.c

# clienttest
TESTS += clienttest
check_PROGRAMS += clienttest
clienttest_SOURCES = clienttest.c

# cts128test
TESTS += cts128test
check_PROGRAMS += cts128test
cts128test_SOURCES = cts128test.c

# destest
TESTS += destest
check_PROGRAMS += destest
destest_SOURCES = destest.c

# dhtest
TESTS += dhtest
check_PROGRAMS += dhtest
dhtest_SOURCES = dhtest.c

# dsatest
TESTS += dsatest
check_PROGRAMS += dsatest
dsatest_SOURCES = dsatest.c

# ecdhtest
TESTS += ecdhtest
check_PROGRAMS += ecdhtest
ecdhtest_SOURCES = ecdhtest.c

# ecdsatest
TESTS += ecdsatest
check_PROGRAMS += ecdsatest
ecdsatest_SOURCES = ecdsatest.c

# ectest
TESTS += ectest
check_PROGRAMS += ectest
ectest_SOURCES = ectest.c

# enginetest
TESTS += enginetest
check_PROGRAMS += enginetest
enginetest_SOURCES = enginetest.c

# evptest
TESTS += evptest.sh
check_PROGRAMS += evptest
evptest_SOURCES = evptest.c
EXTRA_DIST += evptest.sh
EXTRA_DIST += evptests.txt

# explicit_bzero
# explicit_bzero relies on SA_ONSTACK, which is unavailable on Windows
if !HOST_WIN
if !HOST_CYGWIN
TESTS += explicit_bzero
check_PROGRAMS += explicit_bzero
explicit_bzero_SOURCES = explicit_bzero.c
if !HAVE_MEMMEM
explicit_bzero_SOURCES += memmem.c
endif
endif
endif

# exptest
TESTS += exptest
check_PROGRAMS += exptest
exptest_SOURCES = exptest.c

# gcm128test
TESTS += gcm128test
check_PROGRAMS += gcm128test
gcm128test_SOURCES = gcm128test.c

# gost2814789t
TESTS += gost2814789t
check_PROGRAMS += gost2814789t
gost2814789t_SOURCES = gost2814789t.c

# hmactest
TESTS += hmactest
check_PROGRAMS += hmactest
hmactest_SOURCES = hmactest.c

# ideatest
TESTS += ideatest
check_PROGRAMS += ideatest
ideatest_SOURCES = ideatest.c

# igetest
TESTS += igetest
check_PROGRAMS += igetest
igetest_SOURCES = igetest.c

# md4test
TESTS += md4test
check_PROGRAMS += md4test
md4test_SOURCES = md4test.c

# md5test
TESTS += md5test
check_PROGRAMS += md5test
md5test_SOURCES = md5test.c

# mont
TESTS += mont
check_PROGRAMS += mont
mont_SOURCES = mont.c

# ocsp_test
if ENABLE_EXTRATESTS
TESTS += ocsptest.sh
check_PROGRAMS += ocsp_test
ocsp_test_SOURCES = ocsp_test.c
endif
EXTRA_DIST += ocsptest.sh

# optionstest
TESTS += optionstest
check_PROGRAMS += optionstest
optionstest_SOURCES = optionstest.c

# pbkdf2
TESTS += pbkdf2
check_PROGRAMS += pbkdf2
pbkdf2_SOURCES = pbkdf2.c

# pidwraptest
# pidwraptest relies on an OS-specific way to give out pids and is generally
# awkward on systems with slow fork
if ENABLE_EXTRATESTS
TESTS += pidwraptest.sh
check_PROGRAMS += pidwraptest
pidwraptest_SOURCES = pidwraptest.c
endif
EXTRA_DIST += pidwraptest.sh

# pkcs7test
TESTS += pkcs7test
check_PROGRAMS += pkcs7test
pkcs7test_SOURCES = pkcs7test.c

# poly1305test
TESTS += poly1305test
check_PROGRAMS += poly1305test
poly1305test_SOURCES = poly1305test.c

# pq_test
TESTS += pq_test.sh
check_PROGRAMS += pq_test
pq_test_SOURCES = pq_test.c
EXTRA_DIST += pq_test.sh
EXTRA_DIST += pq_expected.txt

# randtest
TESTS += randtest
check_PROGRAMS += randtest
randtest_SOURCES = randtest.c

# rc2test
TESTS += rc2test
check_PROGRAMS += rc2test
rc2test_SOURCES = rc2test.c

# rc4test
TESTS += rc4test
check_PROGRAMS += rc4test
rc4test_SOURCES = rc4test.c

# rfc5280time
check_PROGRAMS += rfc5280time
rfc5280time_SOURCES = rfc5280time.c
if SMALL_TIME_T
TESTS += rfc5280time_small.test
else
TESTS += rfc5280time
endif
EXTRA_DIST += rfc5280time_small.test

# rmdtest
TESTS += rmdtest
check_PROGRAMS += rmdtest
rmdtest_SOURCES = rmdtest.c

# sha1test
TESTS += sha1test
check_PROGRAMS += sha1test
sha1test_SOURCES = sha1test.c

# sha256test
TESTS += sha256test
check_PROGRAMS += sha256test
sha256test_SOURCES = sha256test.c

# sha512test
TESTS += sha512test
check_PROGRAMS += sha512test
sha512test_SOURCES = sha512test.c

# ssltest
TESTS += ssltest.sh
check_PROGRAMS += ssltest
ssltest_SOURCES = ssltest.c
EXTRA_DIST += ssltest.sh
EXTRA_DIST += testssl ca.pem server.pem

# testdsa
TESTS += testdsa.sh
EXTRA_DIST += testdsa.sh
EXTRA_DIST += openssl.cnf

# testenc
TESTS += testenc.sh
EXTRA_DIST += testenc.sh

# testrsa
TESTS += testrsa.sh
EXTRA_DIST += testrsa.sh

# timingsafe
TESTS += timingsafe
check_PROGRAMS += timingsafe
timingsafe_SOURCES = timingsafe.c

# utf8test
TESTS += utf8test
check_PROGRAMS += utf8test
utf8test_SOURCES = utf8test.c

# verifytest
TESTS += verifytest
check_PROGRAMS += verifytest
verifytest_SOURCES = verifytest.c
