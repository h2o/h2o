include_directories(
	.
	../include
	../include/compat
	../crypto/modes
	../crypto/asn1
	../ssl
	../apps/openssl
	../apps/openssl/compat
)

# aeadtest
add_executable(aeadtest aeadtest.c)
target_link_libraries(aeadtest ${OPENSSL_LIBS})
add_test(aeadtest ${CMAKE_CURRENT_SOURCE_DIR}/aeadtest.sh)
set_tests_properties(aeadtest PROPERTIES ENVIRONMENT "srcdir=${CMAKE_CURRENT_SOURCE_DIR}")

# aes_wrap
add_executable(aes_wrap aes_wrap.c)
target_link_libraries(aes_wrap ${OPENSSL_LIBS})
add_test(aes_wrap aes_wrap)

# arc4randomforktest
# Windows/mingw does not have fork, but Cygwin does.
if(NOT CMAKE_HOST_WIN32 AND NOT CMAKE_SYSTEM_NAME MATCHES "MINGW")
add_executable(arc4randomforktest arc4randomforktest.c)
target_link_libraries(arc4randomforktest ${OPENSSL_LIBS})
add_test(arc4randomforktest ${CMAKE_CURRENT_SOURCE_DIR}/arc4randomforktest.sh)
endif()

# asn1test
add_executable(asn1test asn1test.c)
target_link_libraries(asn1test ${OPENSSL_LIBS})
add_test(asn1test asn1test)

# asn1time
add_executable(asn1time asn1time.c)
target_link_libraries(asn1time ${OPENSSL_LIBS})
add_test(asn1time asn1time)

# base64test
add_executable(base64test base64test.c)
target_link_libraries(base64test ${OPENSSL_LIBS})
add_test(base64test base64test)

# bftest
add_executable(bftest bftest.c)
target_link_libraries(bftest ${OPENSSL_LIBS})
add_test(bftest bftest)

# biotest
# the BIO tests rely on resolver results that are OS and environment-specific
if(ENABLE_EXTRATESTS)
	add_executable(biotest biotest.c)
	target_link_libraries(biotest ${OPENSSL_LIBS})
	add_test(biotest biotest)
endif()

# bntest
add_executable(bntest bntest.c)
target_link_libraries(bntest ${OPENSSL_LIBS})
add_test(bntest bntest)

# bytestringtest
add_executable(bytestringtest bytestringtest.c)
target_link_libraries(bytestringtest ${OPENSSL_LIBS})
add_test(bytestringtest bytestringtest)

# casttest
add_executable(casttest casttest.c)
target_link_libraries(casttest ${OPENSSL_LIBS})
add_test(casttest casttest)

# chachatest
add_executable(chachatest chachatest.c)
target_link_libraries(chachatest ${OPENSSL_LIBS})
add_test(chachatest chachatest)

# cipher_list
add_executable(cipher_list cipher_list.c)
target_link_libraries(cipher_list ${OPENSSL_LIBS})
add_test(cipher_list cipher_list)

# cipherstest
add_executable(cipherstest cipherstest.c)
target_link_libraries(cipherstest ${OPENSSL_LIBS})
add_test(cipherstest cipherstest)

# clienttest
add_executable(clienttest clienttest.c)
target_link_libraries(clienttest ${OPENSSL_LIBS})
add_test(clienttest clienttest)

# cts128test
add_executable(cts128test cts128test.c)
target_link_libraries(cts128test ${OPENSSL_LIBS})
add_test(cts128test cts128test)

# destest
add_executable(destest destest.c)
target_link_libraries(destest ${OPENSSL_LIBS})
add_test(destest destest)

# dhtest
add_executable(dhtest dhtest.c)
target_link_libraries(dhtest ${OPENSSL_LIBS})
add_test(dhtest dhtest)

# dsatest
add_executable(dsatest dsatest.c)
target_link_libraries(dsatest ${OPENSSL_LIBS})
add_test(dsatest dsatest)

# ecdhtest
add_executable(ecdhtest ecdhtest.c)
target_link_libraries(ecdhtest ${OPENSSL_LIBS})
add_test(ecdhtest ecdhtest)

# ecdsatest
add_executable(ecdsatest ecdsatest.c)
target_link_libraries(ecdsatest ${OPENSSL_LIBS})
add_test(ecdsatest ecdsatest)

# ectest
add_executable(ectest ectest.c)
target_link_libraries(ectest ${OPENSSL_LIBS})
add_test(ectest ectest)

# enginetest
add_executable(enginetest enginetest.c)
target_link_libraries(enginetest ${OPENSSL_LIBS})
add_test(enginetest enginetest)

# evptest
add_executable(evptest evptest.c)
target_link_libraries(evptest ${OPENSSL_LIBS})
add_test(evptest ${CMAKE_CURRENT_SOURCE_DIR}/evptest.sh)
set_tests_properties(evptest PROPERTIES ENVIRONMENT "srcdir=${CMAKE_CURRENT_SOURCE_DIR}")

# explicit_bzero
# explicit_bzero relies on SA_ONSTACK, which is unavailable on Windows
if(NOT CMAKE_HOST_WIN32)
if(HAVE_MEMMEM)
	add_executable(explicit_bzero explicit_bzero.c)
else()
	add_executable(explicit_bzero explicit_bzero.c memmem.c)
endif()
target_link_libraries(explicit_bzero ${OPENSSL_LIBS})
add_test(explicit_bzero explicit_bzero)
endif()

# exptest
add_executable(exptest exptest.c)
target_link_libraries(exptest ${OPENSSL_LIBS})
add_test(exptest exptest)

# gcm128test
add_executable(gcm128test gcm128test.c)
target_link_libraries(gcm128test ${OPENSSL_LIBS})
add_test(gcm128test gcm128test)

# gost2814789t
add_executable(gost2814789t gost2814789t.c)
target_link_libraries(gost2814789t ${OPENSSL_LIBS})
add_test(gost2814789t gost2814789t)

# hmactest
add_executable(hmactest hmactest.c)
target_link_libraries(hmactest ${OPENSSL_LIBS})
add_test(hmactest hmactest)

# ideatest
add_executable(ideatest ideatest.c)
target_link_libraries(ideatest ${OPENSSL_LIBS})
add_test(ideatest ideatest)

# igetest
add_executable(igetest igetest.c)
target_link_libraries(igetest ${OPENSSL_LIBS})
add_test(igetest igetest)

# md4test
add_executable(md4test md4test.c)
target_link_libraries(md4test ${OPENSSL_LIBS})
add_test(md4test md4test)

# md5test
add_executable(md5test md5test.c)
target_link_libraries(md5test ${OPENSSL_LIBS})
add_test(md5test md5test)

# mont
add_executable(mont mont.c)
target_link_libraries(mont ${OPENSSL_LIBS})
add_test(mont mont)

# ocsp_test
if(ENABLE_EXTRATESTS)
	if(NOT "${OPENSSLDIR}" STREQUAL "")
		add_definitions(-D_PATH_SSL_CA_FILE=\"${OPENSSLDIR}/cert.pem\")
	else()
		add_definitions(-D_PATH_SSL_CA_FILE=\"${CMAKE_INSTALL_PREFIX}/etc/ssl/cert.pem\")
	endif()
	add_executable(ocsp_test ocsp_test.c)
	target_link_libraries(ocsp_test ${OPENSSL_LIBS})
	add_test(ocsptest ${CMAKE_CURRENT_SOURCE_DIR}/ocsptest.sh)
	set_tests_properties(ocsptest PROPERTIES ENVIRONMENT "srcdir=${CMAKE_CURRENT_SOURCE_DIR}")
endif()

# optionstest
add_executable(optionstest optionstest.c)
target_link_libraries(optionstest ${OPENSSL_LIBS})
add_test(optionstest optionstest)

# pbkdf2
add_executable(pbkdf2 pbkdf2.c)
target_link_libraries(pbkdf2 ${OPENSSL_LIBS})
add_test(pbkdf2 pbkdf2)

# pidwraptest
# pidwraptest relies on an OS-specific way to give out pids and is generally
# awkward on systems with slow fork
if(ENABLE_EXTRATESTS)
	add_executable(pidwraptest pidwraptest.c)
	target_link_libraries(pidwraptest ${OPENSSL_LIBS})
	add_test(pidwraptest ${CMAKE_CURRENT_SOURCE_DIR}/pidwraptest.sh)
endif()

# pkcs7test
add_executable(pkcs7test pkcs7test.c)
target_link_libraries(pkcs7test ${OPENSSL_LIBS})
add_test(pkcs7test pkcs7test)

# poly1305test
add_executable(poly1305test poly1305test.c)
target_link_libraries(poly1305test ${OPENSSL_LIBS})
add_test(poly1305test poly1305test)

# pq_test
add_executable(pq_test pq_test.c)
target_link_libraries(pq_test ${OPENSSL_LIBS})
add_test(pq_test ${CMAKE_CURRENT_SOURCE_DIR}/pq_test.sh)
set_tests_properties(pq_test PROPERTIES ENVIRONMENT "srcdir=${CMAKE_CURRENT_SOURCE_DIR}")

# randtest
add_executable(randtest randtest.c)
target_link_libraries(randtest ${OPENSSL_LIBS})
add_test(randtest randtest)

# rc2test
add_executable(rc2test rc2test.c)
target_link_libraries(rc2test ${OPENSSL_LIBS})
add_test(rc2test rc2test)

# rc4test
add_executable(rc4test rc4test.c)
target_link_libraries(rc4test ${OPENSSL_LIBS})
add_test(rc4test rc4test)

# rfc5280time
add_executable(rfc5280time rfc5280time.c)
target_link_libraries(rfc5280time ${OPENSSL_LIBS})
if(SMALL_TIME_T)
	add_test(rfc5280time ${CMAKE_CURRENT_SOURCE_DIR}/rfc5280time_small.test)
else()
	add_test(rfc5280time rfc5280time)
endif()

# rmdtest
add_executable(rmdtest rmdtest.c)
target_link_libraries(rmdtest ${OPENSSL_LIBS})
add_test(rmdtest rmdtest)

# sha1test
add_executable(sha1test sha1test.c)
target_link_libraries(sha1test ${OPENSSL_LIBS})
add_test(sha1test sha1test)

# sha256test
add_executable(sha256test sha256test.c)
target_link_libraries(sha256test ${OPENSSL_LIBS})
add_test(sha256test sha256test)

# sha512test
add_executable(sha512test sha512test.c)
target_link_libraries(sha512test ${OPENSSL_LIBS})
add_test(sha512test sha512test)

# ssltest
add_executable(ssltest ssltest.c)
target_link_libraries(ssltest ${OPENSSL_LIBS})
add_test(ssltest ${CMAKE_CURRENT_SOURCE_DIR}/ssltest.sh)
set_tests_properties(ssltest PROPERTIES ENVIRONMENT "srcdir=${CMAKE_CURRENT_SOURCE_DIR}")

# testdsa
add_test(testdsa ${CMAKE_CURRENT_SOURCE_DIR}/testdsa.sh)
set_tests_properties(testdsa PROPERTIES ENVIRONMENT "srcdir=${CMAKE_CURRENT_SOURCE_DIR}")

# testenc
add_test(testenc ${CMAKE_CURRENT_SOURCE_DIR}/testenc.sh)
set_tests_properties(testenc PROPERTIES ENVIRONMENT "srcdir=${CMAKE_CURRENT_SOURCE_DIR}")

# testrsa
add_test(testrsa ${CMAKE_CURRENT_SOURCE_DIR}/testrsa.sh)
set_tests_properties(testrsa PROPERTIES ENVIRONMENT "srcdir=${CMAKE_CURRENT_SOURCE_DIR}")

# timingsafe
add_executable(timingsafe timingsafe.c)
target_link_libraries(timingsafe ${OPENSSL_LIBS})
add_test(timingsafe timingsafe)

# utf8test
add_executable(utf8test utf8test.c)
target_link_libraries(utf8test ${OPENSSL_LIBS})
add_test(utf8test utf8test)

# verifytest
add_executable(verifytest verifytest.c)
target_link_libraries(verifytest tls ${OPENSSL_LIBS})
add_test(verifytest verifytest)
