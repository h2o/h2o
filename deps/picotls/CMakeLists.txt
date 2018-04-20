CMAKE_MINIMUM_REQUIRED(VERSION 2.8.11)
CMAKE_POLICY(SET CMP0003 NEW)

PROJECT(picotls)

FIND_PACKAGE(PkgConfig REQUIRED)

SET(CMAKE_C_FLAGS "-std=c99 -Wall -O2 -g ${CC_WARNING_FLAGS} ${CMAKE_C_FLAGS}")
INCLUDE_DIRECTORIES(${OPENSSL_INCLUDE_DIR} deps/cifra/src/ext deps/cifra/src deps/micro-ecc deps/picotest include)
SET(MINICRYPTO_LIBRARY_FILES
    deps/micro-ecc/uECC.c
    deps/cifra/src/aes.c
    deps/cifra/src/blockwise.c
    deps/cifra/src/chacha20.c
    deps/cifra/src/chash.c
    deps/cifra/src/curve25519.c
    deps/cifra/src/drbg.c
    deps/cifra/src/hmac.c
    deps/cifra/src/gcm.c
    deps/cifra/src/gf128.c
    deps/cifra/src/modes.c
    deps/cifra/src/poly1305.c
    deps/cifra/src/sha256.c
    deps/cifra/src/sha512.c)

ADD_LIBRARY(picotls-core lib/picotls.c lib/pembase64.c)
ADD_LIBRARY(picotls-minicrypto ${MINICRYPTO_LIBRARY_FILES} lib/cifra.c lib/minicrypto-pem.c lib/uecc.c lib/asn1.c)
ADD_EXECUTABLE(test-minicrypto.t ${MINICRYPTO_LIBRARY_FILES} deps/picotest/picotest.c t/picotls.c t/minicrypto.c lib/asn1.c lib/pembase64.c)

SET(TEST_EXES test-minicrypto.t)

FIND_PACKAGE(OpenSSL)
IF (OPENSSL_FOUND AND NOT (OPENSSL_VERSION VERSION_LESS "1.0.1"))
    MESSAGE(WARNING "Enabling OpenSSL support")
    INCLUDE_DIRECTORIES(${OPENSSL_INCLUDE_DIR})
    ADD_LIBRARY(picotls-openssl lib/openssl.c)
    ADD_EXECUTABLE(cli t/cli.c lib/pembase64.c)
    TARGET_LINK_LIBRARIES(cli picotls-openssl picotls-core ${OPENSSL_LIBRARIES} ${CMAKE_DL_LIBS})
    ADD_EXECUTABLE(test-openssl.t ${MINICRYPTO_LIBRARY_FILES} lib/cifra.c lib/uecc.c lib/asn1.c lib/pembase64.c deps/picotest/picotest.c t/picotls.c t/openssl.c)
    SET_TARGET_PROPERTIES(test-openssl.t PROPERTIES COMPILE_FLAGS "-DPTLS_MEMORY_DEBUG=1")
    TARGET_LINK_LIBRARIES(test-openssl.t ${OPENSSL_LIBRARIES} ${CMAKE_DL_LIBS})
    SET(TEST_EXES ${TEST_EXES} test-openssl.t)
ELSE ()
    MESSAGE(WARNING "Disabling OpenSSL support (requires 1.0.1 or newer)")
ENDIF ()

ADD_CUSTOM_TARGET(check prove --exec '' -v ./*.t DEPENDS ${TEST_EXES})

IF ("${CMAKE_SYSTEM_NAME}" MATCHES "SunOS")
    TARGET_LINK_LIBRARIES(cli "socket" "nsl")
ENDIF ()
