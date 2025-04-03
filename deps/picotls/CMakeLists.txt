CMAKE_MINIMUM_REQUIRED(VERSION 2.8.12)
CMAKE_POLICY(SET CMP0003 NEW)

PROJECT(picotls)

IF (CMAKE_VERSION VERSION_LESS 3.13.0)
  MACRO (TARGET_LINK_DIRECTORIES target scope)
    link_directories(${ARGN})
  ENDMACRO ()
ENDIF ()

FIND_PACKAGE(PkgConfig REQUIRED)
INCLUDE(cmake/boringssl-adjust.cmake)
INCLUDE(cmake/dtrace-utils.cmake)
INCLUDE(cmake/fusion.cmake)
SET(CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake")

CHECK_DTRACE(${PROJECT_SOURCE_DIR}/picotls-probes.d)
CHECK_FUSION_PREREQUISITES()

OPTION(WITH_DTRACE "use USDT (userspace Dtrace probes)" ${HAVE_DTRACE})
OPTION(WITH_FUSION "build 'fusion' AES-GCM engine" ${WITH_FUSION_DEFAULT})
IF (WITH_DTRACE)
    MESSAGE(STATUS "Enabling USDT support")
ENDIF ()
IF (WITH_FUSION)
    MESSAGE(STATUS "Enabling 'fusion' AES-GCM engine")
ENDIF ()
OPTION(WITH_AEGIS "enable AEGIS (requires libaegis)" ${WITH_AEGIS})
OPTION(WITH_MBEDTLS "enable MBEDTLS" ${WITH_MBEDTLS})

SET(CMAKE_C_FLAGS "-std=c99 -Wall -O2 -g ${CC_WARNING_FLAGS} ${CMAKE_C_FLAGS}")
INCLUDE_DIRECTORIES(
    deps/cifra/src/ext
    deps/cifra/src
    deps/micro-ecc
    deps/picotest
    include
    ${CMAKE_CURRENT_BINARY_DIR})
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
SET(CORE_FILES
    lib/hpke.c
    lib/picotls.c
    lib/pembase64.c)
SET(CORE_TEST_FILES
    t/hpke.c
    t/picotls.c)
IF (WITH_DTRACE)
    SET(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -DPICOTLS_USE_DTRACE=1")
    DEFINE_DTRACE_DEPENDENCIES(${PROJECT_SOURCE_DIR}/picotls-probes.d picotls)
    LIST(APPEND CORE_FILES ${CMAKE_CURRENT_BINARY_DIR}/picotls-probes.h)
    LIST(APPEND CORE_TEST_FILES ${CMAKE_CURRENT_BINARY_DIR}/picotls-probes.h)
    IF (DTRACE_USES_OBJFILE)
        LIST(APPEND CORE_FILES ${CMAKE_CURRENT_BINARY_DIR}/picotls-probes.o)
        LIST(APPEND CORE_TEST_FILES ${CMAKE_CURRENT_BINARY_DIR}/picotls-probes.o)
    ENDIF ()
ENDIF ()

PKG_CHECK_MODULES(BROTLI_DEC libbrotlidec)
PKG_CHECK_MODULES(BROTLI_ENC libbrotlienc)
IF (BROTLI_DEC_FOUND AND BROTLI_ENC_FOUND)
    INCLUDE_DIRECTORIES(${BROTLI_DEC_INCLUDE_DIRS} ${BROTLI_ENC_INCLUDE_DIRS})
    SET(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -DPICOTLS_USE_BROTLI=1")
    LIST(APPEND CORE_FILES
        lib/certificate_compression.c)
    LIST(APPEND CORE_EXTRA_LIBS ${BROTLI_DEC_LIBRARIES} ${BROTLI_ENC_LIBRARIES})
    LIST(APPEND CORE_EXTRA_LIBS_DIRS (${BROTLI_DEC_LIBRARY_DIRS} ${BROTLI_ENC_LIBRARY_DIRS}))
ENDIF ()

ADD_LIBRARY(picotls-core ${CORE_FILES})
TARGET_LINK_LIBRARIES(picotls-core ${CORE_EXTRA_LIBS})
TARGET_LINK_DIRECTORIES(picotls-core PUBLIC ${CORE_EXTRA_LIBS_DIRS})

IF (WITH_AEGIS)
    SET(MINICRYPTO_AEGIS_FILES lib/cifra/libaegis.c)
ENDIF ()

ADD_LIBRARY(picotls-minicrypto
    ${MINICRYPTO_LIBRARY_FILES}
    ${MINICRYPTO_AEGIS_FILES}
    lib/cifra.c
    lib/cifra/x25519.c
    lib/cifra/chacha20.c
    lib/cifra/aes128.c
    lib/cifra/aes256.c
    lib/cifra/random.c
    lib/minicrypto-pem.c
    lib/uecc.c
    lib/asn1.c
    lib/ffx.c)
TARGET_LINK_LIBRARIES(picotls-minicrypto picotls-core)
ADD_EXECUTABLE(test-minicrypto.t
    ${MINICRYPTO_LIBRARY_FILES}
    ${MINICRYPTO_AEGIS_FILES}
    deps/picotest/picotest.c
    ${CORE_TEST_FILES}
    t/minicrypto.c
    lib/asn1.c
    lib/pembase64.c
    lib/ffx.c
    lib/cifra/x25519.c
    lib/cifra/chacha20.c
    lib/cifra/aes128.c
    lib/cifra/aes256.c
    lib/cifra/random.c)
SET(TEST_EXES test-minicrypto.t)


SET(PTLSBENCH_LIBS
    picotls-minicrypto picotls-core)

IF (WITH_AEGIS)
  FIND_PACKAGE(aegis)
  IF (aegis_FOUND)
    INCLUDE_DIRECTORIES(${AEGIS_INCLUDE_DIR})
    IF (EXISTS "${AEGIS_INCLUDE_DIR}/aegis.h")
      MESSAGE(STATUS "Enabling AEGIS support (library found in ${aegis_DIR})")
      SET(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -DPTLS_HAVE_AEGIS=1")
      SET(AEGIS_LIBRARIES ${aegis_LIBRARIES})
      TARGET_LINK_LIBRARIES(test-minicrypto.t ${AEGIS_LIBRARIES})
    ELSE()
      MESSAGE(FATAL_ERROR "libaegis found, but aegis.h not found - Define AEGIS_INCLUDE_DIR accordingly")
    ENDIF()
  ELSE()
    MESSAGE(FATAL_ERROR "libaegis not found")
  ENDIF()
ENDIF()

FIND_PACKAGE(OpenSSL)
BORINGSSL_ADJUST()

IF (OPENSSL_FOUND AND NOT (OPENSSL_VERSION VERSION_LESS "1.0.1"))
    MESSAGE(STATUS "  Enabling OpenSSL support")
    INCLUDE_DIRECTORIES(${OPENSSL_INCLUDE_DIR})
    ADD_LIBRARY(picotls-openssl lib/openssl.c)
    TARGET_LINK_LIBRARIES(picotls-openssl ${OPENSSL_CRYPTO_LIBRARIES} ${AEGIS_LIBRARIES} picotls-core ${CMAKE_DL_LIBS})
    ADD_EXECUTABLE(cli t/cli.c lib/pembase64.c)
    TARGET_LINK_LIBRARIES(cli picotls-openssl picotls-core)

    ADD_EXECUTABLE(test-openssl.t
        ${MINICRYPTO_LIBRARY_FILES}
        ${MINICRYPTO_AEGIS_FILES}
        lib/cifra.c
        lib/cifra/x25519.c
        lib/cifra/chacha20.c
        lib/cifra/aes128.c
        lib/cifra/aes256.c
        lib/cifra/random.c
        lib/uecc.c
        lib/asn1.c
        lib/pembase64.c
        lib/ffx.c
        deps/picotest/picotest.c
        ${CORE_TEST_FILES}
        t/openssl.c)
    SET_TARGET_PROPERTIES(test-openssl.t PROPERTIES COMPILE_FLAGS "-DPTLS_MEMORY_DEBUG=1")
    TARGET_LINK_LIBRARIES(test-openssl.t ${OPENSSL_CRYPTO_LIBRARIES} ${AEGIS_LIBRARIES} ${CMAKE_DL_LIBS})

    LIST(APPEND PTLSBENCH_LIBS picotls-openssl ${OPENSSL_CRYPTO_LIBRARIES} ${AEGIS_LIBRARIES} ${CMAKE_DL_LIBS})

    SET(TEST_EXES ${TEST_EXES} test-openssl.t)
ELSE ()
    MESSAGE(WARNING "Disabling OpenSSL support (requires 1.0.1 or newer)")
ENDIF ()

IF (WITH_FUSION)
    ADD_LIBRARY(picotls-fusion lib/fusion.c)
    SET_TARGET_PROPERTIES(picotls-fusion PROPERTIES COMPILE_FLAGS "-mavx2 -maes -mpclmul -mvaes -mvpclmulqdq")
    TARGET_LINK_LIBRARIES(picotls-fusion picotls-core)
    ADD_EXECUTABLE(test-fusion.t
        deps/picotest/picotest.c
        lib/picotls.c
        t/fusion.c)
    TARGET_LINK_LIBRARIES(test-fusion.t picotls-minicrypto)
    SET_TARGET_PROPERTIES(test-fusion.t PROPERTIES COMPILE_FLAGS "-mavx2 -maes -mpclmul -mvaes -mvpclmulqdq")
    IF (WITH_DTRACE)
        ADD_DEPENDENCIES(test-fusion.t generate-picotls-probes)
    ENDIF ()
    SET(TEST_EXES ${TEST_EXES} test-fusion.t)

    SET(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -DPTLS_HAVE_FUSION=1")
    LIST(APPEND PTLSBENCH_LIBS picotls-fusion)
ENDIF ()

IF (WITH_MBEDTLS)
    FIND_PACKAGE(MbedTLS)
    IF (NOT MbedTLS_FOUND)
        MESSAGE(FATAL_ERROR "-DWITH_MBEDTLS set but mbedtls not found")
    ENDIF ()
    message(STATUS "mbedtls/include: ${MBEDTLS_INCLUDE_DIRS}")
    message(STATUS "mbedtls libraries: ${MBEDTLS_LIBRARIES}")
    INCLUDE_DIRECTORIES(${MBEDTLS_INCLUDE_DIRS})
    ADD_LIBRARY(picotls-mbedtls lib/mbedtls.c lib/mbedtls_sign.c)
    ADD_EXECUTABLE(test-mbedtls.t
        deps/picotest/picotest.c
        ${CORE_TEST_FILES}
        t/mbedtls.c)
    TARGET_LINK_LIBRARIES(test-mbedtls.t
        picotls-minicrypto picotls-mbedtls
        ${MBEDTLS_LIBRARIES})
    SET(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -DPTLS_HAVE_MBEDTLS=1")
    LIST(APPEND PTLSBENCH_LIBS picotls-mbedtls ${MBEDTLS_LIBRARIES})
ENDIF ()

ADD_EXECUTABLE(ptlsbench t/ptlsbench.c)
SET_TARGET_PROPERTIES(ptlsbench PROPERTIES COMPILE_FLAGS "-DPTLS_MEMORY_DEBUG=1")
TARGET_LINK_LIBRARIES(ptlsbench ${PTLSBENCH_LIBS})
IF (NOT WITH_FUSION)
    SET_TARGET_PROPERTIES(ptlsbench PROPERTIES EXCLUDE_FROM_ALL 1)
ENDIF ()

ADD_CUSTOM_TARGET(check env BINARY_DIR=${CMAKE_CURRENT_BINARY_DIR} prove --exec '' -v ${CMAKE_CURRENT_BINARY_DIR}/*.t t/*.t WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR} DEPENDS ${TEST_EXES} cli)

IF (CMAKE_SYSTEM_NAME STREQUAL "Linux")
     SET(CMAKE_C_FLAGS "-D_GNU_SOURCE -pthread ${CMAKE_C_FLAGS}")
ELSEIF ("${CMAKE_SYSTEM_NAME}" MATCHES "SunOS")
    TARGET_LINK_LIBRARIES(cli "socket" "nsl")
ENDIF ()

FIND_LIBRARY(LIBC_RESOLV_LIB "resolv")
IF (OPENSSL_FOUND AND LIBC_RESOLV_LIB)
    TARGET_LINK_LIBRARIES(cli ${LIBC_RESOLV_LIB})
ENDIF ()

IF (BUILD_FUZZER)
    IF (NOT CMAKE_CXX_COMPILER_ID STREQUAL "Clang")
        MESSAGE(FATAL_ERROR "The fuzzer needs clang as a compiler")
    ENDIF()

    ADD_EXECUTABLE(fuzz-asn1 fuzz/fuzz-asn1.c)
    SET(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -D_GNU_SOURCE")
    INCLUDE_DIRECTORIES(t include ${OPENSSL_INCLUDE_DIR})
    ADD_DEFINITIONS(-DPTLS_FUZZ_HANDSHAKE=1)
    ADD_EXECUTABLE(fuzz-server-hello fuzz/fuzz-server-hello.c)
    ADD_EXECUTABLE(fuzz-client-hello fuzz/fuzz-client-hello.c)

    IF (OSS_FUZZ)
        # Use https://github.com/google/oss-fuzz compatible options
        SET(LIB_FUZZER FuzzingEngine)
        SET_TARGET_PROPERTIES(fuzz-asn1
            fuzz-server-hello
            fuzz-client-hello
            PROPERTIES
            LINKER_LANGUAGE CXX)
    ELSE()
        SET(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fsanitize=fuzzer-no-link")
        SET(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fsanitize=fuzzer-no-link")
        SET_TARGET_PROPERTIES(fuzz-asn1
            fuzz-server-hello
            fuzz-client-hello
            PROPERTIES
            COMPILE_FLAGS "-fsanitize=fuzzer"
            LINK_FLAGS "-fsanitize=fuzzer")
    ENDIF (OSS_FUZZ)

    TARGET_LINK_LIBRARIES(fuzz-asn1 picotls-minicrypto picotls-core picotls-openssl ${OPENSSL_CRYPTO_LIBRARIES} ${AEGIS_LIBRARIES} ${LIB_FUZZER})
    TARGET_LINK_LIBRARIES(fuzz-server-hello picotls-core picotls-openssl ${OPENSSL_CRYPTO_LIBRARIES} ${AEGIS_LIBRARIES} ${LIB_FUZZER})
    TARGET_LINK_LIBRARIES(fuzz-client-hello picotls-core picotls-openssl ${OPENSSL_CRYPTO_LIBRARIES} ${AEGIS_LIBRARIES} ${LIB_FUZZER})

ENDIF()
