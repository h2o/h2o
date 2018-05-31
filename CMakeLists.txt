# Copyright (c) 2014,2015 DeNA Co., Ltd., Kazuho Oku, Brian Stanback, Laurentiu Nicola, Masanori Ogino, Ryosuke Matsumoto,
#                         David Carlier
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to
# deal in the Software without restriction, including without limitation the
# rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
# sell copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
# FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
# IN THE SOFTWARE.

CMAKE_MINIMUM_REQUIRED(VERSION 2.8.11)
CMAKE_POLICY(SET CMP0003 NEW)

PROJECT(h2o)

SET(VERSION_MAJOR "2")
SET(VERSION_MINOR "2")
SET(VERSION_PATCH "5")
SET(VERSION_PRERELEASE "")
SET(VERSION "${VERSION_MAJOR}.${VERSION_MINOR}.${VERSION_PATCH}${VERSION_PRERELEASE}")
SET(LIBRARY_VERSION_MAJOR "0")
SET(LIBRARY_VERSION_MINOR "13")
SET(LIBRARY_VERSION_PATCH "5")
SET(LIBRARY_VERSION "${LIBRARY_VERSION_MAJOR}.${LIBRARY_VERSION_MINOR}.${LIBRARY_VERSION_PATCH}${VERSION_PRERELEASE}")
SET(LIBRARY_SOVERSION "${LIBRARY_VERSION_MAJOR}.${LIBRARY_VERSION_MINOR}")

INCLUDE(GNUInstallDirs)

CONFIGURE_FILE(${CMAKE_CURRENT_SOURCE_DIR}/version.h.in ${CMAKE_CURRENT_SOURCE_DIR}/include/h2o/version.h)
CONFIGURE_FILE(${CMAKE_CURRENT_SOURCE_DIR}/libh2o.pc.in ${CMAKE_CURRENT_BINARY_DIR}/libh2o.pc @ONLY)
CONFIGURE_FILE(${CMAKE_CURRENT_SOURCE_DIR}/libh2o-evloop.pc.in ${CMAKE_CURRENT_BINARY_DIR}/libh2o-evloop.pc @ONLY)

SET(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} ${CMAKE_CURRENT_SOURCE_DIR}/cmake)

FIND_PACKAGE(PkgConfig)
FIND_PACKAGE(Threads REQUIRED)

FIND_PACKAGE(OpenSSL)
FIND_PACKAGE(ZLIB REQUIRED)

INCLUDE(CheckCSourceCompiles)
CHECK_C_SOURCE_COMPILES("
#include <stdint.h>
int main(void) {
uint64_t a;
__sync_add_and_fetch(&a, 1);
return 0;
}" ARCH_SUPPORTS_64BIT_ATOMICS)

SET(WITH_BUNDLED_SSL_DEFAULT "ON")
IF ((NOT UNIX) OR CYGWIN)
    SET(WITH_BUNDLED_SSL_DEFAULT "OFF")
ENDIF ((NOT UNIX) OR CYGWIN)
IF (OPENSSL_FOUND AND NOT (OPENSSL_VERSION VERSION_LESS "1.0.2"))
    SET(WITH_BUNDLED_SSL_DEFAULT "OFF")
ENDIF (OPENSSL_FOUND AND NOT (OPENSSL_VERSION VERSION_LESS "1.0.2"))
OPTION(WITH_BUNDLED_SSL "whether or not to use the bundled libressl" ${WITH_BUNDLED_SSL_DEFAULT})

OPTION(WITHOUT_LIBS "skip building libs even when possible" OFF)
OPTION(BUILD_SHARED_LIBS "whether to build a shared library" OFF)

FIND_PROGRAM(RUBY ruby)
FIND_PROGRAM(BISON bison)
IF (RUBY AND BISON)
    SET(WITH_MRUBY_DEFAULT "ON")
ELSE ()
    SET(WITH_MRUBY_DEFAULT "OFF")
ENDIF ()
OPTION(WITH_MRUBY "whether or not to build with mruby support" ${WITH_MRUBY_DEFAULT})

OPTION(WITH_PICOTLS "whether or not to build with picotls" "ON")

IF (WITH_BUNDLED_SSL)
    SET(BUNDLED_SSL_INCLUDE_DIR "${CMAKE_CURRENT_BINARY_DIR}/libressl-build/include")
    SET(BUNDLED_SSL_LIBRARIES "${CMAKE_CURRENT_BINARY_DIR}/libressl-build/lib/libssl.a" "${CMAKE_CURRENT_BINARY_DIR}/libressl-build/lib/libcrypto.a")
    ADD_CUSTOM_TARGET(bundled-ssl make -f ${CMAKE_CURRENT_SOURCE_DIR}/misc/libressl.mk SOURCE_DIR=${CMAKE_CURRENT_SOURCE_DIR}/misc
        WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR})
ELSE (WITH_BUNDLED_SSL)
    IF (NOT OPENSSL_FOUND)
        IF ((NOT UNIX) OR CYGWIN)
            MESSAGE(FATAL_ERROR "OpenSSL not found (and the bundled libressl cannot be used on this platform)")
        ENDIF ((NOT UNIX) OR CYGWIN)
        MESSAGE(FATAL_ERROR "OpenSSL not found (nor H2O was configured to used the bundled libressl)")
    ENDIF (NOT OPENSSL_FOUND)
    IF (OPENSSL_VERSION VERSION_LESS "1.0.2")
        MESSAGE(WARNING "*********************************************************************** OpenSSL 1.0.2 is required for HTTP/2 interoperability with web browsers ***********************************************************************")
    ENDIF (OPENSSL_VERSION VERSION_LESS "1.0.2")
    IF(OPENSSL_VERSION VERSION_EQUAL "1.1.0" AND OPENSSL_VERSION STRLESS "1.1.0g")
        MESSAGE(WARNING "*********************************************************************** OpenSSL 1.1.0 ~ 1.1.0f would cause session resumption failed when using external cache ***********************************************************************")
    ENDIF(OPENSSL_VERSION VERSION_EQUAL "1.1.0" AND OPENSSL_VERSION STRLESS "1.1.0g")
ENDIF (WITH_BUNDLED_SSL)

INCLUDE_DIRECTORIES(
    include
    deps/cloexec
    deps/brotli/enc
    deps/golombset
    deps/libgkc
    deps/libyrmcds
    deps/klib
    deps/neverbleed
    deps/picohttpparser
    deps/picotest
    deps/yaml/include
    deps/yoml)

IF (PKG_CONFIG_FOUND)
    PKG_CHECK_MODULES(LIBUV libuv>=1.0.0)
    IF (LIBUV_FOUND)
        INCLUDE_DIRECTORIES(${LIBUV_INCLUDE_DIRS})
        LINK_DIRECTORIES(${LIBUV_LIBRARY_DIRS})
    ENDIF (LIBUV_FOUND)
ENDIF (PKG_CONFIG_FOUND)
IF (NOT LIBUV_FOUND)
    FIND_PACKAGE(LibUV)
    IF (LIBUV_FOUND AND LIBUV_VERSION VERSION_LESS "1.0.0")
        MESSAGE(STATUS "libuv found but ignored; is too old")
        UNSET(LIBUV_FOUND)
    ENDIF ()
    IF (LIBUV_FOUND)
        INCLUDE_DIRECTORIES(${LIBUV_INCLUDE_DIR})
    ENDIF (LIBUV_FOUND)
ENDIF (NOT LIBUV_FOUND)
IF (NOT LIBUV_FOUND)
    SET(LIBUV_LIBRARIES -luv)
ENDIF (NOT LIBUV_FOUND)
IF (DISABLE_LIBUV)
    MESSAGE(STATUS "ignoring found libuv because of DISABLE_LIBUV")
    SET(LIBUV_FOUND FALSE)
ENDIF(DISABLE_LIBUV)

IF (PKG_CONFIG_FOUND)
    PKG_CHECK_MODULES(WSLAY libwslay)
    IF (WSLAY_FOUND)
        INCLUDE_DIRECTORIES(${WSLAY_INCLUDE_DIRS})
        LINK_DIRECTORIES(${WSLAY_LIBRARY_DIRS})
    ENDIF (WSLAY_FOUND)
ENDIF (PKG_CONFIG_FOUND)
IF (NOT WSLAY_FOUND)
    FIND_PACKAGE(Wslay)
    IF (WSLAY_FOUND)
        INCLUDE_DIRECTORIES(${WSLAY_INCLUDE_DIR})
    ENDIF (WSLAY_FOUND)
ENDIF (NOT WSLAY_FOUND)
IF (NOT WSLAY_FOUND)
    SET(WSLAY_LIBRARIES -lwslay)
ENDIF (NOT WSLAY_FOUND)

IF (ZLIB_FOUND)
    INCLUDE_DIRECTORIES(${ZLIB_INCLUDE_DIRS})
    LINK_DIRECTORIES(${ZLIB_LIBRARY_DIRS})
ENDIF (ZLIB_FOUND)

SET(CC_WARNING_FLAGS "-Wall -Wno-unused-value -Wno-unused-function")
IF ("${CMAKE_C_COMPILER_ID}" STREQUAL "GNU")
    IF (NOT ("${CMAKE_C_COMPILER_VERSION}" VERSION_LESS "4.6"))
        SET(CC_WARNING_FLAGS "${CC_WARNING_FLAGS} -Wno-unused-but-set-variable")
    ENDIF ()
    IF (NOT ("${CMAKE_C_COMPILER_VERSION}" VERSION_LESS "4.5"))
        SET(CC_WARNING_FLAGS "${CC_WARNING_FLAGS} -Wno-unused-result")
    ENDIF ()
ENDIF ()

SET(CMAKE_C_FLAGS "-O2 -g ${CC_WARNING_FLAGS} ${CMAKE_C_FLAGS} -DH2O_ROOT=\"${CMAKE_INSTALL_PREFIX}\" -DH2O_CONFIG_PATH=\"${CMAKE_INSTALL_SYSCONFDIR}/h2o.conf\"")

SET(LIBYAML_SOURCE_FILES
    deps/yaml/src/api.c
    deps/yaml/src/dumper.c
    deps/yaml/src/emitter.c
    deps/yaml/src/loader.c
    deps/yaml/src/parser.c
    deps/yaml/src/reader.c
    deps/yaml/src/scanner.c
    deps/yaml/src/writer.c)

SET(BROTLI_SOURCE_FILES
    deps/brotli/enc/backward_references.cc
    deps/brotli/enc/block_splitter.cc
    deps/brotli/enc/brotli_bit_stream.cc
    deps/brotli/enc/compress_fragment.cc
    deps/brotli/enc/compress_fragment_two_pass.cc
    deps/brotli/enc/dictionary.cc
    deps/brotli/enc/encode.cc
    deps/brotli/enc/entropy_encode.cc
    deps/brotli/enc/histogram.cc
    deps/brotli/enc/literal_cost.cc
    deps/brotli/enc/metablock.cc
    deps/brotli/enc/static_dict.cc
    deps/brotli/enc/streams.cc
    deps/brotli/enc/utf8_util.cc
    lib/handler/compress/brotli.cc)

SET(PICOTLS_INCLUDE_DIRECTORIES
    deps/picotls/deps/cifra/src/ext
    deps/picotls/deps/cifra/src
    deps/picotls/deps/micro-ecc
    deps/picotls/include)

SET(PICOTLS_SOURCE_FILES
    deps/picotls/deps/micro-ecc/uECC.c
    deps/picotls/deps/cifra/src/aes.c
    deps/picotls/deps/cifra/src/blockwise.c
    deps/picotls/deps/cifra/src/chacha20.c
    deps/picotls/deps/cifra/src/chash.c
    deps/picotls/deps/cifra/src/curve25519.c
    deps/picotls/deps/cifra/src/drbg.c
    deps/picotls/deps/cifra/src/hmac.c
    deps/picotls/deps/cifra/src/gcm.c
    deps/picotls/deps/cifra/src/gf128.c
    deps/picotls/deps/cifra/src/modes.c
    deps/picotls/deps/cifra/src/poly1305.c
    deps/picotls/deps/cifra/src/sha256.c
    deps/picotls/deps/cifra/src/sha512.c
    deps/picotls/lib/picotls.c
    deps/picotls/lib/cifra.c
    deps/picotls/lib/uecc.c
    deps/picotls/lib/openssl.c)

SET(LIB_SOURCE_FILES
    deps/cloexec/cloexec.c
    deps/libgkc/gkc.c
    deps/libyrmcds/close.c
    deps/libyrmcds/connect.c
    deps/libyrmcds/recv.c
    deps/libyrmcds/send.c
    deps/libyrmcds/send_text.c
    deps/libyrmcds/socket.c
    deps/libyrmcds/strerror.c
    deps/libyrmcds/text_mode.c
    deps/picohttpparser/picohttpparser.c

    lib/common/cache.c
    lib/common/file.c
    lib/common/filecache.c
    lib/common/hostinfo.c
    lib/common/http1client.c
    lib/common/memcached.c
    lib/common/memory.c
    lib/common/multithread.c
    lib/common/serverutil.c
    lib/common/socket.c
    lib/common/socketpool.c
    lib/common/string.c
    lib/common/time.c
    lib/common/timeout.c
    lib/common/url.c

    lib/core/config.c
    lib/core/configurator.c
    lib/core/context.c
    lib/core/headers.c
    lib/core/logconf.c
    lib/core/proxy.c
    lib/core/request.c
    lib/core/token.c
    lib/core/util.c

    lib/handler/access_log.c
    lib/handler/chunked.c
    lib/handler/compress.c
    lib/handler/compress/gzip.c
    lib/handler/errordoc.c
    lib/handler/expires.c
    lib/handler/fastcgi.c
    lib/handler/file.c
    lib/handler/headers.c
    lib/handler/mimemap.c
    lib/handler/proxy.c
    lib/handler/redirect.c
    lib/handler/reproxy.c
    lib/handler/throttle_resp.c
    lib/handler/status.c
    lib/handler/headers_util.c
    lib/handler/status/events.c
    lib/handler/status/requests.c
    lib/handler/http2_debug_state.c
    lib/handler/status/durations.c
    lib/handler/configurator/access_log.c
    lib/handler/configurator/compress.c
    lib/handler/configurator/errordoc.c
    lib/handler/configurator/expires.c
    lib/handler/configurator/fastcgi.c
    lib/handler/configurator/file.c
    lib/handler/configurator/headers.c
    lib/handler/configurator/proxy.c
    lib/handler/configurator/redirect.c
    lib/handler/configurator/reproxy.c
    lib/handler/configurator/throttle_resp.c
    lib/handler/configurator/status.c
    lib/handler/configurator/http2_debug_state.c
    lib/handler/configurator/headers_util.c

    lib/http1.c

    lib/tunnel.c

    lib/http2/cache_digests.c
    lib/http2/casper.c
    lib/http2/connection.c
    lib/http2/frame.c
    lib/http2/hpack.c
    lib/http2/scheduler.c
    lib/http2/stream.c
    lib/http2/http2_debug_state.c)

SET(UNIT_TEST_SOURCE_FILES
    ${LIB_SOURCE_FILES}
    ${LIBYAML_SOURCE_FILES}
    ${BROTLI_SOURCE_FILES}
    deps/picotest/picotest.c
    t/00unit/test.c
    t/00unit/lib/common/cache.c
    t/00unit/lib/common/hostinfo.c
    t/00unit/lib/common/multithread.c
    t/00unit/lib/common/serverutil.c
    t/00unit/lib/common/socket.c
    t/00unit/lib/common/string.c
    t/00unit/lib/common/time.c
    t/00unit/lib/common/url.c
    t/00unit/lib/core/headers.c
    t/00unit/lib/core/proxy.c
    t/00unit/lib/core/util.c
    t/00unit/lib/handler/compress.c
    t/00unit/lib/handler/fastcgi.c
    t/00unit/lib/handler/file.c
    t/00unit/lib/handler/headers.c
    t/00unit/lib/handler/mimemap.c
    t/00unit/lib/handler/redirect.c
    t/00unit/lib/http2/cache_digests.c
    t/00unit/lib/http2/casper.c
    t/00unit/lib/http2/hpack.c
    t/00unit/lib/http2/scheduler.c
    t/00unit/src/ssl.c
    t/00unit/issues/293.c
    t/00unit/issues/percent-encode-zero-byte.c)
LIST(REMOVE_ITEM UNIT_TEST_SOURCE_FILES
    lib/common/cache.c
    lib/common/hostinfo.c
    lib/common/multithread.c
    lib/common/serverutil.c
    lib/common/socket.c
    lib/common/string.c
    lib/common/time.c
    lib/common/url.c
    lib/core/headers.c
    lib/core/proxy.c
    lib/core/util.c
    lib/handler/compress.c
    lib/handler/compress/gzip.c
    lib/handler/fastcgi.c
    lib/handler/file.c
    lib/handler/headers.c
    lib/handler/mimemap.c
    lib/handler/redirect.c
    lib/http2/cache_digests.c
    lib/http2/casper.c
    lib/http2/hpack.c
    lib/http2/scheduler.c)

SET(EXTRA_LIBS ${EXTRA_LIBS} ${CMAKE_THREAD_LIBS_INIT} ${CMAKE_DL_LIBS})

IF (ZLIB_FOUND)
    LIST(INSERT EXTRA_LIBS 0 ${ZLIB_LIBRARIES})
ENDIF (ZLIB_FOUND)

IF (WSLAY_FOUND)
    ADD_LIBRARY(libh2o lib/websocket.c ${LIB_SOURCE_FILES})
    ADD_LIBRARY(libh2o-evloop lib/websocket.c ${LIB_SOURCE_FILES})
ELSE ()
    ADD_LIBRARY(libh2o ${LIB_SOURCE_FILES})
    ADD_LIBRARY(libh2o-evloop ${LIB_SOURCE_FILES})
ENDIF (WSLAY_FOUND)

SET_TARGET_PROPERTIES(libh2o PROPERTIES
    OUTPUT_NAME h2o
    VERSION ${LIBRARY_VERSION}
    SOVERSION ${LIBRARY_SOVERSION})
TARGET_LINK_LIBRARIES(libh2o ${LIBUV_LIBRARIES} ${EXTRA_LIBS})
SET_TARGET_PROPERTIES(libh2o-evloop PROPERTIES
    OUTPUT_NAME h2o-evloop
    COMPILE_FLAGS "-DH2O_USE_LIBUV=0"
    VERSION ${LIBRARY_VERSION}
    SOVERSION ${LIBRARY_SOVERSION})
TARGET_LINK_LIBRARIES(libh2o-evloop ${EXTRA_LIBS})

IF (OPENSSL_FOUND)
    TARGET_INCLUDE_DIRECTORIES(libh2o PUBLIC ${OPENSSL_INCLUDE_DIR})
    TARGET_INCLUDE_DIRECTORIES(libh2o-evloop PUBLIC ${OPENSSL_INCLUDE_DIR})
    TARGET_LINK_LIBRARIES(libh2o ${OPENSSL_LIBRARIES})
    TARGET_LINK_LIBRARIES(libh2o-evloop ${OPENSSL_LIBRARIES})
    IF (LIBUV_FOUND AND NOT WITHOUT_LIBS)
        INSTALL(TARGETS libh2o DESTINATION ${CMAKE_INSTALL_LIBDIR})
    ELSE ()
        SET_TARGET_PROPERTIES(libh2o PROPERTIES EXCLUDE_FROM_ALL 1)
    ENDIF ()
    IF (NOT WITHOUT_LIBS)
	INSTALL(TARGETS libh2o-evloop DESTINATION ${CMAKE_INSTALL_LIBDIR})
    ELSE ()
        SET_TARGET_PROPERTIES(libh2o-evloop PROPERTIES EXCLUDE_FROM_ALL 1)
    ENDIF()
ELSE (OPENSSL_FOUND)
    SET_TARGET_PROPERTIES(libh2o PROPERTIES EXCLUDE_FROM_ALL 1)
    SET_TARGET_PROPERTIES(libh2o-evloop PROPERTIES EXCLUDE_FROM_ALL 1)
ENDIF (OPENSSL_FOUND)

ADD_CUSTOM_TARGET(lib-examples DEPENDS examples-http1client examples-simple examples-socket-client)
IF (WSLAY_FOUND)
    ADD_DEPENDENCIES(lib-examples examples-websocket)
ENDIF (WSLAY_FOUND)

ADD_EXECUTABLE(examples-http1client examples/libh2o/http1client.c)
SET_TARGET_PROPERTIES(examples-http1client PROPERTIES
    EXCLUDE_FROM_ALL 1)
TARGET_LINK_LIBRARIES(examples-http1client libh2o ${LIBUV_LIBRARIES} ${EXTRA_LIBS})

ADD_EXECUTABLE(examples-socket-client examples/libh2o/socket-client.c)
SET_TARGET_PROPERTIES(examples-socket-client PROPERTIES
    EXCLUDE_FROM_ALL 1)
TARGET_LINK_LIBRARIES(examples-socket-client libh2o ${LIBUV_LIBRARIES} ${EXTRA_LIBS})

ADD_EXECUTABLE(examples-simple examples/libh2o/simple.c)
SET_TARGET_PROPERTIES(examples-simple PROPERTIES
    EXCLUDE_FROM_ALL 1)
TARGET_LINK_LIBRARIES(examples-simple libh2o ${LIBUV_LIBRARIES} ${EXTRA_LIBS})

ADD_EXECUTABLE(examples-websocket lib/websocket.c examples/libh2o/websocket.c)
SET_TARGET_PROPERTIES(examples-websocket PROPERTIES
    EXCLUDE_FROM_ALL 1)
TARGET_LINK_LIBRARIES(examples-websocket libh2o ${LIBUV_LIBRARIES} ${WSLAY_LIBRARIES} ${EXTRA_LIBS})

ADD_EXECUTABLE(examples-latency-optimization examples/libh2o/latency-optimization.c)
SET_TARGET_PROPERTIES(examples-latency-optimization PROPERTIES
    COMPILE_FLAGS "-DH2O_USE_LIBUV=0"
    EXCLUDE_FROM_ALL 1)
TARGET_LINK_LIBRARIES(examples-latency-optimization libh2o-evloop ${EXTRA_LIBS})

# standalone server directly links to libh2o using evloop
SET(STANDALONE_SOURCE_FILES
    ${LIB_SOURCE_FILES}
    ${LIBYAML_SOURCE_FILES}
    ${BROTLI_SOURCE_FILES}
    deps/neverbleed/neverbleed.c
    src/main.c
    src/ssl.c)
SET(STANDALONE_COMPILE_FLAGS "-DH2O_USE_LIBUV=0 -DH2O_USE_BROTLI=1")
IF (WITH_MRUBY)
    IF (${CMAKE_C_COMPILER_ID} STREQUAL "Clang")
        SET(MRUBY_TOOLCHAIN "clang")
    ELSE ()
        SET(MRUBY_TOOLCHAIN "gcc")
    ENDIF ()
    ADD_CUSTOM_TARGET(mruby MRUBY_TOOLCHAIN=${MRUBY_TOOLCHAIN} MRUBY_CONFIG=${CMAKE_CURRENT_SOURCE_DIR}/misc/mruby_config.rb MRUBY_BUILD_DIR=${CMAKE_CURRENT_BINARY_DIR}/mruby ruby minirake
        WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/deps/mruby)
    LIST(APPEND STANDALONE_SOURCE_FILES
        lib/handler/mruby.c
        lib/handler/mruby/chunked.c
        lib/handler/mruby/http_request.c
        lib/handler/configurator/mruby.c)
    SET(STANDALONE_COMPILE_FLAGS "${STANDALONE_COMPILE_FLAGS} -DH2O_USE_MRUBY=1")
ENDIF (WITH_MRUBY)
IF (WITH_PICOTLS)
    LIST(APPEND STANDALONE_SOURCE_FILES ${PICOTLS_SOURCE_FILES})
    SET(STANDALONE_COMPILE_FLAGS "${STANDALONE_COMPILE_FLAGS} -DH2O_USE_PICOTLS=1")
    INCLUDE_DIRECTORIES(${PICOTLS_INCLUDE_DIRECTORIES})
ENDIF ()
ADD_EXECUTABLE(h2o ${STANDALONE_SOURCE_FILES})
SET_TARGET_PROPERTIES(h2o PROPERTIES COMPILE_FLAGS ${STANDALONE_COMPILE_FLAGS})
IF (WITH_BUNDLED_SSL)
    TARGET_INCLUDE_DIRECTORIES(h2o BEFORE PUBLIC ${BUNDLED_SSL_INCLUDE_DIR})
    TARGET_LINK_LIBRARIES(h2o ${BUNDLED_SSL_LIBRARIES})
    ADD_DEPENDENCIES(h2o bundled-ssl)
ELSE (WITH_BUNDLED_SSL)
    IF (OPENSSL_FOUND)
        TARGET_INCLUDE_DIRECTORIES(h2o PUBLIC ${OPENSSL_INCLUDE_DIR})
        TARGET_LINK_LIBRARIES(h2o ${OPENSSL_LIBRARIES})
    ENDIF (OPENSSL_FOUND)
ENDIF (WITH_BUNDLED_SSL)
IF (WITH_MRUBY)
    TARGET_INCLUDE_DIRECTORIES(h2o BEFORE PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/deps/mruby/include ${CMAKE_CURRENT_SOURCE_DIR}/deps/mruby-input-stream/src)
    # note: the paths need to be determined before libmruby.flags.mak is generated
    TARGET_LINK_LIBRARIES(h2o
        "${CMAKE_CURRENT_BINARY_DIR}/mruby/host/lib/libmruby.a"
        "${CMAKE_CURRENT_BINARY_DIR}/mruby/host/mrbgems/mruby-onig-regexp/onigmo-6.1.1/.libs/libonigmo.a"
        "m")
    ADD_DEPENDENCIES(h2o mruby)
ENDIF (WITH_MRUBY)
TARGET_LINK_LIBRARIES(h2o ${EXTRA_LIBS})

INSTALL(TARGETS h2o
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR})

IF (NOT WITHOUT_LIBS)
    INSTALL(DIRECTORY include/ DESTINATION ${CMAKE_INSTALL_INCLUDEDIR} FILES_MATCHING PATTERN "*.h")
    IF (LIBUV_FOUND)
        INSTALL(FILES "${CMAKE_BINARY_DIR}/libh2o.pc" DESTINATION ${CMAKE_INSTALL_LIBDIR}/pkgconfig)
    ENDIF ()
    INSTALL(FILES "${CMAKE_BINARY_DIR}/libh2o-evloop.pc" DESTINATION ${CMAKE_INSTALL_LIBDIR}/pkgconfig)
ENDIF ()

INSTALL(PROGRAMS share/h2o/annotate-backtrace-symbols share/h2o/fastcgi-cgi share/h2o/fetch-ocsp-response share/h2o/kill-on-close share/h2o/setuidgid share/h2o/start_server DESTINATION ${CMAKE_INSTALL_DATAROOTDIR}/h2o)
INSTALL(FILES share/h2o/ca-bundle.crt DESTINATION ${CMAKE_INSTALL_DATAROOTDIR}/h2o)
INSTALL(FILES share/h2o/status/index.html DESTINATION ${CMAKE_INSTALL_DATAROOTDIR}/h2o/status)
INSTALL(DIRECTORY doc/ DESTINATION ${CMAKE_INSTALL_DATAROOTDIR}/doc/h2o PATTERN "Makefile" EXCLUDE PATTERN "README.md" EXCLUDE)
INSTALL(DIRECTORY examples/ DESTINATION ${CMAKE_INSTALL_DATAROOTDIR}/doc/h2o/examples)
IF (WITH_MRUBY)
    INSTALL(DIRECTORY share/h2o/mruby DESTINATION ${CMAKE_INSTALL_DATAROOTDIR}/h2o)
ENDIF (WITH_MRUBY)

# tests
ADD_EXECUTABLE(t-00unit-evloop.t ${UNIT_TEST_SOURCE_FILES})
SET_TARGET_PROPERTIES(t-00unit-evloop.t PROPERTIES
    COMPILE_FLAGS "-DH2O_USE_LIBUV=0 -DH2O_USE_BROTLI=1 -DH2O_UNITTEST=1"
    EXCLUDE_FROM_ALL 1)
TARGET_LINK_LIBRARIES(t-00unit-evloop.t ${EXTRA_LIBS})

IF (LIBUV_FOUND)
    ADD_EXECUTABLE(t-00unit-libuv.t ${UNIT_TEST_SOURCE_FILES})
    SET_TARGET_PROPERTIES(t-00unit-libuv.t PROPERTIES
        COMPILE_FLAGS "-DH2O_USE_BROTLI=1 -DH2O_UNITTEST=1"
        EXCLUDE_FROM_ALL 1)
    TARGET_LINK_LIBRARIES(t-00unit-libuv.t ${LIBUV_LIBRARIES} ${EXTRA_LIBS})
ENDIF (LIBUV_FOUND)

IF (WITH_BUNDLED_SSL)
    TARGET_INCLUDE_DIRECTORIES(t-00unit-evloop.t BEFORE PUBLIC ${BUNDLED_SSL_INCLUDE_DIR})
    TARGET_LINK_LIBRARIES(t-00unit-evloop.t ${BUNDLED_SSL_LIBRARIES})
    ADD_DEPENDENCIES(t-00unit-evloop.t bundled-ssl)
    IF (LIBUV_FOUND)
        TARGET_INCLUDE_DIRECTORIES(t-00unit-libuv.t BEFORE PUBLIC ${BUNDLED_SSL_INCLUDE_DIR})
        TARGET_LINK_LIBRARIES(t-00unit-libuv.t ${BUNDLED_SSL_LIBRARIES})
        ADD_DEPENDENCIES(t-00unit-libuv.t bundled-ssl)
    ENDIF (LIBUV_FOUND)
ELSE (WITH_BUNDLED_SSL)
    IF (OPENSSL_FOUND)
        TARGET_INCLUDE_DIRECTORIES(t-00unit-evloop.t PUBLIC ${OPENSSL_INCLUDE_DIR})
        TARGET_LINK_LIBRARIES(t-00unit-evloop.t ${OPENSSL_LIBRARIES})
        IF (LIBUV_FOUND)
            TARGET_INCLUDE_DIRECTORIES(t-00unit-libuv.t PUBLIC ${OPENSSL_INCLUDE_DIR})
            TARGET_LINK_LIBRARIES(t-00unit-libuv.t ${OPENSSL_LIBRARIES})
        ENDIF (LIBUV_FOUND)
    ENDIF (OPENSSL_FOUND)
ENDIF (WITH_BUNDLED_SSL)

ADD_CUSTOM_TARGET(check env H2O_ROOT=. BINARY_DIR=${CMAKE_CURRENT_BINARY_DIR} prove -v t/*.t
    WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
    DEPENDS h2o t-00unit-evloop.t)
IF (LIBUV_FOUND)
    ADD_DEPENDENCIES(check t-00unit-libuv.t)
    IF (OPENSSL_FOUND)
        ADD_DEPENDENCIES(check lib-examples)
    ENDIF ()
ENDIF ()

ADD_CUSTOM_TARGET(check-as-root env H2O_ROOT=. BINARY_DIR=${CMAKE_CURRENT_BINARY_DIR} prove -v t/90root-*.t
    WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR})

IF (BUILD_FUZZER)
    IF(NOT CMAKE_CXX_COMPILER_ID STREQUAL "Clang")
        MESSAGE(FATAL_ERROR "The fuzzer needs clang as a compiler")
    ENDIF()
    ADD_EXECUTABLE(h2o-fuzzer-http1 fuzz/driver.cc)
    ADD_EXECUTABLE(h2o-fuzzer-http2 fuzz/driver.cc)
    ADD_EXECUTABLE(h2o-fuzzer-url fuzz/driver_url.cc)
    SET_TARGET_PROPERTIES(h2o-fuzzer-http1 PROPERTIES COMPILE_FLAGS "-DHTTP1")
    SET_TARGET_PROPERTIES(h2o-fuzzer-http2 PROPERTIES COMPILE_FLAGS "-DHTTP2")
    SET(CMAKE_EXE_LINKER_FLAGS "${CMAKE_C_FLAGS} -fsanitize=address")
    IF (OSS_FUZZ)
        # Use https://github.com/google/oss-fuzz compatible options
        SET(LIB_FUZZER FuzzingEngine)
        SET(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fno-omit-frame-pointer")
        SET(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fno-omit-frame-pointer")
    ELSE ()
        # Default non-oss-fuzz options
        SET(LIB_FUZZER "${CMAKE_CURRENT_BINARY_DIR}/libFuzzer.a")
        SET(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fno-omit-frame-pointer -fsanitize=address -fsanitize-coverage=edge,indirect-calls,8bit-counters")
        SET(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fno-omit-frame-pointer -fsanitize=address -fsanitize-coverage=edge,indirect-calls,8bit-counters")

        ADD_CUSTOM_TARGET(libFuzzer ${CMAKE_CURRENT_SOURCE_DIR}/misc/build_libFuzzer.sh WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR})
        ADD_DEPENDENCIES(h2o-fuzzer-http1 libFuzzer)
        ADD_DEPENDENCIES(h2o-fuzzer-http2 libFuzzer)
        ADD_DEPENDENCIES(h2o-fuzzer-url libFuzzer)
    ENDIF (OSS_FUZZ)

    TARGET_LINK_LIBRARIES(h2o-fuzzer-http1 libh2o-evloop ${EXTRA_LIBS} ${LIB_FUZZER})
    TARGET_LINK_LIBRARIES(h2o-fuzzer-http2 libh2o-evloop ${EXTRA_LIBS} ${LIB_FUZZER})
    TARGET_LINK_LIBRARIES(h2o-fuzzer-url libh2o-evloop ${EXTRA_LIBS} ${LIB_FUZZER})

ENDIF (BUILD_FUZZER)

IF (NOT ARCH_SUPPORTS_64BIT_ATOMICS)
    SET(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -DH2O_NO_64BIT_ATOMICS")
ENDIF (NOT ARCH_SUPPORTS_64BIT_ATOMICS)

# environment-specific tweaks
IF (APPLE)
    SET_SOURCE_FILES_PROPERTIES(lib/socket.c lib/websocket.c src/main.c examples/simple.c examples/websocket.c PROPERTIES COMPILE_FLAGS -Wno-deprecated-declarations)
ELSEIF (CMAKE_SYSTEM_NAME STREQUAL "Linux")
     SET(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -pthread -D_GNU_SOURCE")
     IF (WITH_BUNDLED_SSL)
         TARGET_LINK_LIBRARIES(h2o "rt")
         TARGET_LINK_LIBRARIES(t-00unit-evloop.t "rt")
         IF (LIBUV_FOUND)
             TARGET_LINK_LIBRARIES(t-00unit-libuv.t "rt")
         ENDIF (LIBUV_FOUND)
    ENDIF (WITH_BUNDLED_SSL)
ELSEIF ("${CMAKE_SYSTEM_NAME}" MATCHES "SunOS")
    SET(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -pthreads -D_POSIX_PTHREAD_SEMANTICS")
    TARGET_LINK_LIBRARIES(h2o "socket" "nsl")
    TARGET_LINK_LIBRARIES(t-00unit-evloop.t "socket" "nsl")
    IF (LIBUV_FOUND)
        TARGET_LINK_LIBRARIES(t-00unit-libuv.t "socket" "nsl")
    ENDIF (LIBUV_FOUND)
ELSE ()
    # for FreeBSD, etc.
    SET(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -pthread")
ENDIF ()

# Retain CXX_FLAGS for std c++ compatiability across fuzz build/test environments
IF (NOT OSS_FUZZ)
    SET(CMAKE_CXX_FLAGS "${CMAKE_C_FLAGS}")
ENDIF (NOT OSS_FUZZ)
