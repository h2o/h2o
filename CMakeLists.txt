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
SET(VERSION_MINOR "3")
SET(VERSION_PATCH "0")
SET(VERSION_PRERELEASE "-DEV")
SET(VERSION "${VERSION_MAJOR}.${VERSION_MINOR}.${VERSION_PATCH}${VERSION_PRERELEASE}")
SET(LIBRARY_VERSION_MAJOR "0")
SET(LIBRARY_VERSION_MINOR "16")
SET(LIBRARY_VERSION_PATCH "0")
SET(LIBRARY_VERSION "${LIBRARY_VERSION_MAJOR}.${LIBRARY_VERSION_MINOR}.${LIBRARY_VERSION_PATCH}${VERSION_PRERELEASE}")
SET(LIBRARY_SOVERSION "${LIBRARY_VERSION_MAJOR}.${LIBRARY_VERSION_MINOR}")

INCLUDE(GNUInstallDirs)
INCLUDE(CheckCSourceCompiles)
INCLUDE(CMakePushCheckState)
INCLUDE(ExternalProject)
INCLUDE(deps/picotls/cmake/dtrace-utils.cmake)

CONFIGURE_FILE(${CMAKE_CURRENT_SOURCE_DIR}/version.h.in ${CMAKE_CURRENT_SOURCE_DIR}/include/h2o/version.h)
CONFIGURE_FILE(${CMAKE_CURRENT_SOURCE_DIR}/libh2o.pc.in ${CMAKE_CURRENT_BINARY_DIR}/libh2o.pc @ONLY)
CONFIGURE_FILE(${CMAKE_CURRENT_SOURCE_DIR}/libh2o-evloop.pc.in ${CMAKE_CURRENT_BINARY_DIR}/libh2o-evloop.pc @ONLY)

SET(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} ${CMAKE_CURRENT_SOURCE_DIR}/cmake)

FIND_PACKAGE(PkgConfig)
FIND_PACKAGE(Threads REQUIRED)

IF ((CMAKE_SYSTEM_NAME STREQUAL "Darwin") AND NOT (DEFINED OPENSSL_ROOT_DIR OR DEFINED ENV{OPENSSL_ROOT_DIR}))
    EXECUTE_PROCESS(
        COMMAND brew --prefix openssl
        OUTPUT_VARIABLE OPENSSL_ROOT_DIR
        OUTPUT_STRIP_TRAILING_WHITESPACE
        ERROR_QUIET
    )
    IF (NOT EXISTS ${OPENSSL_ROOT_DIR})
        MESSAGE(STATUS "*************************************************************************\n"
                    "   * Setting OPENSSL_ROOT_DIR to /usr/local. On macOS, OpenSSL should be   *\n"
                    "   * installed using homebrew or OPENSSL_ROOT_DIR must be set to the path  *\n"
                    "   * that has OpenSSL installed.                                           *\n"
                    "   *************************************************************************")
        SET(OPENSSL_ROOT_DIR "/usr/local")
    ENDIF ()
ENDIF ()
FIND_PACKAGE(OpenSSL REQUIRED)
FIND_PACKAGE(ZLIB REQUIRED)

CHECK_C_SOURCE_COMPILES("
#include <stdint.h>
int main(void) {
uint64_t a;
__sync_add_and_fetch(&a, 1);
return 0;
}" ARCH_SUPPORTS_64BIT_ATOMICS)

CMAKE_PUSH_CHECK_STATE()
SET(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -pthread")
CHECK_C_SOURCE_COMPILES("
#define _GNU_SOURCE
#include <sched.h>
#include <pthread.h>
int main(void) {
cpu_set_t s;
CPU_ZERO(&s);
pthread_setaffinity_np(0, sizeof(s), &s);
return 0;
}" HAS_PTHREAD_SETAFFINITY_NP)
CMAKE_POP_CHECK_STATE()

# Find out if libc provices backtrace()
CMAKE_PUSH_CHECK_STATE()
FIND_LIBRARY(LIBC_BACKTRACE_LIB "execinfo")
IF (LIBC_BACKTRACE_LIB)
    SET(CMAKE_REQUIRED_LIBRARIES ${LIBC_BACKTRACE_LIB})
ENDIF()
CHECK_C_SOURCE_COMPILES("
#include <execinfo.h>
int main(void) {
void *p[10];
int ret = backtrace(p, 10);
backtrace_symbols_fd(p, ret, 2);
return 0;
}" LIBC_HAS_BACKTRACE)
CMAKE_POP_CHECK_STATE()

IF (LIBC_HAS_BACKTRACE)
    ADD_DEFINITIONS("-DLIBC_HAS_BACKTRACE")
    IF (LIBC_BACKTRACE_LIB)
        LIST(APPEND EXTRA_LIBS ${LIBC_BACKTRACE_LIB})
    ENDIF ()
ENDIF ()

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

FIND_PROGRAM(CCACHE ccache)
IF (CCACHE)
    SET(WITH_CCACHE_DEFAULT "ON")
ELSE ()
    SET(WITH_CCACHE_DEFAULT "OFF")
ENDIF()
OPTION(WITH_CCACHE "whether or not to build using ccache" ${WITH_CCACHE_DEFAULT})
IF (WITH_CCACHE)
    SET_PROPERTY(GLOBAL PROPERTY RULE_LAUNCH_COMPILE ccache)
    SET_PROPERTY(GLOBAL PROPERTY RULE_LAUNCH_LINK ccache)
ENDIF ()

IF (OPENSSL_VERSION VERSION_LESS "1.0.2")
    MESSAGE(STATUS "*************************************************************************\n"
                "   * OpenSSL 1.0.2 is required for HTTP/2 interoperability with web        *\n"
                "   * browsers.                                                             *\n"
                "   *************************************************************************\n")
ENDIF (OPENSSL_VERSION VERSION_LESS "1.0.2")
IF(OPENSSL_VERSION VERSION_EQUAL "1.1.0" AND OPENSSL_VERSION STRLESS "1.1.0g")
    MESSAGE(STATUS "*************************************************************************\n"
                "   * OpenSSL 1.1.0 ~ 1.1.0f would cause session resumption failed when     *\n"
                "   * using external cache.                                                 *\n"
                "   *************************************************************************\n")
ENDIF(OPENSSL_VERSION VERSION_EQUAL "1.1.0" AND OPENSSL_VERSION STRLESS "1.1.0g")

CHECK_DTRACE(${CMAKE_SOURCE_DIR}/deps/picotls/picotls-probes.d)
OPTION(WITH_DTRACE "use USDT (userspace Dtrace probes)" ${HAVE_DTRACE})
IF (WITH_DTRACE)
    MESSAGE(STATUS "Enabling USDT support")
ENDIF ()

INCLUDE_DIRECTORIES(
    include
    deps/cloexec
    deps/brotli/c/include
    deps/golombset
    deps/hiredis
    deps/libgkc
    deps/libyrmcds
    deps/klib
    deps/neverbleed
    deps/picohttpparser
    deps/picotest
    deps/picotls/deps/cifra/src/ext
    deps/picotls/deps/cifra/src
    deps/picotls/deps/micro-ecc
    deps/picotls/include
    deps/quicly/include
    deps/yaml/include
    deps/yoml
    ${CMAKE_CURRENT_BINARY_DIR})

IF (PKG_CONFIG_FOUND)
    PKG_CHECK_MODULES(LIBUV libuv>=1.0.0)
    IF (LIBUV_FOUND)
        INCLUDE_DIRECTORIES(${LIBUV_INCLUDE_DIRS})
        LINK_DIRECTORIES(${LIBUV_LIBRARY_DIRS})
    ENDIF (LIBUV_FOUND)
ENDIF (PKG_CONFIG_FOUND)
IF (NOT LIBUV_FOUND)
    FIND_PACKAGE(LIBUV)
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
    FIND_PACKAGE(WSLAY)
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

IF (PKG_CONFIG_FOUND)
    PKG_CHECK_MODULES(BROTLI_DEC libbrotlidec)
    PKG_CHECK_MODULES(BROTLI_ENC libbrotlienc)
    IF (BROTLI_DEC_FOUND AND BROTLI_ENC_FOUND)
        SET(BROTLI_FOUND TRUE)
        INCLUDE_DIRECTORIES(${BROTLI_DEC_INCLUDE_DIRS} ${BROTLI_ENC_INCLUDE_DIRS})
        LINK_DIRECTORIES(${BROTLI_DEC_LIBRARY_DIRS} ${BROTLI_ENC_LIBRARY_DIRS})
    ENDIF (BROTLI_DEC_FOUND AND BROTLI_ENC_FOUND)
ENDIF (PKG_CONFIG_FOUND)

SET(CC_WARNING_FLAGS "-Wall -Wno-unused-value -Wno-unused-function -Wno-nullability-completeness -Wno-expansion-to-defined")
IF ("${CMAKE_C_COMPILER_ID}" STREQUAL "GNU")
    IF (NOT ("${CMAKE_C_COMPILER_VERSION}" VERSION_LESS "4.6"))
        SET(CC_WARNING_FLAGS "${CC_WARNING_FLAGS} -Wno-unused-but-set-variable")
    ENDIF ()
    IF (NOT ("${CMAKE_C_COMPILER_VERSION}" VERSION_LESS "4.5"))
        SET(CC_WARNING_FLAGS "${CC_WARNING_FLAGS} -Wno-unused-result")
    ENDIF ()
ENDIF ()

# setup compile flags
SET(CMAKE_C_FLAGS "-g3 ${CC_WARNING_FLAGS} ${CMAKE_C_FLAGS} -DH2O_ROOT=\"${CMAKE_INSTALL_PREFIX}\" -DH2O_CONFIG_PATH=\"${CMAKE_INSTALL_FULL_SYSCONFDIR}/h2o.conf\"")
IF (WITH_DTRACE)
    SET(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -DPICOTLS_USE_DTRACE=1 -DQUICLY_USE_DTRACE=1 -DH2O_USE_DTRACE=1")
ENDIF ()
IF (NOT ARCH_SUPPORTS_64BIT_ATOMICS)
    SET(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -DH2O_NO_64BIT_ATOMICS")
ENDIF (NOT ARCH_SUPPORTS_64BIT_ATOMICS)
IF (CMAKE_SYSTEM_NAME STREQUAL "Linux")
    SET(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -pthread -D_GNU_SOURCE")
ELSEIF ("${CMAKE_SYSTEM_NAME}" MATCHES "SunOS")
    SET(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -pthreads -D_POSIX_PTHREAD_SEMANTICS")
ELSE ()
    # for FreeBSD, etc.
    SET(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -pthread")
ENDIF ()
IF (HAS_PTHREAD_SETAFFINITY_NP)
    SET(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -DH2O_HAS_PTHREAD_SETAFFINITY_NP")
ENDIF (HAS_PTHREAD_SETAFFINITY_NP)

# apply compile flags to C and C++
SET(CMAKE_CXX_FLAGS "${CMAKE_C_FLAGS} ${CMAKE_CXX_FLAGS}")
SET(CMAKE_C_FLAGS "-std=c99 ${CMAKE_C_FLAGS}")

# CMake defaults to a Debug build, whereas H2O defaults to an optimied build
IF(NOT CMAKE_BUILD_TYPE)
    SET(CMAKE_BUILD_TYPE Release)
ENDIF(NOT CMAKE_BUILD_TYPE)
SET(CMAKE_C_FLAGS_DEBUG  "-O0")
SET(CMAKE_C_FLAGS_RELEASE  "-O2")
SET(CMAKE_CXX_FLAGS_DEBUG  "-O0")
SET(CMAKE_CXX_FLAGS_RELEASE  "-O2")


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
    deps/brotli/c/common/dictionary.c
    deps/brotli/c/dec/bit_reader.c
    deps/brotli/c/dec/decode.c
    deps/brotli/c/dec/huffman.c
    deps/brotli/c/dec/state.c
    deps/brotli/c/enc/backward_references.c
    deps/brotli/c/enc/backward_references_hq.c
    deps/brotli/c/enc/bit_cost.c
    deps/brotli/c/enc/block_splitter.c
    deps/brotli/c/enc/brotli_bit_stream.c
    deps/brotli/c/enc/cluster.c
    deps/brotli/c/enc/compress_fragment.c
    deps/brotli/c/enc/compress_fragment_two_pass.c
    deps/brotli/c/enc/dictionary_hash.c
    deps/brotli/c/enc/encode.c
    deps/brotli/c/enc/entropy_encode.c
    deps/brotli/c/enc/histogram.c
    deps/brotli/c/enc/literal_cost.c
    deps/brotli/c/enc/memory.c
    deps/brotli/c/enc/metablock.c
    deps/brotli/c/enc/static_dict.c
    deps/brotli/c/enc/utf8_util.c
    lib/handler/compress/brotli.c)

SET(LIB_SOURCE_FILES
    deps/cloexec/cloexec.c
    deps/hiredis/async.c
    deps/hiredis/hiredis.c
    deps/hiredis/net.c
    deps/hiredis/read.c
    deps/hiredis/sds.c
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
    deps/picotls/deps/cifra/src/blockwise.c
    deps/picotls/deps/cifra/src/chash.c
    deps/picotls/deps/cifra/src/curve25519.c
    deps/picotls/deps/cifra/src/drbg.c
    deps/picotls/deps/cifra/src/hmac.c
    deps/picotls/deps/cifra/src/sha256.c
    deps/picotls/lib/certificate_compression.c
    deps/picotls/lib/picotls.c
    deps/picotls/lib/openssl.c
    deps/picotls/lib/cifra/random.c
    deps/picotls/lib/cifra/x25519.c
    deps/quicly/lib/cc-cubic.c
    deps/quicly/lib/cc-reno.c
    deps/quicly/lib/defaults.c
    deps/quicly/lib/frame.c
    deps/quicly/lib/local_cid.c
    deps/quicly/lib/loss.c
    deps/quicly/lib/quicly.c
    deps/quicly/lib/ranges.c
    deps/quicly/lib/recvstate.c
    deps/quicly/lib/remote_cid.c
    deps/quicly/lib/retire_cid.c
    deps/quicly/lib/sendstate.c
    deps/quicly/lib/sentmap.c
    deps/quicly/lib/streambuf.c

    lib/common/cache.c
    lib/common/file.c
    lib/common/filecache.c
    lib/common/hostinfo.c
    lib/common/http1client.c
    lib/common/http2client.c
    lib/common/http3client.c
    lib/common/httpclient.c
    lib/common/memcached.c
    lib/common/memory.c
    lib/common/multithread.c
    lib/common/redis.c
    lib/common/serverutil.c
    lib/common/socket.c
    lib/common/socketpool.c
    lib/common/string.c
    lib/common/time.c
    lib/common/timerwheel.c
    lib/common/token.c
    lib/common/url.c
    lib/common/balancer/roundrobin.c
    lib/common/balancer/least_conn.c
    lib/common/absprio.c

    lib/core/config.c
    lib/core/configurator.c
    lib/core/context.c
    lib/core/headers.c
    lib/core/logconf.c
    lib/core/proxy.c
    lib/core/request.c
    lib/core/util.c

    lib/handler/access_log.c
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
    lib/handler/server_timing.c
    lib/handler/status.c
    lib/handler/headers_util.c
    lib/handler/status/events.c
    lib/handler/status/requests.c
    lib/handler/status/ssl.c
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
    lib/handler/configurator/server_timing.c
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
    lib/http2/http2_debug_state.c

    lib/http3/frame.c
    lib/http3/qpack.c
    lib/http3/common.c
    lib/http3/server.c)

IF (WITH_DTRACE)
    DEFINE_DTRACE_DEPENDENCIES(${CMAKE_SOURCE_DIR}/deps/picotls/picotls-probes.d picotls)
    DEFINE_DTRACE_DEPENDENCIES(${CMAKE_SOURCE_DIR}/deps/quicly/quicly-probes.d quicly)
    DEFINE_DTRACE_DEPENDENCIES(${CMAKE_SOURCE_DIR}/h2o-probes.d h2o)
    LIST(APPEND LIB_SOURCE_FILES
         ${CMAKE_CURRENT_BINARY_DIR}/picotls-probes.h
         ${CMAKE_CURRENT_BINARY_DIR}/quicly-probes.h
         ${CMAKE_CURRENT_BINARY_DIR}/h2o-probes.h)
    IF (DTRACE_USES_OBJFILE)
        LIST(APPEND LIB_SOURCE_FILES
             ${CMAKE_CURRENT_BINARY_DIR}/picotls-probes.o
             ${CMAKE_CURRENT_BINARY_DIR}/quicly-probes.o
             ${CMAKE_CURRENT_BINARY_DIR}/h2o-probes.o)
    ENDIF ()
ENDIF ()

SET(UNIT_TEST_SOURCE_FILES
    ${LIB_SOURCE_FILES}
    ${LIBYAML_SOURCE_FILES}
    ${BROTLI_SOURCE_FILES}
    deps/picotest/picotest.c
    t/00unit/test.c
    t/00unit/lib/common/balancer/least_conn.c
    t/00unit/lib/common/balancer/roundrobin.c
    t/00unit/lib/common/cache.c
    t/00unit/lib/common/hostinfo.c
    t/00unit/lib/common/httpclient.c
    t/00unit/lib/common/multithread.c
    t/00unit/lib/common/serverutil.c
    t/00unit/lib/common/socket.c
    t/00unit/lib/common/string.c
    t/00unit/lib/common/time.c
    t/00unit/lib/common/url.c
    t/00unit/lib/common/timerwheel.c
    t/00unit/lib/common/absprio.c
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
    t/00unit/lib/http3/frame.c
    t/00unit/lib/http3/qpack.c
    t/00unit/lib/http3/server.c
    t/00unit/src/ssl.c
    t/00unit/issues/293.c
    t/00unit/issues/percent-encode-zero-byte.c)

LIST(REMOVE_ITEM UNIT_TEST_SOURCE_FILES
    lib/common/balancer/least_conn.c
    lib/common/balancer/roundrobin.c
    lib/common/cache.c
    lib/common/hostinfo.c
    lib/common/httpclient.c
    lib/common/multithread.c
    lib/common/serverutil.c
    lib/common/socket.c
    lib/common/string.c
    lib/common/time.c
    lib/common/timerwheel.c
    lib/common/url.c
    lib/common/absprio.c
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
    lib/http2/scheduler.c
    lib/http3/frame.c
    lib/http3/qpack.c
    lib/http3/server.c)

SET(FUZZED_SOURCE_FILES
    ${LIB_SOURCE_FILES}
    ${LIBYAML_SOURCE_FILES}
    ${BROTLI_SOURCE_FILES})

SET(EXTRA_LIBS ${EXTRA_LIBS} m ${CMAKE_THREAD_LIBS_INIT})

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
IF (WSLAY_FOUND)
    TARGET_LINK_LIBRARIES(libh2o ${WSLAY_LIBRARIES} ${LIBUV_LIBRARIES} ${EXTRA_LIBS})
ELSE ()
    TARGET_LINK_LIBRARIES(libh2o ${LIBUV_LIBRARIES} ${EXTRA_LIBS})
ENDIF (WSLAY_FOUND)
SET_TARGET_PROPERTIES(libh2o-evloop PROPERTIES
    OUTPUT_NAME h2o-evloop
    COMPILE_FLAGS "-DH2O_USE_LIBUV=0"
    VERSION ${LIBRARY_VERSION}
    SOVERSION ${LIBRARY_SOVERSION})
IF (WSLAY_FOUND)
    TARGET_LINK_LIBRARIES(libh2o-evloop ${WSLAY_LIBRARIES} ${EXTRA_LIBS})
ELSE ()
    TARGET_LINK_LIBRARIES(libh2o-evloop ${EXTRA_LIBS})
ENDIF (WSLAY_FOUND)

TARGET_INCLUDE_DIRECTORIES(libh2o PUBLIC ${OPENSSL_INCLUDE_DIR})
TARGET_INCLUDE_DIRECTORIES(libh2o-evloop PUBLIC ${OPENSSL_INCLUDE_DIR})
TARGET_LINK_LIBRARIES(libh2o ${OPENSSL_LIBRARIES} ${CMAKE_DL_LIBS})
TARGET_LINK_LIBRARIES(libh2o-evloop ${OPENSSL_LIBRARIES} ${CMAKE_DL_LIBS})
IF (BROTLI_FOUND)
    TARGET_LINK_LIBRARIES(libh2o ${BROTLI_DEC_LIBRARIES} ${BROTLI_ENC_LIBRARIES})
    TARGET_LINK_LIBRARIES(libh2o-evloop ${BROTLI_DEC_LIBRARIES} ${BROTLI_ENC_LIBRARIES})
ENDIF ()

ADD_EXECUTABLE(t-qif t/qif.c)
SET_TARGET_PROPERTIES(t-qif PROPERTIES
    COMPILE_FLAGS "-DH2O_USE_LIBUV=0"
    EXCLUDE_FROM_ALL 1)
TARGET_LINK_LIBRARIES(t-qif libh2o-evloop ${EXTRA_LIBS})

ADD_CUSTOM_TARGET(lib-examples DEPENDS examples-httpclient-libuv examples-simple-libuv examples-socket-client-libuv)
IF (WSLAY_FOUND)
    ADD_DEPENDENCIES(lib-examples examples-websocket-libuv)
ENDIF (WSLAY_FOUND)
ADD_EXECUTABLE(examples-httpclient-libuv src/httpclient.c)
ADD_EXECUTABLE(examples-socket-client-libuv examples/libh2o/socket-client.c)
ADD_EXECUTABLE(examples-simple-libuv examples/libh2o/simple.c)
ADD_EXECUTABLE(examples-websocket-libuv lib/websocket.c examples/libh2o/websocket.c)

ADD_CUSTOM_TARGET(lib-examples-evloop DEPENDS h2o-httpclient examples-simple-evloop examples-socket-client-evloop examples-latency-optimization-evloop)
IF (WSLAY_FOUND)
    ADD_DEPENDENCIES(lib-examples-evloop examples-websocket-evloop)
ENDIF (WSLAY_FOUND)
ADD_EXECUTABLE(examples-latency-optimization-evloop examples/libh2o/latency-optimization.c)
ADD_EXECUTABLE(h2o-httpclient src/httpclient.c)
ADD_EXECUTABLE(examples-socket-client-evloop examples/libh2o/socket-client.c)
ADD_EXECUTABLE(examples-simple-evloop examples/libh2o/simple.c)
ADD_EXECUTABLE(examples-websocket-evloop lib/websocket.c examples/libh2o/websocket.c)


SET_TARGET_PROPERTIES(examples-httpclient-libuv PROPERTIES
    EXCLUDE_FROM_ALL 1)
TARGET_LINK_LIBRARIES(examples-httpclient-libuv libh2o ${LIBUV_LIBRARIES} ${EXTRA_LIBS})

SET_TARGET_PROPERTIES(examples-socket-client-libuv PROPERTIES
    EXCLUDE_FROM_ALL 1)
TARGET_LINK_LIBRARIES(examples-socket-client-libuv libh2o ${LIBUV_LIBRARIES} ${EXTRA_LIBS})

SET_TARGET_PROPERTIES(examples-simple-libuv PROPERTIES
    EXCLUDE_FROM_ALL 1)
TARGET_LINK_LIBRARIES(examples-simple-libuv libh2o ${LIBUV_LIBRARIES} ${EXTRA_LIBS})

SET_TARGET_PROPERTIES(examples-websocket-libuv PROPERTIES
    EXCLUDE_FROM_ALL 1)
TARGET_LINK_LIBRARIES(examples-websocket-libuv libh2o ${LIBUV_LIBRARIES} ${WSLAY_LIBRARIES} ${EXTRA_LIBS})

SET_TARGET_PROPERTIES(examples-latency-optimization-evloop PROPERTIES
    COMPILE_FLAGS "-DH2O_USE_LIBUV=0"
    EXCLUDE_FROM_ALL 1)
TARGET_LINK_LIBRARIES(examples-latency-optimization-evloop libh2o-evloop ${EXTRA_LIBS})

SET_TARGET_PROPERTIES(h2o-httpclient PROPERTIES
    COMPILE_FLAGS "-DH2O_USE_LIBUV=0")
TARGET_LINK_LIBRARIES(h2o-httpclient libh2o-evloop ${EXTRA_LIBS})

SET_TARGET_PROPERTIES(examples-socket-client-evloop PROPERTIES
    COMPILE_FLAGS "-DH2O_USE_LIBUV=0"
    EXCLUDE_FROM_ALL 1)
TARGET_LINK_LIBRARIES(examples-socket-client-evloop libh2o-evloop ${EXTRA_LIBS})

SET_TARGET_PROPERTIES(examples-simple-evloop PROPERTIES
    COMPILE_FLAGS "-DH2O_USE_LIBUV=0"
    EXCLUDE_FROM_ALL 1)
TARGET_LINK_LIBRARIES(examples-simple-evloop libh2o-evloop  ${EXTRA_LIBS})

SET_TARGET_PROPERTIES(examples-websocket-evloop PROPERTIES
    COMPILE_FLAGS "-DH2O_USE_LIBUV=0"
    EXCLUDE_FROM_ALL 1)
TARGET_LINK_LIBRARIES(examples-websocket-evloop libh2o-evloop ${WSLAY_LIBRARIES} ${EXTRA_LIBS})

IF (LIBUV_FOUND AND BROTLI_FOUND AND NOT WITHOUT_LIBS)
    INSTALL(TARGETS libh2o DESTINATION ${CMAKE_INSTALL_LIBDIR})
ELSE ()
    SET_TARGET_PROPERTIES(libh2o PROPERTIES EXCLUDE_FROM_ALL 1)
ENDIF ()
IF (BROTLI_FOUND AND NOT WITHOUT_LIBS)
    INSTALL(TARGETS libh2o-evloop DESTINATION ${CMAKE_INSTALL_LIBDIR})
    INSTALL(TARGETS h2o-httpclient DESTINATION ${CMAKE_INSTALL_BINDIR})
ELSE ()
    SET_TARGET_PROPERTIES(libh2o-evloop PROPERTIES EXCLUDE_FROM_ALL 1)
    SET_TARGET_PROPERTIES(h2o-httpclient PROPERTIES EXCLUDE_FROM_ALL 1)
ENDIF()

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
    ADD_CUSTOM_TARGET(mruby
        MRUBY_TOOLCHAIN=${MRUBY_TOOLCHAIN} MRUBY_CONFIG=${CMAKE_CURRENT_SOURCE_DIR}/misc/mruby_config.rb MRUBY_BUILD_DIR=${CMAKE_CURRENT_BINARY_DIR}/mruby MRUBY_ADDITIONAL_CONFIG=${MRUBY_ADDITIONAL_CONFIG} ruby minirake
        WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/deps/mruby
        BYPRODUCTS "${CMAKE_CURRENT_BINARY_DIR}/mruby/host/lib/libmruby.a"
                   "${CMAKE_CURRENT_BINARY_DIR}/mruby/host/mrbgems/mruby-onig-regexp/onigmo-6.1.2/.libs/libonigmo.a"
    )
    LIST(APPEND STANDALONE_SOURCE_FILES
        lib/handler/mruby.c
        lib/handler/mruby/sender.c
        lib/handler/mruby/http_request.c
        lib/handler/mruby/redis.c
        lib/handler/mruby/sleep.c
        lib/handler/mruby/middleware.c
        lib/handler/mruby/channel.c
        lib/handler/configurator/mruby.c)
    SET(STANDALONE_COMPILE_FLAGS "${STANDALONE_COMPILE_FLAGS} -DH2O_USE_MRUBY=1")
    SET_PROPERTY(DIRECTORY PROPERTY ADDITIONAL_MAKE_CLEAN_FILES ${CMAKE_CURRENT_BINARY_DIR}/mruby/)
ENDIF (WITH_MRUBY)
ADD_EXECUTABLE(h2o ${STANDALONE_SOURCE_FILES})
SET_TARGET_PROPERTIES(h2o PROPERTIES COMPILE_FLAGS ${STANDALONE_COMPILE_FLAGS})
TARGET_INCLUDE_DIRECTORIES(h2o PUBLIC ${OPENSSL_INCLUDE_DIR})
TARGET_LINK_LIBRARIES(h2o ${OPENSSL_LIBRARIES} ${CMAKE_DL_LIBS})
IF (WITH_MRUBY)
    TARGET_INCLUDE_DIRECTORIES(h2o BEFORE PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/deps/mruby/include ${CMAKE_CURRENT_SOURCE_DIR}/deps/mruby-input-stream/src)
    # note: the paths need to be determined before libmruby.flags.mak is generated
    TARGET_LINK_LIBRARIES(h2o
        "${CMAKE_CURRENT_BINARY_DIR}/mruby/host/lib/libmruby.a"
        "${CMAKE_CURRENT_BINARY_DIR}/mruby/host/mrbgems/mruby-onig-regexp/onigmo-6.1.2/.libs/libonigmo.a"
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
INSTALL(DIRECTORY doc/ DESTINATION ${CMAKE_INSTALL_DATAROOTDIR}/doc/h2o PATTERN "Makefile" EXCLUDE PATTERN "h2o.8" EXCLUDE PATTERN "README.md" EXCLUDE)
INSTALL(FILES doc/h2o.8 DESTINATION ${CMAKE_INSTALL_MANDIR}/man8/)
INSTALL(FILES doc/h2o.conf.5 DESTINATION ${CMAKE_INSTALL_MANDIR}/man5/)
INSTALL(DIRECTORY examples/ DESTINATION ${CMAKE_INSTALL_DATAROOTDIR}/doc/h2o/examples)
IF (WITH_MRUBY)
    INSTALL(DIRECTORY share/h2o/mruby DESTINATION ${CMAKE_INSTALL_DATAROOTDIR}/h2o)
ENDIF (WITH_MRUBY)

# tests
ADD_EXECUTABLE(t-00unit-evloop.t ${UNIT_TEST_SOURCE_FILES})
SET_TARGET_PROPERTIES(t-00unit-evloop.t PROPERTIES
    COMPILE_FLAGS "-DH2O_USE_LIBUV=0 -DH2O_USE_BROTLI=1 -DH2O_UNITTEST=1"
    EXCLUDE_FROM_ALL 1)

IF(EXISTS ${CMAKE_CURRENT_SOURCE_DIR}/deps/theft/Makefile AND BROTLI_FOUND)
    ExternalProject_Add(build-theft
                        SOURCE_DIR "${CMAKE_CURRENT_SOURCE_DIR}/deps/theft"
                        BINARY_DIR "${CMAKE_CURRENT_BINARY_DIR}/theft"
                        CONFIGURE_COMMAND "true"
                        BUILD_COMMAND cd "${CMAKE_CURRENT_SOURCE_DIR}/deps/theft" && ${CMAKE_MAKE_PROGRAM} "BUILD=${CMAKE_CURRENT_BINARY_DIR}/theft"
                        INSTALL_COMMAND "true")
    SET_TARGET_PROPERTIES(build-theft PROPERTIES EXCLUDE_FROM_ALL TRUE)
    LINK_DIRECTORIES("${CMAKE_CURRENT_BINARY_DIR}/theft")
    ADD_EXECUTABLE(t-00property-testing.t t/00prop/prop.c)
    ADD_DEPENDENCIES(t-00property-testing.t build-theft)
    TARGET_INCLUDE_DIRECTORIES(t-00property-testing.t BEFORE PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}/deps/theft/inc")
    TARGET_LINK_LIBRARIES(t-00property-testing.t theft libh2o-evloop ${EXTRA_LIBS})
    SET_TARGET_PROPERTIES(t-00property-testing.t PROPERTIES EXCLUDE_FROM_ALL TRUE)
    SET(OPTIONAL_TEST "t-00property-testing.t")
ENDIF ()

IF (LIBUV_FOUND)
    ADD_EXECUTABLE(t-00unit-libuv.t ${UNIT_TEST_SOURCE_FILES})
    SET_TARGET_PROPERTIES(t-00unit-libuv.t PROPERTIES
        COMPILE_FLAGS "-DH2O_USE_BROTLI=1 -DH2O_UNITTEST=1"
        EXCLUDE_FROM_ALL 1)
ENDIF (LIBUV_FOUND)

TARGET_INCLUDE_DIRECTORIES(t-00unit-evloop.t PUBLIC ${OPENSSL_INCLUDE_DIR})
TARGET_LINK_LIBRARIES(t-00unit-evloop.t ${OPENSSL_LIBRARIES} ${EXTRA_LIBS})
IF (LIBUV_FOUND)
    TARGET_INCLUDE_DIRECTORIES(t-00unit-libuv.t PUBLIC ${OPENSSL_INCLUDE_DIR})
    TARGET_LINK_LIBRARIES(t-00unit-libuv.t ${LIBUV_LIBRARIES} ${OPENSSL_LIBRARIES} ${EXTRA_LIBS})
ENDIF (LIBUV_FOUND)

ADD_CUSTOM_TARGET(checkdepends
    WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
    DEPENDS h2o t-00unit-evloop.t ${OPTIONAL_TEST})
IF (LIBUV_FOUND)
    ADD_DEPENDENCIES(checkdepends t-00unit-libuv.t)
ENDIF ()
IF (BROTLI_FOUND)
    IF (LIBUV_FOUND)
        ADD_DEPENDENCIES(checkdepends lib-examples)
    ENDIF ()
    ADD_DEPENDENCIES(checkdepends lib-examples-evloop)
ENDIF ()

ADD_CUSTOM_TARGET(check env H2O_ROOT=. BINARY_DIR=${CMAKE_CURRENT_BINARY_DIR} prove -I. -v t/*.t
    WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
    DEPENDS checkdepends)

ADD_CUSTOM_TARGET(doc ${CMAKE_MAKE_PROGRAM} -f ../misc/doc.mk all BINARY_DIR=${CMAKE_CURRENT_BINARY_DIR}
    WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/doc
    DEPENDS h2o)
ADD_CUSTOM_TARGET(doc-clean ${CMAKE_MAKE_PROGRAM} -f ../misc/doc.mk clean
    WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/doc)
ADD_CUSTOM_TARGET(doc-publish ${CMAKE_MAKE_PROGRAM} -f ../misc/doc.mk publish BINARY_DIR=${CMAKE_CURRENT_BINARY_DIR}
    WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/doc
    DEPENDS h2o)

GET_FILENAME_COMPONENT(EXTERNALPROJECT_SSL_ROOT_DIR ${OPENSSL_INCLUDE_DIR} PATH)

IF (EXISTS ${CMAKE_CURRENT_SOURCE_DIR}/misc/h2get/CMakeLists.txt AND RUBY AND BISON)
    ExternalProject_Add(h2get
                        CONFIGURE_COMMAND ${CMAKE_COMMAND} -DH2GET_SSL_ROOT_DIR=${EXTERNALPROJECT_SSL_ROOT_DIR} ${CMAKE_CURRENT_SOURCE_DIR}/misc/h2get
                        SOURCE_DIR ${CMAKE_CURRENT_SOURCE_DIR}/misc/h2get
                        BINARY_DIR ${CMAKE_CURRENT_BINARY_DIR}/h2get_bin
                        BUILD_COMMAND ${CMAKE_MAKE_PROGRAM}
                        INSTALL_COMMAND true)
    SET_TARGET_PROPERTIES(h2get PROPERTIES EXCLUDE_FROM_ALL TRUE)
    ADD_DEPENDENCIES(checkdepends h2get)
ENDIF ()

ExternalProject_Add(picotls-cli
                    CONFIGURE_COMMAND ${CMAKE_COMMAND} -DOPENSSL_ROOT_DIR=${EXTERNALPROJECT_SSL_ROOT_DIR} ${CMAKE_CURRENT_SOURCE_DIR}/deps/picotls
                    SOURCE_DIR ${CMAKE_CURRENT_SOURCE_DIR}/deps/picotls
                    BINARY_DIR ${CMAKE_CURRENT_BINARY_DIR}/picotls
                    BUILD_COMMAND ${CMAKE_MAKE_PROGRAM} cli
                    INSTALL_COMMAND true)
SET_TARGET_PROPERTIES(picotls-cli PROPERTIES EXCLUDE_FROM_ALL TRUE)
ADD_DEPENDENCIES(checkdepends picotls-cli)

ADD_CUSTOM_TARGET(check-valgrind env H2O_VALGRIND=./misc/h2o_valgrind/ H2O_ROOT=. BINARY_DIR=${CMAKE_CURRENT_BINARY_DIR} prove -I. -v t/*.t
    WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
    DEPENDS h2o t-00unit-evloop.t)

IF (BUILD_FUZZER)
    IF(NOT CMAKE_CXX_COMPILER_ID STREQUAL "Clang")
        MESSAGE(FATAL_ERROR "The fuzzer needs clang as a compiler")
    ENDIF()
    ADD_EXECUTABLE(h2o-fuzzer-http1 fuzz/driver.cc)
    ADD_EXECUTABLE(h2o-fuzzer-http2 fuzz/driver.cc)
    ADD_EXECUTABLE(h2o-fuzzer-url fuzz/driver_url.cc)
    SET_TARGET_PROPERTIES(h2o-fuzzer-http1 PROPERTIES COMPILE_FLAGS "-DHTTP1")
    SET_TARGET_PROPERTIES(h2o-fuzzer-http2 PROPERTIES COMPILE_FLAGS "-DHTTP2")
    SET(CMAKE_EXE_LINKER_FLAGS "${CMAKE_C_FLAGS}")
    IF (OSS_FUZZ)
        # Use https://github.com/google/oss-fuzz compatible options
        SET(LIB_FUZZER FuzzingEngine)
        SET(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fno-omit-frame-pointer")
        SET(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fno-omit-frame-pointer")
    ELSE ()
        EXEC_PROGRAM(${CMAKE_CXX_COMPILER} ARGS "--version 2>&1 | grep version" OUTPUT_VARIABLE _clang_version_info)
        STRING(REGEX REPLACE "^.*[ ]version[ ]([0-9]+)\\.[0-9]+.*" "\\1" CLANG_MAJOR "${_clang_version_info}")
        STRING(REGEX REPLACE "^.*[ ]version[ ][0-9]+\\.([0-9]+).*" "\\1" CLANG_MINOR "${_clang_version_info}")

        IF ("${CLANG_MAJOR}.${CLANG_MINOR}" VERSION_LESS "5.0")
            ADD_CUSTOM_TARGET(libFuzzer ${CMAKE_CURRENT_SOURCE_DIR}/misc/build_libFuzzer.sh WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR})
            ADD_DEPENDENCIES(h2o-fuzzer-http1 libFuzzer)
            ADD_DEPENDENCIES(h2o-fuzzer-http2 libFuzzer)
            ADD_DEPENDENCIES(h2o-fuzzer-url libFuzzer)

            SET(LIB_FUZZER "${CMAKE_CURRENT_BINARY_DIR}/libFuzzer.a")
            SET(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fno-omit-frame-pointer -fsanitize=address -fsanitize-coverage=edge,indirect-calls,8bit-counters")
            SET(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fno-omit-frame-pointer -fsanitize=address -fsanitize-coverage=edge,indirect-calls,8bit-counters")
        ELSE()
            SET(FUZZED_SOURCE_FILES "fuzz/driver.cc" "fuzz/driver_url.cc" ${FUZZED_SOURCE_FILES})
            IF (NOT CMAKE_SYSTEM_NAME STREQUAL "FreeBSD" AND "${CLANG_MAJOR}.${CLANG_MINOR}" VERSION_LESS "7.0")
              SET_SOURCE_FILES_PROPERTIES(${FUZZED_SOURCE_FILES} PROPERTIES COMPILE_FLAGS "-fno-omit-frame-pointer -fsanitize=fuzzer,address -fsanitize-coverage=trace-pc-guard")
            ELSE()
              SET_SOURCE_FILES_PROPERTIES(${FUZZED_SOURCE_FILES} PROPERTIES COMPILE_FLAGS "-fno-omit-frame-pointer -fsanitize=fuzzer,address")
            ENDIF()
            SET_TARGET_PROPERTIES(h2o-fuzzer-http1 h2o-fuzzer-http2 h2o-fuzzer-url PROPERTIES LINK_FLAGS "-fsanitize=fuzzer,address")
            IF (NOT CMAKE_SYSTEM_NAME STREQUAL "FreeBSD" AND "${CLANG_MAJOR}.${CLANG_MINOR}" VERSION_LESS "7.0")
              SET(CMAKE_EXE_LINKER_FLAGS "-fsanitize=address -fsanitize-coverage=trace-pc-guard")
            ELSE()
              SET(CMAKE_EXE_LINKER_FLAGS "-fsanitize=address")
            ENDIF()
        ENDIF()

    ENDIF (OSS_FUZZ)

    TARGET_LINK_LIBRARIES(h2o-fuzzer-http1 libh2o-evloop ${EXTRA_LIBS} ${LIB_FUZZER})
    TARGET_LINK_LIBRARIES(h2o-fuzzer-http2 libh2o-evloop ${EXTRA_LIBS} ${LIB_FUZZER})
    TARGET_LINK_LIBRARIES(h2o-fuzzer-url libh2o-evloop ${EXTRA_LIBS} ${LIB_FUZZER})

ENDIF (BUILD_FUZZER)

# environment-specific tweaks
IF (APPLE)
    SET_SOURCE_FILES_PROPERTIES(lib/socket.c lib/websocket.c src/main.c examples/simple.c examples/websocket.c PROPERTIES COMPILE_FLAGS -Wno-deprecated-declarations)
ELSEIF ("${CMAKE_SYSTEM_NAME}" MATCHES "SunOS")
    TARGET_LINK_LIBRARIES(h2o "socket" "nsl")
    TARGET_LINK_LIBRARIES(t-00unit-evloop.t "socket" "nsl")
    IF (LIBUV_FOUND)
        TARGET_LINK_LIBRARIES(t-00unit-libuv.t "socket" "nsl")
    ENDIF (LIBUV_FOUND)
ENDIF ()

# h2olog
# If BCC is installed to a non-default directory,
# set something like `PKG_CONFIG_PATH=/path/to/bcc/lib/pkgconfig cmake ...`
IF (CMAKE_SYSTEM_NAME STREQUAL "Linux" AND PKG_CONFIG_FOUND)
    PKG_CHECK_MODULES(LIBBCC libbcc)

    EXECUTE_PROCESS(
        COMMAND uname -r
        OUTPUT_VARIABLE KERNEL_VERSION
        OUTPUT_STRIP_TRAILING_WHITESPACE
    )

    SET(REQUIRED_KERNEL_VERSION "4.9.0")
    IF (NOT (KERNEL_VERSION VERSION_LESS REQUIRED_KERNEL_VERSION))
        SET(HAVE_BPF_SUPPORTED_KERNEL ON)
        MESSAGE(STATUS "Checking Linux kernel version ${KERNEL_VERSION} >= ${REQUIRED_KERNEL_VERSION} for h2olog - OK")
    ENDIF ()

    IF (NOT (CMAKE_VERSION VERSION_LESS "3.8"))
        CMAKE_POLICY(SET CMP0057 NEW)
        IF ("cxx_std_11" IN_LIST CMAKE_CXX_COMPILE_FEATURES)
            MESSAGE(STATUS "C++11 OK")
            SET(CXX_11 ON)
        ENDIF ()
    ENDIF ()

    IF (WITH_DTRACE AND LIBBCC_FOUND AND HAVE_BPF_SUPPORTED_KERNEL AND CXX_11)
        SET(WITH_H2OLOG_DEFAULT ON)
    ENDIF ()
ENDIF ()

OPTION(WITH_H2OLOG "use h2olog command" ${WITH_H2OLOG_DEFAULT})
IF (WITH_H2OLOG)
    MESSAGE(STATUS "Supporting h2olog")

    SET(H2OLOG_SOURCE_FILES
        "src/h2olog/h2olog.h"
        "src/h2olog/h2olog.cc"
        "src/h2olog/http_tracer.cc"
        "src/h2olog/json.h"
        "src/h2olog/json.cc"
        "include/h2o/version.h"
    )

    SET(H2OLOG_GEN_DEPS
        "h2o-probes.d"
        "deps/quicly/quicly-probes.d"
        "deps/quicly/include/quicly.h"
    )

    ADD_CUSTOM_COMMAND(
        OUTPUT  "${CMAKE_CURRENT_SOURCE_DIR}/src/h2olog/generated_raw_tracer.cc"
        COMMAND "${CMAKE_CURRENT_SOURCE_DIR}/src/h2olog/misc/gen_raw_tracer.py" "${CMAKE_CURRENT_SOURCE_DIR}" "${CMAKE_CURRENT_SOURCE_DIR}/src/h2olog/generated_raw_tracer.cc"
        DEPENDS ${H2OLOG_GEN_DEPS} "${CMAKE_CURRENT_SOURCE_DIR}/src/h2olog/misc/gen_raw_tracer.py"
    )
    LIST(APPEND H2OLOG_SOURCE_FILES "${CMAKE_CURRENT_SOURCE_DIR}/src/h2olog/generated_raw_tracer.cc")
    LINK_DIRECTORIES("${LIBBCC_LIBRARY_DIRS}")

    ADD_EXECUTABLE(h2olog ${H2OLOG_SOURCE_FILES})
    TARGET_LINK_LIBRARIES(h2olog libh2o-evloop ${EXTRA_LIBS})

    SET_TARGET_PROPERTIES(h2olog PROPERTIES
        CXX_STANDARD 11
        CXX_STANDARD_REQUIRED ON
        CXX_EXTENSIONS OFF
        COMPILE_FLAGS "-DH2O_USE_LIBUV=0"
    )

    TARGET_LINK_LIBRARIES(h2olog "${LIBBCC_LIBRARIES}")
    TARGET_INCLUDE_DIRECTORIES(h2olog
        PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}/src/h2olog"
        PRIVATE "${LIBBCC_INCLUDE_DIRS}"
    )

    INSTALL(TARGETS h2olog RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})
ENDIF (WITH_H2OLOG)

# gitrev
IF ("${VERSION_PRERELEASE}" STREQUAL "-DEV" AND EXISTS "${CMAKE_SOURCE_DIR}/.git")
    ADD_DEFINITIONS("-DH2O_HAS_GITREV_H")
    ADD_CUSTOM_TARGET(gitrev ALL
        COMMAND perl ${CMAKE_CURRENT_SOURCE_DIR}/misc/generate_gitrev.pl
        WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR})
    ADD_DEPENDENCIES(libh2o gitrev)
    ADD_DEPENDENCIES(libh2o-evloop gitrev)
    ADD_DEPENDENCIES(h2o gitrev)
    ADD_DEPENDENCIES(t-00unit-evloop.t gitrev)
    IF (LIBUV_FOUND)
        ADD_DEPENDENCIES(t-00unit-libuv.t gitrev)
    ENDIF (LIBUV_FOUND)
    IF (TARGET h2olog)
        ADD_DEPENDENCIES(h2olog gitrev)
    ENDIF (TARGET h2olog)
ENDIF ()
