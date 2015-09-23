# Copyright (c) 2014,2015 DeNA Co., Ltd., Kazuho Oku, Brian Stanback, Laurentiu Nicola, Masanori Ogino, Ryosuke Matsumoto
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

CMAKE_MINIMUM_REQUIRED(VERSION 2.8.12)
CMAKE_POLICY(SET CMP0003 NEW)

PROJECT(h2o C)

SET(VERSION_MAJOR "1")
SET(VERSION_MINOR "5")
SET(VERSION_PATCH "0")
SET(VERSION_PRERELEASE "-beta4")
SET(VERSION "${VERSION_MAJOR}.${VERSION_MINOR}.${VERSION_PATCH}${VERSION_PRERELEASE}")
SET(LIBRARY_VERSION_MAJOR "0")
SET(LIBRARY_VERSION_MINOR "9")
SET(LIBRARY_VERSION_PATCH "14")
CONFIGURE_FILE(${CMAKE_SOURCE_DIR}/version.h.in ${CMAKE_SOURCE_DIR}/include/h2o/version.h)

SET(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} ${CMAKE_CURRENT_SOURCE_DIR}/cmake)

FIND_PACKAGE(PkgConfig)
FIND_PACKAGE(Threads REQUIRED)

FIND_PACKAGE(OpenSSL)
FIND_PACKAGE(ZLIB REQUIRED)

SET(WITH_BUNDLED_SSL_DEFAULT "ON")
IF ((NOT UNIX) OR CYGWIN)
    SET(WITH_BUNDLED_SSL_DEFAULT "OFF")
ENDIF ((NOT UNIX) OR CYGWIN)
IF (OPENSSL_FOUND AND NOT (OPENSSL_VERSION VERSION_LESS "1.0.2"))
    SET(WITH_BUNDLED_SSL_DEFAULT "OFF")
ENDIF (OPENSSL_FOUND AND NOT (OPENSSL_VERSION VERSION_LESS "1.0.2"))
OPTION(WITH_BUNDLED_SSL "whether or not to use the bundled libressl" ${WITH_BUNDLED_SSL_DEFAULT})

OPTION(BUILD_SHARED_LIBS "whether to build a shared library" OFF)

FIND_PROGRAM(RUBY ruby)
FIND_PROGRAM(BISON bison)
IF ((NOT (${RUBY} STREQUAL "RUBY-NOTFOUND")) AND (NOT (${BISON} STREQUAL "BISON-NOTFOUND")))
    SET(WITH_MRUBY_DEFAULT "ON")
ELSE ()
    SET(WITH_MRUBY_DEFAULT "OFF")
ENDIF ()
OPTION(WITH_MRUBY "whether or not to build with mruby support" ${WITH_MRUBY_DEFAULT})

IF (WITH_BUNDLED_SSL)
    SET(BUNDLED_SSL_INCLUDE_DIR "${CMAKE_BINARY_DIR}/libressl-build/include")
    SET(BUNDLED_SSL_LIBRARIES "${CMAKE_BINARY_DIR}/libressl-build/lib/libssl.a" "${CMAKE_BINARY_DIR}/libressl-build/lib/libcrypto.a")
    ADD_CUSTOM_TARGET(bundled-ssl make -f ${CMAKE_SOURCE_DIR}/misc/libressl.mk SOURCE_DIR=${CMAKE_SOURCE_DIR}/misc
        WORKING_DIRECTORY ${CMAKE_BINARY_DIR})
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
ENDIF (WITH_BUNDLED_SSL)

IF (PKG_CONFIG_FOUND)
    PKG_CHECK_MODULES(LIBUV libuv>=1.0.0)
    IF (LIBUV_FOUND)
        INCLUDE_DIRECTORIES(${LIBUV_INCLUDE_DIRS})
        LINK_DIRECTORIES(${LIBUV_LIBRARY_DIRS})
    ENDIF (LIBUV_FOUND)
ENDIF (PKG_CONFIG_FOUND)
IF (NOT LIBUV_FOUND)
    FIND_PACKAGE(LibUV)
    IF (LIBUV_FOUND)
        INCLUDE_DIRECTORIES(${LIBUV_INCLUDE_DIR})
    ENDIF (LIBUV_FOUND)
ENDIF (NOT LIBUV_FOUND)
IF (NOT LIBUV_FOUND)
    SET(LIBUV_LIBRARIES -luv)
ENDIF (NOT LIBUV_FOUND)

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
    SET(CC_WARNING_FLAGS "${CC_WARNING_FLAGS} -Wno-unused-but-set-variable")
    IF (NOT ("${CMAKE_C_COMPILER_VERSION}" VERSION_LESS "4.5"))
        SET(CC_WARNING_FLAGS "${CC_WARNING_FLAGS} -Wno-unused-result")
    ENDIF ()
ENDIF ()

SET(CMAKE_C_FLAGS "-O2 -g ${CC_WARNING_FLAGS} ${CMAKE_C_FLAGS} -DH2O_ROOT=\"\\\"${CMAKE_INSTALL_PREFIX}\\\"\"")

INCLUDE_DIRECTORIES(
    include
    deps/cloexec
    deps/golombset
    deps/libyrmcds
    deps/klib
    deps/neverbleed
    deps/picohttpparser
    deps/picotest
    deps/yaml/include
    deps/yoml)

SET(LIBYAML_SOURCE_FILES
    deps/yaml/src/api.c
    deps/yaml/src/dumper.c
    deps/yaml/src/emitter.c
    deps/yaml/src/loader.c
    deps/yaml/src/parser.c
    deps/yaml/src/reader.c
    deps/yaml/src/scanner.c
    deps/yaml/src/writer.c)

SET(LIB_SOURCE_FILES
    deps/cloexec/cloexec.c
    deps/libyrmcds/close.c
    deps/libyrmcds/connect.c
    deps/libyrmcds/recv.c
    deps/libyrmcds/send.c
    deps/libyrmcds/socket.c
    deps/libyrmcds/strerror.c
    deps/picohttpparser/picohttpparser.c

    lib/common/file.c
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
    lib/core/proxy.c
    lib/core/request.c
    lib/core/token.c
    lib/core/util.c

    lib/handler/access_log.c
    lib/handler/chunked.c
    lib/handler/expires.c
    lib/handler/fastcgi.c
    lib/handler/file.c
    lib/handler/gzip.c
    lib/handler/headers.c
    lib/handler/mimemap.c
    lib/handler/proxy.c
    lib/handler/redirect.c
    lib/handler/reproxy.c
    lib/handler/configurator/access_log.c
    lib/handler/configurator/expires.c
    lib/handler/configurator/fastcgi.c
    lib/handler/configurator/file.c
    lib/handler/configurator/gzip.c
    lib/handler/configurator/headers.c
    lib/handler/configurator/proxy.c
    lib/handler/configurator/redirect.c
    lib/handler/configurator/reproxy.c

    lib/http1.c

    lib/http2/casper.c
    lib/http2/connection.c
    lib/http2/frame.c
    lib/http2/hpack.c
    lib/http2/scheduler.c
    lib/http2/stream.c)

SET(UNIT_TEST_SOURCE_FILES
    ${LIB_SOURCE_FILES}
    ${LIBYAML_SOURCE_FILES}
    deps/picotest/picotest.c
    t/00unit/test.c
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
    t/00unit/lib/handler/fastcgi.c
    t/00unit/lib/handler/file.c
    t/00unit/lib/handler/gzip.c
    t/00unit/lib/handler/headers.c
    t/00unit/lib/handler/mimemap.c
    t/00unit/lib/handler/redirect.c
    t/00unit/lib/http2/casper.c
    t/00unit/lib/http2/hpack.c
    t/00unit/lib/http2/scheduler.c
    t/00unit/src/ssl.c
    t/00unit/issues/293.c)
LIST(REMOVE_ITEM UNIT_TEST_SOURCE_FILES
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
    lib/handler/fastcgi.c
    lib/handler/file.c
    lib/handler/gzip.c
    lib/handler/headers.c
    lib/handler/mimemap.c
    lib/handler/redirect.c
    lib/http2/casper.c
    lib/http2/hpack.c
    lib/http2/scheduler.c)

SET(EXTRA_LIBRARIES ${CMAKE_THREAD_LIBS_INIT} ${CMAKE_DL_LIBS})

IF (ZLIB_FOUND)
    LIST(INSERT EXTRA_LIBRARIES 0 ${ZLIB_LIBRARIES})
ENDIF (ZLIB_FOUND)

ADD_LIBRARY(libh2o ${LIB_SOURCE_FILES})
ADD_LIBRARY(libh2o-evloop ${LIB_SOURCE_FILES})
SET_TARGET_PROPERTIES(libh2o PROPERTIES OUTPUT_NAME h2o)
SET_TARGET_PROPERTIES(libh2o-evloop PROPERTIES
    OUTPUT_NAME h2o-evloop
    COMPILE_FLAGS "-DH2O_USE_LIBUV=0")
IF (OPENSSL_FOUND)
    TARGET_INCLUDE_DIRECTORIES(libh2o BEFORE PUBLIC ${OPENSSL_INCLUDE_DIR})
    TARGET_INCLUDE_DIRECTORIES(libh2o-evloop BEFORE PUBLIC ${OPENSSL_INCLUDE_DIR})
    TARGET_LINK_LIBRARIES(libh2o ${OPENSSL_LIBRARIES})
    TARGET_LINK_LIBRARIES(libh2o-evloop ${OPENSSL_LIBRARIES})
    IF (LIBUV_FOUND)
        INSTALL(TARGETS libh2o DESTINATION lib)
    ELSE (LIBUV_FOUND)
        SET_TARGET_PROPERTIES(libh2o PROPERTIES EXCLUDE_FROM_ALL 1)
    ENDIF (LIBUV_FOUND)
    INSTALL(TARGETS libh2o-evloop DESTINATION lib)
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
TARGET_LINK_LIBRARIES(examples-http1client libh2o ${LIBUV_LIBRARIES} ${EXTRA_LIBRARIES})

ADD_EXECUTABLE(examples-socket-client examples/libh2o/socket-client.c)
SET_TARGET_PROPERTIES(examples-socket-client PROPERTIES
    EXCLUDE_FROM_ALL 1)
TARGET_LINK_LIBRARIES(examples-socket-client libh2o ${LIBUV_LIBRARIES} ${EXTRA_LIBRARIES})

ADD_EXECUTABLE(examples-simple examples/libh2o/simple.c)
SET_TARGET_PROPERTIES(examples-simple PROPERTIES
    EXCLUDE_FROM_ALL 1)
TARGET_LINK_LIBRARIES(examples-simple libh2o ${LIBUV_LIBRARIES} ${EXTRA_LIBRARIES})

ADD_EXECUTABLE(examples-websocket lib/websocket.c examples/libh2o/websocket.c)
SET_TARGET_PROPERTIES(examples-websocket PROPERTIES
    EXCLUDE_FROM_ALL 1)
TARGET_LINK_LIBRARIES(examples-websocket libh2o ${LIBUV_LIBRARIES} ${WSLAY_LIBRARIES} ${EXTRA_LIBRARIES})

# standalone server directly links to libh2o using evloop
SET(STANDALONE_SOURCE_FILES ${LIB_SOURCE_FILES} ${LIBYAML_SOURCE_FILES} deps/neverbleed/neverbleed.c src/ssl.c src/main.c)
SET(STANDALONE_COMPILE_FLAGS "-DH2O_USE_LIBUV=0")
IF (WITH_MRUBY)
    IF (${CMAKE_C_COMPILER_ID} STREQUAL "Clang")
        SET(MRUBY_TOOLCHAIN "clang")
    ELSE ()
        SET(MRUBY_TOOLCHAIN "gcc")
    ENDIF ()
    ADD_CUSTOM_TARGET(mruby MRUBY_TOOLCHAIN=${MRUBY_TOOLCHAIN} MRUBY_CONFIG=${CMAKE_SOURCE_DIR}/misc/mruby_config.rb MRUBY_BUILD_DIR=${CMAKE_BINARY_DIR}/mruby ruby minirake
        WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}/deps/mruby)
    LIST(APPEND STANDALONE_SOURCE_FILES
        lib/handler/mruby.c
        lib/handler/configurator/mruby.c)
    SET(STANDALONE_COMPILE_FLAGS "${STANDALONE_COMPILE_FLAGS} -DH2O_USE_MRUBY=1")
ENDIF (WITH_MRUBY)
ADD_EXECUTABLE(h2o ${STANDALONE_SOURCE_FILES})
SET_TARGET_PROPERTIES(h2o PROPERTIES COMPILE_FLAGS ${STANDALONE_COMPILE_FLAGS})
IF (WITH_BUNDLED_SSL)
    TARGET_INCLUDE_DIRECTORIES(h2o BEFORE PUBLIC ${BUNDLED_SSL_INCLUDE_DIR})
    TARGET_LINK_LIBRARIES(h2o ${BUNDLED_SSL_LIBRARIES})
    ADD_DEPENDENCIES(h2o bundled-ssl)
ELSE (WITH_BUNDLED_SSL)
    IF (OPENSSL_FOUND)
        TARGET_INCLUDE_DIRECTORIES(h2o BEFORE PUBLIC ${OPENSSL_INCLUDE_DIR})
        TARGET_LINK_LIBRARIES(h2o ${OPENSSL_LIBRARIES})
    ENDIF (OPENSSL_FOUND)
ENDIF (WITH_BUNDLED_SSL)
IF (WITH_MRUBY)
    TARGET_INCLUDE_DIRECTORIES(h2o BEFORE PRIVATE ${CMAKE_SOURCE_DIR}/deps/mruby/include)
    # note: the paths need to be determined before libmruby.flags.mak is generated
    TARGET_LINK_LIBRARIES(h2o
        "${CMAKE_BINARY_DIR}/mruby/host/lib/libmruby.a"
        "${CMAKE_BINARY_DIR}/mruby/host/mrbgems/mruby-onig-regexp/Onigmo-Onigmo-5.15.0/.libs/libonig.a"
        "m")
    ADD_DEPENDENCIES(h2o mruby)
ENDIF (WITH_MRUBY)
TARGET_LINK_LIBRARIES(h2o ${EXTRA_LIBRARIES})

INSTALL(TARGETS h2o
    RUNTIME DESTINATION bin
    LIBRARY DESTINATION lib)

ADD_EXECUTABLE(setuidgid src/setuidgid.c)
INSTALL(TARGETS setuidgid RUNTIME DESTINATION share/h2o)

INSTALL(DIRECTORY include/ DESTINATION include FILES_MATCHING PATTERN "*.h")

INSTALL(PROGRAMS share/h2o/annotate-backtrace-symbols share/h2o/fetch-ocsp-response share/h2o/kill-on-close share/h2o/start_server DESTINATION share/h2o)
INSTALL(DIRECTORY doc/ DESTINATION share/doc/h2o PATTERN "Makefile" EXCLUDE PATTERN "README.md" EXCLUDE)

# tests
ADD_EXECUTABLE(t-00unit-evloop.t ${UNIT_TEST_SOURCE_FILES})
SET_TARGET_PROPERTIES(t-00unit-evloop.t PROPERTIES
    COMPILE_FLAGS "-DH2O_USE_LIBUV=0 -DH2O_UNITTEST=1"
    EXCLUDE_FROM_ALL 1)
TARGET_LINK_LIBRARIES(t-00unit-evloop.t ${EXTRA_LIBRARIES})
ADD_EXECUTABLE(t-00unit-libuv.t ${UNIT_TEST_SOURCE_FILES})
SET_TARGET_PROPERTIES(t-00unit-libuv.t PROPERTIES
    COMPILE_FLAGS "-DH2O_UNITTEST=1"
    EXCLUDE_FROM_ALL 1)
TARGET_LINK_LIBRARIES(t-00unit-libuv.t ${LIBUV_LIBRARIES} ${EXTRA_LIBRARIES})
IF (WITH_BUNDLED_SSL)
    TARGET_INCLUDE_DIRECTORIES(t-00unit-evloop.t BEFORE PUBLIC ${BUNDLED_SSL_INCLUDE_DIR})
    TARGET_LINK_LIBRARIES(t-00unit-evloop.t ${BUNDLED_SSL_LIBRARIES})
    ADD_DEPENDENCIES(t-00unit-evloop.t bundled-ssl)
    TARGET_INCLUDE_DIRECTORIES(t-00unit-libuv.t BEFORE PUBLIC ${BUNDLED_SSL_INCLUDE_DIR})
    TARGET_LINK_LIBRARIES(t-00unit-libuv.t ${BUNDLED_SSL_LIBRARIES})
    ADD_DEPENDENCIES(t-00unit-libuv.t bundled-ssl)
ELSE (WITH_BUNDLED_SSL)
    IF (OPENSSL_FOUND)
        TARGET_INCLUDE_DIRECTORIES(t-00unit-evloop.t BEFORE PUBLIC ${OPENSSL_INCLUDE_DIR})
        TARGET_LINK_LIBRARIES(t-00unit-evloop.t ${OPENSSL_LIBRARIES})
        TARGET_INCLUDE_DIRECTORIES(t-00unit-libuv.t BEFORE PUBLIC ${OPENSSL_INCLUDE_DIR})
        TARGET_LINK_LIBRARIES(t-00unit-libuv.t ${OPENSSL_LIBRARIES})
    ENDIF (OPENSSL_FOUND)
ENDIF (WITH_BUNDLED_SSL)

ADD_CUSTOM_TARGET(check env H2O_ROOT=. BINARY_DIR=${CMAKE_BINARY_DIR} prove -v t/*.t
    WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
    DEPENDS h2o t-00unit-evloop.t)
IF (LIBUV_FOUND)
    ADD_DEPENDENCIES(check t-00unit-libuv.t lib-examples)
ENDIF (LIBUV_FOUND)

ADD_CUSTOM_TARGET(check-as-root env H2O_ROOT=. BINARY_DIR=${CMAKE_BINARY_DIR} prove -v t/90root-*.t
    WORKING_DIRECTORY ${CMAKE_SOURCE_DIR})

# environment-specific tweaks
IF (APPLE)
    SET_SOURCE_FILES_PROPERTIES(lib/socket.c lib/websocket.c src/main.c examples/simple.c examples/websocket.c PROPERTIES COMPILE_FLAGS -Wno-deprecated-declarations)
ELSEIF (CMAKE_SYSTEM_NAME STREQUAL "Linux")
     SET(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -D_GNU_SOURCE")
     IF (WITH_BUNDLED_SSL)
        TARGET_LINK_LIBRARIES(h2o "rt")
        TARGET_LINK_LIBRARIES(t-00unit-evloop.t "rt")
        TARGET_LINK_LIBRARIES(t-00unit-libuv.t "rt")
    ENDIF (WITH_BUNDLED_SSL)
ENDIF (APPLE)
IF ("${CMAKE_SYSTEM_NAME}" MATCHES "SunOS")
    SET(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -D_POSIX_PTHREAD_SEMANTICS")
    TARGET_LINK_LIBRARIES(h2o "socket" "nsl")
    TARGET_LINK_LIBRARIES(t-00unit-evloop.t "socket" "nsl")
    TARGET_LINK_LIBRARIES(t-00unit-libuv.t "socket" "nsl")
ENDIF ("${CMAKE_SYSTEM_NAME}" MATCHES "SunOS")
