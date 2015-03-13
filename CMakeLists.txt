CMAKE_MINIMUM_REQUIRED(VERSION 2.8)
CMAKE_POLICY(SET CMP0003 NEW)

PROJECT(h2o)

SET(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} ${CMAKE_CURRENT_SOURCE_DIR}/cmake)

FIND_PACKAGE(PkgConfig)
FIND_PACKAGE(Threads REQUIRED)

IF (PKG_CONFIG_FOUND)
    PKG_CHECK_MODULES(OPENSSL openssl)
    IF (OPENSSL_FOUND)
        INCLUDE_DIRECTORIES(${OPENSSL_INCLUDE_DIRS})
        LINK_DIRECTORIES(${OPENSSL_LIBRARY_DIRS})
    ENDIF (OPENSSL_FOUND)
ENDIF (PKG_CONFIG_FOUND)
IF (NOT OPENSSL_FOUND)
    FIND_PACKAGE(OpenSSL REQUIRED)
    INCLUDE_DIRECTORIES(${OPENSSL_INCLUDE_DIR})
ENDIF (NOT OPENSSL_FOUND)
IF (OPENSSL_VERSION VERSION_LESS "1.0.2")
    MESSAGE(WARNING "*********************************************************************** OpenSSL 1.0.2 is required for HTTP/2 interoperability with web browsers ***********************************************************************")
ENDIF (OPENSSL_VERSION VERSION_LESS "1.0.2")

IF (PKG_CONFIG_FOUND)
    PKG_CHECK_MODULES(LIBYAML libyaml)
    IF (LIBYAML_FOUND)
        INCLUDE_DIRECTORIES(${LIBYAML_INCLUDE_DIRS})
        LINK_DIRECTORIES(${LIBYAML_LIBRARY_DIRS})
    ENDIF (LIBYAML_FOUND)
ENDIF (PKG_CONFIG_FOUND)
IF (NOT LIBYAML_FOUND)
    FIND_PACKAGE(LibYAML REQUIRED)
    INCLUDE_DIRECTORIES(${LIBYAML_INCLUDE_DIR})
ENDIF (NOT LIBYAML_FOUND)

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

SET(CMAKE_C_FLAGS "-O2 -g -Wall -Wno-unused-function ${CMAKE_C_FLAGS} -DH2O_ROOT=\"\\\"${CMAKE_INSTALL_PREFIX}\\\"\"")

INCLUDE_DIRECTORIES(
    include
    deps/klib
    deps/picohttpparser
    deps/picotest
    deps/yoml)

SET(LIB_SOURCE_FILES
    deps/picohttpparser/picohttpparser.c

    lib/common/hostinfo.c
    lib/common/http1client.c
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
    lib/handler/file.c
    lib/handler/headers.c
    lib/handler/mimemap.c
    lib/handler/proxy.c
    lib/handler/redirect.c
    lib/handler/reproxy.c
    lib/handler/configurator/access_log.c
    lib/handler/configurator/expires.c
    lib/handler/configurator/file.c
    lib/handler/configurator/headers.c
    lib/handler/configurator/proxy.c
    lib/handler/configurator/redirect.c
    lib/handler/configurator/reproxy.c

    lib/http1.c

    lib/http2/connection.c
    lib/http2/frame.c
    lib/http2/hpack.c
    lib/http2/scheduler.c
    lib/http2/stream.c)

SET(UNIT_TEST_SOURCE_FILES
    ${LIB_SOURCE_FILES}
    deps/picotest/picotest.c
    t/00unit/test.c
    t/00unit/lib/common/multithread.c
    t/00unit/lib/common/serverutil.c
    t/00unit/lib/common/string.c
    t/00unit/lib/common/time.c
    t/00unit/lib/common/url.c
    t/00unit/lib/core/headers.c
    t/00unit/lib/core/proxy.c
    t/00unit/lib/handler/file.c
    t/00unit/lib/handler/headers.c
    t/00unit/lib/handler/mimemap.c
    t/00unit/lib/http2/hpack.c
    t/00unit/lib/http2/scheduler.c)
LIST(REMOVE_ITEM UNIT_TEST_SOURCE_FILES
    lib/common/multithread.c
    lib/common/serverutil.c
    lib/common/string.c
    lib/common/time.c
    lib/common/url.c
    lib/core/headers.c
    lib/core/proxy.c
    lib/handler/file.c
    lib/handler/headers.c
    lib/handler/mimemap.c
    lib/http2/hpack.c
    lib/http2/scheduler.c)

SET(EXTRA_LIBRARIES ${CMAKE_THREAD_LIBS_INIT} ${CMAKE_DL_LIBS})

ADD_LIBRARY(libh2o STATIC ${LIB_SOURCE_FILES})
SET_TARGET_PROPERTIES(libh2o PROPERTIES OUTPUT_NAME h2o)

ADD_CUSTOM_TARGET(lib-examples DEPENDS examples-http1client examples-simple examples-socket-client)
IF (WSLAY_FOUND)
    ADD_DEPENDENCIES(lib-examples examples-websocket)
ENDIF (WSLAY_FOUND)

ADD_EXECUTABLE(examples-http1client examples/libh2o/http1client.c)
SET_TARGET_PROPERTIES(examples-http1client PROPERTIES
    EXCLUDE_FROM_ALL 1)
TARGET_LINK_LIBRARIES(examples-http1client libh2o ${OPENSSL_LIBRARIES} ${LIBUV_LIBRARIES} ${EXTRA_LIBRARIES})

ADD_EXECUTABLE(examples-socket-client examples/libh2o/socket-client.c)
SET_TARGET_PROPERTIES(examples-socket-client PROPERTIES
    EXCLUDE_FROM_ALL 1)
TARGET_LINK_LIBRARIES(examples-socket-client libh2o ${OPENSSL_LIBRARIES} ${LIBUV_LIBRARIES} ${EXTRA_LIBRARIES})

ADD_EXECUTABLE(examples-simple examples/libh2o/simple.c)
SET_TARGET_PROPERTIES(examples-simple PROPERTIES
    EXCLUDE_FROM_ALL 1)
TARGET_LINK_LIBRARIES(examples-simple libh2o ${OPENSSL_LIBRARIES} ${LIBUV_LIBRARIES} ${EXTRA_LIBRARIES})

ADD_EXECUTABLE(examples-websocket lib/websocket.c examples/libh2o/websocket.c)
SET_TARGET_PROPERTIES(examples-websocket PROPERTIES
    EXCLUDE_FROM_ALL 1)
TARGET_LINK_LIBRARIES(examples-websocket libh2o ${OPENSSL_LIBRARIES} ${LIBUV_LIBRARIES} ${WSLAY_LIBRARIES} ${EXTRA_LIBRARIES})

# directly links to libh2o using evloop
ADD_EXECUTABLE(h2o ${LIB_SOURCE_FILES} src/main.c)
SET_TARGET_PROPERTIES(h2o PROPERTIES COMPILE_FLAGS "-DH2O_USE_LIBUV=0")
TARGET_LINK_LIBRARIES(h2o ${OPENSSL_LIBRARIES} ${LIBYAML_LIBRARIES} ${EXTRA_LIBRARIES})

INSTALL(TARGETS h2o
    RUNTIME DESTINATION bin
    LIBRARY DESTINATION lib)

# only install libh2o if libuv is found
IF (LIBUV_FOUND)
  INSTALL(TARGETS libh2o DESTINATION lib)
  INSTALL(DIRECTORY include/ DESTINATION include FILES_MATCHING PATTERN "*.h")
ELSE (LIBUV_FOUND)
  SET_TARGET_PROPERTIES(libh2o PROPERTIES EXCLUDE_FROM_ALL 1)
ENDIF (LIBUV_FOUND)

INSTALL(PROGRAMS share/h2o/fetch-ocsp-response DESTINATION share/h2o)

# tests
ADD_EXECUTABLE(t-00unit-evloop.t ${UNIT_TEST_SOURCE_FILES})
SET_TARGET_PROPERTIES(t-00unit-evloop.t PROPERTIES
    COMPILE_FLAGS "-DH2O_USE_LIBUV=0 -DH2O_UNITTEST=1"
    EXCLUDE_FROM_ALL 1)
TARGET_LINK_LIBRARIES(t-00unit-evloop.t ${OPENSSL_LIBRARIES} ${LIBYAML_LIBRARIES} ${EXTRA_LIBRARIES})
ADD_EXECUTABLE(t-00unit-libuv.t ${UNIT_TEST_SOURCE_FILES})
SET_TARGET_PROPERTIES(t-00unit-libuv.t PROPERTIES
    COMPILE_FLAGS "-DH2O_UNITTEST=1"
    EXCLUDE_FROM_ALL 1)
TARGET_LINK_LIBRARIES(t-00unit-libuv.t ${OPENSSL_LIBRARIES} ${LIBUV_LIBRARIES} ${LIBYAML_LIBRARIES} ${EXTRA_LIBRARIES})

ADD_CUSTOM_TARGET(check env H2O_ROOT=. BINARY_DIR=${CMAKE_BINARY_DIR} prove -v t/*.t
    WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
    DEPENDS h2o t-00unit-evloop.t)
IF (LIBUV_FOUND)
    ADD_DEPENDENCIES(check t-00unit-libuv.t lib-examples)
ENDIF (LIBUV_FOUND)

# environment-specific tweaks
IF (APPLE)
    SET_SOURCE_FILES_PROPERTIES(lib/socket.c lib/websocket.c src/main.c examples/simple.c examples/websocket.c PROPERTIES COMPILE_FLAGS -Wno-deprecated-declarations)
ELSEIF (CMAKE_SYSTEM_NAME STREQUAL "Linux")
     SET(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -D_GNU_SOURCE")
ENDIF (APPLE)
