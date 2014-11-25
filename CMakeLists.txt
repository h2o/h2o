CMAKE_MINIMUM_REQUIRED(VERSION 2.8)
CMAKE_POLICY(SET CMP0003 NEW)

PROJECT(h2o)

SET(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} ${CMAKE_CURRENT_SOURCE_DIR}/cmake)
FIND_PACKAGE(Threads)
FIND_PACKAGE(OpenSSL REQUIRED)
FIND_PACKAGE(LibUV)
FIND_PACKAGE(LibYAML)
FIND_PACKAGE(Wslay)

SET(CMAKE_C_FLAGS "-O2 -g -Wall -Wno-unused-function ${CMAKE_C_FLAGS}")

INCLUDE_DIRECTORIES(
    include
    deps/klib
    deps/picohttpparser
    deps/picotest
    deps/yoml
    ${OPENSSL_INCLUDE_DIR})
IF (LIBUV_FOUND)
    INCLUDE_DIRECTORIES(${LIBUV_INCLUDE_DIR})
ELSE (LIBUV_FOUND)
    SET(LIBUV_LIBRARIES -luv)
ENDIF (LIBUV_FOUND)
IF (LIBYAML_FOUND)
    INCLUDE_DIRECTORIES(${LIBYAML_INCLUDE_DIR})
ELSE (LIBYAML_FOUND)
    SET(LIBYAML_LIBRARIES -lyaml)
ENDIF (LIBYAML_FOUND)
IF (WSLAY_FOUND)
    INCLUDE_DIRECTORIES(${WSLAY_INCLUDE_DIR})
ELSE (WSLAY_FOUND)
    SET(WSLAY_LIBRARIES -lwslay -lnettle)
ENDIF (WSLAY_FOUND)

SET(LIB_SOURCE_FILES
    deps/picohttpparser/picohttpparser.c
    lib/access_log.c
    lib/chunked.c
    lib/context.c
    lib/config.c
    lib/file.c
    lib/headers.c
    lib/http1.c
    lib/http1client.c
    lib/http2/connection.c
    lib/http2/frame.c
    lib/http2/hpack.c
    lib/http2/stream.c
    lib/memory.c
    lib/mimemap.c
    lib/proxy.c
    lib/request.c
    lib/rproxy.c
    lib/socket.c
    lib/socketpool.c
    lib/string.c
    lib/timeout.c
    lib/token.c
    lib/util.c)

SET(EXTRA_LIBRARIES ${CMAKE_DL_LIBS})

ADD_LIBRARY(libh2o STATIC ${LIB_SOURCE_FILES})
SET_TARGET_PROPERTIES(libh2o PROPERTIES OUTPUT_NAME h2o)
SET_TARGET_PROPERTIES(libh2o PROPERTIES EXCLUDE_FROM_ALL 1)

ADD_CUSTOM_TARGET(lib-examples DEPENDS examples-http1client examples-simple examples-socket-client)
IF (WSLAY_FOUND)
    ADD_DEPENDENCIES(lib-examples examples-websocket)
ENDIF (WSLAY_FOUND)

ADD_EXECUTABLE(examples-http1client examples/libh2o/http1client.c)
SET_TARGET_PROPERTIES(examples-http1client PROPERTIES
    EXCLUDE_FROM_ALL 1)
TARGET_LINK_LIBRARIES(examples-http1client libh2o ${OPENSSL_LIBRARIES} ${LIBUV_LIBRARIES} ${CMAKE_THREAD_LIBS_INIT} ${EXTRA_LIBRARIES})

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
TARGET_LINK_LIBRARIES(h2o ${OPENSSL_LIBRARIES} ${LIBYAML_LIBRARIES} ${CMAKE_THREAD_LIBS_INIT} ${EXTRA_LIBRARIES})

# tests
ADD_EXECUTABLE(t-00unit-evloop.t ${LIB_SOURCE_FILES} deps/picotest/picotest.c lib/t/test.c)
SET_TARGET_PROPERTIES(t-00unit-evloop.t PROPERTIES
    COMPILE_FLAGS "-DH2O_USE_LIBUV=0 -DH2O_UNITTEST=1"
    EXCLUDE_FROM_ALL 1)
TARGET_LINK_LIBRARIES(t-00unit-evloop.t ${OPENSSL_LIBRARIES} ${LIBYAML_LIBRARIES} pthread ${EXTRA_LIBRARIES})
ADD_EXECUTABLE(t-00unit-libuv.t ${LIB_SOURCE_FILES} deps/picotest/picotest.c lib/t/test.c)
SET_TARGET_PROPERTIES(t-00unit-libuv.t PROPERTIES
    COMPILE_FLAGS "-DH2O_UNITTEST=1"
    EXCLUDE_FROM_ALL 1)
TARGET_LINK_LIBRARIES(t-00unit-libuv.t ${OPENSSL_LIBRARIES} ${LIBUV_LIBRARIES} ${LIBYAML_LIBRARIES} pthread ${EXTRA_LIBRARIES})

ADD_CUSTOM_TARGET(test env BINARY_DIR=${CMAKE_BINARY_DIR} prove -v t/*/*.t
    WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
    DEPENDS h2o t-00unit-evloop.t)
IF (LIBUV_FOUND)
    ADD_DEPENDENCIES(test t-00unit-libuv.t lib-examples)
ENDIF (LIBUV_FOUND)

# environment-specific tweaks
IF (APPLE)
    SET_SOURCE_FILES_PROPERTIES(lib/socket.c lib/websocket.c src/main.c examples/simple.c examples/websocket.c PROPERTIES COMPILE_FLAGS -Wno-deprecated-declarations)
ELSEIF (CMAKE_SYSTEM_NAME STREQUAL "Linux")
     SET(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -D_GNU_SOURCE")
ENDIF (APPLE)
