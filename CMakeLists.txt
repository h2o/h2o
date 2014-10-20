CMAKE_MINIMUM_REQUIRED(VERSION 2.8)
CMAKE_POLICY(SET CMP0003 NEW)

PROJECT(h2o)

SET(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} ${CMAKE_CURRENT_SOURCE_DIR}/cmake)
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
    lib/http2/connection.c
    lib/http2/frame.c
    lib/http2/hpack.c
    lib/http2/stream.c
    lib/memory.c
    lib/mimemap.c
    lib/request.c
    lib/rproxy.c
    lib/socket.c
    lib/string.c
    lib/timeout.c
    lib/token.c
    lib/util.c)

ADD_LIBRARY(libh2o STATIC ${LIB_SOURCE_FILES})
SET_TARGET_PROPERTIES(libh2o PROPERTIES OUTPUT_NAME h2o)
SET_TARGET_PROPERTIES(libh2o PROPERTIES EXCLUDE_FROM_ALL 1)

ADD_EXECUTABLE(examples-socket-client examples/socket-client.c)
SET_TARGET_PROPERTIES(examples-socket-client PROPERTIES EXCLUDE_FROM_ALL 1)
TARGET_LINK_LIBRARIES(examples-socket-client libh2o ${OPENSSL_LIBRARIES} ${LIBUV_LIBRARIES})

ADD_EXECUTABLE(examples-simple examples/simple.c)
SET_TARGET_PROPERTIES(examples-simple PROPERTIES EXCLUDE_FROM_ALL 1)
TARGET_LINK_LIBRARIES(examples-simple libh2o ${OPENSSL_LIBRARIES} ${LIBUV_LIBRARIES})

ADD_EXECUTABLE(examples-websocket lib/websocket.c examples/websocket.c)
SET_TARGET_PROPERTIES(examples-websocket PROPERTIES EXCLUDE_FROM_ALL 1)
TARGET_LINK_LIBRARIES(examples-websocket libh2o ${OPENSSL_LIBRARIES} ${LIBUV_LIBRARIES} ${WSLAY_LIBRARIES})

# directly links to libh2o using evloop
ADD_EXECUTABLE(h2o ${LIB_SOURCE_FILES} src/main.c)
SET_TARGET_PROPERTIES(h2o PROPERTIES COMPILE_FLAGS "-DH2O_USE_LIBUV=0")
TARGET_LINK_LIBRARIES(h2o ${OPENSSL_LIBRARIES} ${LIBYAML_LIBRARIES} pthread)

# tests
ADD_EXECUTABLE(unittest_evloop ${LIB_SOURCE_FILES} deps/picotest/picotest.c lib/t/test.c)
SET_TARGET_PROPERTIES(unittest_evloop PROPERTIES COMPILE_FLAGS "-DH2O_USE_LIBUV=0 -DH2O_UNITTEST=1")
SET_TARGET_PROPERTIES(unittest_evloop PROPERTIES OUTPUT_NAME t/unittest_evloop.t)
TARGET_LINK_LIBRARIES(unittest_evloop ${OPENSSL_LIBRARIES} ${LIBYAML_LIBRARIES} pthread)
ADD_EXECUTABLE(unittest_libuv ${LIB_SOURCE_FILES} deps/picotest/picotest.c lib/t/test.c)
SET_TARGET_PROPERTIES(unittest_libuv PROPERTIES COMPILE_FLAGS "-DH2O_UNITTEST=1")
SET_TARGET_PROPERTIES(unittest_libuv PROPERTIES OUTPUT_NAME t/unittest_libuv.t)
TARGET_LINK_LIBRARIES(unittest_libuv ${OPENSSL_LIBRARIES} ${LIBUV_LIBRARIES} ${LIBYAML_LIBRARIES} pthread)

ADD_CUSTOM_TARGET(test prove -r DEPENDS unittest_evloop)
IF (LIBUV_FOUND)
    ADD_DEPENDENCIES(test unittest_libuv)
ENDIF (LIBUV_FOUND)

# environment-specific tweaks
IF (APPLE)
    SET_SOURCE_FILES_PROPERTIES(lib/socket.c src/main.c PROPERTIES COMPILE_FLAGS -Wno-deprecated-declarations)
ENDIF (APPLE)
