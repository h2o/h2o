CMAKE_MINIMUM_REQUIRED(VERSION 2.8)
CMAKE_POLICY(SET CMP0003 NEW)

PROJECT(h2o)

SET(CMAKE_C_FLAGS "-O2 -g -Wall -Wno-unused-function -DH2O_USE_LIBUV=0 ${CMAKE_C_FLAGS}")

INCLUDE_DIRECTORIES(include deps/picohttpparser deps/klib)

ADD_LIBRARY(h2o STATIC deps/picohttpparser/picohttpparser.c lib/access_log.c lib/chunked_encoder.c lib/context.c lib/file.c lib/headers.c lib/http1.c lib/http2/connection.c lib/http2/frame.c lib/http2/hpack.c lib/http2/stream.c lib/memory.c lib/mimemap.c lib/request.c lib/rproxy.c lib/socket.c lib/timeout.c lib/token.c lib/util.c)

ADD_EXECUTABLE(examples/simple examples/simple.c)
TARGET_LINK_LIBRARIES(examples/simple h2o ssl crypto)
