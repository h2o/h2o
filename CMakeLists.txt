CMAKE_MINIMUM_REQUIRED(VERSION 2.8)
CMAKE_POLICY(SET CMP0003 NEW)

PROJECT(h2o)

SET(CMAKE_C_FLAGS "-O2 -g -Wall -Wno-unused-function ${CMAKE_C_FLAGS}")

INCLUDE_DIRECTORIES(include deps/picohttpparser deps/klib)

ADD_LIBRARY(h2o STATIC deps/picohttpparser/picohttpparser.c src/access_log.c src/chunked_encoder.c src/file.c src/headers.c src/http1.c src/http2/connection.c src/http2/frame.c src/http2/hpack.c src/http2/stream.c src/loop_context.c src/memory.c src/mimemap.c src/request.c src/rproxy.c src/socket.c src/socket_loop.c src/timeout.c src/token.c src/util.c)

ADD_EXECUTABLE(examples/simple examples/simple.c)
TARGET_LINK_LIBRARIES(examples/simple h2o ssl crypto)
