CMAKE_MINIMUM_REQUIRED(VERSION 2.8)
CMAKE_POLICY(SET CMP0003 NEW)

PROJECT(h2o)

SET(CMAKE_C_FLAGS "-O2 -g -Wall -Wno-unused-function ${CMAKE_C_FLAGS}")

INCLUDE_DIRECTORIES(include deps/picohttpparser deps/klib)

ADD_LIBRARY(libh2o STATIC deps/picohttpparser/picohttpparser.c lib/access_log.c lib/chunked.c lib/context.c lib/file.c lib/headers.c lib/http1.c lib/http2/connection.c lib/http2/frame.c lib/http2/hpack.c lib/http2/stream.c lib/memory.c lib/mimemap.c lib/request.c lib/rproxy.c lib/socket.c lib/timeout.c lib/token.c lib/util.c)
SET_TARGET_PROPERTIES(libh2o PROPERTIES OUTPUT_NAME h2o)

ADD_EXECUTABLE(examples/simple examples/simple.c)
TARGET_LINK_LIBRARIES(examples/simple libh2o ssl crypto uv)

ADD_EXECUTABLE(examples/websocket lib/websocket.c examples/websocket.c)
TARGET_LINK_LIBRARIES(examples/websocket libh2o ssl crypto uv wslay nettle)

# directly links to libh2o using evloop
ADD_EXECUTABLE(h2o deps/picohttpparser/picohttpparser.c lib/access_log.c lib/chunked.c lib/context.c lib/file.c lib/headers.c lib/http1.c lib/http2/connection.c lib/http2/frame.c lib/http2/hpack.c lib/http2/stream.c lib/memory.c lib/mimemap.c lib/request.c lib/rproxy.c lib/socket.c lib/timeout.c lib/token.c lib/util.c src/main.c)
SET_TARGET_PROPERTIES(h2o PROPERTIES COMPILE_FLAGS "-DH2O_USE_LIBUV=0")
TARGET_LINK_LIBRARIES(h2o ssl crypto)
