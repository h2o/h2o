CMAKE_MINIMUM_REQUIRED(VERSION 2.8)
CMAKE_POLICY(SET CMP0003 NEW)

PROJECT(h2o)

SET(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall -Wno-unused-function -g")

INCLUDE_DIRECTORIES(include deps/picohttpparser deps/klib)

ADD_LIBRARY(core OBJECT deps/picohttpparser/picohttpparser.c src/access_log.c src/chunked_encoder.c src/file.c src/headers.c src/http1.c src/loop_context.c src/mempool.c src/mimemap.c src/request.c src/rproxy.c src/timeout.c src/token.c src/util.c)

ADD_EXECUTABLE(examples/simple examples/simple.c $<TARGET_OBJECTS:core>)
TARGET_LINK_LIBRARIES(examples/simple uv)
