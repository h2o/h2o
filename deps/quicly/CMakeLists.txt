CMAKE_MINIMUM_REQUIRED(VERSION 2.8.11)
CMAKE_POLICY(SET CMP0003 NEW)

PROJECT(quicly)

FIND_PACKAGE(OpenSSL REQUIRED)
IF (OPENSSL_FOUND AND (OPENSSL_VERSION VERSION_LESS "1.0.2"))
    MESSAGE(FATAL "OpenSSL 1.0.2 or above is missing")
ENDIF ()

SET(CMAKE_C_FLAGS "-std=c99 -Wall -O2 -g ${CC_WARNING_FLAGS} ${CMAKE_C_FLAGS}")
INCLUDE_DIRECTORIES(${OPENSSL_INCLUDE_DIR} deps/dcc deps/klib deps/picotls/include deps/picotest include)

SET(PICOTLS_OPENSSL_FILES
    deps/picotls/lib/openssl.c
    deps/picotls/lib/pembase64.c
    deps/picotls/lib/picotls.c)

SET(QUICLY_LIBRARY_FILES
    deps/dcc/cc.c
    deps/dcc/cc_cubic.c
    deps/dcc/cc_newreno.c
    lib/frame.c
    lib/loss.c
    lib/quicly.c
    lib/ranges.c
    lib/recvstate.c
    lib/sendstate.c
    lib/sentmap.c
    lib/streambuf.c)

SET(UNITTEST_SOURCE_FILES
    deps/picotest/picotest.c
    t/frame.c
    t/maxsender.c
    t/loss.c
    t/ranges.c
    t/sentmap.c
    t/simple.c
    t/stream-concurrency.c
    t/test.c)

ADD_LIBRARY(quicly ${QUICLY_LIBRARY_FILES})

ADD_EXECUTABLE(cli ${PICOTLS_OPENSSL_FILES} src/cli.c)
TARGET_LINK_LIBRARIES(cli quicly ${OPENSSL_LIBRARIES} ${CMAKE_DL_LIBS})

ADD_EXECUTABLE(test.t ${PICOTLS_OPENSSL_FILES} ${UNITTEST_SOURCE_FILES})
TARGET_LINK_LIBRARIES(test.t quicly ${OPENSSL_LIBRARIES} ${CMAKE_DL_LIBS})

ADD_EXECUTABLE(udpfw t/udpfw.c)

ADD_CUSTOM_TARGET(check env BINARY_DIR=${CMAKE_CURRENT_BINARY_DIR} prove --exec "sh -c" -v ${CMAKE_CURRENT_BINARY_DIR}/*.t t/*.t
    WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
    DEPENDS cli test.t)

IF (CMAKE_SYSTEM_NAME STREQUAL "Linux")
     SET(CMAKE_C_FLAGS "-D_GNU_SOURCE -pthread ${CMAKE_C_FLAGS}")
ENDIF ()

IF (BUILD_FUZZER)
    IF(NOT CMAKE_CXX_COMPILER_ID STREQUAL "Clang")
        MESSAGE(FATAL_ERROR "The fuzzer needs clang as a compiler")
    ENDIF()
    ADD_EXECUTABLE(quicly-fuzzer-packet fuzz/packet.cc ${PICOTLS_OPENSSL_FILES})
    SET(LIB_FUZZER "${CMAKE_CURRENT_BINARY_DIR}/libFuzzer.a")
    SET(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fno-omit-frame-pointer -fsanitize=address,undefined -fsanitize-coverage=edge,indirect-calls,8bit-counters")
    SET(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -g -fno-omit-frame-pointer -fsanitize=address,undefined -fsanitize-coverage=edge,indirect-calls,8bit-counters")
    SET(CMAKE_EXE_LINKER_FLAGS "${CMAKE_C_FLAGS}")

    ADD_CUSTOM_TARGET(libFuzzer ${CMAKE_CURRENT_SOURCE_DIR}/misc/build_libFuzzer.sh WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR})
    ADD_DEPENDENCIES(quicly-fuzzer-packet libFuzzer)
    TARGET_LINK_LIBRARIES(quicly-fuzzer-packet quicly ${OPENSSL_LIBRARIES} ${CMAKE_DL_LIBS} ${LIB_FUZZER})
ENDIF()

