CMAKE_MINIMUM_REQUIRED(VERSION 2.8.11)
CMAKE_POLICY(SET CMP0003 NEW)

PROJECT(quicly)

INCLUDE(deps/picotls/cmake/dtrace-utils.cmake)

FIND_PACKAGE(OpenSSL REQUIRED)
IF (OPENSSL_FOUND AND (OPENSSL_VERSION VERSION_LESS "1.0.2"))
    MESSAGE(FATAL "OpenSSL 1.0.2 or above is missing")
ENDIF ()

CHECK_DTRACE(${CMAKE_SOURCE_DIR}/deps/picotls/probes.d)
OPTION(WITH_DTRACE "use USDT (userspace Dtrace probes)" ${HAVE_DTRACE})
IF (WITH_DTRACE)
    MESSAGE(STATUS "Enabling USDT support")
ENDIF ()

SET(CMAKE_C_FLAGS "-std=c99 -Wall -O2 -g ${CC_WARNING_FLAGS} ${CMAKE_C_FLAGS}")
INCLUDE_DIRECTORIES(
    ${OPENSSL_INCLUDE_DIR}
    deps/klib
    deps/picotls/include
    deps/picotest include
    ${CMAKE_CURRENT_BINARY_DIR})

SET(PICOTLS_OPENSSL_FILES
    deps/picotls/lib/openssl.c
    deps/picotls/lib/pembase64.c
    deps/picotls/lib/picotls.c)

SET(QUICLY_LIBRARY_FILES
    lib/frame.c
    lib/loss.c
    lib/cc-reno.c
    lib/defaults.c
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

IF (WITH_DTRACE)
    SET(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -DPICOTLS_USE_DTRACE=1 -DQUICLY_USE_DTRACE=1")
    DEFINE_DTRACE_DEPENDENCIES(${CMAKE_SOURCE_DIR}/deps/picotls/probes.d picotls)
    DEFINE_DTRACE_DEPENDENCIES(${CMAKE_SOURCE_DIR}/probes.d quicly)
    LIST(APPEND PICOTLS_OPENSSL_FILES ${CMAKE_CURRENT_BINARY_DIR}/picotls-probes.h)
    LIST(APPEND QUICLY_LIBRARY_FILES ${CMAKE_CURRENT_BINARY_DIR}/quicly-probes.h)
    LIST(APPEND UNITTEST_SOURCE_FILES ${CMAKE_CURRENT_BINARY_DIR}/quicly-probes.h)
    IF (DTRACE_USES_OBJFILE)
        LIST(APPEND PICOTLS_OPENSSL_FILES ${CMAKE_CURRENT_BINARY_DIR}/picotls-probes.o)
        LIST(APPEND QUICLY_LIBRARY_FILES ${CMAKE_CURRENT_BINARY_DIR}/quicly-probes.o)
        LIST(APPEND UNITTEST_SOURCE_FILES ${CMAKE_CURRENT_BINARY_DIR}/quicly-probes.o)
    ENDIF ()
ENDIF ()

ADD_LIBRARY(quicly ${QUICLY_LIBRARY_FILES})

ADD_EXECUTABLE(cli ${PICOTLS_OPENSSL_FILES} src/cli.c)
TARGET_LINK_LIBRARIES(cli quicly ${OPENSSL_LIBRARIES} ${CMAKE_DL_LIBS})

ADD_EXECUTABLE(test.t ${PICOTLS_OPENSSL_FILES} ${UNITTEST_SOURCE_FILES})
TARGET_LINK_LIBRARIES(test.t quicly ${OPENSSL_LIBRARIES} ${CMAKE_DL_LIBS})

ADD_EXECUTABLE(examples-echo ${PICOTLS_OPENSSL_FILES} examples/echo.c)
TARGET_LINK_LIBRARIES(examples-echo quicly ${OPENSSL_LIBRARIES} ${CMAKE_DL_LIBS})

ADD_EXECUTABLE(udpfw t/udpfw.c)

ADD_CUSTOM_TARGET(check env BINARY_DIR=${CMAKE_CURRENT_BINARY_DIR} WITH_DTRACE=${WITH_DTRACE} prove --exec "sh -c" -v ${CMAKE_CURRENT_BINARY_DIR}/*.t t/*.t
    WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
    DEPENDS cli test.t)

ADD_CUSTOM_TARGET(format clang-format -i `git ls-files include lib src t | egrep '\\.[ch]$$'`)

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

