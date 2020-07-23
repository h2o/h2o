FUNCTION (CHECK_DTRACE d_file)
    MESSAGE(STATUS "Detecting USDT support")
    SET(HAVE_DTRACE "OFF" PARENT_SCOPE)
    SET(DTRACE_USES_OBJFILE "OFF" PARENT_SCOPE)
    IF ((CMAKE_SYSTEM_NAME STREQUAL "Darwin") OR (CMAKE_SYSTEM_NAME STREQUAL "Linux"))
        # USDT is not (yet) supported on platforms (e.g., FreeBSD, Solaris) that require pre-link modification of .o files
        EXECUTE_PROCESS(
            COMMAND dtrace -o .tmp.dprobes.h -s ${d_file} -h
            RESULT_VARIABLE DTRACE_RESULT)
        FILE(REMOVE .tmp.dprobes.h)
        IF (DTRACE_RESULT EQUAL 0)
            MESSAGE(STATUS "Detecting USDT support - found")
            SET(HAVE_DTRACE "ON" PARENT_SCOPE)
            IF (CMAKE_SYSTEM_NAME STREQUAL "Linux")
                SET(DTRACE_USES_OBJFILE "ON" PARENT_SCOPE)
            ENDIF ()
        ELSE ()
            MESSAGE(STATUS "Detecting USDT support - not found")
        ENDIF ()
    ELSE ()
        MESSAGE(STATUS "Detecting USDT support - disabled on this platform")
    ENDIF ()
ENDFUNCTION ()

FUNCTION (DEFINE_DTRACE_DEPENDENCIES d_file prefix)
    ADD_CUSTOM_COMMAND(
        OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/${prefix}-probes.h
        COMMAND dtrace -o ${CMAKE_CURRENT_BINARY_DIR}/${prefix}-probes.h -s ${d_file} -h
        DEPENDS ${d_file})
    ADD_CUSTOM_TARGET(generate-${prefix}-probes DEPENDS ${CMAKE_CURRENT_BINARY_DIR}/${prefix}-probes.h)
    SET_SOURCE_FILES_PROPERTIES(${CMAKE_CURRENT_BINARY_DIR}/${prefix}-probes.h PROPERTIES GENERATED TRUE)
    IF (DTRACE_USES_OBJFILE)
        ADD_CUSTOM_COMMAND(
            OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/${prefix}-probes.o
            COMMAND dtrace -o ${CMAKE_CURRENT_BINARY_DIR}/${prefix}-probes.o -s ${d_file} -G
            DEPENDS ${d_file})
        ADD_DEPENDENCIES(generate-${prefix}-probes ${CMAKE_CURRENT_BINARY_DIR}/${prefix}-probes.o)
        SET_SOURCE_FILES_PROPERTIES(${CMAKE_CURRENT_BINARY_DIR}/${prefix}-probes.o PROPERTIES GENERATED TRUE)
    ENDIF ()
ENDFUNCTION ()
