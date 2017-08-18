cmake_minimum_required (VERSION 2.8.8)
include(CheckFunctionExists)
include(CheckLibraryExists)
include(CheckIncludeFiles)
include(CheckTypeSize)

project (LibreSSL C)

enable_testing()

file(READ ${CMAKE_SOURCE_DIR}/ssl/VERSION SSL_VERSION)
string(STRIP ${SSL_VERSION} SSL_VERSION)
string(REPLACE ":" "." SSL_VERSION ${SSL_VERSION})
string(REGEX REPLACE "\\..*" "" SSL_MAJOR_VERSION ${SSL_VERSION})

file(READ ${CMAKE_SOURCE_DIR}/crypto/VERSION CRYPTO_VERSION)
string(STRIP ${CRYPTO_VERSION} CRYPTO_VERSION)
string(REPLACE ":" "." CRYPTO_VERSION ${CRYPTO_VERSION})
string(REGEX REPLACE "\\..*" "" CRYPTO_MAJOR_VERSION ${CRYPTO_VERSION})

file(READ ${CMAKE_SOURCE_DIR}/tls/VERSION TLS_VERSION)
string(STRIP ${TLS_VERSION} TLS_VERSION)
string(REPLACE ":" "." TLS_VERSION ${TLS_VERSION})
string(REGEX REPLACE "\\..*" "" TLS_MAJOR_VERSION ${TLS_VERSION})

option(ENABLE_ASM "Enable assembly" ON)
option(ENABLE_EXTRATESTS "Enable extra tests that may be unreliable on some platforms" OFF)
option(ENABLE_NC "Enable installing TLS-enabled nc(1)" OFF)
set(OPENSSLDIR ${OPENSSLDIR} CACHE PATH "Set the default openssl directory" FORCE)

set(BUILD_NC true)

if(CMAKE_SYSTEM_NAME MATCHES "Darwin")
	add_definitions(-fno-common)
endif()

if(CMAKE_SYSTEM_NAME MATCHES "OpenBSD")
	add_definitions(-DHAVE_ATTRIBUTE__BOUNDED__)
endif()

if(CMAKE_SYSTEM_NAME MATCHES "Linux")
	add_definitions(-D_DEFAULT_SOURCE)
	add_definitions(-D_BSD_SOURCE)
	add_definitions(-D_POSIX_SOURCE)
	add_definitions(-D_GNU_SOURCE)
endif()

if(CMAKE_SYSTEM_NAME MATCHES "MINGW")
	set(BUILD_NC false)
endif()

if(MSVC)
	set(BUILD_NC false)
endif()

if(CMAKE_SYSTEM_NAME MATCHES "HP-UX")
	if(CMAKE_C_COMPILER MATCHES "gcc")
		set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall -std=gnu99 -fno-strict-aliasing")
		set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -mlp64")
	else()
		set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -g -O2 +DD64 +Otype_safety=off")
	endif()
	set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -D_XOPEN_SOURCE=600 -D__STRICT_ALIGNMENT")
endif()

if(CMAKE_SYSTEM_NAME MATCHES "SunOS")
	set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall -std=gnu99 -fno-strict-aliasing")
	set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -D__EXTENSIONS__")
	set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -D_XOPEN_SOURCE=600")
	set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -DBSD_COMP")
	set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fpic -m64")
endif()

add_definitions(-DLIBRESSL_INTERNAL)
add_definitions(-DOPENSSL_NO_HW_PADLOCK)

set(CMAKE_POSITION_INDEPENDENT_CODE true)

if (CMAKE_COMPILER_IS_GNUCC OR CMAKE_C_COMPILER_ID MATCHES "Clang")
	add_definitions(-Wno-pointer-sign)
endif()

if(MSVC)
	add_definitions(-Dinline=__inline)
	add_definitions(-Drestrict)
	add_definitions(-D_CRT_SECURE_NO_WARNINGS)
	add_definitions(-D_CRT_DEPRECATED_NO_WARNINGS)
	add_definitions(-D_REENTRANT -D_POSIX_THREAD_SAFE_FUNCTIONS)
	add_definitions(-DWIN32_LEAN_AND_MEAN -D_WIN32_WINNT=0x0501)
	add_definitions(-DCPPFLAGS -DOPENSSL_NO_SPEED -DNO_SYSLOG -DNO_CRYPT)

	set(MSVC_DISABLED_WARNINGS_LIST
		"C4057" # C4057: 'initializing' : 'unsigned char *' differs in
		        # indirection to slightly different base types from 'char [2]'
		"C4100" # 'exarg' : unreferenced formal parameter
		"C4127" # conditional expression is constant
		"C4242" # 'function' : conversion from 'int' to 'uint8_t',
		        # possible loss of data
		"C4244" # 'function' : conversion from 'int' to 'uint8_t',
		        # possible loss of data
		"C4706" # assignment within conditional expression
		"C4820" # 'bytes' bytes padding added after construct 'member_name'
		"C4996" # 'read': The POSIX name for this item is deprecated. Instead,
		        # use the ISO C++ conformant name: _read.
	)
	string(REPLACE "C" " -wd" MSVC_DISABLED_WARNINGS_STR
		${MSVC_DISABLED_WARNINGS_LIST})
	set(CMAKE_C_FLAGS  "-MP -W4 ${MSVC_DISABLED_WARNINGS_STR}")
endif()

check_function_exists(asprintf HAVE_ASPRINTF)
if(HAVE_ASPRINTF)
	add_definitions(-DHAVE_ASPRINTF)
endif()

check_function_exists(inet_pton HAVE_INET_PTON)
if(HAVE_INET_PTON)
	add_definitions(-DHAVE_INET_PTON)
endif()

check_function_exists(reallocarray HAVE_REALLOCARRAY)
if(HAVE_REALLOCARRAY)
	add_definitions(-DHAVE_REALLOCARRAY)
endif()

check_function_exists(strcasecmp HAVE_STRCASECMP)
if(HAVE_STRCASECMP)
	add_definitions(-DHAVE_STRCASECMP)
endif()

check_function_exists(strlcat HAVE_STRLCAT)
if(HAVE_STRLCAT)
	add_definitions(-DHAVE_STRLCAT)
endif()

check_function_exists(strlcpy HAVE_STRLCPY)
if(HAVE_STRLCPY)
	add_definitions(-DHAVE_STRLCPY)
endif()

check_function_exists(strndup HAVE_STRNDUP)
if(HAVE_STRNDUP)
	add_definitions(-DHAVE_STRNDUP)
endif()

if(MSVC)
	set(HAVE_STRNLEN true)
	add_definitions(-DHAVE_STRNLEN)
else()
	check_function_exists(strnlen HAVE_STRNLEN)
	if(HAVE_STRNLEN)
		add_definitions(-DHAVE_STRNLEN)
	endif()
endif()

check_function_exists(strsep HAVE_STRSEP)
if(HAVE_STRSEP)
	add_definitions(-DHAVE_STRSEP)
endif()

check_function_exists(timegm HAVE_TIMEGM)
if(HAVE_TIMEGM)
	add_definitions(-DHAVE_TIMEGM)
endif()

check_function_exists(arc4random_buf HAVE_ARC4RANDOM_BUF)
if(HAVE_ARC4RANDOM_BUF)
	add_definitions(-DHAVE_ARC4RANDOM_BUF)
endif()

check_function_exists(arc4random_uniform HAVE_ARC4RANDOM_UNIFORM)
if(HAVE_ARC4RANDOM_UNIFORM)
	add_definitions(-DHAVE_ARC4RANDOM_UNIFORM)
endif()

check_function_exists(explicit_bzero HAVE_EXPLICIT_BZERO)
if(HAVE_EXPLICIT_BZERO)
	add_definitions(-DHAVE_EXPLICIT_BZERO)
endif()

check_function_exists(getauxval HAVE_GETAUXVAL)
if(HAVE_GETAUXVAL)
	add_definitions(-DHAVE_GETAUXVAL)
endif()

check_function_exists(getentropy HAVE_GETENTROPY)
if(HAVE_GETENTROPY)
	add_definitions(-DHAVE_GETENTROPY)
endif()

check_function_exists(timingsafe_bcmp HAVE_TIMINGSAFE_BCMP)
if(HAVE_TIMINGSAFE_BCMP)
	add_definitions(-DHAVE_TIMINGSAFE_BCMP)
endif()

check_function_exists(timingsafe_memcmp HAVE_TIMINGSAFE_MEMCMP)
if(HAVE_MEMCMP)
	add_definitions(-DHAVE_MEMCMP)
endif()

check_function_exists(memmem HAVE_MEMMEM)
if(HAVE_MEMMEM)
	add_definitions(-DHAVE_MEMMEM)
endif()

check_include_files(err.h HAVE_ERR_H)
if(HAVE_ERR_H)
	add_definitions(-DHAVE_ERR_H)
endif()

if(ENABLE_ASM)
	if("${CMAKE_C_COMPILER_ABI}" STREQUAL "ELF")
		if("${CMAKE_SYSTEM_PROCESSOR}" MATCHES "(x86_64|amd64)")
			set(HOST_ASM_ELF_X86_64 true)
		elseif(CMAKE_SYSTEM_NAME STREQUAL "SunOS" AND "${CMAKE_SYSTEM_PROCESSOR}" STREQUAL "i386")
			set(HOST_ASM_ELF_X86_64 true)
		endif()
	elseif(APPLE AND "${CMAKE_SYSTEM_PROCESSOR}" STREQUAL "x86_64")
		set(HOST_ASM_MACOSX_X86_64 true)
	endif()
endif()

set(OPENSSL_LIBS ssl crypto)
if(CMAKE_HOST_WIN32)
	set(OPENSSL_LIBS ${OPENSSL_LIBS} ws2_32)
endif()
if(CMAKE_SYSTEM_NAME MATCHES "Linux")
	check_library_exists(rt clock_gettime "time.h" HAVE_CLOCK_GETTIME)
	if (HAVE_CLOCK_GETTIME)
		set(OPENSSL_LIBS ${OPENSSL_LIBS} rt)
	endif()
endif()
if(CMAKE_SYSTEM_NAME MATCHES "HP-UX")
	set(OPENSSL_LIBS ${OPENSSL_LIBS} pthread)
endif()
if(CMAKE_SYSTEM_NAME MATCHES "SunOS")
	set(OPENSSL_LIBS ${OPENSSL_LIBS} nsl socket)
endif()

if(NOT (CMAKE_SYSTEM_NAME MATCHES "(Darwin|MINGW|CYGWIN)" OR MSVC))
	set(BUILD_SHARED true)
endif()

check_type_size(time_t SIZEOF_TIME_T)
if(SIZEOF_TIME_T STREQUAL "4")
	set(SMALL_TIME_T true)
	message(WARNING " ** Warning, this system is unable to represent times past 2038\n"
	                " ** It will behave incorrectly when handling valid RFC5280 dates")
endif()
add_definitions(-DSIZEOF_TIME_T=${SIZEOF_TIME_T})

add_subdirectory(crypto)
add_subdirectory(ssl)
add_subdirectory(apps)
add_subdirectory(tls)
add_subdirectory(include)
if(NOT MSVC)
	add_subdirectory(man)
	add_subdirectory(tests)
endif()

configure_file(
	"${CMAKE_CURRENT_SOURCE_DIR}/cmake_uninstall.cmake.in"
	"${CMAKE_CURRENT_BINARY_DIR}/cmake_uninstall.cmake"
	IMMEDIATE @ONLY)

add_custom_target(uninstall
	COMMAND ${CMAKE_COMMAND} -P ${CMAKE_CURRENT_BINARY_DIR}/cmake_uninstall.cmake)
