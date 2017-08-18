if(BUILD_NC)

include_directories(
	.
	./compat
	../../include
	../../include/compat
)

set(
	NC_SRC
	atomicio.c
	netcat.c
	socks.c
	compat/socket.c
)

check_function_exists(b64_ntop HAVE_B64_NTOP)
if(HAVE_B64_NTOP)
	add_definitions(-DHAVE_B64_NTOP)
else()
	set(NC_SRC ${NC_SRC} compat/base64.c)
endif()

check_function_exists(accept4 HAVE_ACCEPT4)
if(HAVE_ACCEPT4)
	add_definitions(-DHAVE_ACCEPT4)
else()
	set(NC_SRC ${NC_SRC} compat/accept4.c)
endif()

check_function_exists(readpassphrase HAVE_READPASSPHRASE)
if(HAVE_READPASSPHRASE)
	add_definitions(-DHAVE_READPASSPHRASE)
else()
	set(NC_SRC ${NC_SRC} compat/readpassphrase.c)
endif()

check_function_exists(strtonum HAVE_STRTONUM)
if(HAVE_STRTONUM)
	add_definitions(-DHAVE_STRTONUM)
else()
	set(NC_SRC ${NC_SRC} compat/strtonum.c)
endif()

if(NOT "${OPENSSLDIR}" STREQUAL "")
	add_definitions(-DDEFAULT_CA_FILE=\"${OPENSSLDIR}/cert.pem\")
else()
	add_definitions(-DDEFAULT_CA_FILE=\"${CMAKE_INSTALL_PREFIX}/etc/ssl/cert.pem\")
endif()

add_executable(nc ${NC_SRC})
target_link_libraries(nc tls ${OPENSSL_LIBS})

if(ENABLE_NC)
	install(TARGETS nc DESTINATION bin)
	install(FILES nc.1 DESTINATION share/man/man1)
endif()

endif()
