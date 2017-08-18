include_directories(
	.
	../../include
	../../include/compat
)

set(
	OPENSSL_SRC
	apps.c
	asn1pars.c
	ca.c
	ciphers.c
	cms.c
	crl.c
	crl2p7.c
	dgst.c
	dh.c
	dhparam.c
	dsa.c
	dsaparam.c
	ec.c
	ecparam.c
	enc.c
	errstr.c
	gendh.c
	gendsa.c
	genpkey.c
	genrsa.c
	nseq.c
	ocsp.c
	openssl.c
	passwd.c
	pkcs12.c
	pkcs7.c
	pkcs8.c
	pkey.c
	pkeyparam.c
	pkeyutl.c
	prime.c
	rand.c
	req.c
	rsa.c
	rsautl.c
	s_cb.c
	s_client.c
	s_server.c
	s_socket.c
	s_time.c
	sess_id.c
	smime.c
	speed.c
	spkac.c
	ts.c
	verify.c
	version.c
	x509.c
)

if(CMAKE_HOST_UNIX)
	set(OPENSSL_SRC ${OPENSSL_SRC} apps_posix.c)
	set(OPENSSL_SRC ${OPENSSL_SRC} certhash.c)
endif()

if(CMAKE_HOST_WIN32)
	set(OPENSSL_SRC ${OPENSSL_SRC} apps_win.c)
	set(OPENSSL_SRC ${OPENSSL_SRC} certhash_win.c)
	set(OPENSSL_SRC ${OPENSSL_SRC} compat/poll_win.c)
endif()

check_function_exists(strtonum HAVE_STRTONUM)
if(HAVE_STRTONUM)
	add_definitions(-DHAVE_STRTONUM)
else()
	set(OPENSSL_SRC ${OPENSSL_SRC} compat/strtonum.c)
endif()

add_executable(openssl ${OPENSSL_SRC})
target_link_libraries(openssl ${OPENSSL_LIBS})

install(TARGETS openssl DESTINATION bin)
install(FILES openssl.1 DESTINATION share/man/man1)

if(NOT "${OPENSSLDIR}" STREQUAL "")
	set(CONF_DIR "${OPENSSLDIR}")
else()
	set(CONF_DIR "${CMAKE_INSTALL_PREFIX}/etc/ssl")
endif()
install(FILES cert.pem openssl.cnf x509v3.cnf DESTINATION ${CONF_DIR})
install(DIRECTORY DESTINATION ${CONF_DIR}/cert)
