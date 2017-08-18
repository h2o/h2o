include_directories(
	.
	../include
	../include/compat
)

set(
	SSL_SRC
	bio_ssl.c
	bs_ber.c
	bs_cbb.c
	bs_cbs.c
	d1_both.c
	d1_clnt.c
	d1_enc.c
	d1_lib.c
	d1_meth.c
	d1_pkt.c
	d1_srtp.c
	d1_srvr.c
	pqueue.c
	s23_clnt.c
	s23_lib.c
	s23_pkt.c
	s23_srvr.c
	s3_both.c
	s3_cbc.c
	s3_clnt.c
	s3_lib.c
	s3_pkt.c
	s3_srvr.c
	ssl_algs.c
	ssl_asn1.c
	ssl_cert.c
	ssl_ciph.c
	ssl_err.c
	ssl_err2.c
	ssl_lib.c
	ssl_rsa.c
	ssl_sess.c
	ssl_stat.c
	ssl_txt.c
	t1_clnt.c
	t1_enc.c
	t1_lib.c
	t1_meth.c
	t1_reneg.c
	t1_srvr.c
)

if (BUILD_SHARED)
	add_library(ssl-objects OBJECT ${SSL_SRC})
	add_library(ssl STATIC $<TARGET_OBJECTS:ssl-objects>)
	add_library(ssl-shared SHARED $<TARGET_OBJECTS:ssl-objects>)
	if (MSVC)
		target_link_libraries(ssl-shared crypto-shared Ws2_32.lib)
	endif()
	set_target_properties(ssl-shared PROPERTIES OUTPUT_NAME ssl)
	set_target_properties(ssl-shared PROPERTIES VERSION ${SSL_VERSION}
		SOVERSION ${SSL_MAJOR_VERSION})
	install(TARGETS ssl ssl-shared DESTINATION lib)
else()
	add_library(ssl STATIC ${SSL_SRC})
	install(TARGETS ssl DESTINATION lib)
endif()
