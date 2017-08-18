include $(top_srcdir)/Makefile.am.common

if BUILD_NC

if ENABLE_NC
bin_PROGRAMS = nc
else
noinst_PROGRAMS = nc
endif

EXTRA_DIST = nc.1
EXTRA_DIST += CMakeLists.txt

nc_LDADD = $(PLATFORM_LDADD) $(PROG_LDADD)
nc_LDADD += $(abs_top_builddir)/crypto/libcrypto.la
nc_LDADD += $(abs_top_builddir)/ssl/libssl.la
nc_LDADD += $(abs_top_builddir)/tls/libtls.la

AM_CPPFLAGS += -I$(top_srcdir)/apps/nc/compat
if OPENSSLDIR_DEFINED
AM_CPPFLAGS += -DDEFAULT_CA_FILE=\"@OPENSSLDIR@/cert.pem\"
else
AM_CPPFLAGS += -DDEFAULT_CA_FILE=\"$(sysconfdir)/ssl/cert.pem\"
endif

nc_SOURCES = atomicio.c
nc_SOURCES += netcat.c
nc_SOURCES += socks.c
noinst_HEADERS = atomicio.h
noinst_HEADERS += compat/sys/socket.h

nc_SOURCES += compat/socket.c

if !HAVE_B64_NTOP
nc_SOURCES += compat/base64.c
endif

if !HAVE_ACCEPT4
nc_SOURCES += compat/accept4.c
endif

if !HAVE_READPASSPHRASE
nc_SOURCES += compat/readpassphrase.c
endif

if !HAVE_STRTONUM
nc_SOURCES += compat/strtonum.c
endif

endif
