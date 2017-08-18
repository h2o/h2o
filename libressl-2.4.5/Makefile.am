SUBDIRS = crypto ssl tls include apps tests man
ACLOCAL_AMFLAGS = -I m4

pkgconfigdir = $(libdir)/pkgconfig
pkgconfig_DATA = libcrypto.pc libssl.pc libtls.pc openssl.pc

EXTRA_DIST = README.md README.windows VERSION config scripts
EXTRA_DIST += CMakeLists.txt cmake_uninstall.cmake.in

.PHONY: install_sw
install_sw: install
