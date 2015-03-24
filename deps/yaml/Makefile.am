## Run `./bootstrap` to generate the "Makefile.in" files in this directory and
## the "$SUBDIRS" subdirectories.

SUBDIRS = include src . tests win32

EXTRA_DIST = README LICENSE CMakeLists.txt doc/doxygen.cfg

pkgconfigdir = $(libdir)/pkgconfig
pkgconfig_DATA = yaml-0.1.pc

maintainer-clean-local:
	-rm -f aclocal.m4 config.h.in configure config/*
	-find ${builddir} -name Makefile.in -exec rm -f '{}' ';'

.PHONY: bootstrap
bootstrap: maintainer-clean
	./bootstrap

