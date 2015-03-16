SOURCE_DIR=.
VERSION=2.1.4
ARCHIVE=$(SOURCE_DIR)/libressl-$(VERSION).tar.gz
DEST=$(shell pwd)/libressl-build

all: $(DEST)/lib/libssl.a

$(DEST)/lib/libssl.a:
	if [ ! -e "libressl-$(VERSION)" ] ; then tar xzf "$(ARCHIVE)" ; fi
	if [ ! -e "libressl-$(VERSION)/Makefile" ] ; then (cd libressl-$(VERSION) && ./configure --prefix="$(DEST)" --disable-shared) ; fi
	(cd libressl-$(VERSION) && make && make install)
