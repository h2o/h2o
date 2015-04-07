SOURCE_DIR=.
VERSION=2.1.6
ARCHIVE=$(SOURCE_DIR)/libressl-$(VERSION).tar.gz
DEST=libressl-build

all: $(DEST)/lib/libssl.a

$(DEST)/lib/libssl.a:
	if [ ! -e "libressl-$(VERSION)" ] ; then tar xzf "$(ARCHIVE)" ; fi
	if [ ! -e "libressl-$(VERSION)/Makefile" ] ; then (P=`pwd`/$(DEST); cd libressl-$(VERSION) && ./configure --prefix="$$P" --disable-shared) ; fi
	(cd libressl-$(VERSION) && make && make install)
