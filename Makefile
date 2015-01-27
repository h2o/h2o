# Makefile for libyrmcds

PREFIX = /usr/local

CC = gcc
CXX = g++ -std=gnu++11
CPPFLAGS = -D_GNU_SOURCE

# Uncomment the next line to remove the internal lock used to
# serialize sending commands.
#
#CPPFLAGS += -DLIBYRMCDS_NO_INTERNAL_LOCK

OPTFLAGS = -gdwarf-3 -O2
CFLAGS = -Wall -Wconversion $(OPTFLAGS)
CXXFLAGS = $(CFLAGS) -Wnon-virtual-dtor -Woverloaded-virtual
LDFLAGS = -L.
LDLIBS = -lyrmcds -lpthread

EXE = yc yc-cnt
LIB = libyrmcds.a
PACKAGES = build-essential subversion doxygen

CHEADERS = $(wildcard *.h)
CSOURCES = $(wildcard *.c)
COBJECTS = $(patsubst %.c,%.o,$(CSOURCES))
LIB_OBJECTS = $(filter-out yc.o yc-cnt.o,$(COBJECTS))

all: lib $(EXE)
lib: $(LIB)

# LZ4 is optional.  Run "make lz4; make" to build LZ4 enabled library.
lz4:
	svn checkout -r 127 http://lz4.googlecode.com/svn/trunk/ lz4

ifeq ($(wildcard lz4), lz4)
$(info LZ4 transparent compression is *enabled*)
CPPFLAGS += -DLIBYRMCDS_USE_LZ4
LZ4_CFLAGS = -std=c99 -O3
lz4/lib/lz4.o: lz4/lib/lz4.c
	$(CC) $(LZ4_CFLAGS) -Ilz4/lib -c -o $@ $<
LIB_OBJECTS += lz4/lib/lz4.o
endif

yc: yc.o
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $< $(LDLIBS)

yc-cnt: yc-cnt.o
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $< $(LDLIBS)

$(COBJECTS): $(CHEADERS)
$(EXE): $(LIB)

$(LIB): $(LIB_OBJECTS)
	$(AR) rcs $@ $^

html:
	rm -rf html
	doxygen

serve: html
	@cd html; python -m SimpleHTTPServer 8888 || true

clean:
	rm -rf *.o html $(EXE) $(LIB)

setup:
	sudo apt-get install -y $(PACKAGES)

.PHONY: all lib tests install html serve clean setup
