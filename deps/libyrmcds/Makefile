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
TEST_SOURCES = $(wildcard t/*.c)
TESTS = $(patsubst %.c,%,$(TEST_SOURCES))

all: lib $(EXE)
lib: $(LIB)

# LZ4 is optional.  Run "make lz4; make" to build LZ4 enabled library.
LZ4_TAG = r127
WGET = wget -q -P lz4/lib
lz4:
	mkdir -p lz4/lib
	$(WGET) https://raw.githubusercontent.com/Cyan4973/lz4/$(LZ4_TAG)/lib/lz4.c
	$(WGET) https://raw.githubusercontent.com/Cyan4973/lz4/$(LZ4_TAG)/lib/lz4.h

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

t/%.exe: t/%.c $(LIB)
	$(CC) -I$(shell pwd) $(CFLAGS) $(LDFLAGS) -o $@ $< $(LDLIBS)

$(TESTS): $(LIB)
	@$(MAKE) -s $@.exe
	@echo Running ./$@.exe
	@./$@.exe
	@echo

test: $(TESTS)

html:
	rm -rf html
	doxygen

serve: html
	@cd html; python -m SimpleHTTPServer 8888 || true

clean:
	rm -rf *.o t/*.exe html $(EXE) $(LIB)

setup:
	sudo apt-get install -y $(PACKAGES)

.PHONY: all lib test html serve clean setup
