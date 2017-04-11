CFLAGS += -g -O0 -std=gnu99 -fPIC -Wall -Wextra -Werror \
	  -Wno-unused-parameter -Wno-missing-field-initializers
CPPFLAGS += -I./ext

ifdef WITH_ASAN
	LDFLAGS += -fsanitize=address
	CFLAGS += -fsanitize=address
endif

ifdef WITH_COVERAGE
	LDFLAGS += -coverage
	CFLAGS += -coverage
endif

ifdef WITH_VALGRIND
	VALGRIND := valgrind --leak-check=full --show-reachable=yes --track-origins=yes
	TEST_OPT := --no-exec
endif

TARGETS = testaes testmodes testsha1 testsha2 testsha3 testsalsa20 \
	  testcurve25519 testpoly1305 testnorx testchacha20poly1305 \
	  testdrbg
all: $(TARGETS)

SOURCES = aes.o sha256.o sha512.o chash.o hmac.o pbkdf2.o modes.o eax.o \
	  gf128.o blockwise.o cmac.o salsa20.o chacha20.o curve25519.o \
	  gcm.o cbcmac.o ccm.o sha3.o sha1.o poly1305.o \
	  norx.o chacha20poly1305.o drbg.o ocb.o

testaes: $(SOURCES) testaes.o
testmodes: $(SOURCES) testmodes.o
testsha1: $(SOURCES) testsha1.o
testsha2: $(SOURCES) testsha2.o
testsha3: $(SOURCES) testsha3.o
testsalsa20: $(SOURCES) testsalsa20.o
testcurve25519: $(SOURCES) testcurve25519.o
testpoly1305: $(SOURCES) testpoly1305.o
testnorx: $(SOURCES) testnorx.o
testchacha20poly1305: $(SOURCES) testchacha20poly1305.o
testdrbg: $(SOURCES) testdrbg.o

clean:
	rm -f *.o *.pyc $(TARGETS) *.gcov *.gcda *.gcno

test: $(TARGETS)
	for x in $(TARGETS) ; do \
		echo "Running $$x" ; \
		$(VALGRIND) ./$$x $(TEST_OPT) ; \
	done

cover: test
	gcov *.c
	echo 'Lines with missing coverage:'
	grep '#####' *.gcov | grep -vE '(cutest|testutil).h.gcov'
