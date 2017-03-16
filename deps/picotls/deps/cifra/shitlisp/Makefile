CFLAGS += -g -O0 -std=gnu99 -fPIC -Wall -Wextra -Werror -Wno-unused-parameter
CPPFLAGS += -I../src -I../../bignum/out -I../../shitlisp/out

all: cifra.so

SOURCES = aes.o sha256.o sha512.o chash.o hmac.o pbkdf2.o modes.o eax.o \
	  blockwise.o cmac.o salsa20.o chacha20.o curve25519.o

cifra.so: $(addprefix ../src/, $(SOURCES)) sl-cifra.o
	$(CC) $(CPPFLAGS) $(CFLAGS) -o $@ $^ -shared

clean:
	rm -f *.o *.pyc $(TARGETS) *.gcov *.gcda *.gcno

test: $(wildcard test-*.sl) cifra.so
	../../shitlisp/out/shitlisp --mod=./cifra.so $(wildcard test-*.sl)

