# Tested on FreeBSD, Ubuntu 10.04 and Cygwin
CC=gcc
CFLAGS=-c -Wall -std=c99 -pedantic
LDFLAGS=-lcrypto -lssl

all: test_client

test_client: test_client.o openssl_hostname_validation.o
	$(CC) test_client.o openssl_hostname_validation.o -o test_client $(LDFLAGS)

clean:
	rm -rf *.o test_client
