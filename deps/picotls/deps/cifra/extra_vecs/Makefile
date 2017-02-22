CFLAGS += -std=gnu99 -O0 -g -Wall -Werror

all: run

openssl-hash: openssl-hash.c
	$(CC) $(CFLAGS) -o $@ $^ -lcrypto

run: openssl-hash
	./openssl-hash
	python python-hash.py

clean:
	rm -rf *.o openssl-hash
