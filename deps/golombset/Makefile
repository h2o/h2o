all: test.exe golombset

check: test.exe
	./test.exe

test.exe: test.c golombset.h
	$(CC) -Wall -g test.c -o $@

golombset: cmd.c golombset.h
	$(CC) -Wall -g cmd.c -o $@

clean:
	rm -f test.exe golombset

.PHONY: check clean
