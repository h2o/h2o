CC?=     cc
CFLAGS+= -Wall -fsanitize=address -fstack-protector -g
LIBS+=   -lpthread -lssl -lcrypto
TARGET=  test-neverbleed
OBJS=    test.o neverbleed.o

all:    $(TARGET)

.c.o:
	$(CC) $(CFLAGS) -c $<

$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) -o $@ $(OBJS) $(LIBS) $(LDFLAGS)

check: $(TARGET)
	prove -v t/test_handshake.t

clean:
	rm -fr $(OBJS) $(TARGET)

.PHONY: clean check
