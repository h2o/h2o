CFLAGS+=-g -Wall -O2
LDFLAGS+=$(shell pkg-config --libs libbpf)
OBJS=irqbalance.o

all: irqbalance

irqbalance: $(OBJS)
	$(CC) $(CFLAGS) $< $(LDFLAGS) -o $@

irqbalance.o: irqbalance.skel.h

%.o: %.c
	$(CC) $(FLAGS) -c $< -o $@

%.skel.h: %.bpf.o
	bpftool gen skeleton $< > $@

%.bpf.o: %.bpf.c
	clang $(CFLAGS) -target bpf -c $< -o $@

clean:
	-rm -f *.o *.skel.h

.PHONY: clean
