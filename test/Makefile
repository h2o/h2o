CC=gcc
CXX=g++
CFLAGS=-g -Wall -O2 -I..
CXXFLAGS=$(CFLAGS)
PROGS=kbtree_test khash_keith khash_keith2 khash_test klist_test kseq_test kseq_bench \
		kseq_bench2 ksort_test ksort_test-stl kvec_test kmin_test kstring_bench kstring_bench2

all:$(PROGS)

clean:
		rm -fr $(PROGS) *.dSYM

kbtree_test:kbtree_test.c ../kbtree.h
		$(CC) $(CFLAGS) -o $@ kbtree_test.c

khash_keith:khash_keith.c ../khash.h
		$(CC) $(CFLAGS) -o $@ khash_keith.c

khash_keith2:khash_keith2.c ../khash.h
		$(CC) $(CFLAGS) -o $@ khash_keith2.c

khash_test:khash_test.c ../khash.h
		$(CC) $(CFLAGS) -o $@ khash_test.c

klist_test:klist_test.c ../klist.h
		$(CC) $(CFLAGS) -o $@ klist_test.c

kseq_test:kseq_test.c ../kseq.h
		$(CC) $(CFLAGS) -o $@ kseq_test.c -lz

kseq_bench:kseq_bench.c ../kseq.h
		$(CC) $(CFLAGS) -o $@ kseq_bench.c -lz

kseq_bench2:kseq_bench2.c ../kseq.h
		$(CC) $(CFLAGS) -o $@ kseq_bench2.c -lz

ksort_test:ksort_test.c ../ksort.h
		$(CC) $(CFLAGS) -o $@ ksort_test.c

ksort_test-stl:ksort_test.cc ../ksort.h
		$(CXX) $(CXXFLAGS) -o $@ ksort_test.cc

kvec_test:kvec_test.cc ../kvec.h
		$(CXX) $(CXXFLAGS) -o $@ kvec_test.cc

kmin_test:kmin_test.c ../kmin.h ../kmin.c
		$(CC) $(CFLAGS) -o $@ kmin_test.c ../kmin.c

kstring_bench:kstring_bench.c ../kstring.h ../kstring.c
		$(CC) $(CFLAGS) -o $@ kstring_bench.c ../kstring.c

kstring_bench2:kstring_bench2.c ../kstring.h ../kstring.c
		$(CC) $(CFLAGS) -o $@ kstring_bench2.c ../kstring.c

