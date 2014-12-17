#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <time.h>
#include "ksort.h"

KSORT_INIT_GENERIC(int)

int main(int argc, char *argv[])
{
	int i, N = 10000000;
	int *array, x;
	clock_t t1, t2;
	if (argc > 1) N = atoi(argv[1]);
	array = (int*)malloc(sizeof(int) * N);

	srand48(11);
	for (i = 0; i < N; ++i) array[i] = (int)lrand48();
	t1 = clock();
	x = ks_ksmall(int, N, array, 10500);
	t2 = clock();
	fprintf(stderr, "ksmall [%d]: %.3lf\n", x, (double)(t2-t1)/CLOCKS_PER_SEC);

	srand48(11);
	for (i = 0; i < N; ++i) array[i] = (int)lrand48();
	t1 = clock();
	ks_introsort(int, N, array);
	t2 = clock();
	fprintf(stderr, "introsort [%d]: %.3lf\n", array[10500], (double)(t2-t1)/CLOCKS_PER_SEC);
	for (i = 0; i < N-1; ++i) {
		if (array[i] > array[i+1]) {
			fprintf(stderr, "Bug in introsort!\n");
			exit(1);
		}
	}

#ifndef _ALIGNED_ONLY
	{ // test unaligned ksmall
		srand48(11);
		unsigned char *a;
		int *b;
		a = malloc(N * sizeof(int) + 1);
		b = (int*)(a + 1);
		for (i = 0; i < N; ++i) b[i] = (int)lrand48();
		t1 = clock();
		ks_introsort(int, N, b);
		t2 = clock();
		fprintf(stderr, "introsort [%d]: %.3lf (unaligned: 0x%lx) \n", b[10500], (double)(t2-t1)/CLOCKS_PER_SEC, (size_t)b);
	}
#endif

	t1 = clock();
	ks_introsort(int, N, array);
	t2 = clock();
	fprintf(stderr, "introsort (sorted): %.3lf\n", (double)(t2-t1)/CLOCKS_PER_SEC);

	srand48(11);
	for (i = 0; i < N; ++i) array[i] = (int)lrand48();
	t1 = clock();
	ks_combsort(int, N, array);
	t2 = clock();
	fprintf(stderr, "combsort: %.3lf\n", (double)(t2-t1)/CLOCKS_PER_SEC);
	for (i = 0; i < N-1; ++i) {
		if (array[i] > array[i+1]) {
			fprintf(stderr, "Bug in combsort!\n");
			exit(1);
		}
	}

	srand48(11);
	for (i = 0; i < N; ++i) array[i] = (int)lrand48();
	t1 = clock();
	ks_mergesort(int, N, array, 0);
	t2 = clock();
	fprintf(stderr, "mergesort: %.3lf\n", (double)(t2-t1)/CLOCKS_PER_SEC);
	for (i = 0; i < N-1; ++i) {
		if (array[i] > array[i+1]) {
			fprintf(stderr, "Bug in mergesort!\n");
			exit(1);
		}
	}

	t1 = clock();
	ks_mergesort(int, N, array, 0);
	t2 = clock();
	fprintf(stderr, "mergesort (sorted): %.3lf\n", (double)(t2-t1)/CLOCKS_PER_SEC);

	srand48(11);
	for (i = 0; i < N; ++i) array[i] = (int)lrand48();
	t1 = clock();
	ks_heapmake(int, N, array);
	ks_heapsort(int, N, array);
	t2 = clock();
	fprintf(stderr, "heapsort: %.3lf\n", (double)(t2-t1)/CLOCKS_PER_SEC);
	for (i = 0; i < N-1; ++i) {
		if (array[i] > array[i+1]) {
			fprintf(stderr, "Bug in heapsort!\n");
			exit(1);
		}
	}

	free(array);
	return 0;
}
