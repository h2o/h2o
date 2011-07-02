#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include "kstring.h"

#define N 10000000

int main()
{
	int i;
	clock_t t;
	kstring_t s, s2;
	srand48(11);
	s.l = s.m = 0; s.s = 0;
	t = clock();
	for (i = 0; i < N; ++i) {
		int x = lrand48();
		s.l = 0;
		kputw(x, &s);
	}
	fprintf(stderr, "kputw: %lf\n", (double)(clock() - t) / CLOCKS_PER_SEC);
	srand48(11);
	t = clock();
	for (i = 0; i < N; ++i) {
		int x = lrand48();
		s.l = 0;
		ksprintf(&s, "%d", x);
	}
	fprintf(stderr, "ksprintf: %lf\n", (double)(clock() - t) / CLOCKS_PER_SEC);

	srand48(11);
	s2.l = s2.m = 0; s2.s = 0;
	t = clock();
	for (i = 0; i < N; ++i) {
		int x = lrand48();
		s2.l = s.l = 0;
		kputw(x, &s2);
		kputs(s2.s, &s);
	}
	fprintf(stderr, "kputw+kputs: %lf\n", (double)(clock() - t) / CLOCKS_PER_SEC);
	srand48(11);
	t = clock();
	for (i = 0; i < N; ++i) {
		int x = lrand48();
		s2.l = s.l = 0;
		kputw(x, &s2);
		ksprintf(&s, "%s", s2.s);
	}
	fprintf(stderr, "kputw+ksprintf: %lf\n", (double)(clock() - t) / CLOCKS_PER_SEC);
	return 0;
}
