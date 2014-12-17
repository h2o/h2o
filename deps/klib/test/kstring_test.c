#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "kstring.h"

int nfail = 0;

void check(const char *what, const kstring_t *ks, const char *correct)
{
	if (ks->l != strlen(correct) || strcmp(ks->s, correct) != 0) {
		fprintf(stderr, "%s produced \"%.*s\" (\"%s\" is correct)\tFAIL\n", what, (int)(ks->l), ks->s, correct);
		nfail++;
	}
}

void test_kputw(kstring_t *ks, int n)
{
	char buf[16];

	ks->l = 0;
	kputw(n, ks);

	sprintf(buf, "%d", n);
	check("kputw()", ks, buf);
}

void test_kputl(kstring_t *ks, long n)
{
	char buf[24];

	ks->l = 0;
	kputl(n, ks);

	sprintf(buf, "%ld", n);
	check("kputl()", ks, buf);
}

int main()
{
	kstring_t ks;

	ks.l = ks.m = 0;
	ks.s = NULL;

	test_kputw(&ks, 0);
	test_kputw(&ks, 1);
	test_kputw(&ks, 37);
	test_kputw(&ks, 12345);
	test_kputw(&ks, -12345);
	test_kputw(&ks, INT_MAX);
	test_kputw(&ks, -INT_MAX);
	test_kputw(&ks, INT_MIN);

	test_kputl(&ks, 0);
	test_kputl(&ks, 1);
	test_kputl(&ks, 37);
	test_kputl(&ks, 12345);
	test_kputl(&ks, -12345);
	test_kputl(&ks, INT_MAX);
	test_kputl(&ks, -INT_MAX);
	test_kputl(&ks, INT_MIN);
	test_kputl(&ks, LONG_MAX);
	test_kputl(&ks, -LONG_MAX);
	test_kputl(&ks, LONG_MIN);

	free(ks.s);

	if (nfail > 0) {
		fprintf(stderr, "Total failures: %d\n", nfail);
		return EXIT_FAILURE;
	}

	return EXIT_SUCCESS;
}
