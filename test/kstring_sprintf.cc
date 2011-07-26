#include <stdio.h>
#include <time.h>
#include <stdlib.h>
#include <iostream>
#include <sstream>
#include "kstring.h"

using namespace std;

int main(int argc, char *argv)
{
	int i, N = 1<<21;
	kstring_t str;
	clock_t beg;
	char buf[256];
	ostringstream ostr;

	str.l = str.m = 0; str.s = 0;

	beg = clock();
	for (i = 0; i < N; ++i) {
		str.l = 0;
		ksprintf_fast(&str, "%d\n", i);
	}
	printf("int, ksprintf_fast(): %.3f\n", (double)(clock() - beg) / CLOCKS_PER_SEC);

	beg = clock();
	for (i = 0; i < N; ++i)
		sprintf(buf, "%d\n", i);
	printf("int, sprintf(): %.3f\n", (double)(clock() - beg) / CLOCKS_PER_SEC);

	beg = clock();
	for (i = 0; i < N; ++i) {
		str.l = 0;
		kputw(i, &str); kputc('\n', &str);
	}
	printf("int, kputw/kputc(): %.3f\n", (double)(clock() - beg) / CLOCKS_PER_SEC);

	beg = clock();
	for (i = 0; i < N; ++i) {
		ostr.seekp(0);
		ostr<<i<<endl;
	}
	printf("int, ostream: %.3f\n", (double)(clock() - beg) / CLOCKS_PER_SEC);

	beg = clock();
	for (i = 0; i < N; ++i) {
		str.l = 0;
		ksprintf_fast(&str, "%g\n", (double)i);
	}
	printf("double, ksprintf_fast(): %.3f\n", (double)(clock() - beg) / CLOCKS_PER_SEC);

	beg = clock();
	for (i = 0; i < N; ++i)
		sprintf(buf, "%g\n", (double)i);
	printf("double, sprintf(): %.3f\n", (double)(clock() - beg) / CLOCKS_PER_SEC);

	return 0;
}
