#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include "kstring.h"

#ifdef __APPLE__
#define HAVE_STRNSTR
#endif

#ifdef __linux__
#define HAVE_MEMMEM
#endif

static int str_len = 1024*1024*128;
static int pat_len = 30;
static int alphabet = 2;
static int repeat = 50;

char *gen_data(int len, int a)
{
	char *data;
	int i;
	long x;
	srand48(11);
	data = malloc(len);
	for (i = 0; i < len; ++i)
		data[i] = (int)(a * drand48()) + '!';
	data[str_len - 1] = 0;
	return data;
}
// http://srcvault.scali.eu.org/cgi-bin/Syntax/c/BoyerMoore.c
char *BoyerMoore( unsigned char *data, unsigned int dataLength, unsigned char *string, unsigned int strLength )
{
	unsigned int skipTable[256], i;
	unsigned char *search;
	register unsigned char lastChar;

	if (strLength == 0)
		return NULL;

	for (i = 0; i < 256; i++)
		skipTable[i] = strLength;
	search = string;
	i = --strLength;
	do {
		skipTable[*search++] = i;
	} while (i--);
	lastChar = *--search;
	search = data + strLength;
	dataLength -= strLength+(strLength-1);
	while ((int)dataLength > 0 ) {
		unsigned int skip;
		skip = skipTable[*search];
		search += skip;
		dataLength -= skip;
		skip = skipTable[*search];
		search += skip;
		dataLength -= skip;
		skip = skipTable[*search];
		if (*search != lastChar) {
			search += skip;
			dataLength -= skip;
			continue;
		}
		i = strLength;
		do {
			if (i-- == 0) return search;
		} while (*--search == string[i]);
		search += (strLength - i + 1);
		dataLength--;
	}
	return NULL;
}

int main()
{
	char *data;
	int i;
	clock_t t;
	t = clock();
	data = gen_data(str_len, alphabet);
	fprintf(stderr, "Generate data in %.3f sec\n", (float)(clock() - t) / CLOCKS_PER_SEC);
	{
		t = clock(); srand48(1331);
		for (i = 0; i < repeat; ++i) {
			int y = lrand48() % (str_len - pat_len);
			char *ret;
			ret = kmemmem(data, str_len, data + y, pat_len, 0);
//			printf("%d, %d\n", (int)(ret - data), y);
		}
		fprintf(stderr, "Search patterns in %.3f sec\n", (float)(clock() - t) / CLOCKS_PER_SEC);
	}
	if (1) {
		t = clock(); srand48(1331);
		for (i = 0; i < repeat; ++i) {
			int y = lrand48() % (str_len - pat_len);
			char *ret;
			ret = BoyerMoore(data, str_len, data + y, pat_len);
//			printf("%d, %d\n", (int)(ret - data), y);
		}
		fprintf(stderr, "Search patterns in %.3f sec\n", (float)(clock() - t) / CLOCKS_PER_SEC);
	}
#ifdef HAVE_STRNSTR
	if (1) {
		char *tmp;
		t = clock(); srand48(1331);
		tmp = calloc(pat_len+1, 1);
		for (i = 0; i < repeat; ++i) {
			int y = lrand48() % (str_len - pat_len);
			char *ret;
			memcpy(tmp, data + y, pat_len);
			ret = strnstr(data, tmp, str_len);
		}
		fprintf(stderr, "Search patterns in %.3f sec\n", (float)(clock() - t) / CLOCKS_PER_SEC);		
	}
#endif
#ifdef HAVE_MEMMEM
	if (1) {
		t = clock(); srand48(1331);
		for (i = 0; i < repeat; ++i) {
			int y = lrand48() % (str_len - pat_len);
			char *ret;
			ret = memmem(data, str_len, data + y, pat_len);
//			printf("%d, %d\n", (int)(ret - data), y);
		}
		fprintf(stderr, "Search patterns in %.3f sec\n", (float)(clock() - t) / CLOCKS_PER_SEC);
	}
#endif
	return 0;
}
