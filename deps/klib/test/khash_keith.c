/*
 * This is an optimized version of the following C++ program:
 *
 *   http://keithlea.com/javabench/src/cpp/hash.cpp
 *
 * Keith in his benchmark (http://keithlea.com/javabench/data) showed that the
 * Java implementation is twice as fast as the C++ version. In fact, this is
 * only because the C++ implementation is substandard. Most importantly, Keith
 * is using "sprintf()" to convert an integer to a string, which is known to be
 * extremely inefficient.
 */
#include <stdio.h>
#include "khash.h"
KHASH_MAP_INIT_STR(str, int)

inline void int2str(int c, int base, char *ret)
{
	const char *tab = "0123456789abcdef";
	if (c == 0) ret[0] = '0', ret[1] = 0;
	else {
		int l, x, y;
		char buf[16];
		for (l = 0, x = c < 0? -c : c; x > 0; x /= base) buf[l++] = tab[x%base];
		if (c < 0) buf[l++] = '-';
		for (x = l - 1, y = 0; x >= 0; --x) ret[y++] = buf[x];
		ret[y] = 0;
	}
}

#ifndef _USE_STRDUP
#define BLOCK_SIZE 0x100000
int main(int argc, char *argv[])
{
	char **mem = 0;
	int i, l, n = 1000000, ret, block_end = 0, curr = 0, c = 0;
	khash_t(str) *h;
	h = kh_init(str);
	if (argc > 1) n = atoi(argv[1]);
	mem = malloc(sizeof(void*));
	mem[0] = malloc(BLOCK_SIZE); // memory buffer to avoid memory fragmentation
	curr = block_end = 0;
	for (i = 1; i <= n; ++i) {
		char buf[16];
		int2str(i, 16, buf);
		khint_t k = kh_put(str, h, buf, &ret);
		l = strlen(buf) + 1;
		if (block_end + l > BLOCK_SIZE) {
			++curr; block_end = 0;
			mem = realloc(mem, (curr + 1) * sizeof(void*));
			mem[curr] = malloc(BLOCK_SIZE);
		}
		memcpy(mem[curr] + block_end, buf, l);
		kh_key(h, k) = mem[curr] + block_end;
		block_end += l;
		kh_val(h, k) = i;
	}
	for (i = 1; i <= n; ++i) {
		char buf[16];
		int2str(i, 10, buf);
		khint_t k = kh_get(str, h, buf);
		if (k != kh_end(h)) ++c;
	}
	printf("%d\n", c);
	for (ret = 0; ret <= curr; ++ret) free(mem[ret]);
	free(mem);
	kh_destroy(str, h);
	return 0;
}
#else // _USE_STRDUP
int main(int argc, char *argv[])
{
	int i, l, n = 1000000, ret, c = 0;
	khash_t(str) *h;
	khint_t k;
	h = kh_init(str);
	if (argc > 1) n = atoi(argv[1]);
	for (i = 1; i <= n; ++i) {
		char buf[16];
		int2str(i, 16, buf);
		k = kh_put(str, h, strdup(buf), &ret);
		kh_val(h, k) = i;
	}
	for (i = 1; i <= n; ++i) {
		char buf[16];
		int2str(i, 10, buf);
		k = kh_get(str, h, buf);
		if (k != kh_end(h)) ++c;
	}
	for (k = kh_begin(h); k != kh_end(h); ++k) // explicitly freeing memory takes 10-20% CPU time.
		if (kh_exist(h, k)) free((char*)kh_key(h, k));
	printf("%d\n", c);
	kh_destroy(str, h);
	return 0;
}
#endif
