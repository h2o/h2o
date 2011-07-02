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

int main(int argc, char *argv[])
{
	int i, l, n = 1000, ret;
	khash_t(str) *h, *h2;
	khint_t k;
	h = kh_init(str);
	h2 = kh_init(str);
	if (argc > 1) n = atoi(argv[1]);
	for (i = 0; i < 10000; ++i) {
		char buf[32];
		strcpy(buf, "foo_");
		int2str(i, 10, buf+4);
		k = kh_put(str, h, strdup(buf), &ret);
		kh_val(h, k) = i;
	}
	for (i = 0; i < n; ++i) {
		for (k = kh_begin(h); k != kh_end(h); ++k) {
			if (kh_exist(h, k)) {
				khint_t k2 = kh_put(str, h2, kh_key(h, k), &ret);
				if (ret) { // absent
					kh_key(h2, k2) = strdup(kh_key(h, k));
					kh_val(h2, k2) = kh_val(h, k);
				} else kh_val(h2, k2) += kh_val(h, k);
			}
		}
	}
	k = kh_get(str, h, "foo_1"); printf("%d", kh_val(h, k));
	k = kh_get(str, h, "foo_9999"); printf(" %d", kh_val(h, k));
	k = kh_get(str, h2, "foo_1"); printf(" %d", kh_val(h2, k));
	k = kh_get(str, h2, "foo_9999"); printf(" %d\n", kh_val(h2, k));
	for (k = kh_begin(h); k != kh_end(h); ++k)
		if (kh_exist(h, k)) free((char*)kh_key(h, k));
	for (k = kh_begin(h2); k != kh_end(h2); ++k)
		if (kh_exist(h2, k)) free((char*)kh_key(h2, k));
	kh_destroy(str, h);
	kh_destroy(str, h2);
	return 0;
}
