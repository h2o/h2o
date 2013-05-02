#include <stdio.h>
#include <assert.h>
#include <time.h>
#include <stdlib.h>
#include <string.h>

#include "khash.h"
KHASH_SET_INIT_STR(str)
KHASH_MAP_INIT_INT(int, unsigned char)

typedef struct {
	unsigned key;
	unsigned char val;
} int_unpack_t;

typedef struct {
	unsigned key;
	unsigned char val;
} __attribute__ ((__packed__)) int_packed_t;

#define hash_eq(a, b) ((a).key == (b).key)
#define hash_func(a) ((a).key)

KHASH_INIT(iun, int_unpack_t, char, 0, hash_func, hash_eq)
KHASH_INIT(ipk, int_packed_t, char, 0, hash_func, hash_eq)

static int data_size = 5000000;
static unsigned *int_data;
static char **str_data;

void ht_init_data()
{
	int i;
	char buf[256];
	khint32_t x = 11;
	printf("--- generating data... ");
	int_data = (unsigned*)calloc(data_size, sizeof(unsigned));
	str_data = (char**)calloc(data_size, sizeof(char*));
	for (i = 0; i < data_size; ++i) {
		int_data[i] = (unsigned)(data_size * ((double)x / UINT_MAX) / 4) * 271828183u;
		sprintf(buf, "%x", int_data[i]);
		str_data[i] = strdup(buf);
		x = 1664525L * x + 1013904223L;
	}
	printf("done!\n");
}

void ht_destroy_data()
{
	int i;
	for (i = 0; i < data_size; ++i) free(str_data[i]);
	free(str_data); free(int_data);
}

void ht_khash_int()
{
	int i, ret;
	unsigned *data = int_data;
	khash_t(int) *h;
	unsigned k;

	h = kh_init(int);
	for (i = 0; i < data_size; ++i) {
		k = kh_put(int, h, data[i], &ret);
		kh_val(h, k) = i&0xff;
		if (!ret) kh_del(int, h, k);
	}
	printf("[ht_khash_int] size: %u\n", kh_size(h));
	kh_destroy(int, h);
}

void ht_khash_str()
{
	int i, ret;
	char **data = str_data;
	khash_t(str) *h;
	unsigned k;

	h = kh_init(str);
	for (i = 0; i < data_size; ++i) {
		k = kh_put(str, h, data[i], &ret);
		if (!ret) kh_del(str, h, k);
	}
	printf("[ht_khash_int] size: %u\n", kh_size(h));
	kh_destroy(str, h);
}

void ht_khash_unpack()
{
	int i, ret;
	unsigned *data = int_data;
	khash_t(iun) *h;
	unsigned k;

	h = kh_init(iun);
	for (i = 0; i < data_size; ++i) {
		int_unpack_t x;
		x.key = data[i]; x.val = i&0xff;
		k = kh_put(iun, h, x, &ret);
		if (!ret) kh_del(iun, h, k);
	}
	printf("[ht_khash_unpack] size: %u (sizeof=%ld)\n", kh_size(h), sizeof(int_unpack_t));
	kh_destroy(iun, h);
}

void ht_khash_packed()
{
	int i, ret;
	unsigned *data = int_data;
	khash_t(ipk) *h;
	unsigned k;

	h = kh_init(ipk);
	for (i = 0; i < data_size; ++i) {
		int_packed_t x;
		x.key = data[i]; x.val = i&0xff;
		k = kh_put(ipk, h, x, &ret);
		if (!ret) kh_del(ipk, h, k);
	}
	printf("[ht_khash_packed] size: %u (sizeof=%ld)\n", kh_size(h), sizeof(int_packed_t));
	kh_destroy(ipk, h);
}

void ht_timing(void (*f)(void))
{
	clock_t t = clock();
	(*f)();
	printf("[ht_timing] %.3lf sec\n", (double)(clock() - t) / CLOCKS_PER_SEC);
}

int main(int argc, char *argv[])
{
	if (argc > 1) data_size = atoi(argv[1]);
	ht_init_data();
	ht_timing(ht_khash_int);
	ht_timing(ht_khash_str);
	ht_timing(ht_khash_unpack);
	ht_timing(ht_khash_packed);
	ht_destroy_data();
	return 0;
}
