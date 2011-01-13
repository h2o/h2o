#include <stdio.h>
#include <assert.h>
#include <time.h>
#include <stdlib.h>
#include <string.h>

#include "khash.h"
KHASH_SET_INIT_STR(str)
KHASH_SET_INIT_INT(int)

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
	ht_destroy_data();
	return 0;
}
