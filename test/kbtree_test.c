#include <stdio.h>
#include <assert.h>
#include <time.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

typedef const char *str_t;

#include "kbtree.h"
KBTREE_INIT(int, uint32_t, kb_generic_cmp)
KBTREE_INIT(str, str_t, kb_str_cmp)

static int data_size = 5000000;
static unsigned *int_data;
static char **str_data;

void ht_init_data()
{
	int i;
	char buf[256];
	printf("--- generating data... ");
	srand48(11);
	int_data = (unsigned*)calloc(data_size, sizeof(unsigned));
	str_data = (char**)calloc(data_size, sizeof(char*));
	for (i = 0; i < data_size; ++i) {
		int_data[i] = (unsigned)(data_size * drand48() / 4) * 271828183u;
		sprintf(buf, "%x", int_data[i]);
		str_data[i] = strdup(buf);
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
	int i;
	unsigned *data = int_data;
	uint32_t *l, *u;
	kbtree_t(int) *h;

	h = kb_init(int, KB_DEFAULT_SIZE);
	for (i = 0; i < data_size; ++i) {
		if (kb_get(int, h, data[i]) == 0) kb_put(int, h, data[i]);
		else kb_del(int, h, data[i]);
	}
	printf("[ht_khash_int] size: %d\n", kb_size(h));
	if (1) {
		int cnt = 0;
		uint32_t x, y;
		kb_interval(int, h, 2174625464u, &l, &u);
		printf("interval for 2174625464: (%u, %u)\n", l? *l : 0, u? *u : 0);
#define traverse_f(p) { if (cnt == 0) y = *p; ++cnt; }
		__kb_traverse(uint32_t, h, traverse_f);
		__kb_get_first(uint32_t, h, x);
		printf("# of elements from traversal: %d\n", cnt);
		printf("first element: %d == %d\n", x, y);
	}
	__kb_destroy(h);
}
void ht_khash_str()
{
	int i;
	char **data = str_data;
	kbtree_t(str) *h;

	h = kb_init(str, KB_DEFAULT_SIZE);
	for (i = 0; i < data_size; ++i) {
		if (kb_get(str, h, data[i]) == 0) kb_put(str, h, data[i]);
		else kb_del(str, h, data[i]);
	}
	printf("[ht_khash_int] size: %d\n", kb_size(h));
	__kb_destroy(h);
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
