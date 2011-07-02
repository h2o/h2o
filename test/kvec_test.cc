#include <vector>
#include <time.h>
#include <stdio.h>
#include <stdlib.h>
#include "kvec.h"

int main()
{
	int M = 10, N = 20000000, i, j;
	clock_t t;
	t = clock();
	for (i = 0; i < M; ++i) {
		int *array = (int*)malloc(N * sizeof(int));
		for (j = 0; j < N; ++j) array[j] = j;
		free(array);
	}
	printf("C array, preallocated: %.3f sec\n",
		   (float)(clock() - t) / CLOCKS_PER_SEC);
	t = clock();
	for (i = 0; i < M; ++i) {
		int *array = 0, max = 0;
		for (j = 0; j < N; ++j) {
			if (j == max) {
				max = !max? 1 : max << 1;
				array = (int*)realloc(array, sizeof(int)*max);
			}
			array[j] = j;
		}
		free(array);
	}
	printf("C array, dynamic: %.3f sec\n",
		   (float)(clock() - t) / CLOCKS_PER_SEC);
	t = clock();
	for (i = 0; i < M; ++i) {
		kvec_t(int) array;
		kv_init(array);
		kv_resize(int, array, N);
		for (j = 0; j < N; ++j) kv_a(int, array, j) = j;
		kv_destroy(array);
	}
	printf("C vector, dynamic(kv_a): %.3f sec\n",
		   (float)(clock() - t) / CLOCKS_PER_SEC);
	t = clock();
	for (i = 0; i < M; ++i) {
		kvec_t(int) array;
		kv_init(array);
		for (j = 0; j < N; ++j)
			kv_push(int, array, j);
		kv_destroy(array);
	}
	printf("C vector, dynamic(kv_push): %.3f sec\n",
		   (float)(clock() - t) / CLOCKS_PER_SEC);
	t = clock();
	for (i = 0; i < M; ++i) {
		std::vector<int> array;
		array.reserve(N);
		for (j = 0; j < N; ++j) array[j] = j;
	}
	printf("C++ vector, preallocated: %.3f sec\n",
		   (float)(clock() - t) / CLOCKS_PER_SEC);
	t = clock();
	for (i = 0; i < M; ++i) {
		std::vector<int> array;
		for (j = 0; j < N; ++j) array.push_back(j);
	}
	printf("C++ vector, dynamic: %.3f sec\n",
		   (float)(clock() - t) / CLOCKS_PER_SEC);
	return 0;
}
