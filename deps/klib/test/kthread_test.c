#include <stdio.h>
#include <assert.h>
#include <stdlib.h>
#include <pthread.h>
#if HAVE_CILK
#include <cilk/cilk.h>
#include <cilk/cilk_api.h>
#endif

typedef struct {
	int max_iter, w, h;
	double xmin, xmax, ymin, ymax;
	int *k;
} global_t;

static void compute(void *_g, int i, int tid)
{
	global_t *g = (global_t*)_g;
	double x, x0 = g->xmin + (g->xmax - g->xmin) * (i%g->w) / g->w;
	double y, y0 = g->ymin + (g->ymax - g->ymin) * (i/g->w) / g->h;
	int k;

	assert(g->k[i] < 0);
	x = x0, y = y0;
	for (k = 0; k < g->max_iter; ++k) {
		double z = x * y;
		x *= x; y *= y;
		if (x + y >= 4) break;
		x = x - y + x0;
		y = z + z + y0; 
	}
	g->k[i] = k;
}

void kt_for(int n_threads, int n_items, void (*func)(void*,int,int), void *data);

int main(int argc, char *argv[])
{
	int i, tmp, tot, type = 0, n_threads = 2;
	global_t global = { 10240*100, 800, 600, -2., -1.2, -1.2, 1.2, 0 };
//	global_t global = { 10240*1, 8, 6, -2., -1.2, -1.2, 1.2, 0 };

	if (argc > 1) {
		type = argv[1][0] == 'o'? 2 : argv[1][0] == 'c'? 3 : argv[1][0] == 'n'? 1 : 0;
		if (argv[1][0] >= '0' && argv[1][0] <= '9')
			n_threads = atoi(argv[1]);
	} else {
		fprintf(stderr, "Usage: ./a.out [openmp | cilk | #threads]\n");
	}
	tot = global.w * global.h;
	global.k = calloc(tot, sizeof(int));
	for (i = 0; i < tot; ++i) global.k[i] = -1;
	if (type == 0) {
		kt_for(n_threads, tot, compute, &global);
	} else if (type == 2) {
		#pragma omp parallel for
		for (i = 0; i < tot; ++i)
			compute(&global, i, 0);
	} else if (type == 3) {
		#if HAVE_CILK
		cilk_for (i = 0; i < tot; ++i)
			compute(&global, i, 0);
		#endif
	}
	for (i = tmp = 0; i < tot; ++i) tmp += (global.k[i] < 0);
	free(global.k);
	assert(tmp == 0);
	return 0;
}
