#include <pthread.h>
#include <stdlib.h>
#include <stdint.h>

/**************************************************************
 *** Fixed-sized single-writer-multi-reader lock-free deque ***
 **************************************************************/

typedef int dqval_t;

typedef struct {
	int n_bits;
	unsigned mask;
	volatile uint64_t anchor;
	dqval_t *a;
} deque_t;

#define dq_is_full(q) ((uint32_t)(q)->anchor == 1U<<(q)->n_bits)
#define dq_size(q) ((int32_t)(q)->anchor)

deque_t *dq_init(int n_bits)
{
	deque_t *d;
	d = calloc(1, sizeof(deque_t));
	d->n_bits = n_bits;
	d->mask = (1U<<n_bits) - 1;
	d->a = calloc(1<<n_bits, sizeof(dqval_t));
	return d;
}

void dq_destroy(deque_t *d)
{
	free(d->a); free(d);
}

int dq_enq(deque_t *q, int is_back, const dqval_t *v)
{
	uint64_t ov, nv;
	do {
		if (dq_is_full(q)) return -1;
		ov = q->anchor;
		q->a[(is_back? ((ov>>32) + (uint32_t)ov) : (ov>>32) + q->mask) & q->mask] = *v;
		nv = is_back? ov + 1 : ov>>32 == 0? (uint64_t)q->mask<<32 | ((uint32_t)ov + 1) : ov - 0xffffffffU;
	} while (!__sync_bool_compare_and_swap(&q->anchor, ov, nv));
	return 0;
}

int dq_deq(deque_t *q, int is_back, dqval_t *v)
{
	uint64_t ov, nv;
	do {
		if (dq_size(q) == 0) return -1;
		ov = q->anchor;
		*v = q->a[is_back? ((ov>>32) + (uint32_t)ov - 1) & q->mask : ov>>32];
		nv = is_back? ov - 1 : ov>>32 == q->mask? (uint32_t)ov - 1 : ov + 0xffffffffU;
	} while (!__sync_bool_compare_and_swap(&q->anchor, ov, nv));
	return 0;
}

/**********************************
 *** Paralelize simple for loop ***
 **********************************/

struct ktf_worker_t;

typedef struct {
	int n, size;
	void *global;
	void *local;
	int (*func)(void*,void*);
	struct ktf_worker_t *w;
	int finished;
} kt_for_t;

typedef struct ktf_worker_t {
	kt_for_t *f;
	deque_t *q;
	int i;
} ktf_worker_t;

static void *ktf_worker(void *data)
{
	ktf_worker_t *w = (ktf_worker_t*)data;
	while (!w->f->finished) {
		int k = -1;
		if (dq_size(w->q) == 0) { // work-stealing
			int i, max, max_i;
			for (i = 0, max = -1, max_i = -1; i < w->f->n; ++i)
				if (max < dq_size(w->f->w[i].q))
					max = dq_size(w->f->w[i].q), max_i = i;
			if (dq_deq(w->f->w[max_i].q, 0, &k) < 0) k = -1;
		} else if (dq_deq(w->q, 1, &k) < 0) k = -1;
		if (k >= 0) w->f->func(w->f->global, (uint8_t*)w->f->local + w->f->size * k);
	}
	return 0;
}

void kt_for(int n, int (*func)(void*,void*), void *global, int m, int size, void *local, int dq_bits)
{
	kt_for_t *f;
	pthread_t *tid;
	int i, k;

	if (dq_bits <= 0) dq_bits = 10;
	f = calloc(1, sizeof(kt_for_t));
	f->n = n - 1, f->size = size;
	f->global = global, f->local = local;
	f->func = func;

	f->w = calloc(f->n, sizeof(ktf_worker_t));
	for (i = 0; i < f->n; ++i) {
		ktf_worker_t *wi = &f->w[i];
		wi->f = f, wi->i = i;
		wi->q = dq_init(dq_bits);
	}

	tid = calloc(f->n, sizeof(pthread_t));
	for (i = 0; i < f->n; ++i) pthread_create(&tid[i], 0, ktf_worker, &f->w[i]);

	for (k = 0; k < m; ++k) {
		int min, min_i;
		for (i = 0, min = 1<<dq_bits, min_i = -1; i < f->n; ++i)
			if (min > dq_size(f->w[i].q)) min = dq_size(f->w[i].q), min_i = i;
		if (min < 1<<dq_bits) dq_enq(f->w[min_i].q, 0, &k);
		else func(global, (uint8_t*)f->local + f->size * k);
	}
	f->finished = 1;

	for (i = 0; i < f->n; ++i) pthread_join(tid[i], 0);
	for (i = 0; i < f->n; ++i) dq_destroy(f->w[i].q);
	free(tid); free(f->w); free(f);
}
