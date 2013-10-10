#include <pthread.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>

#define HT_DQ_BITS 5 // 1<<HT_DQ_BITS is size of deque associated with each worker

/*************************
 *** Fixed-sized deque ***
 *************************/

typedef int dqval_t;

typedef struct { // a ring buffer
	int lock;
	int n_bits;
	int first, count;
	unsigned mask;
	dqval_t *a;
} deque_t;

#define dq_is_full(q) ((uint32_t)(q)->count == 1U<<(q)->n_bits)
#define dq_size(q) ((q)->count)

deque_t *dq_init(int n_bits)
{
	deque_t *d;
	d = (deque_t*)calloc(1, sizeof(deque_t));
	d->n_bits = n_bits;
	d->mask = (1U<<n_bits) - 1;
	d->a = (dqval_t*)calloc(1<<n_bits, sizeof(dqval_t));
	return d;
}

void dq_destroy(deque_t *d) { free(d->a); free(d); }

int dq_enq(deque_t *q, int is_back, const dqval_t *v) // put to the deque
{
	int ret = 0;
	while (__sync_lock_test_and_set(&q->lock, 1)); // this mimics a spin lock
	if (!dq_is_full(q)) {
		q->a[(is_back? q->first + q->count : q->first + q->mask) & q->mask] = *v;
		q->first = is_back? q->first : q->first? q->first - 1 : q->mask;
		++q->count;
	} else ret = -1; // the queue is full
	__sync_lock_release(&q->lock);
	return ret;
}

int dq_deq(deque_t *q, int is_back, dqval_t *v) // get from the queue
{
	int ret = 0;
	while (__sync_lock_test_and_set(&q->lock, 1));
	if (dq_size(q)) {
		*v = q->a[is_back? (q->first + q->count + q->mask) & q->mask : q->first];
		q->first = is_back? q->first : q->first == q->mask? 0 : q->first + 1;
		--q->count;
	} else ret = -1; // the queue is empty
	__sync_lock_release(&q->lock);
	return ret;
}

/**********************************
 *** Paralelize simple for loop ***
 **********************************/

struct ktf_worker_t;

typedef struct {
	int n, size; // n: number of workers; size: size of each items element
	void *shared;
	void *items;
	int (*func)(void*,int,void*);
	struct ktf_worker_t *w;
	int finished;
} kt_for_t;

typedef struct ktf_worker_t {
	kt_for_t *f;
	deque_t *q;
	int i;
} ktf_worker_t;

static inline int steal_work(kt_for_t *f) // steal work from the worker with the highest load
{
	int i, max = -1, max_i = -1, k = -1;
	for (i = 0; i < f->n; ++i)
		if (max < dq_size(f->w[i].q)) // max is not accurate as other workers may steal from the same queue, but it does not matter.
			max = dq_size(f->w[i].q), max_i = i;
	if (max_i < 0 || dq_deq(f->w[max_i].q, 0, &k) < 0) k = -1;
	return k;
}

static void *ktf_worker(void *data)
{
	ktf_worker_t *w = (ktf_worker_t*)data;
	for (;;) {
		int k = -1;
		if (dq_deq(w->q, 1, &k) < 0) k = steal_work(w->f);
		if (k >= 0) w->f->func(w->f->shared, k, (uint8_t*)w->f->items + w->f->size * k);
		else if (w->f->finished) break;
	}
	return 0;
}

/**
 * Parallelize a simple "for" loop
 *
 * @param n_threads    total number of threads
 * @param func         function in the form of func(void *shared, int item_id, void *item);
 * @param shared       shared data used by $func
 * @param n_items      number of items to process
 * @param item_size    size of each item
 * @param items        item
 *
 * This function parallelizes such a "for" loop:
 *
 *   shared_type *shared;
 *   item_type items[n_items];
 *   for (int i = 0; i < n_items; ++i)
 *     func(shared, &items[i]);
 *
 * with:
 *
 *   ht_for(n_threads, func, shared, n_items, sizeof(item_type), items);
 */
void kt_for(int n_threads, int (*func)(void*,int,void*), void *shared, int n_items, int item_size, void *items)
{
	kt_for_t *f;
	pthread_t *tid;
	int i, k, dq_bits = HT_DQ_BITS;

	f = (kt_for_t*)calloc(1, sizeof(kt_for_t));
	f->n = n_threads - 1, f->size = item_size;
	f->shared = shared, f->items = items;
	f->func = func;

	f->w = (ktf_worker_t*)calloc(f->n, sizeof(ktf_worker_t));
	for (i = 0; i < f->n; ++i)
		f->w[i].f = f, f->w[i].i = i, f->w[i].q = dq_init(dq_bits);

	tid = (pthread_t*)calloc(f->n, sizeof(pthread_t));
	for (i = 0; i < f->n; ++i) pthread_create(&tid[i], 0, ktf_worker, &f->w[i]);

	for (k = 0; k < n_items; ++k) {
		int min, min_i;
		for (i = 0, min = 1<<dq_bits, min_i = -1; i < f->n; ++i) // find the worker with the lowest load
			if (min > dq_size(f->w[i].q)) min = dq_size(f->w[i].q), min_i = i;
		if (min < 1<<dq_bits) dq_enq(f->w[min_i].q, 0, &k);
		else f->func(shared, k, (uint8_t*)f->items + f->size * k);
	}
	f->finished = 1;
	while ((k = steal_work(f)) >= 0) func(shared, k, (uint8_t*)f->items + f->size * k); // help the unfinished workers

	for (i = 0; i < f->n; ++i) pthread_join(tid[i], 0);
	for (i = 0; i < f->n; ++i) dq_destroy(f->w[i].q);
	free(tid); free(f->w); free(f);
}
