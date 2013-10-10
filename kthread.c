#include <pthread.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>

#define KT_DQ_BITS 5 // 1<<HT_DQ_BITS is size of deque associated with each worker

/*************************
 *** Fixed-sized deque ***
 *************************/

typedef uint64_t dqval_t;

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

/****************************
 *** Spawn/sync interface ***
 ****************************/

#include "kthread.h"

typedef struct {
	int n_items, item_size, n_finished;
	int (*func)(void*,int,void*);
	void *shared, *items;
} kt_task_t;

typedef struct {
	struct kthread_t *t;
	deque_t *q;
	int type;
	pthread_t tid;
	pthread_mutex_t lock;
	pthread_cond_t cv;
} kt_worker_t;

struct kthread_t {
	int n_threads;
	kt_worker_t *w;
	int n_tasks, max_tasks;
	kt_task_t *tasks;
	pthread_t self;
	pthread_mutex_t lock;
	pthread_cond_t cv;
	int to_sync, done;
};

static inline int steal_task(kthread_t *t)
{
	int i, max = -1, max_i = -1;
	uint64_t k = (uint64_t)-1;
	for (i = 0; i < t->n_threads; ++i)
		if (max < dq_size(t->w[i].q)) // max is not accurate as other workers may steal from the same queue, but it does not matter.
			max = dq_size(t->w[i].q), max_i = i;
	if (max_i < 0 || dq_deq(t->w[max_i].q, 0, &k) < 0) k = (uint64_t)-1;
	return k;
}

static inline void do_task(kthread_t *t, uint64_t sid)
{
	kt_task_t *s = &t->tasks[sid>>32];
	s->func(s->shared, (int)sid, (uint8_t*)s->items + s->item_size * (uint32_t)sid);
}

static void *slave(void *data)
{
	kt_worker_t *w = (kt_worker_t*)data;
	for (;;) {
		uint64_t sid;
		if (dq_deq(w->q, 1, &sid) < 0)
			sid = steal_task(w->t);
		if (sid == (uint64_t)-1) { // if still fail to find a task, sleep and wait for the signal
			if (w->type == 2) break;
			pthread_mutex_lock(&w->lock);
			w->type = 0; // wait
			while (w->type == 0) pthread_cond_wait(&w->cv, &w->lock);
			pthread_mutex_unlock(&w->lock);
			if (w->type == 2) break;
		} else do_task(w->t, sid);
	}
	return 0;
}

static void *master(void *data)
{
	kthread_t *t = (kthread_t*)data;
	int i, n_tasks = 0, to_sync = 0;
	for (i = 0; i < t->n_threads; ++i)
		pthread_create(&t->w[i].tid, 0, slave, &t->w[i]);
	while (!to_sync) {
		int next_tasks, tid, iid;
		uint64_t sid;
		pthread_mutex_lock(&t->lock);
		while (n_tasks == t->n_tasks && !t->to_sync)
			pthread_cond_wait(&t->cv, &t->lock);
		next_tasks = t->n_tasks, to_sync = t->to_sync;
		pthread_mutex_unlock(&t->lock);
		for (tid = n_tasks; tid < next_tasks; ++tid) {
			kt_task_t *s = &t->tasks[tid];
			for (iid = 0; iid < s->n_items; ++iid) {
				int min, min_i;
				for (i = 0, min = 1<<KT_DQ_BITS, min_i = -1; i < t->n_threads; ++i)
					if (min > dq_size(t->w[i].q)) min = dq_size(t->w[i].q), min_i = i;
				sid = (uint64_t)tid<<32 | iid;
				if (min < 1<<KT_DQ_BITS) {
					kt_worker_t *w = &t->w[min_i];
					dq_enq(w->q, 0, &sid);
					if (w->type == 0) {
						pthread_mutex_lock(&w->lock);
						w->type = 1;
						pthread_cond_signal(&w->cv);
						pthread_mutex_unlock(&w->lock);
					}
				} else do_task(t, sid);
			}
		}
		while ((sid = steal_task(t)) != (uint64_t)-1) do_task(t, sid);
		n_tasks = next_tasks;
	}
	for (i = 0; i < t->n_threads; ++i) {
		pthread_mutex_lock(&t->w[i].lock);
		t->w[i].type = 2;
		pthread_cond_signal(&t->w[i].cv);
		pthread_mutex_unlock(&t->w[i].lock);
	}
	for (i = 0; i < t->n_threads; ++i) pthread_join(t->w[i].tid, 0);
	return 0;
}

kthread_t *kt_init(int n_threads)
{
	kthread_t *t;
	int i;
	t = calloc(1, sizeof(kthread_t));
	t->n_threads = n_threads - 1;
	t->w = calloc(t->n_threads, sizeof(kt_worker_t));
	pthread_mutex_init(&t->lock, 0);
	pthread_cond_init(&t->cv, 0);
	for (i = 0; i < t->n_threads; ++i) {
		t->w[i].q = dq_init(KT_DQ_BITS);
		t->w[i].t = t;
		pthread_mutex_init(&t->w[i].lock, 0);
		pthread_cond_init(&t->w[i].cv, 0);
	}
	pthread_create(&t->self, 0, master, t);
	return t;
}

void kt_sync(kthread_t *t)
{
	int i;
	pthread_mutex_lock(&t->lock);
	t->to_sync = 1;
	pthread_cond_signal(&t->cv);
	pthread_mutex_unlock(&t->lock);
	pthread_join(t->self, 0);

	pthread_cond_destroy(&t->cv);
	pthread_mutex_destroy(&t->lock);
	for (i = 0; i < t->n_threads; ++i) {
		pthread_cond_destroy(&t->w[i].cv);
		pthread_mutex_destroy(&t->w[i].lock);
		dq_destroy(t->w[i].q);
	}
	free(t->tasks); free(t->w); free(t);
}

void kt_spawn(kthread_t *t, int (*func)(void*,int,void*), void *shared, int n_items, int item_size, void *items)
{
	kt_task_t *p;
	pthread_mutex_lock(&t->lock);
	if (t->n_tasks == t->max_tasks) {
		t->max_tasks = t->max_tasks? t->max_tasks<<1 : 2;
		t->tasks = realloc(t->tasks, t->max_tasks * sizeof(kt_task_t));
	}
	p = &t->tasks[t->n_tasks++];
	p->func = func, p->shared = shared;
	p->n_items = n_items, p->item_size = item_size, p->items = items, p->n_finished = 0;
	pthread_cond_signal(&t->cv);
	pthread_mutex_unlock(&t->lock);
}
