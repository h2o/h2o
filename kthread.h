#ifndef KTHREAD_H
#define KTHREAD_H

struct kthread_t;
typedef struct kthread_t kthread_t;

#ifdef __cplusplus
extern "C" {
#endif

kthread_t *kt_init(int n_threads);
void kt_spawn(kthread_t *t, int (*func)(void*,int,void*), void *shared, int n_items, int item_size, void *items);
void kt_sync(kthread_t *t);

#ifdef __cplusplus
}
#endif

static inline void kt_for(int n_threads, int (*func)(void*,int,void*), void *shared, int n_items, int item_size, void *items)
{
	kthread_t *t;
	t = kt_init(n_threads);
	kt_spawn(t, func, shared, n_items, item_size, items);
	kt_sync(t);
}

#endif
