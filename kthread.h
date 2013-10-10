#ifndef KTHREAD_H
#define KTHREAD_H

struct kthread_t;
typedef struct kthread_t kthread_t;

kthread_t *kt_init(int n_threads);
void kt_spawn(kthread_t *t, int (*func)(void*,int,void*), void *shared, int n_items, int item_size, void *items);
void kt_sync(kthread_t *t);

#endif
