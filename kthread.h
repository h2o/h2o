#ifndef KTHREAD_H
#define KTHREAD_H

#include <stdlib.h>

#define KTF_DEF_DQBITS 10

typedef int (*kt_for_f)(void *global, void *local);

void kt_for(int n, kt_for_f func, void *global, int m, int size, void *local, int dq_bits);

#endif
