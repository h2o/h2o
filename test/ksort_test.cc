#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <time.h>
#include <algorithm>

#include "ksort.h"
KSORT_INIT_GENERIC(int)

using namespace std;

/**********************************
 * BEGIN OF PAUL'S IMPLEMENTATION *
 **********************************/

/* Attractive Chaos: I have added inline where necessary. */

/*
Copyright (c) 2004 Paul Hsieh
All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:

    Redistributions of source code must retain the above copyright notice,
    this list of conditions and the following disclaimer.

    Redistributions in binary form must reproduce the above copyright notice,
    this list of conditions and the following disclaimer in the documentation
    and/or other materials provided with the distribution.

    Neither the name of sorttest nor the names of its contributors may be
    used to endorse or promote products derived from this software without
    specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
POSSIBILITY OF SUCH DAMAGE.
*/

/*

Recommended flags:
------------------

Intel C/C++:
icl /O2 /G6 /Qaxi /Qxi /Qip sorttest.c

WATCOM C/C++:
wcl386 /otexan /6r sorttest.c

GCC:
gcc -O3 -mcpu=athlon-xp -march=athlon-xp sorttest.c

MSVC:
cl /O2 /Ot /Og /G6 sorttest.c

*/

static inline void sort2 (int * numbers) {
int tmp;

    if (numbers[0] <= numbers[1]) return;
    tmp = numbers[0];
    numbers[0] = numbers[1];
    numbers[1] = tmp;
}

static inline void sort3 (int * numbers) {
int tmp;

    if (numbers[0] <= numbers[1]) {
        if (numbers[1] <= numbers[2]) return;
        if (numbers[2] <= numbers[0]) {
            tmp = numbers[0];
            numbers[0] = numbers[2];
            numbers[2] = numbers[1];
            numbers[1] = tmp;
            return;
        }
        tmp = numbers[1];
    } else {
        tmp = numbers[0];
        if (numbers[0] <= numbers[2]) {
            numbers[0] = numbers[1];
            numbers[1] = tmp;
            return;
        }
        if (numbers[2] <= numbers[1]) {
            numbers[0] = numbers[2];
            numbers[2] = tmp;
            return;
        }
        numbers[0] = numbers[1];
    }
    numbers[1] = numbers[2];
    numbers[2] = tmp;
}

static inline void sort4 (int * num) {
int tmp;
  if (num[0] < num[1]) {
    if (num[1] < num[2]) {
      if (num[1] < num[3]) {
        if (num[2] >= num[3]) {
          tmp = num[2];
          num[2] = num[3];
          num[3] = tmp;
        }
      } else {
        tmp = num[1];
        if (num[0] < num[3]) {
          num[1] = num[3];
        } else {
          num[1] = num[0];
          num[0] = num[3];
        }
        num[3] = num[2];
        num[2] = tmp;
      }
    } else {
      if (num[0] < num[2]) {
        if (num[2] < num[3]) {
          if (num[1] < num[3]) {
            tmp = num[1];
          } else {
            tmp = num[3];
            num[3] = num[1];
          }
          num[1] = num[2];
          num[2] = tmp;
        } else {
          if (num[0] < num[3]) {
            tmp = num[3];
          } else {
            tmp = num[0];
            num[0] = num[3];
          }
          num[3] = num[1];
          num[1] = tmp;
        }
      } else {
        if (num[0] < num[3]) {
          tmp = num[0];
          num[0] = num[2];
          if (num[1] < num[3]) {
            num[2] = num[1];
          } else {
            num[2] = num[3];
            num[3] = num[1];
          }
          num[1] = tmp;
        } else {
          if (num[2] < num[3]) {
            tmp = num[0];
            num[0] = num[2];
            num[2] = tmp;
            tmp = num[1];
            num[1] = num[3];
          } else {
            tmp = num[1];
            num[1] = num[2];
            num[2] = num[0];
            num[0] = num[3];
          }
          num[3] = tmp;
        }
      }
    }
  } else {
    tmp = num[0];
    if (tmp < num[2]) {
      if (tmp < num[3]) {
        num[0] = num[1];
        num[1] = tmp;
        if (num[2] >= num[3]) {
          tmp = num[2];
          num[2] = num[3];
          num[3] = tmp;
        }
      } else {
        if (num[1] < num[3]) {
          num[0] = num[1];
          num[1] = num[3];
        } else {
          num[0] = num[3];
        }
        num[3] = num[2];
        num[2] = tmp;
      }
    } else {
      if (num[1] < num[2]) {
        if (num[2] < num[3]) {
          num[0] = num[1];
          num[1] = num[2];
          if (tmp < num[3]) {
            num[2] = tmp;
          } else {
            num[2] = num[3];
            num[3] = tmp;
          }
        } else {
          if (num[1] < num[3]) {
            num[0] = num[1];
            num[1] = num[3];
          } else {
            num[0] = num[3];
          }
          num[3] = tmp;
        }
      } else {
        if (num[1] < num[3]) {
          num[0] = num[2];
          if (tmp < num[3]) {
            num[2] = tmp;
          } else {
            num[2] = num[3];
            num[3] = tmp;
          }
        } else {
          if (num[2] < num[3]) {
            num[0] = num[2];
            num[2] = num[1];
            num[1] = num[3];
            num[3] = tmp;
          } else {
            num[0] = num[3];
            num[3] = tmp;
            tmp = num[1];
            num[1] = num[2];
            num[2] = tmp;
          }
        }
      }
    }
  }
}

static inline void sortAlt2 (int * numbers, int * altNumbers) {
    if (numbers[0] <= numbers[1]) {
        altNumbers[0] = numbers[0];
        altNumbers[1] = numbers[1];
    } else {
        altNumbers[0] = numbers[1];
        altNumbers[1] = numbers[0];
    }
}

static inline void sortAlt3 (int * numbers, int * altNumbers) {
    if (numbers[0] <= numbers[1]) {
        if (numbers[1] <= numbers[2]) {
            altNumbers[0] = numbers[0];
            altNumbers[1] = numbers[1];
            altNumbers[2] = numbers[2];
        } else if (numbers[2] <= numbers[0]) {
            altNumbers[0] = numbers[2];
            altNumbers[1] = numbers[0];
            altNumbers[2] = numbers[1];
        } else {
            altNumbers[0] = numbers[0];
            altNumbers[1] = numbers[2];
            altNumbers[2] = numbers[1];
        }
    } else {
        if (numbers[0] <= numbers[2]) {
            altNumbers[0] = numbers[1];
            altNumbers[1] = numbers[0];
            altNumbers[2] = numbers[2];
        } else if (numbers[2] <= numbers[1]) {
            altNumbers[0] = numbers[2];
            altNumbers[1] = numbers[1];
            altNumbers[2] = numbers[0];
        } else {
            altNumbers[0] = numbers[1];
            altNumbers[1] = numbers[2];
            altNumbers[2] = numbers[0];
        }
    }
}

/*
 *  Insert Sort
 */

inline void insertSort (int numbers[], int qty) {
int i, j, idx, q4;
int tmp;

    if (qty <= 4) {
        if (qty == 4) sort4 (numbers);
        else if (qty == 3) sort3 (numbers);
        else if (qty == 2) sort2 (numbers);
        return;
    }

    q4 = qty - 4;

    for (i=0; i < q4; i++) {
        idx = i;
        for (j=i+1; j < qty; j++) {
            if (numbers[j] < numbers[idx]) idx = j;
        }
        if (idx != i) {
            tmp = numbers[idx];
            numbers[idx] = numbers[i];
            numbers[i] = tmp;
        }
    }

    sort4 (numbers + q4);
}

/*
 *  Heap Sort
 */

/* Assure the heap property for entries from top to last */
static void siftDown (int numbers[], int top, int last) {
int tmp = numbers[top];
int maxIdx = top;

    while (last >= (maxIdx += maxIdx)) {

        /* This is where the comparison occurrs and where a sufficiently
           good compiler can use a computed conditional result rather
           than using control logic. */
        if (maxIdx != last && numbers[maxIdx] < numbers[maxIdx + 1]) maxIdx++;

        if (tmp >= numbers[maxIdx]) break;
        numbers[top] = numbers[maxIdx];
        top = maxIdx;
    }
    numbers[top] = tmp;
}

/* Peel off the top siftDown operation since its parameters are trivial to
   fill in directly (and this saves us some moves.) */
static void siftDown0 (int numbers[], int last) {
int tmp;

    if (numbers[0] < numbers[1]) {
        tmp = numbers[1];
        numbers[1] = numbers[0];
        siftDown (numbers, 1, last);
    } else {
        tmp = numbers[0];
    }
    numbers[0] = numbers[last];
    numbers[last] = tmp;
}

void heapSort (int numbers[], int qty) {
int i;

    if (qty <= 4) {
        if (qty == 4) sort4 (numbers);
        else if (qty == 3) sort3 (numbers);
        else if (qty == 2) sort2 (numbers);
        return;
    }

    i = qty / 2;
    /* Enforce the heap property for each position in the tree */
    for (  qty--; i >  0; i--) siftDown  (numbers, i, qty);
    for (i = qty; i > 0; i--) siftDown0 (numbers, i);
}

/*
 *  Quick Sort
 */

static int medianOf3 (int * numbers, int i, int j) {
int tmp;

    if (numbers[0] <= numbers[i]) {
        if (numbers[j] <= numbers[0]) return numbers[0]; /* j 0 i */
        if (numbers[i] <= numbers[j]) j = i;             /* 0 i j */
                                                         /* 0 j i */
    } else {
        if (numbers[0] <= numbers[j]) return numbers[0]; /* i 0 j */
        if (numbers[j] <= numbers[i]) j = i;             /* j i 0 */
                                                         /* i j 0 */
    }
    tmp = numbers[j];
    numbers[j] = numbers[0];
    numbers[0] = tmp;
    return tmp;
}

static void quickSortRecurse (int * numbers, int left, int right) {
int pivot, lTmp, rTmp;

    qsrStart:;

#if defined(__GNUC__)
    if (right <= left + 8) {
        insertSort (numbers + left, right - left + 1);
        return;
    }
#else
    if (right <= left + 3) {
        if (right == left + 1) {
            sort2 (numbers + left);
        } else if (right == left + 2) {
            sort3 (numbers + left);
        } else if (right == left + 3) {
            sort4 (numbers + left);
        }
        return;
    }
#endif

    lTmp = left;
    rTmp = right;

    pivot = medianOf3 (numbers + left, (right-left) >> 1, right-1-left);

    goto QStart;
    while (1) {
        do {
            right--;
            if (left >= right) goto QEnd;
            QStart:;
        } while (numbers[right] > pivot);
        numbers[left] = numbers[right];
        do { 
            left++;
            if (left >= right) {
                left = right;
                goto QEnd;
            }
        } while (numbers[ left] < pivot);
        numbers[right] = numbers[left];
    }
    QEnd:;
    numbers[left] = pivot;

    /* Only recurse the smaller partition */

    if (left-1 - lTmp <= rTmp - left - 1) {
        if (lTmp < left) quickSortRecurse (numbers,   lTmp, left-1);

        /* Set up for larger partition */
        left++;
        right = rTmp;
    } else {
        if (rTmp > left) quickSortRecurse (numbers, left+1,   rTmp);

        /* Set up for larger partition */
        right = left - 1;
        left = lTmp;
    }

    /* Rerun with larger partition (recursion not required.) */
    goto qsrStart;
}

void quickSort (int numbers[], int qty) {
    if (qty < 2) return;
    quickSortRecurse (numbers, 0, qty - 1);
}

/*
 *  Merge Sort
 */

static void mergesortInPlace (int * numbers, int * altNumbers, int qty);

/* Perform mergesort, but store results in altNumbers */

static void mergesortExchange (int * numbers, int * altNumbers, int qty) {
int half, i0, i1, i;

    if (qty == 2) {
        sortAlt2 (numbers, altNumbers);
        return;
    }
    if (qty == 3) {
        sortAlt3 (numbers, altNumbers);
        return;
    }

    half = (qty + 1)/2;

    mergesortInPlace (numbers, altNumbers, half);
    mergesortInPlace (numbers + half, altNumbers, qty - half);

    i0 = 0; i1 = half;

    for (i=0; i < qty; i++) {
        if (i1 >= qty || (i0 < half && numbers[i0] < numbers[i1])) {
            altNumbers[i] = numbers[i0];
            i0++;
        } else {
            altNumbers[i] = numbers[i1];
            i1++;
        }
    }
}

/* Perform mergesort and store results in numbers */

static void mergesortInPlace (int * numbers, int * altNumbers, int qty) {
int half, i0, i1, i;

#if 0
    if (qty == 2) {
        sort2 (numbers);
        return;
    }
    if (qty == 3) {
        sort3 (numbers);
        return;
    }
    if (qty == 4) {
        sort4 (numbers);
        return;
    }
#else
    if (qty <= 12) {
        insertSort (numbers, qty);
        return;
    }
#endif

    half = (qty + 1)/2;

    mergesortExchange (numbers, altNumbers, half);
    mergesortExchange (numbers + half, altNumbers + half, qty - half);

    i0 = 0; i1 = half;

    for (i=0; i < qty; i++) {
        if (i1 >= qty || (i0 < half && altNumbers[i0] < altNumbers[i1])) {
            numbers[i] = altNumbers[i0];
            i0++;
        } else {
            numbers[i] = altNumbers[i1];
            i1++;
        }
    }
}

#include <stdlib.h>

void mergeSort (int numbers[], int qty) {
int * tmpArray;

    if (qty <= 12) {
        insertSort (numbers, qty);
        return;
    }

    tmpArray = (int *) malloc (qty * sizeof (int));
    mergesortInPlace (numbers, tmpArray, qty);
    free (tmpArray);
}

/********************************
 * END OF PAUL'S IMPLEMENTATION *
 ********************************/

#define rstype_t unsigned
#define rskey(x) (x)

#define RS_MIN_SIZE 32

typedef struct {
	rstype_t *b, *e;
} bucket_t;

static inline void rs_insertsort(rstype_t *s, rstype_t *t)
{
	rstype_t *i, *j, swap_tmp;
	for (i = s + 1; i < t; ++i)
		for (j = i; j > s && rskey(*j) < rskey(*(j-1)); --j) {
			swap_tmp = *j; *j = *(j-1); *(j-1) = swap_tmp;
		}
}

void rs_classify(rstype_t *beg, rstype_t *end, int n_bits, int s, bucket_t *b)
{
	rstype_t *i, tmp;
	int m = (1<<n_bits) - 1;
	bucket_t *k, *l, *be;

	be = b + (1<<n_bits);
	for (k = b; k != be; ++k) k->b = k->e = beg;
	for (i = beg; i != end; ++i) ++b[rskey(*i)>>s&m].e;
	if (b[0].e == end) return; // no need to sort
	for (k = b + 1; k != be; ++k)
		k->e += (k-1)->e - beg, k->b = (k-1)->e;
	for (k = b; k != be;) {
		if (k->b == k->e) { ++k; continue; }
		l = b + (rskey(*k->b)>>s&m);
		if (k == l) { ++k->b; continue; }
//		while (b + (rskey(*l->b)>>s&m) == l) ++l->b;
		tmp = *l->b; *l->b++ = *k->b; *k->b = tmp;
	}
	for (k = b + 1; k != be; ++k) k->b = (k-1)->e;
	b->b = beg;
}

void rs_sort(rstype_t *beg, rstype_t *end, int n_bits, int s)
{
	if (end - beg > RS_MIN_SIZE) {
		bucket_t *b;
		int i;
		b = (bucket_t*)alloca(sizeof(bucket_t) * (1<<n_bits));
		rs_classify(beg, end, n_bits, s, b);
		if (s) {
			s = s > n_bits? s - n_bits : 0;
			for (i = 0; i != 1<<n_bits; ++i)
				if (b[i].e > b[i].b + 1) rs_sort(b[i].b, b[i].e, n_bits, s);
		}
	} else if (end - beg > 1) rs_insertsort(beg, end);
}

/*************************
 *** END OF RADIX SORT ***
 *************************/

struct intcmp_t {
	inline int operator() (int a, int b) const {
		return a < b? -1 : a > b? 1 : 0;
	}
};

int compare_int(int a, int b)
{
	return a < b? -1 : a > b? 1 : 0;
}
int compare(const void *a, const void *b)
{
	return *((int*)a) - *((int*)b);
}

int main(int argc, char *argv[])
{
	int i, N = 50000000;
	int *array, *temp;
	clock_t t1, t2;
	if (argc == 1) fprintf(stderr, "Usage: %s [%d]\n", argv[0], N);
	if (argc > 1) N = atoi(argv[1]);
	temp = (int*)malloc(sizeof(int) * N);
	array = (int*)malloc(sizeof(int) * N);

	srand48(11);
	for (i = 0; i < N; ++i) array[i] = (int)lrand48();
	t1 = clock();
	rs_sort((unsigned*)array, (unsigned*)array + N, 8, 24);
	t2 = clock();
	fprintf(stderr, "radix sort: %.3lf\n", (double)(t2-t1)/CLOCKS_PER_SEC);
	for (i = 0; i < N-1; ++i) {
		if (array[i] > array[i+1]) {
			fprintf(stderr, "Bug in radix sort!\n");
			exit(1);
		}
	}
	t1 = clock();
	rs_sort((unsigned*)array, (unsigned*)array + N, 8, 24);
	t2 = clock();
	fprintf(stderr, "radix sort (sorted): %.3lf\n", (double)(t2-t1)/CLOCKS_PER_SEC);

	srand48(11);
	for (i = 0; i < N; ++i) array[i] = (int)lrand48();
	t1 = clock();
	sort(array, array+N);
	t2 = clock();
	fprintf(stderr, "STL introsort: %.3lf\n", (double)(t2-t1)/CLOCKS_PER_SEC);
	t1 = clock();
	sort(array, array+N);
	t2 = clock();
	fprintf(stderr, "STL introsort (sorted): %.3lf\n", (double)(t2-t1)/CLOCKS_PER_SEC);

	srand48(11);
	for (i = 0; i < N; ++i) array[i] = (int)lrand48();
	t1 = clock();
	stable_sort(array, array+N);
	t2 = clock();
	fprintf(stderr, "STL stablesort: %.3lf\n", (double)(t2-t1)/CLOCKS_PER_SEC);
	t1 = clock();
	stable_sort(array, array+N);
	t2 = clock();
	fprintf(stderr, "STL stablesort (sorted): %.3lf\n", (double)(t2-t1)/CLOCKS_PER_SEC);

	srand48(11);
	for (i = 0; i < N; ++i) array[i] = (int)lrand48();
	t1 = clock();
	make_heap(array, array+N);
	sort_heap(array, array+N);
	t2 = clock();
	fprintf(stderr, "STL heapsort: %.3lf\n", (double)(t2-t1)/CLOCKS_PER_SEC);
	for (i = 0; i < N-1; ++i) {
		if (array[i] > array[i+1]) {
			fprintf(stderr, "Bug in heap_sort!\n");
			exit(1);
		}
	}
	t1 = clock();
	make_heap(array, array+N);
	sort_heap(array, array+N);
	t2 = clock();
	fprintf(stderr, "STL heapsort (sorted): %.3lf\n", (double)(t2-t1)/CLOCKS_PER_SEC);

	srand48(11);
	for (i = 0; i < N; ++i) array[i] = (int)lrand48();
	t1 = clock();
	ks_combsort(int, N, array);
	t2 = clock();
	fprintf(stderr, "combsort: %.3lf\n", (double)(t2-t1)/CLOCKS_PER_SEC);
	for (i = 0; i < N-1; ++i) {
		if (array[i] > array[i+1]) {
			fprintf(stderr, "Bug in combsort!\n");
			exit(1);
		}
	}

	srand48(11);
	for (i = 0; i < N; ++i) array[i] = (int)lrand48();
	t1 = clock();
	qsort(array, N, sizeof(int), compare);
	t2 = clock();
	fprintf(stderr, "libc qsort: %.3lf\n", (double)(t2-t1)/CLOCKS_PER_SEC);

	srand48(11);
	for (i = 0; i < N; ++i) array[i] = (int)lrand48();
	t1 = clock();
	ks_introsort(int, N, array);
	t2 = clock();
	fprintf(stderr, "my introsort: %.3lf\n", (double)(t2-t1)/CLOCKS_PER_SEC);
	for (i = 0; i < N-1; ++i) {
		if (array[i] > array[i+1]) {
			fprintf(stderr, "Bug in intro_sort!\n");
			exit(1);
		}
	}
	t1 = clock();
	ks_introsort(int, N, array);
	t2 = clock();
	fprintf(stderr, "introsort (sorted): %.3lf\n", (double)(t2-t1)/CLOCKS_PER_SEC);

	srand48(11);
	for (i = 0; i < N; ++i) array[i] = (int)lrand48();
	t1 = clock();
	ks_mergesort(int, N, array, 0);
	t2 = clock();
	fprintf(stderr, "iterative mergesort: %.3lf\n", (double)(t2-t1)/CLOCKS_PER_SEC);
	for (i = 0; i < N-1; ++i) {
		if (array[i] > array[i+1]) {
			fprintf(stderr, "Bug in merge_sort!\n");
			exit(1);
		}
	}
	t1 = clock();
	ks_mergesort(int, N, array, 0);
	t2 = clock();
	fprintf(stderr, "iterative mergesort (sorted): %.3lf\n", (double)(t2-t1)/CLOCKS_PER_SEC);

	srand48(11);
	for (i = 0; i < N; ++i) array[i] = (int)lrand48();
	t1 = clock();
	ks_heapmake(int, N, array);
	ks_heapsort(int, N, array);
	t2 = clock();
	fprintf(stderr, "my heapsort: %.3lf\n", (double)(t2-t1)/CLOCKS_PER_SEC);
	for (i = 0; i < N-1; ++i) {
		if (array[i] > array[i+1]) {
			fprintf(stderr, "Bug in heap_sort!\n");
			exit(1);
		}
	}
	t1 = clock();
	ks_heapmake(int, N, array);
	ks_heapsort(int, N, array);
	t2 = clock();
	fprintf(stderr, "heapsort (sorted): %.3lf\n", (double)(t2-t1)/CLOCKS_PER_SEC);

	srand48(11);
	for (i = 0; i < N; ++i) array[i] = (int)lrand48();
	t1 = clock();
	heapSort(array, N);
	t2 = clock();
	fprintf(stderr, "Paul's heapsort: %.3lf\n", (double)(t2-t1)/CLOCKS_PER_SEC);
	for (i = 0; i < N-1; ++i) {
		if (array[i] > array[i+1]) {
			fprintf(stderr, "Bug in intro_sort!\n");
			exit(1);
		}
	}

	srand48(11);
	for (i = 0; i < N; ++i) array[i] = (int)lrand48();
	t1 = clock();
	quickSort(array, N);
	t2 = clock();
	fprintf(stderr, "Paul's quicksort: %.3lf\n", (double)(t2-t1)/CLOCKS_PER_SEC);
	for (i = 0; i < N-1; ++i) {
		if (array[i] > array[i+1]) {
			fprintf(stderr, "Bug in intro_sort!\n");
			exit(1);
		}
	}

	srand48(11);
	for (i = 0; i < N; ++i) array[i] = (int)lrand48();
	t1 = clock();
	mergeSort(array, N);
	t2 = clock();
	fprintf(stderr, "Paul's mergesort: %.3lf\n", (double)(t2-t1)/CLOCKS_PER_SEC);
	for (i = 0; i < N-1; ++i) {
		if (array[i] > array[i+1]) {
			fprintf(stderr, "Bug in intro_sort!\n");
			exit(1);
		}
	}

	free(array); free(temp);
	return 0;
}
