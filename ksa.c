/*
 * Copyright (c) 2008 Yuta Mori    All Rights Reserved.
 *               2011 Attractive Chaos <attractor@live.co.uk>
 *
 * Permission is hereby granted, free of charge, to any person
 * obtaining a copy of this software and associated documentation
 * files (the "Software"), to deal in the Software without
 * restriction, including without limitation the rights to use,
 * copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the
 * Software is furnished to do so, subject to the following
 * conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES
 * OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT
 * HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY,
 * WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
 * OTHER DEALINGS IN THE SOFTWARE.
 */

/* This is a library for constructing the suffix array for a string containing
 * multiple sentinels with sentinels all represented by 0. The last symbol in
 * the string must be a sentinel. The library is modified from an early version
 * of Yuta Mori's SAIS library, but is slower than the lastest SAIS by about
 * 30%, partly due to the recent optimization Yuta has applied and partly due
 * to the extra comparisons between sentinels. This is not the first effort in
 * supporting multi-sentinel strings, but is probably the easiest to use. */

#include <stdlib.h>

#ifdef _KSA64
#include <stdint.h>
typedef int64_t saint_t;
#define SAINT_MAX INT64_MAX
#define SAIS_CORE ksa_core64
#define SAIS_BWT  ksa_bwt64
#define SAIS_MAIN ksa_sa64
#else
#include <limits.h>
typedef int saint_t;
#define SAINT_MAX INT_MAX
#define SAIS_CORE ksa_core
#define SAIS_BWT  ksa_bwt
#define SAIS_MAIN ksa_sa
#endif

/* T is of type "const unsigned char*". If T[i] is a sentinel, chr(i) takes a negative value */
#define chr(i) (cs == sizeof(saint_t) ? ((const saint_t *)T)[i] : (T[i]? (saint_t)T[i] : i - SAINT_MAX))

/** Count the occurrences of each symbol */
static void getCounts(const unsigned char *T, saint_t *C, saint_t n, saint_t k, int cs)
{
	saint_t i;
	for (i = 0; i < k; ++i) C[i] = 0;
	for (i = 0; i < n; ++i) {
		saint_t c = chr(i);
		++C[c > 0? c : 0];
	}
}

/**
 * Find the end of each bucket
 *
 * @param C   occurrences computed by getCounts(); input
 * @param B   start/end of each bucket; output
 * @param k   size of alphabet
 * @param end compute the end of bucket if true; otherwise compute the end
 */
static inline void getBuckets(const saint_t *C, saint_t *B, saint_t k, saint_t end)
{
	saint_t i, sum = 0;
	if (end) for (i = 0; i < k; ++i) sum += C[i], B[i] = sum;
	else for (i = 0; i < k; ++i) sum += C[i], B[i] = sum - C[i];
}

/** Induced sort */
static void induceSA(const unsigned char *T, saint_t *SA, saint_t *C, saint_t *B, saint_t n, saint_t k, saint_t cs)
{
	saint_t *b, i, j;
	saint_t  c0, c1;
	/* left-to-right induced sort (for L-type) */
	if (C == B) getCounts(T, C, n, k, cs);
	getBuckets(C, B, k, 0);	/* find starts of buckets */
	for (i = 0, b = 0, c1 = -1; i < n; ++i) {
		j = SA[i], SA[i] = ~j;
		if (0 < j) { /* >0 if j-1 is L-type; <0 if S-type; ==0 undefined */
			--j;
			if ((c0 = chr(j)) != c1) {
				B[c1 > 0? c1 : 0] = b - SA;
				c1 = c0;
				b = SA + B[c1 > 0? c1 : 0];
			}
			*b++ = (0 < j && chr(j - 1) < c1) ? ~j : j;
		}
	}
	/* right-to-left induced sort (for S-type) */
	if (C == B) getCounts(T, C, n, k, cs);
	getBuckets(C, B, k, 1);	/* find ends of buckets */
	for (i = n - 1, b = 0, c1 = -1; 0 <= i; --i) {
		if (0 < (j = SA[i])) { /* the prefix is S-type */
			--j;
			if ((c0 = chr(j)) != c1) {
				B[c1 > 0? c1 : 0] = b - SA;
				c1 = c0;
				b = SA + B[c1 > 0? c1 : 0];
			}
			if (c0 > 0) *--b = (j == 0 || chr(j - 1) > c1) ? ~j : j;
		} else SA[i] = ~j; /* if L-type, change the sign */
	}
}

/**
 * Recursively construct the suffix array for a string containing multiple
 * sentinels. NULL is taken as the sentinel.
 *
 * @param T   NULL terminated input string (there can be multiple NULLs)
 * @param SA  output suffix array
 * @param fs  working space available in SA (typically 0 when first called)
 * @param n   length of T, including the trailing NULL
 * @param k   size of the alphabet (typically 256 when first called)
 * @param cs  # bytes per element in T; 1 or sizeof(saint_t) (typically 1 when first called)
 *
 * @return    0 upon success
 */
int SAIS_CORE(const unsigned char *T, saint_t *SA, saint_t fs, saint_t n, saint_t k, int cs)
{
	saint_t *C, *B;
	saint_t  i, j, c, m, q, qlen, name;
	saint_t  c0, c1;

	/* STAGE I: reduce the problem by at least 1/2 sort all the S-substrings */
	if (k <= fs) C = SA + n, B = (k <= fs - k) ? C + k : C;
	else {
		if ((C = (saint_t*)malloc(k * (1 + (cs == 1)) * sizeof(saint_t))) == NULL) return -2;
		B = cs == 1? C + k : C;
	}
	getCounts(T, C, n, k, cs);
	getBuckets(C, B, k, 1);	/* find ends of buckets */
	for (i = 0; i < n; ++i) SA[i] = 0;
	/* mark L and S (the t array in Nong et al.), and keep the positions of LMS in the buckets */
	for (i = n - 2, c = 1, c1 = chr(n - 1); 0 <= i; --i, c1 = c0) {
		if ((c0 = chr(i)) < c1 + c) c = 1; /* c1 = chr(i+1); c==1 if in an S run */
		else if (c) SA[--B[c1 > 0? c1 : 0]] = i + 1, c = 0;
	}
	induceSA(T, SA, C, B, n, k, cs);
	if (fs < k) free(C);
	/* pack all the sorted LMS into the first m items of SA 
	   2*m must be not larger than n (see Nong et al. for the proof) */
	for (i = 0, m = 0; i < n; ++i) {
		saint_t p = SA[i];
		if (p == n - 1) SA[m++] = p;
		else if (0 < p && chr(p - 1) > (c0 = chr(p))) {
			for (j = p + 1; j < n && c0 == (c1 = chr(j)); ++j);
			if (j < n && c0 < c1) SA[m++] = p;
		}
	}
	for (i = m; i < n; ++i) SA[i] = 0;	/* init the name array buffer */
	/* store the length of all substrings */
	for (i = n - 2, j = n, c = 1, c1 = chr(n - 1); 0 <= i; --i, c1 = c0) {
		if ((c0 = chr(i)) < c1 + c) c = 1; /* c1 = chr(i+1) */
		else if (c) SA[m + ((i + 1) >> 1)] = j - i - 1, j = i + 1, c = 0;
	}
	/* find the lexicographic names of all substrings */
	for (i = 0, name = 0, q = n, qlen = 0; i < m; ++i) {
		saint_t p = SA[i], plen = SA[m + (p >> 1)], diff = 1;
		if (plen == qlen) {
			for (j = 0; j < plen && chr(p + j) == chr(q + j); j++);
			if (j == plen) diff = 0;
		}
		if (diff) ++name, q = p, qlen = plen;
		SA[m + (p >> 1)] = name;
	}

	/* STAGE II: solve the reduced problem; recurse if names are not yet unique */
	if (name < m) {
		saint_t *RA = SA + n + fs - m - 1;
		for (i = n - 1, j = m - 1; m <= i; --i)
			if (SA[i] != 0) RA[j--] = SA[i];
		RA[m] = 0; // add a sentinel; in the resulting SA, SA[0]==m always stands
		if (SAIS_CORE((unsigned char *)RA, SA, fs + n - m * 2 - 2, m + 1, name + 1, sizeof(saint_t)) != 0) return -2;
		for (i = n - 2, j = m - 1, c = 1, c1 = chr(n - 1); 0 <= i; --i, c1 = c0) {
			if ((c0 = chr(i)) < c1 + c) c = 1;
			else if (c) RA[j--] = i + 1, c = 0; /* get p1 */
		}
		for (i = 0; i < m; ++i) SA[i] = RA[SA[i+1]]; /* get index  */
	}

	/* STAGE III: induce the result for the original problem */
	if (k <= fs) C = SA + n, B = (k <= fs - k) ? C + k : C;
	else {
		if ((C = (saint_t*)malloc(k * (1 + (cs == 1)) * sizeof(saint_t))) == NULL) return -2;
		B = cs == 1? C + k : C;
	}
	/* put all LMS characters into their buckets */
	getCounts(T, C, n, k, cs);
	getBuckets(C, B, k, 1);	/* find ends of buckets */
	for (i = m; i < n; ++i) SA[i] = 0; /* init SA[m..n-1] */
	for (i = m - 1; 0 <= i; --i) {
		j = SA[i], SA[i] = 0;
		c = chr(j);
		SA[--B[c > 0? c : 0]] = j;
	}
	induceSA(T, SA, C, B, n, k, cs);
	if (fs < k) free(C);
	return 0;
}

/**
 * Construct the suffix array for a NULL terminated string possibly containing
 * multiple sentinels (NULLs).
 *
 * @param T[0..n-1]  NULL terminated input string
 * @param SA[0..n-1] output suffix array
 * @param n          length of the given string, including NULL
 * @param k          size of the alphabet including the sentinel; no more than 256
 * @return           0 upon success
 */
int SAIS_MAIN(const unsigned char *T, saint_t *SA, saint_t n, int k)
{
	if (T == NULL || SA == NULL || T[n - 1] != '\0' || n <= 0) return -1;
	if (k < 0 || k > 256) k = 256;
	return SAIS_CORE(T, SA, 0, n, (saint_t)k, 1);
}

int SAIS_BWT(unsigned char *T, saint_t n, int k)
{
	saint_t *SA, i;
	int ret;
	if ((SA = malloc(n * sizeof(saint_t))) == 0) return -1;
	if ((ret = SAIS_MAIN(T, SA, n, k)) != 0) return ret;
	for (i = 0; i < n; ++i)
		if (SA[i]) SA[i] = T[SA[i] - 1]; // if SA[i]==0, SA[i]=0
	for (i = 0; i < n; ++i) T[i] = SA[i];
	free(SA);
	return 0;
}
