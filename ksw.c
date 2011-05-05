#include <stdlib.h>
#include <stdint.h>
#include <emmintrin.h>
#include "ksw.h"

#include <stdio.h>

#ifdef __GNUC__
#define LIKELY(x) __builtin_expect((x),1)
#define UNLIKELY(x) __builtin_expect((x),0)
#else
#define LIKELY(x) (x)
#define UNLIKELY(x) (x)
#endif

struct _ksw_query_t {
	int slen;
	uint8_t shift;
	__m128i *qp, *H0, *H1, *E;
};

ksw_query_t *ksw_qinit(int qlen, const uint8_t *query, int p, int m, const int8_t *mat)
{
	ksw_query_t *q;
	uint8_t *aligned;
	int8_t *t;
	int qlen16, slen, a, tmp;

	slen = (qlen + p - 1) / p;
	qlen16 = (qlen + 15) >> 4 << 4;
	q = malloc(sizeof(ksw_query_t) + 256 + qlen16 * (m + 2)); // a single block of memory
	q->qp = (__m128i*)(((size_t)q + sizeof(ksw_query_t) + 15) >> 4 << 4); // align memory
	q->H0 = q->qp + qlen16 * m;
	q->H1 = q->H0 + qlen16;
	q->E  = q->H1 + qlen16;
	q->slen = slen;
	// compute shift
	tmp = m * m;
	for (a = 0, q->shift = 127; a < tmp; ++a) // find the minimum score (should be negative)
		if (mat[a] < (int8_t)q->shift) q->shift = mat[a];
	q->shift = 256 - q->shift; // NB: q->shift is uint8_t
	// An example: p=8, qlen=19, slen=3 and segmentation:
	//  {{0,3,6,9,12,15,18,-1},{1,4,7,10,13,16,-1,-1},{2,5,8,11,14,17,-1,-1}}
	t = (int8_t*)q->qp;
	for (a = 0; a < m; ++a) {
		int i, k;
		const int8_t *ma = mat + a * m;
		for (i = 0; i < slen; ++i)
			for (k = i; k < qlen16; k += slen) { // p iterations
				*t++ = (k >= qlen? 0 : ma[query[k]]) + q->shift;
				//printf("%d,%d,%d,%d\n", a, i, k, *(t-1));
			}
	}
	return q;
}

int ksw_sse2_16(ksw_query_t *q, int tlen, const uint8_t *target, unsigned _o, unsigned _e) // the first gap costs -(_o+_e)
{
	int slen, i, score;
	__m128i zero, gapo, gape, shift, gmax, *H0, *H1, *E;

#define __set_16(ret, xx) do { \
		uint16_t t16 = ((uint16_t)(xx) << 8) | ((uint16_t)(xx) & 0x00ff); \
		(ret) = _mm_insert_epi16((ret), t16, 0); \
		(ret) = _mm_shufflelo_epi16((ret), 0); \
		(ret) = _mm_shuffle_epi32((ret), 0); \
	} while (0)

#define __max_16(ret, xx) do { \
		__m128i t; \
		(xx) = _mm_max_epu8((xx), _mm_srli_si128((xx), 8)); \
		(xx) = _mm_max_epu8((xx), _mm_srli_si128((xx), 4)); \
		(xx) = _mm_max_epu8((xx), _mm_srli_si128((xx), 2)); \
		(xx) = _mm_max_epu8((xx), _mm_srli_si128((xx), 1)); \
    	(ret) = _mm_extract_epi16((xx), 0) & 0x00ff; \
	} while (0)

	// initialization
	zero = _mm_xor_si128(zero, zero);
	gmax = _mm_xor_si128(gmax, gmax);
	__set_16(gapo, _o + _e);
	__set_16(gape, _e);
	H0 = q->H0; H1 = q->H1; E = q->E;
	slen = q->slen;
	__set_16(shift, q->shift);
	for (i = 0; i < slen; ++i) {
		_mm_store_si128(E + i, zero);
		_mm_store_si128(H0 + i, zero);
	}
	// the core loop
	for (i = 0; i < tlen; ++i) {
		int j, k, cmp;
		__m128i e, h, f, max, t, *S = q->qp + target[i] * slen; // s is the 1st score vector
		max = _mm_xor_si128(max, max);
		f = _mm_xor_si128(f, f);
		h = _mm_load_si128(H0 + slen - 1); // h={2,5,8,11,14,17,-1,-1} in the above example
		h = _mm_slli_si128(h, 1); // h=H(i-1,-1); << instead of >> because x86 is little-endian
		for (score=0;score<16;++score)printf("%d ", ((int8_t*)&S[0])[score]);printf("\n");
		for (j = 0; LIKELY(j < slen); ++j) {
			// at the beginning, h=H'(i-1,j-1)
			h = _mm_adds_epu8(h, S[j]);
			h = _mm_subs_epu8(h, shift); // h=H'(i-1,j-1)+S(i,j)
			e = _mm_load_si128(E + j); // e=E'(i,j)
			h = _mm_max_epu8(h, e);
			h = _mm_max_epu8(h, f); // h=H'(i,j)
			max = _mm_max_epu8(max, h); // set max
			_mm_store_si128(H1 + j, h); // save to H'(i,j)
			// now compute E(i+1,j)
			h = _mm_subs_epu8(h, gapo); // h=H'(i,j)-gapo
			e = _mm_subs_epu8(e, gape); // e=E'(i,j)-gape
			e = _mm_max_epu8(e, h); // e=E'(i+1,j)
			_mm_store_si128(E + j, e); // save to E'(i+1,j)
			// now compute F'(i,j+1)
			f = _mm_subs_epu8(f, gape);
			f = _mm_max_epu8(f, h);
			// get H'(i-1,j) and prepare for the next j
			h = _mm_load_si128(H0 + j); // h=H'(i-1,j)
		}
		gmax = _mm_max_epu8(gmax, max); // NB: H(i,j) updated in the lazy-F loop cannot exceed max
		// NB: we do not need to set E(i,j) as we disallow adjecent insertion and then deletion
		for (k = 0; LIKELY(k < 16); ++k) {
			f = _mm_slli_si128(f, 1);
			for (j = 0; LIKELY(j < slen); ++j) {
				h = _mm_load_si128(H1 + j);
				h = _mm_max_epu8(h, f); // h=H'(i,j)
				_mm_store_si128(H1 + j, h);
				h = _mm_subs_epu8(h, gapo);
				f = _mm_subs_epu8(f, gape);
				cmp = _mm_movemask_epi8(_mm_cmpeq_epi8(_mm_subs_epu8(f, h), zero));
				if (UNLIKELY(cmp == 0xffff)) goto end_loop;
			}
		}
end_loop:
		S = H1; H1 = H0; H0 = S; // swap H0 and H1
	}
	__max_16(score, gmax);
	return score;
}

int main()
{
	int8_t mat[] = {1, -3, -3, 1};
	uint8_t *t = (uint8_t*)"\1\0\1\1\0\0";
	uint8_t *q = (uint8_t*)"\1\1";
	ksw_query_t *qq = ksw_qinit(2, q, 16, 2, mat);
	int s = ksw_sse2_16(qq, 6, t, 5, 2);
	free(qq);
	printf("%d\n", s);
	return 0;
}
