/* The MIT License

   Copyright (c) 2011 by Attractive Chaos <attractor@live.co.uk>

   Permission is hereby granted, free of charge, to any person obtaining
   a copy of this software and associated documentation files (the
   "Software"), to deal in the Software without restriction, including
   without limitation the rights to use, copy, modify, merge, publish,
   distribute, sublicense, and/or sell copies of the Software, and to
   permit persons to whom the Software is furnished to do so, subject to
   the following conditions:

   The above copyright notice and this permission notice shall be
   included in all copies or substantial portions of the Software.

   THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
   EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
   MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
   NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
   BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
   ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
   CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
   SOFTWARE.
*/

#include <stdlib.h>
#include <stdint.h>
#include <emmintrin.h>
#include "ksw.h"

#ifdef __GNUC__
#define LIKELY(x) __builtin_expect((x),1)
#define UNLIKELY(x) __builtin_expect((x),0)
#else
#define LIKELY(x) (x)
#define UNLIKELY(x) (x)
#endif

struct _ksw_query_t {
	int qlen, slen;
	uint8_t shift, mdiff;
	__m128i *qp, *H0, *H1, *E, *Hmax;
};

ksw_query_t *ksw_qinit(int p, int qlen, const uint8_t *query, int m, const int8_t *mat)
{
	ksw_query_t *q;
	int8_t *t;
	int qlen16, slen, a, tmp;

	slen = (qlen + p - 1) / p;
	qlen16 = (qlen + 15) >> 4 << 4;
	q = malloc(sizeof(ksw_query_t) + 256 + qlen16 * (m + 4)); // a single block of memory
	q->qp = (__m128i*)(((size_t)q + sizeof(ksw_query_t) + 15) >> 4 << 4); // align memory
	q->H0 = q->qp + (qlen16 * m) / 16;
	q->H1 = q->H0 + qlen16 / 16;
	q->E  = q->H1 + qlen16 / 16;
	q->Hmax = q->E + qlen16 / 16;
	q->slen = slen; q->qlen = qlen;
	// compute shift
	tmp = m * m;
	for (a = 0, q->shift = 127, q->mdiff = 0; a < tmp; ++a) { // find the minimum and maximum score
		if (mat[a] < (int8_t)q->shift) q->shift = mat[a];
		if (mat[a] > (int8_t)q->mdiff) q->mdiff = mat[a];
	}
	q->shift = 256 - q->shift; // NB: q->shift is uint8_t
	q->mdiff += q->shift; // this is the difference between the min and max scores
	// An example: p=8, qlen=19, slen=3 and segmentation:
	//  {{0,3,6,9,12,15,18,-1},{1,4,7,10,13,16,-1,-1},{2,5,8,11,14,17,-1,-1}}
	t = (int8_t*)q->qp;
	for (a = 0; a < m; ++a) {
		int i, k;
		const int8_t *ma = mat + a * m;
		for (i = 0; i < slen; ++i)
			for (k = i; k < qlen16; k += slen) // p iterations
				*t++ = (k >= qlen? 0 : ma[query[k]]) + q->shift;
	}
	return q;
}

int ksw_sse2_16(ksw_query_t *q, int tlen, const uint8_t *target, ksw_aux_t *a) // the first gap costs -(_o+_e)
{
	int slen, i, sum, score;
	__m128i zero, gapoe, gape, shift, gmax, reduce, thres, *H0, *H1, *E, *Hmax;

#define __max_16(ret, xx) do { \
		(xx) = _mm_max_epu8((xx), _mm_srli_si128((xx), 8)); \
		(xx) = _mm_max_epu8((xx), _mm_srli_si128((xx), 4)); \
		(xx) = _mm_max_epu8((xx), _mm_srli_si128((xx), 2)); \
		(xx) = _mm_max_epu8((xx), _mm_srli_si128((xx), 1)); \
    	(ret) = _mm_extract_epi16((xx), 0) & 0x00ff; \
	} while (0)

	// initialization
	a->te = -1;
	gmax = zero = _mm_set1_epi32(0);
	gapoe = _mm_set1_epi8(a->gapo + a->gape);
	gape = _mm_set1_epi8(a->gape);
	shift = _mm_set1_epi8(q->shift);
	thres = _mm_set1_epi8(254 - q->mdiff); // when max score exceeds this, shift all scores by "reduce" below
	reduce = _mm_set1_epi8(127);
	H0 = q->H0; H1 = q->H1; E = q->E; Hmax = q->Hmax;
	slen = q->slen;
	for (i = 0; i < slen; ++i) {
		_mm_store_si128(E + i, zero);
		_mm_store_si128(H0 + i, zero);
	}
	// the core loop
	for (i = 0, sum = 0; i < tlen; ++i) {
		int j, k, cmp;
		__m128i e, h, f = zero, max = zero, *S = q->qp + target[i] * slen; // s is the 1st score vector
		h = _mm_load_si128(H0 + slen - 1); // h={2,5,8,11,14,17,-1,-1} in the above example
		h = _mm_slli_si128(h, 1); // h=H(i-1,-1); << instead of >> because x86 is little-endian
		for (j = 0; LIKELY(j < slen); ++j) {
			/* SW cells are computed in the following order:
			 *   H(i,j)   = max{H(i-1,j-1)+S(i,j), E(i,j), F(i,j)}
			 *   E(i+1,j) = max{H(i,j)-q, E(i,j)-r}
			 *   F(i,j+1) = max{H(i,j)-q, F(i,j)-r}
			 */
			// compute H'(i,j); note that at the beginning, h=H'(i-1,j-1)
			h = _mm_adds_epu8(h, S[j]);
			h = _mm_subs_epu8(h, shift); // h=H'(i-1,j-1)+S(i,j)
			e = _mm_load_si128(E + j); // e=E'(i,j)
			h = _mm_max_epu8(h, e);
			h = _mm_max_epu8(h, f); // h=H'(i,j)
			max = _mm_max_epu8(max, h); // set max
			_mm_store_si128(H1 + j, h); // save to H'(i,j)
			// now compute E'(i+1,j)
			h = _mm_subs_epu8(h, gapoe); // h=H'(i,j)-gapo
			e = _mm_subs_epu8(e, gape); // e=E'(i,j)-gape
			e = _mm_max_epu8(e, h); // e=E'(i+1,j)
			_mm_store_si128(E + j, e); // save to E'(i+1,j)
			// now compute F'(i,j+1)
			f = _mm_subs_epu8(f, gape);
			f = _mm_max_epu8(f, h);
			// get H'(i-1,j) and prepare for the next j
			h = _mm_load_si128(H0 + j); // h=H'(i-1,j)
		}
		// NB: we do not need to set E(i,j) as we disallow adjecent insertion and then deletion
		for (k = 0; LIKELY(k < 16); ++k) { // this block mimics SWPS3; NB: H(i,j) updated in the lazy-F loop cannot exceed max
			f = _mm_slli_si128(f, 1);
			for (j = 0; LIKELY(j < slen); ++j) {
				h = _mm_load_si128(H1 + j);
				h = _mm_max_epu8(h, f); // h=H'(i,j)
				_mm_store_si128(H1 + j, h);
				h = _mm_subs_epu8(h, gapoe);
				f = _mm_subs_epu8(f, gape);
				cmp = _mm_movemask_epi8(_mm_cmpeq_epi8(_mm_subs_epu8(f, h), zero));
				if (UNLIKELY(cmp == 0xffff)) goto end_loop;
			}
		}
end_loop:
		if (_mm_movemask_epi8(_mm_cmpeq_epi8(_mm_subs_epu8(max, gmax), zero)) != 0xffff) { // if max > gmax at any position
			int imax, igmax;
			__max_16(imax, max);   // maximum in max
			__max_16(igmax, gmax); // maximum in gmax
			if (imax > igmax) { // if the max has been updated
				a->te = i; // the end position on the target
				for (j = 0; LIKELY(j < slen); ++j) // keep the H1 vector
					_mm_store_si128(Hmax + j, _mm_load_si128(H1 + j));
			}
			gmax = _mm_max_epu8(gmax, max); // update gmax
			if (_mm_movemask_epi8(_mm_cmpeq_epi8(_mm_subs_epu8(gmax, thres), zero)) != 0xffff) { // reduce
				/* When overflow is going to happen, subtract 127 from all scores. This heuristic
				 * may miss the best alignment, but in practice this should happen very rarely. */
				sum += 127;
				gmax = _mm_subs_epu8(gmax, reduce);
				//int k;for (k=0;k<16;++k)printf("%d ", ((uint8_t*)&thres)[k]);printf("\n");
				for (j = 0; LIKELY(j < slen); ++j) {
					h = _mm_subs_epu8(_mm_load_si128(H1 + j), reduce);
					_mm_store_si128(H1 + j, h);
					e = _mm_subs_epu8(_mm_load_si128(E + j), reduce);
					_mm_store_si128(E + j, e);
				}
			}
		}
		S = H1; H1 = H0; H0 = S; // swap H0 and H1
	}
	__max_16(score, gmax);
	a->score = score + sum;
	{ // get a->qe, the end of query match
		int max = -1;
		uint8_t *t = (uint8_t*)Hmax;
		for (i = 0, score = 0, a->qe = -1; i < q->qlen; ++i, ++t)
			if ((int)*t > max) max = *t, a->qe = i / 16 + i % 16 * slen;
	}
	return a->score;
}

/*******************************************
 * Main function (not compiled by default) *
 *******************************************/

#ifdef _KSW_MAIN

#include <unistd.h>
#include <stdio.h>
#include <zlib.h>
#include "kseq.h"
KSEQ_INIT(gzFile, gzread)

unsigned char seq_nt4_table[256] = {
	4, 4, 4, 4,  4, 4, 4, 4,  4, 4, 4, 4,  4, 4, 4, 4, 
	4, 4, 4, 4,  4, 4, 4, 4,  4, 4, 4, 4,  4, 4, 4, 4, 
	4, 4, 4, 4,  4, 4, 4, 4,  4, 4, 4, 4,  4, 4, 4, 4,
	4, 4, 4, 4,  4, 4, 4, 4,  4, 4, 4, 4,  4, 4, 4, 4, 
	4, 0, 4, 1,  4, 4, 4, 2,  4, 4, 4, 4,  4, 4, 4, 4, 
	4, 4, 4, 4,  3, 4, 4, 4,  4, 4, 4, 4,  4, 4, 4, 4, 
	4, 0, 4, 1,  4, 4, 4, 2,  4, 4, 4, 4,  4, 4, 4, 4, 
	4, 4, 4, 4,  3, 4, 4, 4,  4, 4, 4, 4,  4, 4, 4, 4, 
	4, 4, 4, 4,  4, 4, 4, 4,  4, 4, 4, 4,  4, 4, 4, 4, 
	4, 4, 4, 4,  4, 4, 4, 4,  4, 4, 4, 4,  4, 4, 4, 4, 
	4, 4, 4, 4,  4, 4, 4, 4,  4, 4, 4, 4,  4, 4, 4, 4, 
	4, 4, 4, 4,  4, 4, 4, 4,  4, 4, 4, 4,  4, 4, 4, 4, 
	4, 4, 4, 4,  4, 4, 4, 4,  4, 4, 4, 4,  4, 4, 4, 4, 
	4, 4, 4, 4,  4, 4, 4, 4,  4, 4, 4, 4,  4, 4, 4, 4, 
	4, 4, 4, 4,  4, 4, 4, 4,  4, 4, 4, 4,  4, 4, 4, 4, 
	4, 4, 4, 4,  4, 4, 4, 4,  4, 4, 4, 4,  4, 4, 4, 4
};

int main(int argc, char *argv[])
{
	int c, sa = 1, sb = 3, i, j, k, forward_only = 0;
	int8_t mat[25];
	ksw_aux_t a;
	gzFile fpt, fpq;
	kseq_t *kst, *ksq;
	// parse command line
	a.gapo = 5; a.gape = 2; a.T = 20;
	while ((c = getopt(argc, argv, "a:b:q:r:ft:")) >= 0) {
		switch (c) {
			case 'a': sa = atoi(optarg); break;
			case 'b': sb = atoi(optarg); break;
			case 'q': a.gapo = atoi(optarg); break;
			case 'r': a.gape = atoi(optarg); break;
			case 't': a.T = atoi(optarg); break;
			case 'f': forward_only = 1; break;
		}
	}
	if (optind + 2 > argc) {
		fprintf(stderr, "Usage: ksw [-a%d] [-b%d] [-q%d] [-r%d] <target.fa> <query.fa>\n", sa, sb, a.gapo, a.gape);
		return 1;
	}
	// initialize scoring matrix
	for (i = k = 0; i < 5; ++i) {
		for (j = 0; j < 4; ++j)
			mat[k++] = i == j? sa : -sb;
		mat[k++] = 0; // ambiguous base
	}
	for (j = 0; j < 5; ++j) mat[k++] = 0;
	// open file
	fpt = gzopen(argv[optind],   "r"); kst = kseq_init(fpt);
	fpq = gzopen(argv[optind+1], "r"); ksq = kseq_init(fpq);
	// all-pair alignment
	while (kseq_read(ksq) > 0) {
		ksw_query_t *q[2];
		for (i = 0; i < ksq->seq.l; ++i) ksq->seq.s[i] = seq_nt4_table[(int)ksq->seq.s[i]];
		q[0] = ksw_qinit(16, ksq->seq.l, (uint8_t*)ksq->seq.s, 5, mat);
		if (!forward_only) { // reverse
			for (i = 0; i < ksq->seq.l/2; ++i) {
				int t = ksq->seq.s[i];
				ksq->seq.s[i] = ksq->seq.s[ksq->seq.l-1-i];
				ksq->seq.s[ksq->seq.l-1-i] = t;
			}
			for (i = 0; i < ksq->seq.l; ++i)
				ksq->seq.s[i] = ksq->seq.s[i] == 4? 4 : 3 - ksq->seq.s[i];
			q[1] = ksw_qinit(16, ksq->seq.l, (uint8_t*)ksq->seq.s, 5, mat);
		} else q[1] = 0;
		gzrewind(fpt); kseq_rewind(kst);
		while (kseq_read(kst) > 0) {
			int s;
			for (i = 0; i < kst->seq.l; ++i) kst->seq.s[i] = seq_nt4_table[(int)kst->seq.s[i]];
			s = ksw_sse2_16(q[0], kst->seq.l, (uint8_t*)kst->seq.s, &a);
			printf("%s\t%s\t+\t%d\t%d\t%d\n", ksq->name.s, kst->name.s, s, a.te+1, a.qe+1);
			if (q[1]) {
				s = ksw_sse2_16(q[1], kst->seq.l, (uint8_t*)kst->seq.s, &a);
				printf("%s\t%s\t-\t%d\t%d\t%d\n", ksq->name.s, kst->name.s, s, a.te+1, a.qe+1);
			}
		}
		free(q[0]); free(q[1]);
	}
	kseq_destroy(kst); gzclose(fpt);
	kseq_destroy(ksq); gzclose(fpq);
	return 0;
}
#endif
