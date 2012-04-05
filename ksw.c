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

const kswr_t g_defr = { 0, -1, -1, -1, -1, -1, -1 };

struct _kswq_t {
	int qlen, slen;
	uint8_t shift, mdiff, max, size;
	__m128i *qp, *H0, *H1, *E, *Hmax;
};

/**
 * Initialize the query data structure
 *
 * @param size   Number of bytes used to store a score; valid valures are 1 or 2
 * @param qlen   Length of the query sequence
 * @param query  Query sequence
 * @param m      Size of the alphabet
 * @param mat    Scoring matrix in a one-dimension array
 *
 * @return       Query data structure
 */
kswq_t *ksw_qinit(int size, int qlen, const uint8_t *query, int m, const int8_t *mat)
{
	kswq_t *q;
	int slen, a, tmp, p;

	size = size > 1? 2 : 1;
	p = 8 * (3 - size); // # values per __m128i
	slen = (qlen + p - 1) / p; // segmented length
	q = (kswq_t*)malloc(sizeof(kswq_t) + 256 + 16 * slen * (m + 4)); // a single block of memory
	q->qp = (__m128i*)(((size_t)q + sizeof(kswq_t) + 15) >> 4 << 4); // align memory
	q->H0 = q->qp + slen * m;
	q->H1 = q->H0 + slen;
	q->E  = q->H1 + slen;
	q->Hmax = q->E + slen;
	q->slen = slen; q->qlen = qlen; q->size = size;
	// compute shift
	tmp = m * m;
	for (a = 0, q->shift = 127, q->mdiff = 0; a < tmp; ++a) { // find the minimum and maximum score
		if (mat[a] < (int8_t)q->shift) q->shift = mat[a];
		if (mat[a] > (int8_t)q->mdiff) q->mdiff = mat[a];
	}
	q->max = q->mdiff;
	q->shift = 256 - q->shift; // NB: q->shift is uint8_t
	q->mdiff += q->shift; // this is the difference between the min and max scores
	// An example: p=8, qlen=19, slen=3 and segmentation:
	//  {{0,3,6,9,12,15,18,-1},{1,4,7,10,13,16,-1,-1},{2,5,8,11,14,17,-1,-1}}
	if (size == 1) {
		int8_t *t = (int8_t*)q->qp;
		for (a = 0; a < m; ++a) {
			int i, k, nlen = slen * p;
			const int8_t *ma = mat + a * m;
			for (i = 0; i < slen; ++i)
				for (k = i; k < nlen; k += slen) // p iterations
					*t++ = (k >= qlen? 0 : ma[query[k]]) + q->shift;
		}
	} else {
		int16_t *t = (int16_t*)q->qp;
		for (a = 0; a < m; ++a) {
			int i, k, nlen = slen * p;
			const int8_t *ma = mat + a * m;
			for (i = 0; i < slen; ++i)
				for (k = i; k < nlen; k += slen) // p iterations
					*t++ = (k >= qlen? 0 : ma[query[k]]);
		}
	}
	return q;
}

kswr_t ksw_u8(kswq_t *q, int tlen, const uint8_t *target, int _gapo, int _gape, int xtra) // the first gap costs -(_o+_e)
{
	int slen, i, m_b, n_b, te = -1, gmax = 0, minsc, endsc;
	uint64_t *b;
	__m128i zero, gapoe, gape, shift, *H0, *H1, *E, *Hmax;
	kswr_t r;

#define __max_16(ret, xx) do { \
		(xx) = _mm_max_epu8((xx), _mm_srli_si128((xx), 8)); \
		(xx) = _mm_max_epu8((xx), _mm_srli_si128((xx), 4)); \
		(xx) = _mm_max_epu8((xx), _mm_srli_si128((xx), 2)); \
		(xx) = _mm_max_epu8((xx), _mm_srli_si128((xx), 1)); \
    	(ret) = _mm_extract_epi16((xx), 0) & 0x00ff; \
	} while (0)

	// initialization
	r = g_defr;
	minsc = (xtra&KSW_XSUBO)? xtra&0xffff : 0x10000;
	endsc = (xtra&KSW_XSTOP)? xtra&0xffff : 0x10000;
	m_b = n_b = 0; b = 0;
	zero = _mm_set1_epi32(0);
	gapoe = _mm_set1_epi8(_gapo + _gape);
	gape = _mm_set1_epi8(_gape);
	shift = _mm_set1_epi8(q->shift);
	H0 = q->H0; H1 = q->H1; E = q->E; Hmax = q->Hmax;
	slen = q->slen;
	for (i = 0; i < slen; ++i) {
		_mm_store_si128(E + i, zero);
		_mm_store_si128(H0 + i, zero);
		_mm_store_si128(Hmax + i, zero);
	}
	// the core loop
	for (i = 0; i < tlen; ++i) {
		int j, k, cmp, imax;
		__m128i e, h, f = zero, max = zero, *S = q->qp + target[i] * slen; // s is the 1st score vector
		h = _mm_load_si128(H0 + slen - 1); // h={2,5,8,11,14,17,-1,-1} in the above example
		h = _mm_slli_si128(h, 1); // h=H(i-1,-1); << instead of >> because x64 is little-endian
		for (j = 0; LIKELY(j < slen); ++j) {
			/* SW cells are computed in the following order:
			 *   H(i,j)   = max{H(i-1,j-1)+S(i,j), E(i,j), F(i,j)}
			 *   E(i+1,j) = max{H(i,j)-q, E(i,j)-r}
			 *   F(i,j+1) = max{H(i,j)-q, F(i,j)-r}
			 */
			// compute H'(i,j); note that at the beginning, h=H'(i-1,j-1)
			h = _mm_adds_epu8(h, _mm_load_si128(S + j));
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
				if (UNLIKELY(cmp == 0xffff)) goto end_loop16;
			}
		}
end_loop16:
		//int k;for (k=0;k<16;++k)printf("%d ", ((uint8_t*)&max)[k]);printf("\n");
		__max_16(imax, max); // imax is the maximum number in max
		if (imax >= minsc) { // write the b array; this condition adds branching unfornately
			if (n_b == 0 || (int32_t)b[n_b-1] + 1 != i) { // then append
				if (n_b == m_b) {
					m_b = m_b? m_b<<1 : 8;
					b = (uint64_t*)realloc(b, 8 * m_b);
				}
				b[n_b++] = (uint64_t)imax<<32 | i;
			} else if ((int)(b[n_b-1]>>32) < imax) b[n_b-1] = (uint64_t)imax<<32 | i; // modify the last
		}
		if (imax > gmax) {
			gmax = imax; te = i; // te is the end position on the target
			for (j = 0; LIKELY(j < slen); ++j) // keep the H1 vector
				_mm_store_si128(Hmax + j, _mm_load_si128(H1 + j));
			if (gmax + q->shift >= 255 || gmax >= endsc) break;
		}
		S = H1; H1 = H0; H0 = S; // swap H0 and H1
	}
	r.score = gmax + q->shift < 255? gmax : 255;
	r.te = te;
	if (r.score != 255) { // get a->qe, the end of query match; find the 2nd best score
		int max = -1, low, high, qlen = slen * 16;
		uint8_t *t = (uint8_t*)Hmax;
		for (i = 0; i < qlen; ++i, ++t)
			if ((int)*t > max) max = *t, r.qe = i / 16 + i % 16 * slen;
		//printf("%d,%d\n", max, gmax);
		if (b) {
			i = (r.score + q->max - 1) / q->max;
			low = te - i; high = te + i;
			for (i = 0; i < n_b; ++i) {
				int e = (int32_t)b[i];
				if ((e < low || e > high) && b[i]>>32 > (uint32_t)r.score2)
					r.score2 = b[i]>>32, r.te2 = e;
			}
		}
	}
	free(b);
	return r;
}

kswr_t ksw_i16(kswq_t *q, int tlen, const uint8_t *target, int _gapo, int _gape, int xtra) // the first gap costs -(_o+_e)
{
	int slen, i, m_b, n_b, te = -1, gmax = 0, minsc, endsc;
	uint64_t *b;
	__m128i zero, gapoe, gape, *H0, *H1, *E, *Hmax;
	kswr_t r;

#define __max_8(ret, xx) do { \
		(xx) = _mm_max_epi16((xx), _mm_srli_si128((xx), 8)); \
		(xx) = _mm_max_epi16((xx), _mm_srli_si128((xx), 4)); \
		(xx) = _mm_max_epi16((xx), _mm_srli_si128((xx), 2)); \
    	(ret) = _mm_extract_epi16((xx), 0); \
	} while (0)

	// initialization
	r = g_defr;
	minsc = (xtra&KSW_XSUBO)? xtra&0xffff : 0x10000;
	endsc = (xtra&KSW_XSTOP)? xtra&0xffff : 0x10000;
	m_b = n_b = 0; b = 0;
	zero = _mm_set1_epi32(0);
	gapoe = _mm_set1_epi16(_gapo + _gape);
	gape = _mm_set1_epi16(_gape);
	H0 = q->H0; H1 = q->H1; E = q->E; Hmax = q->Hmax;
	slen = q->slen;
	for (i = 0; i < slen; ++i) {
		_mm_store_si128(E + i, zero);
		_mm_store_si128(H0 + i, zero);
		_mm_store_si128(Hmax + i, zero);
	}
	// the core loop
	for (i = 0; i < tlen; ++i) {
		int j, k, imax;
		__m128i e, h, f = zero, max = zero, *S = q->qp + target[i] * slen; // s is the 1st score vector
		h = _mm_load_si128(H0 + slen - 1); // h={2,5,8,11,14,17,-1,-1} in the above example
		h = _mm_slli_si128(h, 2);
		for (j = 0; LIKELY(j < slen); ++j) {
			h = _mm_adds_epi16(h, *S++);
			e = _mm_load_si128(E + j);
			h = _mm_max_epi16(h, e);
			h = _mm_max_epi16(h, f);
			max = _mm_max_epi16(max, h);
			_mm_store_si128(H1 + j, h);
			h = _mm_subs_epu16(h, gapoe);
			e = _mm_subs_epu16(e, gape);
			e = _mm_max_epi16(e, h);
			_mm_store_si128(E + j, e);
			f = _mm_subs_epu16(f, gape);
			f = _mm_max_epi16(f, h);
			h = _mm_load_si128(H0 + j);
		}
		for (k = 0; LIKELY(k < 16); ++k) {
			f = _mm_slli_si128(f, 2);
			for (j = 0; LIKELY(j < slen); ++j) {
				h = _mm_load_si128(H1 + j);
				h = _mm_max_epi16(h, f);
				_mm_store_si128(H1 + j, h);
				h = _mm_subs_epu16(h, gapoe);
				f = _mm_subs_epu16(f, gape);
				if(UNLIKELY(!_mm_movemask_epi8(_mm_cmpgt_epi16(f, h)))) goto end_loop8;
			}
		}
end_loop8:
		__max_8(imax, max);
		if (imax >= minsc) {
			if (n_b == 0 || (int32_t)b[n_b-1] + 1 != i) {
				if (n_b == m_b) {
					m_b = m_b? m_b<<1 : 8;
					b = (uint64_t*)realloc(b, 8 * m_b);
				}
				b[n_b++] = (uint64_t)imax<<32 | i;
			} else if ((int)(b[n_b-1]>>32) < imax) b[n_b-1] = (uint64_t)imax<<32 | i; // modify the last
		}
		if (imax > gmax) {
			gmax = imax; te = i;
			for (j = 0; LIKELY(j < slen); ++j)
				_mm_store_si128(Hmax + j, _mm_load_si128(H1 + j));
			if (gmax >= endsc) break;
		}
		S = H1; H1 = H0; H0 = S;
	}
	r.score = gmax; r.te = te;
	{
		int max = -1, low, high, qlen = slen * 8;
		uint16_t *t = (uint16_t*)Hmax;
		for (i = 0, r.qe = -1; i < qlen; ++i, ++t)
			if ((int)*t > max) max = *t, r.qe = i / 8 + i % 8 * slen;
		if (b) {
			i = (r.score + q->max - 1) / q->max;
			low = te - i; high = te + i;
			for (i = 0; i < n_b; ++i) {
				int e = (int32_t)b[i];
				if ((e < low || e > high) && b[i]>>32 > (uint32_t)r.score2)
					r.score2 = b[i]>>32, r.te2 = e;
			}
		}
	}
	free(b);
	return r;
}

static void revseq(int l, uint8_t *s)
{
	int i, t;
	for (i = 0; i < l>>1; ++i)
		t = s[i], s[i] = s[l - 1 - i], s[l - 1 - i] = t;
}

kswr_t ksw_align(int qlen, uint8_t *query, int tlen, uint8_t *target, int m, const int8_t *mat, int gapo, int gape, int xtra, kswq_t **qry)
{
	int size;
	kswq_t *q;
	kswr_t r, rr;
	kswr_t (*func)(kswq_t*, int, const uint8_t*, int, int, int);

	q = (qry && *qry)? *qry : ksw_qinit((xtra&KSW_XBYTE)? 1 : 2, qlen, query, m, mat);
	if (qry && *qry == 0) *qry = q;
	func = q->size == 2? ksw_i16 : ksw_u8;
	size = q->size;
	r = func(q, tlen, target, gapo, gape, xtra);
	if (qry == 0) free(q);
	if ((xtra&KSW_XSTART) == 0 || ((xtra&KSW_XSUBO) && r.score < (xtra&0xffff))) return r;
	revseq(r.qe + 1, query); revseq(r.te + 1, target); // +1 because qe/te points to the exact end, not the position after the end
	q = ksw_qinit(size, r.qe + 1, query, m, mat);
	rr = func(q, tlen, target, gapo, gape, KSW_XSTOP | r.score);
	revseq(r.qe + 1, query); revseq(r.te + 1, target);
	free(q);
	if (r.score == rr.score)
		r.tb = r.te - rr.te, r.qb = r.qe - rr.qe;
	return r;
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
	int c, sa = 1, sb = 3, i, j, k, forward_only = 0, max_rseq = 0;
	int8_t mat[25];
	int gapo = 5, gape = 2, minsc = 0, xtra = KSW_XSTART;
	uint8_t *rseq = 0;
	gzFile fpt, fpq;
	kseq_t *kst, *ksq;

	// parse command line
	while ((c = getopt(argc, argv, "a:b:q:r:ft:1")) >= 0) {
		switch (c) {
			case 'a': sa = atoi(optarg); break;
			case 'b': sb = atoi(optarg); break;
			case 'q': gapo = atoi(optarg); break;
			case 'r': gape = atoi(optarg); break;
			case 't': minsc = atoi(optarg); break;
			case 'f': forward_only = 1; break;
			case '1': xtra |= KSW_XBYTE; break;
		}
	}
	if (optind + 2 > argc) {
		fprintf(stderr, "Usage: ksw [-1] [-f] [-a%d] [-b%d] [-q%d] [-r%d] [-t%d] <target.fa> <query.fa>\n", sa, sb, gapo, gape, minsc);
		return 1;
	}
	if (minsc > 0xffff) minsc = 0xffff;
	if (minsc > 0) xtra |= KSW_XSUBO | minsc;
	// initialize scoring matrix
	for (i = k = 0; i < 4; ++i) {
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
		kswq_t *q[2] = {0, 0};
		kswr_t r;
		for (i = 0; i < (int)ksq->seq.l; ++i) ksq->seq.s[i] = seq_nt4_table[(int)ksq->seq.s[i]];
		if (!forward_only) { // reverse
			if ((int)ksq->seq.m > max_rseq) {
				max_rseq = ksq->seq.m;
				rseq = (uint8_t*)realloc(rseq, max_rseq);
			}
			for (i = 0, j = ksq->seq.l - 1; i < (int)ksq->seq.l; ++i, --j)
				rseq[j] = ksq->seq.s[i] == 4? 4 : 3 - ksq->seq.s[i];
		}
		gzrewind(fpt); kseq_rewind(kst);
		while (kseq_read(kst) > 0) {
			for (i = 0; i < (int)kst->seq.l; ++i) kst->seq.s[i] = seq_nt4_table[(int)kst->seq.s[i]];
			r = ksw_align(ksq->seq.l, (uint8_t*)ksq->seq.s, kst->seq.l, (uint8_t*)kst->seq.s, 5, mat, gapo, gape, xtra, &q[0]);
			if (r.score >= minsc)
				printf("%s\t%d\t%d\t%s\t%d\t%d\t%d\t%d\t%d\n", kst->name.s, r.tb, r.te+1, ksq->name.s, r.qb, r.qe+1, r.score, r.score2, r.te2);
			if (rseq) {
				r = ksw_align(ksq->seq.l, rseq, kst->seq.l, (uint8_t*)kst->seq.s, 5, mat, gapo, gape, xtra, &q[1]);
				if (r.score >= minsc)
					printf("%s\t%d\t%d\t%s\t%d\t%d\t%d\t%d\t%d\n", kst->name.s, r.tb, r.te+1, ksq->name.s, (int)ksq->seq.l - r.qb, (int)ksq->seq.l - 1 - r.qe, r.score, r.score2, r.te2);
			}
		}
		free(q[0]); free(q[1]);
	}
	free(rseq);
	kseq_destroy(kst); gzclose(fpt);
	kseq_destroy(ksq); gzclose(fpq);
	return 0;
}
#endif
