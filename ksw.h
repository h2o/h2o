#ifndef __AC_KSW_H
#define __AC_KSW_H

struct _ksw_query_t;
typedef struct _ksw_query_t ksw_query_t;

typedef struct {
	// input
	unsigned gapo, gape; // the first gap costs gapo+gape
	unsigned T; // threshold
	// output
	int score, te, qe, score2, te2;
	int tb, qb; // tb and qb are only generated when calling ksw_align_16()
} ksw_aux_t;

#ifdef __cplusplus
extern "C" {
#endif

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
	ksw_query_t *ksw_qinit(int size, int qlen, const uint8_t *query, int m, const int8_t *mat); // to free, simply call free()

	/**
	 * Compute the maximum local score for queries initialized with ksw_qinit(1, ...)
	 *
	 * @param q       Query data structure returned by ksw_qinit(1, ...)
	 * @param tlen    Length of the target sequence
	 * @param target  Target sequence
	 * @param a       Auxiliary data structure (see ksw.h)
	 *
	 * @return        The maximum local score; if the returned value equals 255, the SW may not be finished
	 */
	int ksw_sse2_8(ksw_query_t *q, int tlen, const uint8_t *target, ksw_aux_t *a, int cutsc);

	/** Compute the maximum local score for queries initialized with ksw_qinit(2, ...) */
	int ksw_sse2_16(ksw_query_t *q, int tlen, const uint8_t *target, ksw_aux_t *a);

	/** Unified interface for ksw_sse2_8() and ksw_sse2_16() */
	int ksw_sse2(ksw_query_t *q, int tlen, const uint8_t *target, ksw_aux_t *a);

	int ksw_align_short(int qlen, uint8_t *query, int tlen, uint8_t *target, int m, const int8_t *mat, ksw_aux_t *a);

#ifdef __cplusplus
}
#endif

#endif
