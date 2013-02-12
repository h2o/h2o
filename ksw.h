#ifndef __AC_KSW_H
#define __AC_KSW_H

#include <stdint.h>

#define KSW_XBYTE  0x10000
#define KSW_XSTOP  0x20000
#define KSW_XSUBO  0x40000
#define KSW_XSTART 0x80000

struct _kswq_t;
typedef struct _kswq_t kswq_t;

typedef struct {
	int score; // best score
	int te, qe; // target end and query end
	int score2, te2; // second best score and ending position on the target
	int tb, qb; // target start and query start
} kswr_t;

#ifdef __cplusplus
extern "C" {
#endif

	/**
	 * Aligning two sequences
	 *
	 * @param qlen    length of the query sequence (typically <tlen)
	 * @param query   query sequence with 0 <= query[i] < m
	 * @param tlen    length of the target sequence
	 * @param target  target sequence
	 * @param m       number of residue types
	 * @param mat     m*m scoring matrix in one-dimention array
	 * @param gapo    gap open penalty; a gap of length l cost "-(gapo+l*gape)"
	 * @param gape    gap extension penalty
	 * @param xtra    extra information (see below)
	 * @param qry     query profile (see below)
	 *
	 * @return        alignment information in a struct; unset values to -1
	 *
	 * When xtra==0, ksw_align() uses a signed two-byte integer to store a
	 * score and only finds the best score and the end positions. The 2nd best
	 * score or the start positions are not attempted. The default behavior can
	 * be tuned by setting KSW_X* flags:
	 *
	 *   KSW_XBYTE:  use an unsigned byte to store a score. If overflow occurs,
	 *               kswr_t::score will be set to 255
	 *
	 *   KSW_XSUBO:  track the 2nd best score and the ending position on the
	 *               target if the 2nd best is higher than (xtra&0xffff)
	 *
	 *   KSW_XSTOP:  stop if the maximum score is above (xtra&0xffff)
	 *
	 *   KSW_XSTART: find the start positions
	 *
	 * When *qry==NULL, ksw_align() will compute and allocate the query profile
	 * and when the function returns, *qry will point to the profile, which can
	 * be deallocated simply by free(). If one query is aligned against multiple
	 * target sequences, *qry should be set to NULL during the first call and
	 * freed after the last call. Note that qry can equal 0. In this case, the
	 * query profile will be deallocated in ksw_align().
	 */
	kswr_t ksw_align(int qlen, uint8_t *query, int tlen, uint8_t *target, int m, const int8_t *mat, int gapo, int gape, int xtra, kswq_t **qry);

	int ksw_extend(int qlen, const uint8_t *query, int tlen, const uint8_t *target, int m, const int8_t *mat, int gapo, int gape, int w, int h0, int *_qle, int *_tle);
	int ksw_global(int qlen, const uint8_t *query, int tlen, const uint8_t *target, int m, const int8_t *mat, int gapo, int gape, int w, int *_n_cigar, uint32_t **_cigar);

#ifdef __cplusplus
}
#endif

#endif
