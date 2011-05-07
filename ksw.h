#ifndef __AC_KSW_H
#define __AC_KSW_H

struct _ksw_query_t;
typedef struct _ksw_query_t ksw_query_t;

typedef struct {
	// input
	unsigned gapo, gape; // the first gap costs gapo+gape
	unsigned T; // threshold
	// output
	int score, te, qe;
} ksw_aux_t;

#ifdef __cplusplus
extern "C" {
#endif

ksw_query_t *ksw_qinit(int p, int qlen, const uint8_t *query, int m, const int8_t *mat); // to free, simply call free()
int ksw_sse2_16(ksw_query_t *q, int tlen, const uint8_t *target, ksw_aux_t *a);

#ifdef __cplusplus
}
#endif

#endif
