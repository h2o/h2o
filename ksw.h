#ifndef __AC_KSW_H
#define __AC_KSW_H

struct _ksw_query_t;
typedef struct _ksw_query_t ksw_query_t;

#ifdef __cplusplus
extern "C" {
#endif

ksw_query_t *ksw_qinit(int qlen, const uint8_t *query, int p, int m, const int8_t *mat);
int ksw_sse2_16(ksw_query_t *q, int tlen, const uint8_t *target, unsigned o, unsigned e); // first gap costs -(o+e)

#ifdef __cplusplus
}
#endif

#endif
