#ifndef AC_SCHMM_H_
#define AC_SCHMM_H_

/*
 * Last Modified: 2008-03-10
 * Version: 0.1.0-8
 *
 * 2008-03-10, 0.1.0-8: make icc report two more "VECTORIZED"
 * 2008-03-10, 0.1.0-7: accelerate for some CPU
 * 2008-02-07, 0.1.0-6: simulate sequences
 * 2008-01-15, 0.1.0-5: goodness of fit
 * 2007-11-20, 0.1.0-4: add function declaration of hmm_post_decode()
 * 2007-11-09: fix a memory leak
 */

#include <stdlib.h>

#define HMM_VERSION "0.1.0-7"

#define HMM_FORWARD  0x02
#define HMM_BACKWARD 0x04
#define HMM_VITERBI  0x40
#define HMM_POSTDEC  0x80

#ifndef FLOAT
#define FLOAT double
#endif
#define HMM_TINY     1e-25
#define HMM_INF      1e300

typedef struct
{
	int m, n; // number of symbols, number of states
	FLOAT **a, **e; // transition matrix and emitting probilities
	FLOAT **ae; // auxiliary array for acceleration, should be calculated by hmm_pre_backward()
	FLOAT *a0; // trasition matrix from the start state
} hmm_par_t;

typedef struct
{
	int L;
	unsigned status;
	char *seq;
	FLOAT **f, **b, *s;
	int *v; // Viterbi path
	int *p; // posterior decoding
} hmm_data_t;

typedef struct
{
	int m, n;
	FLOAT Q0, **A, **E, *A0;
} hmm_exp_t;

typedef struct
{
	int l, *obs;
	FLOAT *thr;
} hmm_gof_t;

#ifdef __cplusplus
extern "C" {
#endif
	/* initialize and destroy hmm_par_t */
	hmm_par_t *hmm_new_par(int m, int n);
	void hmm_delete_par(hmm_par_t *hp);
	/* initialize and destroy hmm_data_t */
	hmm_data_t *hmm_new_data(int L, const char *seq, const hmm_par_t *hp);
	void hmm_delete_data(hmm_data_t *hd);
	/* initialize and destroy hmm_exp_t */
	hmm_exp_t *hmm_new_exp(const hmm_par_t *hp);
	void hmm_delete_exp(hmm_exp_t *he);
	/* Viterbi, forward and backward algorithms */
	FLOAT hmm_Viterbi(const hmm_par_t *hp, hmm_data_t *hd);
	void hmm_pre_backward(hmm_par_t *hp);
	void hmm_forward(const hmm_par_t *hp, hmm_data_t *hd);
	void hmm_backward(const hmm_par_t *hp, hmm_data_t *hd);
	/* log-likelihood of the observations (natural based) */
	FLOAT hmm_lk(const hmm_data_t *hd);
	/* posterior probability at the position on the sequence */
	FLOAT hmm_post_state(const hmm_par_t *hp, const hmm_data_t *hd, int u, FLOAT *prob);
	/* posterior decoding */
	void hmm_post_decode(const hmm_par_t *hp, hmm_data_t *hd);
	/* expected counts of transitions and emissions */
	hmm_exp_t *hmm_expect(const hmm_par_t *hp, const hmm_data_t *hd);
	/* add he0 counts to he1 counts*/
	void hmm_add_expect(const hmm_exp_t *he0, hmm_exp_t *he1);
	/* the Q function that should be maximized in EM */
	FLOAT hmm_Q(const hmm_par_t *hp, const hmm_exp_t *he);
	FLOAT hmm_Q0(const hmm_par_t *hp, hmm_exp_t *he);
	/* simulate sequences */
	char *hmm_simulate(const hmm_par_t *hp, int L);
#ifdef __cplusplus
}
#endif

static inline void **calloc2(int n_row, int n_col, int size)
{
	char **p;
	int k;
	p = (char**)malloc(sizeof(char*) * n_row);
	for (k = 0; k != n_row; ++k)
		p[k] = (char*)calloc(n_col, size);
	return (void**)p;
}

#endif
