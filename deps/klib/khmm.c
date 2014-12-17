#include <math.h>
#include <stdio.h>
#include <assert.h>
#include <string.h>
#include <stdlib.h>
#include "khmm.h"

// new/delete hmm_par_t

hmm_par_t *hmm_new_par(int m, int n)
{
	hmm_par_t *hp;
	int i;
	assert(m > 0 && n > 0);
	hp = (hmm_par_t*)calloc(1, sizeof(hmm_par_t));
	hp->m = m; hp->n = n;
	hp->a0 = (FLOAT*)calloc(n, sizeof(FLOAT));
	hp->a = (FLOAT**)calloc2(n, n, sizeof(FLOAT));
	hp->e = (FLOAT**)calloc2(m + 1, n, sizeof(FLOAT));
	hp->ae = (FLOAT**)calloc2((m + 1) * n, n, sizeof(FLOAT));
	for (i = 0; i != n; ++i) hp->e[m][i] = 1.0;
	return hp;
}
void hmm_delete_par(hmm_par_t *hp)
{
	int i;
	if (hp == 0) return;
	for (i = 0; i != hp->n; ++i) free(hp->a[i]);
	for (i = 0; i <= hp->m; ++i) free(hp->e[i]);
	for (i = 0; i < (hp->m + 1) * hp->n; ++i) free(hp->ae[i]);
	free(hp->a); free(hp->e); free(hp->a0); free(hp->ae);
	free(hp);
}

// new/delete hmm_data_t

hmm_data_t *hmm_new_data(int L, const char *seq, const hmm_par_t *hp)
{
	hmm_data_t *hd;
	hd = (hmm_data_t*)calloc(1, sizeof(hmm_data_t));
	hd->L = L;
	hd->seq = (char*)malloc(L + 1);
	memcpy(hd->seq + 1, seq, L);
	return hd;
}
void hmm_delete_data(hmm_data_t *hd)
{
	int i;
	if (hd == 0) return;
	for (i = 0; i <= hd->L; ++i) {
		if (hd->f) free(hd->f[i]);
		if (hd->b) free(hd->b[i]);
	}
	free(hd->f); free(hd->b); free(hd->s); free(hd->v); free(hd->p); free(hd->seq);
	free(hd);
}

// new/delete hmm_exp_t

hmm_exp_t *hmm_new_exp(const hmm_par_t *hp)
{
	hmm_exp_t *he;
	assert(hp);
	he = (hmm_exp_t*)calloc(1, sizeof(hmm_exp_t));
	he->m = hp->m; he->n = hp->n;
	he->A0 = (FLOAT*)calloc(hp->n, sizeof(FLOAT));
	he->A = (FLOAT**)calloc2(hp->n, hp->n, sizeof(FLOAT));
	he->E = (FLOAT**)calloc2(hp->m + 1, hp->n, sizeof(FLOAT));
	return he;
}
void hmm_delete_exp(hmm_exp_t *he)
{
	int i;
	if (he == 0) return;
	for (i = 0; i != he->n; ++i) free(he->A[i]);
	for (i = 0; i <= he->m; ++i) free(he->E[i]);
	free(he->A); free(he->E); free(he->A0);
	free(he);
}

// Viterbi algorithm

FLOAT hmm_Viterbi(const hmm_par_t *hp, hmm_data_t *hd)
{
	FLOAT **la, **le, *preV, *curV, max;
	int **Vmax, max_l; // backtrace matrix
	int k, l, b, u;
	
	if (hd->v) free(hd->v);
	hd->v = (int*)calloc(hd->L+1, sizeof(int));
	la = (FLOAT**)calloc2(hp->n, hp->n, sizeof(FLOAT));
	le = (FLOAT**)calloc2(hp->m + 1, hp->n, sizeof(FLOAT));
	Vmax = (int**)calloc2(hd->L+1, hp->n, sizeof(int));
	preV = (FLOAT*)malloc(sizeof(FLOAT) * hp->n);
	curV = (FLOAT*)malloc(sizeof(FLOAT) * hp->n);
	for (k = 0; k != hp->n; ++k)
		for (l = 0; l != hp->n; ++l)
			la[k][l] = log(hp->a[l][k]); // this is not a bug
	for (b = 0; b != hp->m; ++b)
		for (k = 0; k != hp->n; ++k)
			le[b][k] = log(hp->e[b][k]);
	for (k = 0; k != hp->n; ++k) le[hp->m][k] = 0.0;
	// V_k(1)
	for (k = 0; k != hp->n; ++k) {
		preV[k] = le[(int)hd->seq[1]][k] + log(hp->a0[k]);
		Vmax[1][k] = 0;
	}
	// all the rest
	for (u = 2; u <= hd->L; ++u) {
		FLOAT *tmp, *leu = le[(int)hd->seq[u]];
		for (k = 0; k != hp->n; ++k) {
			FLOAT *laa = la[k];
			for (l = 0, max = -HMM_INF, max_l = -1; l != hp->n; ++l) {
				if (max < preV[l] + laa[l]) {
					max = preV[l] + laa[l];
					max_l = l;
				}
			}
			assert(max_l >= 0); // cannot be zero
			curV[k] = leu[k] + max;
			Vmax[u][k] = max_l;
		}
		tmp = curV; curV = preV; preV = tmp; // swap
	}
	// backtrace
	for (k = 0, max_l = -1, max = -HMM_INF; k != hp->n; ++k) {
		if (max < preV[k]) {
			max = preV[k]; max_l = k;
		}
	}
	assert(max_l >= 0); // cannot be zero
	hd->v[hd->L] = max_l;
	for (u = hd->L; u >= 1; --u)
		hd->v[u-1] = Vmax[u][hd->v[u]];
	for (k = 0; k != hp->n; ++k) free(la[k]);
	for (b = 0; b < hp->m; ++b) free(le[b]);
	for (u = 0; u <= hd->L; ++u) free(Vmax[u]);
	free(la); free(le); free(Vmax); free(preV); free(curV);
	hd->status |= HMM_VITERBI;
	return max;
}

// forward algorithm

void hmm_forward(const hmm_par_t *hp, hmm_data_t *hd)
{
	FLOAT sum, tmp, **at;
	int u, k, l;
	int n, m, L;
	assert(hp && hd);
	// allocate memory for hd->f and hd->s
	n = hp->n; m = hp->m; L = hd->L;
	if (hd->s) free(hd->s);
	if (hd->f) { 
		for (k = 0; k <= hd->L; ++k) free(hd->f[k]);
		free(hd->f);
	}
	hd->f = (FLOAT**)calloc2(hd->L+1, hp->n, sizeof(FLOAT));
	hd->s = (FLOAT*)calloc(hd->L+1, sizeof(FLOAT));
	hd->status &= ~(unsigned)HMM_FORWARD;
	// at[][] array helps to improve the cache efficiency
	at = (FLOAT**)calloc2(n, n, sizeof(FLOAT));
	// transpose a[][]
	for (k = 0; k != n; ++k)
		for (l = 0; l != n; ++l)
			at[k][l] = hp->a[l][k];
	// f[0], but it should never be used
	hd->s[0] = 1.0;
	for (k = 0; k != n; ++k) hd->f[0][k] = 0.0;
	// f[1]
	for (k = 0, sum = 0.0; k != n; ++k)
		sum += (hd->f[1][k] = hp->a0[k] * hp->e[(int)hd->seq[1]][k]);
	for (k = 0; k != n; ++k) hd->f[1][k] /= sum;
	hd->s[1] = sum;
	// f[2..hmmL], the core loop
	for (u = 2; u <= L; ++u) {
		FLOAT *fu = hd->f[u], *fu1 = hd->f[u-1], *eu = hp->e[(int)hd->seq[u]];
		for (k = 0, sum = 0.0; k != n; ++k) {
			FLOAT *aa = at[k];
			for (l = 0, tmp = 0.0; l != n; ++l) tmp += fu1[l] * aa[l];
			sum += (fu[k] = eu[k] * tmp);
		}
		for (k = 0; k != n; ++k) fu[k] /= sum;
		hd->s[u] = sum;
	}
	// free at array
	for (k = 0; k != hp->n; ++k) free(at[k]);
	free(at);
	hd->status |= HMM_FORWARD;
}

//  precalculate hp->ae

void hmm_pre_backward(hmm_par_t *hp)
{
	int m, n, b, k, l;
	assert(hp);
	m = hp->m; n = hp->n;
	for (b = 0; b <= m; ++b) {
		for (k = 0; k != n; ++k) {
			FLOAT *p = hp->ae[b * hp->n + k];
			for (l = 0; l != n; ++l)
				p[l] = hp->e[b][l] * hp->a[k][l];
		}
	}
}

// backward algorithm

void hmm_backward(const hmm_par_t *hp, hmm_data_t *hd)
{
	FLOAT tmp;
	int k, l, u;
	int m, n, L;
	assert(hp && hd);
	assert(hd->status & HMM_FORWARD);
	// allocate memory for hd->b
	m = hp->m; n = hp->n; L = hd->L;
	if (hd->b) { 
		for (k = 0; k <= hd->L; ++k) free(hd->b[k]);
		free(hd->b);
	}
	hd->status &= ~(unsigned)HMM_BACKWARD;
	hd->b = (FLOAT**)calloc2(L+1, hp->n, sizeof(FLOAT));
	// b[L]
	for (k = 0; k != hp->n; ++k) hd->b[L][k] = 1.0 / hd->s[L];
	// b[1..L-1], the core loop
	for (u = L-1; u >= 1; --u) {
		FLOAT *bu1 = hd->b[u+1], **p = hp->ae + (int)hd->seq[u+1] * n;
		for (k = 0; k != n; ++k) {
			FLOAT *q = p[k];
			for (l = 0, tmp = 0.0; l != n; ++l) tmp += q[l] * bu1[l];
			hd->b[u][k] = tmp / hd->s[u];
		}
	}
	hd->status |= HMM_BACKWARD;
	for (l = 0, tmp = 0.0; l != n; ++l)
		tmp += hp->a0[l] * hd->b[1][l] * hp->e[(int)hd->seq[1]][l];
	if (tmp > 1.0 + 1e-6 || tmp < 1.0 - 1e-6) // in theory, tmp should always equal to 1
		fprintf(stderr, "++ Underflow may have happened (%lg).\n", tmp);
}

// log-likelihood of the observation

FLOAT hmm_lk(const hmm_data_t *hd)
{
    FLOAT sum = 0.0, prod = 1.0;
	int u, L;
	L = hd->L;
	assert(hd->status & HMM_FORWARD);
	for (u = 1; u <= L; ++u) {
		prod *= hd->s[u];
		if (prod < HMM_TINY || prod >= 1.0/HMM_TINY) { // reset
			sum += log(prod);
			prod = 1.0;
		}
	}
	sum += log(prod);
	return sum;
}

// posterior decoding

void hmm_post_decode(const hmm_par_t *hp, hmm_data_t *hd)
{
	int u, k;
	assert(hd->status && HMM_BACKWARD);
	if (hd->p) free(hd->p);
	hd->p = (int*)calloc(hd->L + 1, sizeof(int));
	for (u = 1; u <= hd->L; ++u) {
		FLOAT prob, max, *fu = hd->f[u], *bu = hd->b[u], su = hd->s[u];
		int max_k;
		for (k = 0, max = -1.0, max_k = -1; k != hp->n; ++k) {
			if (max < (prob = fu[k] * bu[k] * su)) {
				max = prob; max_k = k;
			}
		}
		assert(max_k >= 0);
		hd->p[u] = max_k;
	}
	hd->status |= HMM_POSTDEC;
}

// posterior probability of states

FLOAT hmm_post_state(const hmm_par_t *hp, const hmm_data_t *hd, int u, FLOAT *prob)
{
	FLOAT sum = 0.0, ss = hd->s[u], *fu = hd->f[u], *bu = hd->b[u];
	int k;
	for (k = 0; k != hp->n; ++k)
		sum += (prob[k] = fu[k] * bu[k] * ss);
	return sum; // in theory, this should always equal to 1.0
}

// expected counts

hmm_exp_t *hmm_expect(const hmm_par_t *hp, const hmm_data_t *hd)
{
	int k, l, u, b, m, n;
	hmm_exp_t *he;
	assert(hd->status & HMM_BACKWARD);
	he = hmm_new_exp(hp);
	// initialization
	m = hp->m; n = hp->n;
	for (k = 0; k != n; ++k)
		for (l = 0; l != n; ++l) he->A[k][l] = HMM_TINY;
	for (b = 0; b <= m; ++b)
		for (l = 0; l != n; ++l) he->E[b][l] = HMM_TINY;
	// calculate A_{kl} and E_k(b), k,l\in[0,n)
	for (u = 1; u < hd->L; ++u) {
		FLOAT *fu = hd->f[u], *bu = hd->b[u], *bu1 = hd->b[u+1], ss = hd->s[u];
		FLOAT *Ec = he->E[(int)hd->seq[u]], **p = hp->ae + (int)hd->seq[u+1] * n;
		for (k = 0; k != n; ++k) {
			FLOAT *q = p[k], *AA = he->A[k], fuk = fu[k];
			for (l = 0; l != n; ++l) // this is cache-efficient
				AA[l] += fuk * q[l] * bu1[l];
			Ec[k] += fuk * bu[k] * ss;
		}
	}
	// calculate A0_l
	for (l = 0; l != n; ++l)
		he->A0[l] += hp->a0[l] * hp->e[(int)hd->seq[1]][l] * hd->b[1][l];
	return he;
}

FLOAT hmm_Q0(const hmm_par_t *hp, hmm_exp_t *he)
{
	int k, l, b;
	FLOAT sum = 0.0;
	for (k = 0; k != hp->n; ++k) {
		FLOAT tmp;
		for (b = 0, tmp = 0.0; b != hp->m; ++b) tmp += he->E[b][k];
		for (b = 0; b != hp->m; ++b)
			sum += he->E[b][k] * log(he->E[b][k] / tmp);
	}
	for (k = 0; k != hp->n; ++k) {
		FLOAT tmp, *A = he->A[k];
		for (l = 0, tmp = 0.0; l != hp->n; ++l) tmp += A[l];
		for (l = 0; l != hp->n; ++l) sum += A[l] * log(A[l] / tmp);
	}
	return (he->Q0 = sum);
}

// add he0 to he1

void hmm_add_expect(const hmm_exp_t *he0, hmm_exp_t *he1)
{
	int b, k, l;
	assert(he0->m == he1->m && he0->n == he1->n);
	for (k = 0; k != he1->n; ++k) {
		he1->A0[k] += he0->A0[k];
		for (l = 0; l != he1->n; ++l)
			he1->A[k][l] += he0->A[k][l];
	}
	for (b = 0; b != he1->m; ++b) {
		for (l = 0; l != he1->n; ++l)
			he1->E[b][l] += he0->E[b][l];
	}
}

// the EM-Q function

FLOAT hmm_Q(const hmm_par_t *hp, const hmm_exp_t *he)
{
	FLOAT sum = 0.0;
	int bb, k, l;
	for (bb = 0; bb != he->m; ++bb) {
		FLOAT *eb = hp->e[bb], *Eb = he->E[bb];
		for (k = 0; k != hp->n; ++k) {
			if (eb[k] <= 0.0) return -HMM_INF;
			sum += Eb[k] * log(eb[k]);
		}
	}
	for (k = 0; k != he->n; ++k) {
		FLOAT *Ak = he->A[k], *ak = hp->a[k];
		for (l = 0; l != he->n; ++l) {
			if (ak[l] <= 0.0) return -HMM_INF;
			sum += Ak[l] * log(ak[l]);
		}
	}
	return (sum -= he->Q0);
}

// simulate sequence

char *hmm_simulate(const hmm_par_t *hp, int L)
{
	int i, k, l, b;
	FLOAT x, y, **et;
	char *seq;
	seq = (char*)calloc(L+1, 1);
	// calculate the transpose of hp->e[][]
	et = (FLOAT**)calloc2(hp->n, hp->m, sizeof(FLOAT));
	for (k = 0; k != hp->n; ++k)
		for (b = 0; b != hp->m; ++b)
			et[k][b] = hp->e[b][k];
	// the initial state, drawn from a0[]
	x = drand48();
	for (k = 0, y = 0.0; k != hp->n; ++k) {
		y += hp->a0[k];
		if (y >= x) break;
	}
	// main loop
	for (i = 0; i != L; ++i) {
		FLOAT *el, *ak = hp->a[k];
		x = drand48();
		for (l = 0, y = 0.0; l != hp->n; ++l) {
			y += ak[l];
			if (y >= x) break;
		}
		el = et[l];
		x = drand48();
		for (b = 0, y = 0.0; b != hp->m; ++b) {
			y += el[b];
			if (y >= x) break;
		} 
		seq[i] = b;
		k = l;
	}
	for (k = 0; k != hp->n; ++k) free(et[k]);
	free(et);
	return seq;
}
