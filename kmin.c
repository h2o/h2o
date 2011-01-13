/* The MIT License

   Copyright (c) 2008, by Heng Li <lh3@live.co.uk>

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

/* Hooke-Jeeves algorithm for nonlinear minimization
   Heng Li, Februay 3, 2008
 
   Based on the pseudocodes by Bell and Pike (CACM 9(9):684-685), and
   the revision by Tomlin and Smith (CACM 12(11):637-638). Both of the
   papers are comments on Kaupe's Algorithm 178 "Direct Search" (ACM
   6(6):313-314). The original algorithm was designed by Hooke and
   Jeeves (ACM 8:212-229). This program is further revised according to
   Johnson's implementation at Netlib (opt/hooke.c).
 
   Hooke-Jeeves algorithm is very simple and it works quite well on a
   few examples. However, it might fail to converge due to its heuristic
   nature. A possible improvement, as is suggested by Johnson, may be to
   choose a small r at the beginning to quickly approach to the minimum
   and a large r at later step to hit the minimum.
 */

#include <stdlib.h>
#include <string.h>
#include <math.h>
#include "kmin.h"

static double __kmin_hj_aux(kmin_f func, int n, double *x1, void *data, double fx1, double *dx, int *n_calls)
{
	int k, j = *n_calls;
	double ftmp;
	for (k = 0; k != n; ++k) {
		x1[k] += dx[k];
		ftmp = func(n, x1, data); ++j;
		if (ftmp < fx1) fx1 = ftmp;
		else { /* search the opposite direction */
			dx[k] = 0.0 - dx[k];
			x1[k] += dx[k] + dx[k];
			ftmp = func(n, x1, data); ++j;
			if (ftmp < fx1) fx1 = ftmp;
			else x1[k] -= dx[k]; /* back to the original x[k] */
		}
	}
	*n_calls = j;
	return fx1; /* here: fx1=f(n,x1) */
}

double kmin_hj(kmin_f func, int n, double *x, void *data, double r, double eps, int max_calls)
{
	double fx, fx1, *x1, *dx, radius;
	int k, n_calls = 0;
	x1 = (double*)calloc(n, sizeof(double));
	dx = (double*)calloc(n, sizeof(double));
	for (k = 0; k != n; ++k) { /* initial directions, based on MGJ */
		dx[k] = fabs(x[k]) * r;
		if (dx[k] == 0) dx[k] = r;
	}
	radius = r;
	fx1 = fx = func(n, x, data); ++n_calls;
	for (;;) {
		memcpy(x1, x, n * sizeof(double)); /* x1 = x */
		fx1 = __kmin_hj_aux(func, n, x1, data, fx, dx, &n_calls);
		while (fx1 < fx) {
			for (k = 0; k != n; ++k) {
				double t = x[k];
				dx[k] = x1[k] > x[k]? fabs(dx[k]) : 0.0 - fabs(dx[k]);
				x[k] = x1[k];
				x1[k] = x1[k] + x1[k] - t;
			}
			fx = fx1;
			if (n_calls >= max_calls) break;
			fx1 = func(n, x1, data); ++n_calls;
			fx1 = __kmin_hj_aux(func, n, x1, data, fx1, dx, &n_calls);
			if (fx1 >= fx) break;
			for (k = 0; k != n; ++k)
				if (fabs(x1[k] - x[k]) > .5 * fabs(dx[k])) break;
			if (k == n) break;
		}
		if (radius >= eps) {
			if (n_calls >= max_calls) break;
			radius *= r;
			for (k = 0; k != n; ++k) dx[k] *= r;
		} else break; /* converge */
	}
	free(x1); free(dx);
	return fx1;
}
