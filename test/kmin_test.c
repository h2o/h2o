#include <stdio.h>
#include <math.h>
#include "kmin.h"

static int n_evals;

double f_Chebyquad(int n, double *x, void *data)
{
    int i, j;
    double y[20][20], f;
    int np, iw;
    double sum;
    for (j = 0; j != n; ++j) {
		y[0][j] = 1.;
		y[1][j] = 2. * x[j] - 1.;
    }
    for (i = 1; i != n; ++i)
		for (j = 0; j != n; ++j)
			y[i+1][j] = 2. * y[1][j] * y[i][j] - y[i-1][j];
    f = 0.;
    np = n + 1;
    iw = 1;
    for (i = 0; i != np; ++i) {
		sum = 0.;
		for (j = 0; j != n; ++j) sum += y[i][j];
		sum /= n;
		if (iw > 0) sum += 1. / ((i - 1) * (i + 1));
		iw = -iw;
		f += sum * sum;
    }
	++n_evals;
    return f;
}

int main()
{
	double x[20], y;
	int n, i;
	printf("\nMinimizer: Hooke-Jeeves\n");
	for (n = 2; n <= 8; n += 2) {
		for (i = 0; i != n; ++i) x[i] = (double)(i + 1) / n;
		n_evals = 0;
		y = kmin_hj(f_Chebyquad, n, x, 0, KMIN_RADIUS, KMIN_EPS, KMIN_MAXCALL);
		printf("n=%d,min=%.8lg,n_evals=%d\n", n, y, n_evals);
	}
	printf("\n");
	return 0;
}
