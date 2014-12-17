#ifndef AC_KMATH_H
#define AC_KMATH_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

	/**********************************
	 * Pseudo-random number generator *
	 **********************************/

	typedef uint64_t krint64_t;

	struct _krand_t;
	typedef struct _krand_t krand_t;

	#define kr_drand(_kr) ((kr_rand(_kr) >> 11) * (1.0/9007199254740992.0))
	#define kr_sample(_kr, _k, _cnt) ((*(_cnt))++ < (_k)? *(_cnt) - 1 : kr_rand(_kr) % *(_cnt))

	krand_t *kr_srand(krint64_t seed);
	krint64_t kr_rand(krand_t *kr);

	/**************************
	 * Non-linear programming *
	 **************************/

	#define KMIN_RADIUS  0.5
	#define KMIN_EPS     1e-7
	#define KMIN_MAXCALL 50000

	typedef double (*kmin_f)(int, double*, void*);
	typedef double (*kmin1_f)(double, void*);

	double kmin_hj(kmin_f func, int n, double *x, void *data, double r, double eps, int max_calls); // Hooke-Jeeves'
	double kmin_brent(kmin1_f func, double a, double b, void *data, double tol, double *xmin); // Brent's 1-dimenssion

	/*********************
	 * Special functions *
	 *********************/

	double kf_lgamma(double z); // log gamma function
	double kf_erfc(double x); // complementary error function
	double kf_gammap(double s, double z); // regularized lower incomplete gamma function
	double kf_gammaq(double s, double z); // regularized upper incomplete gamma function
	double kf_betai(double a, double b, double x); // regularized incomplete beta function

#ifdef __cplusplus
}
#endif

#endif
