/* 
   64-bit Mersenne Twister pseudorandom number generator. Adapted from:

     http://www.math.sci.hiroshima-u.ac.jp/~m-mat/MT/VERSIONS/C-LANG/mt19937-64.c

   which was written by Takuji Nishimura and Makoto Matsumoto and released
   under the 3-clause BSD license.
*/

#include <stdlib.h>
#include "krand.h"

#define KR_NN 312
#define KR_MM 156
#define KR_UM 0xFFFFFFFF80000000ULL /* Most significant 33 bits */
#define KR_LM 0x7FFFFFFFULL /* Least significant 31 bits */

struct _krand_t {
	int mti;
	krint64_t mt[KR_NN];
};

static void kr_srand0(krint64_t seed, krand_t *kr)
{
	kr->mt[0] = seed;
	for (kr->mti = 1; kr->mti < KR_NN; ++kr->mti) 
		kr->mt[kr->mti] = 6364136223846793005ULL * (kr->mt[kr->mti - 1] ^ (kr->mt[kr->mti - 1] >> 62)) + kr->mti;
}

krand_t *kr_srand(krint64_t seed)
{
	krand_t *kr;
	kr = malloc(sizeof(krand_t));
	kr_srand0(seed, kr);
	return kr;
}

krint64_t kr_rand(krand_t *kr)
{
	krint64_t x;
	static const krint64_t mag01[2] = { 0, 0xB5026F5AA96619E9ULL };
    if (kr->mti >= KR_NN) {
		int i;
		if (kr->mti == KR_NN + 1) kr_srand0(5489ULL, kr);
        for (i = 0; i < KR_NN - KR_MM; ++i) {
            x = (kr->mt[i] & KR_UM) | (kr->mt[i+1] & KR_LM);
            kr->mt[i] = kr->mt[i + KR_MM] ^ (x>>1) ^ mag01[(int)(x&1)];
        }
        for (; i < KR_NN - 1; ++i) {
            x = (kr->mt[i] & KR_UM) | (kr->mt[i+1] & KR_LM);
            kr->mt[i] = kr->mt[i + (KR_MM - KR_NN)] ^ (x>>1) ^ mag01[(int)(x&1)];
        }
        x = (kr->mt[KR_NN - 1] & KR_UM) | (kr->mt[0] & KR_LM);
        kr->mt[KR_NN - 1] = kr->mt[KR_MM - 1] ^ (x>>1) ^ mag01[(int)(x&1)];
        kr->mti = 0;
    }
    x = kr->mt[kr->mti++];
    x ^= (x >> 29) & 0x5555555555555555ULL;
    x ^= (x << 17) & 0x71D67FFFEDA60000ULL;
    x ^= (x << 37) & 0xFFF7EEE000000000ULL;
    x ^= (x >> 43);
    return x;
}

#ifdef _KR_MAIN
int main(int argc, char *argv[])
{
	long i, N = 200000000;
	krand_t *kr;
	if (argc > 1) N = atol(argv[1]);
	kr = kr_srand(11);
	for (i = 0; i < N; ++i) kr_rand(kr);
	return 0;
}
#endif
