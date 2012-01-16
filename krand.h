#ifndef AC_KRAND_H
#define AC_KRAND_H

#include <stdint.h>

typedef uint64_t krint64_t;

struct _krand_t;
typedef struct _krand_t krand_t;

#define kr_drand(_kr) ((kr_rand(_kr) >> 11) * (1.0/9007199254740992.0))
#define kr_sample(_kr, _k, _cnt) ((*(_cnt))++ < (_k)? *(_cnt) - 1 : kr_rand(_kr) % *(_cnt))

#ifdef __cplusplus
extern "C" {
#endif

krand_t *kr_srand(krint64_t seed);
krint64_t kr_rand(krand_t *kr);

#ifdef __cplusplus
}
#endif

#endif
