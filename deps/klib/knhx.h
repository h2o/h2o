#ifndef KNHX_H_
#define KNHX_H_

#define KNERR_MISSING_LEFT   0x01
#define KNERR_MISSING_RGHT   0x02
#define KNERR_BRACKET        0x04
#define KNERR_COLON          0x08

typedef struct {
	int parent, n;
	int *child;
	char *name;
	double d;
} knhx1_t;

#ifndef KSTRING_T
#define KSTRING_T kstring_t
typedef struct __kstring_t {
	size_t l, m;
	char *s;
} kstring_t;
#endif

#ifdef __cplusplus
extern "C" {
#endif

	knhx1_t *kn_parse(const char *nhx, int *_n, int *_error);
	void kn_format(const knhx1_t *node, int root, kstring_t *s);

#ifdef __cplusplus
}
#endif

#endif
