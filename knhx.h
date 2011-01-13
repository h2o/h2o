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

#endif
