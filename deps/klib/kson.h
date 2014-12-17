#ifndef KSON_H
#define KSON_H

#include <string.h>

#define KSON_TYPE_NO_QUOTE  1
#define KSON_TYPE_SGL_QUOTE 2
#define KSON_TYPE_DBL_QUOTE 3
#define KSON_TYPE_BRACKET   4
#define KSON_TYPE_BRACE     5

#define KSON_OK              0
#define KSON_ERR_EXTRA_LEFT  1
#define KSON_ERR_EXTRA_RIGHT 2
#define KSON_ERR_NO_KEY      3

typedef struct kson_node_s {
	unsigned long long type:3, n:61;
	char *key;
	union {
		struct kson_node_s **child;
		char *str;
	} v;
} kson_node_t;

typedef struct {
	long n_nodes;
	kson_node_t *root;
} kson_t;

#ifdef __cplusplus
extern "C" {
#endif

	kson_t *kson_parse(const char *json);
	void kson_destroy(kson_t *kson);
	const kson_node_t *kson_by_path(const kson_node_t *root, int path_len, ...);
	void kson_format(const kson_node_t *root);

#ifdef __cplusplus
}
#endif

#define kson_is_internal(p) ((p)->type == KSON_TYPE_BRACKET || (p)->type == KSON_TYPE_BRACE)

static inline const kson_node_t *kson_by_key(const kson_node_t *p, const char *key)
{
	long i;
	if (!kson_is_internal(p)) return 0;
	for (i = 0; i < (long)p->n; ++i) {
		const kson_node_t *q = p->v.child[i];
		if (q->key && strcmp(q->key, key) == 0)
			return q;
	}
	return 0;
}

static inline const kson_node_t *kson_by_index(const kson_node_t *p, long i)
{
	if (!kson_is_internal(p)) return 0;
	return 0 <= i && i < (long)p->n? p->v.child[i] : 0;
}

#endif
