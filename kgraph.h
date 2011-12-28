#ifndef AC_KGRAPH_H
#define AC_KGRAPH_H

#include <stdint.h>
#include <stdlib.h>
#include "khash.h"
#include "kbtree.h"

typedef unsigned kgint_t;

#define kgraph_t(name) kh_##name##_t

#define __KG_BASIC(name, SCOPE, vertex_t, arc_t, ehn) \
	SCOPE kgraph_t(name) *kg_init_##name(void) { return kh_init(name); } \
	SCOPE void kg_destroy_##name(kgraph_t(name) *g) { \
		khint_t k; \
		if (g == 0) return; \
		for (k = kh_begin(g); k != kh_end(g); ++k) \
			if (kh_exist(g, k)) kh_destroy(ehn, kh_val(g, k)._arc); \
		kh_destroy(name, g); \
	} \
	SCOPE vertex_t *kg_get_v_##name(kgraph_t(name) *g, kgint_t v) { \
		khint_t k = kh_get(name, g, v); \
		return k == kh_end(g)? 0 : &kh_val(g, k); \
	} \
	SCOPE vertex_t *kg_put_v_##name(kgraph_t(name) *g, kgint_t v, int *absent) { \
		khint_t k; \
		k = kh_put(name, g, v, absent); \
		if (*absent) kh_val(g, k)._arc = kh_init(ehn); \
		return &kh_val(g, k); \
	} \
	SCOPE void kg_put_a_##name(kgraph_t(name) *g, kgint_t vbeg, kgint_t vend, int dir, arc_t **pb, arc_t **pe) { \
		vertex_t *p; \
		khint_t k; \
		int absent; \
		p = kg_put_v_##name(g, vbeg, &absent); \
		k = kh_put(ehn, p->_arc, vend<<2|dir, &absent); \
		*pb = &kh_val(p->_arc, k); \
		p = kg_put_v_##name(g, vend, &absent); \
		k = kh_put(ehn, p->_arc, vbeg<<2|(~dir&3), &absent); \
		*pe = &kh_val(p->_arc, k); \
	} \
	SCOPE vertex_t *kg_del_v_##name(kgraph_t(name) *g, kgint_t v) { \
		khint_t k, k0, k2, k3; \
		khash_t(ehn) *h; \
		k0 = k = kh_get(name, g, v); \
		if (k == kh_end(g)) return 0; /* not present in the graph */ \
		h = kh_val(g, k)._arc; \
		for (k = kh_begin(h); k != kh_end(h); ++k) /* remove v from its neighbors */ \
			if (kh_exist(h, k)) { \
				k2 = kh_get(name, g, kh_key(h, k)>>2); \
				/* assert(k2 != kh_end(g)); */ \
				k3 = kh_get(ehn, kh_val(g, k2)._arc, v<<2|(~kh_key(h, k)&3)); \
				/* assert(k3 != kh_end(kh_val(g, k2)._arc)); */ \
				kh_del(ehn, kh_val(g, k2)._arc, k3); \
			} \
		kh_destroy(ehn, h); \
		kh_del(name, g, k0); \
		return &kh_val(g, k0); \
	}

#define KGRAPH_PRINT(name, SCOPE) \
	SCOPE void kg_print_##name(kgraph_t(name) *g) { \
		khint_t k, k2; \
		for (k = kh_begin(g); k != kh_end(g); ++k) \
			if (kh_exist(g, k)) { \
				printf("v %u\n", kh_key(g, k)); \
				for (k2 = kh_begin(kh_val(g, k)._arc); k2 != kh_end(kh_val(g, k)._arc); ++k2) \
					if (kh_exist(kh_val(g, k)._arc, k2) && kh_key(g, k) < kh_key(kh_val(g, k)._arc, k2)>>2) \
						printf("a %u%c%c%u\n", kh_key(g, k), "><"[kh_key(kh_val(g, k)._arc, k2)>>1&1], \
								"><"[kh_key(kh_val(g, k)._arc, k2)&1], kh_key(kh_val(g, k)._arc, k2)>>2); \
			} \
	}

#define KGRAPH_INIT(name, SCOPE, vertex_t, arc_t, ehn) \
	KHASH_INIT2(name, SCOPE, kgint_t, vertex_t, 1, kh_int_hash_func, kh_int_hash_equal) \
	__KG_BASIC(name, SCOPE, vertex_t, arc_t, ehn)

#endif
