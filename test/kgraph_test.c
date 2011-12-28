#include <stdio.h>
#include "kgraph.h"

KHASH_INIT2(e32, extern, uint32_t, int, 1, kh_int_hash_func, kh_int_hash_equal)

typedef struct {
	int i;
	khash_t(e32) *_arc;
} vertex_t;

KGRAPH_INIT(g, extern, vertex_t, int, e32)
KGRAPH_PRINT(g, extern)

int main()
{
	int *pb, *pe;
	kgraph_t(g) *g;
	g = kg_init_g();
	kg_put_a_g(g, 10, 20, 0, &pb, &pe);
	kg_put_a_g(g, 20, 30, 0, &pb, &pe);
	kg_put_a_g(g, 30, 10, 1, &pb, &pe);
	kg_del_v_g(g, 20);
	kg_print_g(g);
	kg_destroy_g(g);
	return 0;
}
