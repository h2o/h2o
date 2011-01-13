#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "knhx.h"

typedef struct {
	int error, n, max;
	knhx1_t *node;
} knaux_t;

static inline char *add_node(const char *s, knaux_t *aux, int x)
{
	char *p, *nbeg, *nend = 0;
	knhx1_t *r;
	if (aux->n == aux->max) {
		aux->max = aux->max? aux->max<<1 : 8;
		aux->node = (knhx1_t*)realloc(aux->node, sizeof(knhx1_t) * aux->max);
	}
	r = aux->node + (aux->n++);
	r->n = x; r->parent = -1;
	for (p = (char*)s, nbeg = p, r->d = -1.0; *p && *p != ',' && *p != ')'; ++p) {
		if (*p == '[') {
			if (nend == 0) nend = p;
			do ++p; while (*p && *p != ']');
			if (*p == 0) {
				aux->error |= KNERR_BRACKET;
				break;
			}
		} else if (*p == ':') {
			if (nend == 0) nend = p;
			r->d = strtod(p + 1, &p);
			--p;
		} else if (!isgraph(*p)) if (nend == 0) nend = p;
	}
	if (nend == 0) nend = p;
	if (nend != nbeg) {
		r->name = (char*)calloc(nend - nbeg + 1, 1);
		strncpy(r->name, nbeg, nend - nbeg);
	} else r->name = strdup("");
	return p;
}

knhx1_t *kn_parse(const char *nhx, int *_n, int *_error)
{
	char *p;
	int *stack, top, max;
	knaux_t *aux;
	knhx1_t *ret;

#define __push_back(y) do {										\
		if (top == max) {										\
			max = max? max<<1 : 16;								\
			stack = (int*)realloc(stack, sizeof(int) * max);	\
		}														\
		stack[top++] = (y);										\
	} while (0)													\

	stack = 0; top = max = 0;
	p = (char*)nhx;
	aux = (knaux_t*)calloc(1, sizeof(knaux_t));
	while (*p) {
		while (*p && !isgraph(*p)) ++p;
		if (*p == 0) break;
		if (*p == ',') ++p;
		else if (*p == '(') {
			__push_back(-1);
			++p;
		} else if (*p == ')') {
			int x = aux->n, m, i;
			for (i = top - 1; i >= 0; --i)
				if (stack[i] < 0) break;
			m = top - 1 - i;
			p = add_node(p + 1, aux, m);
			aux->node[x].child = (int*)calloc(m, sizeof(int));
			for (i = top - 1, m = m - 1; m >= 0; --m, --i) {
				aux->node[x].child[m] = stack[i];
				aux->node[stack[i]].parent = x;
			}
			top = i;
			__push_back(x);
		} else {
			__push_back(aux->n);
			p = add_node(p, aux, 0);
		}
	}
	*_n = aux->n;
	*_error = aux->error;
	ret = aux->node;
	free(aux); free(stack);
	return ret;
}

#ifdef KNHX_MAIN
int main(int argc, char *argv[])
{
	char *s = "((a[abc],d1)x:0.5,((b[&&NHX:S=MOUSE],h2)[&&NHX:S=HUMAN:B=99][blabla][&&NHX:K=foo],c))";
	knhx1_t *node;
	int i, n, error;
	node = kn_parse(s, &n, &error);
	for (i = 0; i < n; ++i) {
		knhx1_t *p = node + i;
		printf("%s[%d]: %d,%d,%lg\n", p->name, i, p->parent, p->n, p->d);
	}
	return 0;
}
#endif
