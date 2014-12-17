#include <string.h>
#include <stdlib.h>
#include <stdarg.h>
#include <assert.h>
#include <ctype.h>
#include <stdio.h>
#include "kson.h"

/*************
 *** Parse ***
 *************/

kson_node_t *kson_parse_core(const char *json, long *_n, int *error, long *parsed_len)
{
	long *stack = 0, top = 0, max = 0, n_a = 0, m_a = 0, i, j;
	kson_node_t *a = 0, *u;
	const char *p, *q;
	size_t *tmp;

#define __push_back(y) do { \
		if (top == max) { \
			max = max? max<<1 : 4; \
			stack = (long*)realloc(stack, sizeof(long) * max); \
		} \
		stack[top++] = (y); \
	} while (0)

#define __new_node(z) do { \
		if (n_a == m_a) { \
			long old_m = m_a; \
			m_a = m_a? m_a<<1 : 4; \
			a = (kson_node_t*)realloc(a, sizeof(kson_node_t) * m_a); \
			memset(a + old_m, 0, sizeof(kson_node_t) * (m_a - old_m)); \
		} \
		*(z) = &a[n_a++]; \
	} while (0)

	assert(sizeof(size_t) == sizeof(kson_node_t*));
	*error = KSON_OK;
	for (p = json; *p; ++p) {
		while (*p && isspace(*p)) ++p;
		if (*p == 0) break;
		if (*p == ',') { // comma is somewhat redundant
		} else if (*p == '[' || *p == '{') {
			int t = *p == '['? -1 : -2;
			if (top < 2 || stack[top-1] != -3) { // unnamed internal node
				__push_back(n_a);
				__new_node(&u);
				__push_back(t);
			} else stack[top-1] = t; // named internal node
		} else if (*p == ']' || *p == '}') {
			long i, start, t = *p == ']'? -1 : -2;
			for (i = top - 1; i >= 0 && stack[i] != t; --i);
			if (i < 0) { // error: an extra right bracket
				*error = KSON_ERR_EXTRA_RIGHT;
				break;
			}
			start = i;
			u = &a[stack[start-1]];
			u->key = u->v.str;
			u->n = top - 1 - start;
			u->v.child = (kson_node_t**)malloc(u->n * sizeof(kson_node_t*));
			tmp = (size_t*)u->v.child;
			for (i = start + 1; i < top; ++i)
				tmp[i - start - 1] = stack[i];
			u->type = *p == ']'? KSON_TYPE_BRACKET : KSON_TYPE_BRACE;
			if ((top = start) == 1) break; // completed one object; remaining characters discarded
		} else if (*p == ':') {
			if (top == 0 || stack[top-1] == -3) {
				*error = KSON_ERR_NO_KEY;
				break;
			}
			__push_back(-3);
		} else {
			int c = *p;
			// get the node to modify
			if (top >= 2 && stack[top-1] == -3) { // we have a key:value pair here
				--top;
				u = &a[stack[top-1]];
				u->key = u->v.str; // move old value to key
			} else { // don't know if this is a bare value or a key:value pair; keep it as a value for now
				__push_back(n_a);
				__new_node(&u);
			}
			// parse string
			if (c == '\'' || c == '"') {
				for (q = ++p; *q && *q != c; ++q)
					if (*q == '\\') ++q;
			} else {
				for (q = p; *q && *q != ']' && *q != '}' && *q != ',' && *q != ':' && *q != '\n'; ++q)
					if (*q == '\\') ++q;
			}
			u->v.str = (char*)malloc(q - p + 1); strncpy(u->v.str, p, q - p); u->v.str[q-p] = 0; // equivalent to u->v.str=strndup(p, q-p)
			u->type = c == '\''? KSON_TYPE_SGL_QUOTE : c == '"'? KSON_TYPE_DBL_QUOTE : KSON_TYPE_NO_QUOTE;
			p = c == '\'' || c == '"'? q : q - 1;
		}
	}
	while (*p && isspace(*p)) ++p; // skip trailing blanks
	if (parsed_len) *parsed_len = p - json;
	if (top != 1) *error = KSON_ERR_EXTRA_LEFT;

	for (i = 0; i < n_a; ++i)
		for (j = 0, u = &a[i], tmp = (size_t*)u->v.child; j < (long)u->n; ++j)
			u->v.child[j] = &a[tmp[j]];

	free(stack);
	*_n = n_a;
	return a;
}

void kson_destroy(kson_t *kson)
{
	long i;
	if (kson == 0) return;
	for (i = 0; i < kson->n_nodes; ++i) {
		free(kson->root[i].key); free(kson->root[i].v.str);
	}
	free(kson->root); free(kson);
}

kson_t *kson_parse(const char *json)
{
	kson_t *kson;
	int error;
	kson = (kson_t*)calloc(1, sizeof(kson_t));
	kson->root = kson_parse_core(json, &kson->n_nodes, &error, 0);
	if (error) {
		kson_destroy(kson);
		return 0;
	}
	return kson;
}

/*************
 *** Query ***
 *************/

const kson_node_t *kson_by_path(const kson_node_t *p, int depth, ...)
{
	va_list ap;
	va_start(ap, depth);
	while (p && depth > 0) {
		if (p->type == KSON_TYPE_BRACE) {
			p = kson_by_key(p, va_arg(ap, const char*));
		} else if (p->type == KSON_TYPE_BRACKET) {
			p = kson_by_index(p, va_arg(ap, long));
		} else break;
		--depth;
	}
	va_end(ap);
	return p;
}

/**************
 *** Fromat ***
 **************/

void kson_format_recur(const kson_node_t *p, int depth)
{
	long i;
	if (p->key) printf("\"%s\":", p->key);
	if (p->type == KSON_TYPE_BRACKET || p->type == KSON_TYPE_BRACE) {
		putchar(p->type == KSON_TYPE_BRACKET? '[' : '{');
		if (p->n) {
			putchar('\n'); for (i = 0; i <= depth; ++i) fputs("  ", stdout);
			for (i = 0; i < (long)p->n; ++i) {
				if (i) {
					int i;
					putchar(',');
					putchar('\n'); for (i = 0; i <= depth; ++i) fputs("  ", stdout);
				}
				kson_format_recur(p->v.child[i], depth + 1);
			}
			putchar('\n'); for (i = 0; i < depth; ++i) fputs("  ", stdout);
		}
		putchar(p->type == KSON_TYPE_BRACKET? ']' : '}');
	} else {
		if (p->type != KSON_TYPE_NO_QUOTE)
			putchar(p->type == KSON_TYPE_SGL_QUOTE? '\'' : '"');
		fputs(p->v.str, stdout);
		if (p->type != KSON_TYPE_NO_QUOTE)
			putchar(p->type == KSON_TYPE_SGL_QUOTE? '\'' : '"');
	}
}

void kson_format(const kson_node_t *root)
{
	kson_format_recur(root, 0);
	putchar('\n');
}

/*********************
 *** Main function ***
 *********************/

#ifdef KSON_MAIN
#define kroundup32(x) (--(x), (x)|=(x)>>1, (x)|=(x)>>2, (x)|=(x)>>4, (x)|=(x)>>8, (x)|=(x)>>16, ++(x))
int main(int argc, char *argv[])
{
	kson_t *kson = 0;
	if (argc > 1) {
		FILE *fp;
		int len = 0, max = 0, tmp, i;
		char *json = 0, buf[0x10000];
		if ((fp = fopen(argv[1], "rb")) != 0) {
			// read the entire file into a string
			while ((tmp = fread(buf, 1, 0x10000, fp)) != 0) {
				if (len + tmp + 1 > max) {
					max = len + tmp + 1;
					kroundup32(max);
					json = (char*)realloc(json, max);
				}
				memcpy(json + len, buf, tmp);
				len += tmp;
			}
			fclose(fp);
			// parse
			kson = kson_parse(json);
			free(json);
			if (kson) {
				kson_format(kson->root);
				if (argc > 2) {
					// path finding
					const kson_node_t *p = kson->root;
					for (i = 2; i < argc && p; ++i) {
						if (p->type == KSON_TYPE_BRACKET)
							p = kson_by_index(p, atoi(argv[i]));
						else if (p->type == KSON_TYPE_BRACE)
							p = kson_by_key(p, argv[i]);
						else p = 0;
					}
					if (p) {
						if (kson_is_internal(p)) printf("Reached an internal node\n");
						else printf("Value: %s\n", p->v.str);
					} else printf("Failed to find the slot\n");
				}
			} else printf("Failed to parse\n");
		}
	} else {
		kson = kson_parse("{'a' : 1,'b':[0,'isn\\'t',true],'d':[{\n\n\n}]}");
		if (kson) {
			const kson_node_t *p = kson_by_path(kson->root, 2, "b", 1);
			if (p) printf("*** %s\n", p->v.str);
			else printf("!!! not found\n");
			kson_format(kson->root);
		} else {
			printf("Failed to parse\n");
		}
	}
	kson_destroy(kson);
	return 0;
}
#endif
