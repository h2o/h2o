#include <stdarg.h>
#include <stdio.h>
#include <ctype.h>
#include <string.h>
#include <stdint.h>
#include "kstring.h"

int ksprintf(kstring_t *s, const char *fmt, ...)
{
	va_list ap;
	int l;
	va_start(ap, fmt);
	l = vsnprintf(s->s + s->l, s->m - s->l, fmt, ap); // This line does not work with glibc 2.0. See `man snprintf'.
	va_end(ap);
	if (l + 1 > s->m - s->l) {
		s->m = s->l + l + 2;
		kroundup32(s->m);
		s->s = (char*)realloc(s->s, s->m);
		va_start(ap, fmt);
		l = vsnprintf(s->s + s->l, s->m - s->l, fmt, ap);
	}
	va_end(ap);
	s->l += l;
	return l;
}

char *kstrtok(const char *str, const char *sep, ks_tokaux_t *aux)
{
	const char *p, *start;
	if (sep) { // set up the table
		if (str == 0 && (aux->tab[0]&1)) return 0; // no need to set up if we have finished
		aux->finished = 0;
		if (sep[1]) {
			aux->sep = -1;
			aux->tab[0] = aux->tab[1] = aux->tab[2] = aux->tab[3] = 0;
			for (p = sep; *p; ++p) aux->tab[*p>>6] |= 1ull<<(*p&0x3f);
		} else aux->sep = sep[0];
	}
	if (aux->finished) return 0;
	else if (str) aux->p = str - 1, aux->finished = 0;
	if (aux->sep < 0) {
		for (p = start = aux->p + 1; *p; ++p)
			if (aux->tab[*p>>6]>>(*p&0x3f)&1) break;
	} else {
		for (p = start = aux->p + 1; *p; ++p)
			if (*p == aux->sep) break;
	}
	aux->p = p; // end of token
	if (*p == 0) aux->finished = 1; // no more tokens
	return (char*)start;
}

// s MUST BE a null terminated string; l = strlen(s)
int ksplit_core(char *s, int delimiter, int *_max, int **_offsets)
{
	int i, n, max, last_char, last_start, *offsets, l;
	n = 0; max = *_max; offsets = *_offsets;
	l = strlen(s);
	
#define __ksplit_aux do {												\
		if (_offsets) {													\
			s[i] = 0;													\
			if (n == max) {												\
				max = max? max<<1 : 2;									\
				offsets = (int*)realloc(offsets, sizeof(int) * max);	\
			}															\
			offsets[n++] = last_start;									\
		} else ++n;														\
	} while (0)

	for (i = 0, last_char = last_start = 0; i <= l; ++i) {
		if (delimiter == 0) {
			if (isspace(s[i]) || s[i] == 0) {
				if (isgraph(last_char)) __ksplit_aux; // the end of a field
			} else {
				if (isspace(last_char) || last_char == 0) last_start = i;
			}
		} else {
			if (s[i] == delimiter || s[i] == 0) {
				if (last_char != 0 && last_char != delimiter) __ksplit_aux; // the end of a field
			} else {
				if (last_char == delimiter || last_char == 0) last_start = i;
			}
		}
		last_char = s[i];
	}
	*_max = max; *_offsets = offsets;
	return n;
}

/**********************
 * Boyer-Moore search *
 **********************/

typedef unsigned char ubyte_t;

// reference: http://www-igm.univ-mlv.fr/~lecroq/string/node14.html
static int *ksBM_prep(const ubyte_t *pat, int m)
{
	int i, *suff, *prep, *bmGs, *bmBc;
	prep = calloc(m + 256, sizeof(int));
	bmGs = prep; bmBc = prep + m;
	{ // preBmBc()
		for (i = 0; i < 256; ++i) bmBc[i] = m;
		for (i = 0; i < m - 1; ++i) bmBc[pat[i]] = m - i - 1;
	}
	suff = calloc(m, sizeof(int));
	{ // suffixes()
		int f = 0, g;
		suff[m - 1] = m;
		g = m - 1;
		for (i = m - 2; i >= 0; --i) {
			if (i > g && suff[i + m - 1 - f] < i - g)
				suff[i] = suff[i + m - 1 - f];
			else {
				if (i < g) g = i;
				f = i;
				while (g >= 0 && pat[g] == pat[g + m - 1 - f]) --g;
				suff[i] = f - g;
			}
		}
	}
	{ // preBmGs()
		int j = 0;
		for (i = 0; i < m; ++i) bmGs[i] = m;
		for (i = m - 1; i >= 0; --i)
			if (suff[i] == i + 1)
				for (; j < m - 1 - i; ++j)
					if (bmGs[j] == m)
						bmGs[j] = m - 1 - i;
		for (i = 0; i <= m - 2; ++i)
			bmGs[m - 1 - suff[i]] = m - 1 - i;
	}
	free(suff);
	return prep;
}

void *kmemmem(const void *_str, int n, const void *_pat, int m, int **_prep)
{
	int i, j, *prep = 0, *bmGs, *bmBc;
	const ubyte_t *str, *pat;
	str = (const ubyte_t*)_str; pat = (const ubyte_t*)_pat;
	prep = (_prep == 0 || *_prep == 0)? ksBM_prep(pat, m) : *_prep;
	if (_prep && *_prep == 0) *_prep = prep;
	bmGs = prep; bmBc = prep + m;
	j = 0;
	while (j <= n - m) {
		for (i = m - 1; i >= 0 && pat[i] == str[i+j]; --i);
		if (i >= 0) {
			int max = bmBc[str[i+j]] - m + 1 + i;
			if (max < bmGs[i]) max = bmGs[i];
			j += max;
		} else return (void*)(str + j);
	}
	if (_prep == 0) free(prep);
	return 0;
}

char *kstrstr(const char *str, const char *pat, int **_prep)
{
	return (char*)kmemmem(str, strlen(str), pat, strlen(pat), _prep);
}

char *kstrnstr(const char *str, const char *pat, int n, int **_prep)
{
	return (char*)kmemmem(str, n, pat, strlen(pat), _prep);
}

/****************
 * fast sprintf *
 ****************/

static inline void enlarge(kstring_t *s, int l)
{
	if (s->l + l + 1 >= s->m) {
		s->m = s->l + l + 2;
		kroundup32(s->m);
		s->s = (char*)realloc(s->s, s->m);
	}
}

static int get_base(int c)
{
	if (c == 'o') return 8;
	if (c == 'x') return 16;
	return 10;
}

int ksprintf_fast(kstring_t *s, const char *fmt, ...)
{

#define write_integer(_ap, _s, _type, _base) do { \
		_type c = va_arg(_ap, _type); \
		if (c == 0) { \
			enlarge(_s, 1); \
			_s->s[_s->l++] = '0'; \
			_s->s[_s->l] = 0; \
		} else { \
			char buf[32]; \
			int l, ll; \
			_type x; \
			for (l = 0, x = c < 0? -c : c; x > 0; x /= _base) buf[l++] = "0123456789abcdef"[x%_base]; \
			if (c < 0) buf[l++] = '-'; \
			enlarge(_s, l); \
			for (ll = l - 1; ll >= 0; --ll) _s->s[_s->l++] = buf[ll]; \
			_s->s[_s->l] = 0; \
		} \
	} while (0)

	va_list ap;
	const char *p = fmt, *q;
	va_start(ap, fmt);
	while (*p) {
		if (*p == '%') {
			++p;
			if (*p == '%') {
				enlarge(s, 1);
				s->s[s->l++] = '%';
				s->s[s->l] = 0;
			} else if (*p == 's') { // %s
				char *r = va_arg(ap, char*);
				int l = strlen(r);
				enlarge(s, l);
				memcpy(s->s + s->l, r, l);
				s->l += l;
				s->s[s->l] = 0;
			} else if (*p == 'c') { // %c
				enlarge(s, 1);
				s->s[s->l++] = va_arg(ap, int);
				s->s[s->l] = 0;
			} else if (*p == 'd' || *p == 'i') { // %d or %i
				write_integer(ap, s, int, 10);
			} else if (*p == 'u' || *p == 'o' || *p == 'x') { // %u, %o or %x
				int base = get_base(*p);
				write_integer(ap, s, unsigned, base);
			} else if (*p == 'l') {
				++p;
				if (*p == 'l') {
					++p;
					if (*p == 'd' || *p == 'i') { // %lld or %lli
						write_integer(ap, s, long long, 10);
					} else if (*p == 'u' || *p == 'o' || *p == 'x') {
						int base = get_base(*p);
						write_integer(ap, s, unsigned long long, base);
					}
				} else if (*p == 'd' || *p == 'i') { // %ld or %li
					write_integer(ap, s, long, 10);
				} else if (*p == 'u' || *p == 'o' || *p == 'x') {
					int base = get_base(*p);
					write_integer(ap, s, unsigned long, base);
				}
			}
			++p;
		} else {
			q = p;
			while (*p && *p != '%') ++p;
			enlarge(s, p - q);
			memcpy(s->s + s->l, q, p - q);
			s->l += p - q;
			s->s[s->l] = 0;
		}
	}
	va_end(ap);

#undef write_integer

	return 0;
}

/***********************
 * The main() function *
 ***********************/

#ifdef KSTRING_MAIN
#include <stdio.h>
int main()
{
	kstring_t *s;
	int *fields, n, i;
	ks_tokaux_t aux;
	char *p;
	s = (kstring_t*)calloc(1, sizeof(kstring_t));
	{ // test ksprintf_fast()
		long xx = -10;
		ksprintf_fast(s, " pooiu %% %s %ld %c %x", "+++", xx, '*', 100); printf("'%s'\n", s->s); s->l = 0;
	}
	// test ksprintf()
	ksprintf(s, " abcdefg:    %d ", 100);
	printf("'%s'\n", s->s);
	// test ksplit()
	fields = ksplit(s, 0, &n);
	for (i = 0; i < n; ++i)
		printf("field[%d] = '%s'\n", i, s->s + fields[i]);
	// test kstrtok()
	s->l = 0;
	for (p = kstrtok("ab:cde:fg/hij::k", ":/", &aux); p; p = kstrtok(0, 0, &aux)) {
		kputsn(p, aux.p - p, s);
		kputc('\n', s);
	}
	printf("%s", s->s);
	// free
	free(s->s); free(s); free(fields);

	{
		static char *str = "abcdefgcdgcagtcakcdcd";
		static char *pat = "cd";
		char *ret, *s = str;
		int *prep = 0;
		while ((ret = kstrstr(s, pat, &prep)) != 0) {
			printf("match: %s\n", ret);
			s = ret + prep[0];
		}
		free(prep);
	}
	return 0;
}
#endif
