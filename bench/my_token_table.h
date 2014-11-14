#ifdef _MSC_VER
	#include <intrin.h>
#else
	#include <x86intrin.h>
#endif
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <assert.h>

#ifndef MIE_ALIGN
	#ifdef _MSC_VER
		#define MIE_ALIGN(x) __declspec(align(x))
	#else
		#define MIE_ALIGN(x) __attribute__((aligned(x)))
	#endif
#endif

#include <memory.h>

inline uint32_t hash(const char *p, size_t n)
{
	uint64_t v = 14695981039346656037ULL;
	for (size_t i = 0; i < n; i++) {
		v ^= uint8_t(h2o_tolower(p[i]));
//		v ^= uint8_t(p[i]);
		v *= 1099511628211ULL;
	}
	v ^= v >> 26;
	return uint32_t(v % 181);
}

inline __m128i toLowerSSE(const char *p)
{
	uint64_t factor = 0x0101010101010101ull;
	uint64_t Am1 = ('A' - 1) * factor;
	uint64_t Zp1 = ('Z' + 1) * factor;
	uint64_t amA = ('a' - 'A') * factor;
	MIE_ALIGN(16) uint64_t Am1Tbl[2] = { Am1, Am1 };
	MIE_ALIGN(16) uint64_t Zp1Tbl[2] = { Zp1, Zp1 };
	MIE_ALIGN(16) uint64_t amATbl[2] = { amA, amA };
	__m128i x, t0, t1;
	x = _mm_loadu_si128((const __m128i*)p);
	t0 = _mm_cmpgt_epi8(x, *(const __m128i*)Am1Tbl);
	t1 = _mm_cmpgt_epi8(*(const __m128i*)Zp1Tbl, x);
	t0 = _mm_and_si128(t0, t1);
	t0 = _mm_and_si128(t0, *(const __m128i*)amATbl);
	x = _mm_add_epi8(x, t0);
	return x;
}
#ifdef __AVX2__
inline __m256i toLowerAVX(const char *p)
{
	uint64_t factor = 0x0101010101010101ull;
	uint64_t Am1 = ('A' - 1) * factor;
	uint64_t Zp1 = ('Z' + 1) * factor;
	uint64_t amA = ('a' - 'A') * factor;
	MIE_ALIGN(16) uint64_t Am1Tbl[4] = { Am1, Am1, Am1, Am1 };
	MIE_ALIGN(16) uint64_t Zp1Tbl[4] = { Zp1, Zp1, Zp1, Zp1 };
	MIE_ALIGN(16) uint64_t amATbl[4] = { amA, amA, amA, amA };
	__m256i x, t0, t1;
	x = _mm256_loadu_si256((const __m256i*)p);
	t0 = _mm256_cmpgt_epi8(x, *(const __m256i*)Am1Tbl);
	t1 = _mm256_cmpgt_epi8(*(const __m256i*)Zp1Tbl, x);
	t0 = _mm256_and_si256(t0, t1);
	t0 = _mm256_and_si256(t0, *(const __m256i*)amATbl);
	x = _mm256_add_epi8(x, t0);
	return x;
}
#endif

void put(__m128i x)
{
	puts("dump");
	char buf[17] = {0};
	_mm_storeu_si128((__m128i*)buf, x);
	int i;
	for (i = 0; i < 16; i++) {
		printf("buf[%d]=%02x (%c)\n", i, (uint8_t)buf[i], buf[i]);
	}
}
/*
	does text begin with [key, keyLen)?
	ignore case of text.
	@note key must not contain [A-Z].
*/
int match_case_small_str(const char *text, const char *key, size_t keyLen)
{
	assert(keyLen <= 32);
#ifdef __AVX2__
	__m256i t = toLowerAVX(text);
	__m256i k = _mm256_loadu_si256((const __m256i*)key);
	t = _mm256_cmpeq_epi8(t, k);
	uint64_t m = _mm256_movemask_epi8(t);
	uint64_t mask = ((uint64_t)1 << keyLen) - 1;
	return (m & mask) == mask;
#else
	if (keyLen <= 16) {
		__m128i t = toLowerSSE(text);
		__m128i k = _mm_loadu_si128((const __m128i*)key);
		t = _mm_cmpeq_epi8(t, k);
		uint32_t m = _mm_movemask_epi8(t);
		uint32_t mask = (1 << keyLen) - 1;
		return (m & mask) == mask;
	}
	__m128i t1 = toLowerSSE(text);
	__m128i t2 = toLowerSSE(text + 16);
	__m128i k1 = _mm_loadu_si128((const __m128i*)key);
	__m128i k2 = _mm_loadu_si128((const __m128i*)(key + 16));
	t1 = _mm_cmpeq_epi8(t1, k1);
	t2 = _mm_cmpeq_epi8(t2, k2);
	uint64_t m1 = _mm_movemask_epi8(t1);
	uint64_t m2 = _mm_movemask_epi8(t2);
	m1 |= m2 << 16;
	uint64_t mask =((uint64_t)1 << keyLen) - 1;
	return (m1 & mask) == mask;
#endif
}

const h2o_token_t *my_h2o_lookup_token(const char *name, size_t len)
{
	int8_t hashTbl[] = {
		-1, -1, 13, -1, 4, -1, -1, -1, 38, 6,
		-1, -1, -1, 36, -1, 24, -1, -1, 47, -1,
		-1, -1, -1, 1, -1, 53, 45, -1, -1, 27,
		-1, -1, -1, -1, -1, 40, 29, -1, -1, -1,
		-1, -1, 37, 21, -1, -1, 26, 11, 30, -1,
		9, -1, 42, -1, -1, -1, -1, -1, -1, -1,
		-1, 49, 23, 14, -1, -1, -1, -1, 46, 52,
		-1, 12, 48, -1, -1, 50, -1, -1, 25, -1,
		-1, -1, 10, -1, 33, -1, 17, -1, 2, -1,
		-1, -1, -1, -1, -1, -1, -1, -1, 31, -1,
		-1, -1, -1, 39, 41, -1, 55, 44, -1, -1,
		-1, -1, 32, -1, -1, -1, -1, -1, 43, -1,
		-1, -1, 28, -1, -1, -1, -1, -1, -1, 8,
		-1, -1, 51, -1, -1, -1, -1, 15, -1, 3,
		34, 18, -1, -1, -1, -1, -1, 5, -1, -1,
		-1, 16, -1, -1, -1, -1, -1, 54, -1, -1,
		-1, 0, 22, -1, -1, -1, -1, -1, -1, -1,
		-1, -1, -1, -1, -1, 20, -1, -1, 19, 35,
		7,
};
	uint32_t h = hash(name, len);
	int8_t pos = hashTbl[h];
	// printf("name=%s, len=%zd h=%d, pos=%d\n", name, len, h, pos);
	if (pos < 0) return NULL;
	const st_h2o_buf_t *p = &h2o__tokens[pos].buf;
	if (len != p->len) return NULL;
	if (!match_case_small_str(name, p->base, len)) return NULL;
	return h2o__tokens + pos;
}

