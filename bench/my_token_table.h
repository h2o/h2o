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

inline uint32_t hash(const char *name, size_t len)
{
#if 0
	uint32_t buf[8] = { 0, 0, 0, 0, 0, 0, 0, 0 };
	char *p = (char *)buf;
	int i;
	for (i = 0; i < len; i++) p[i] = h2o_tolower(name[i]);
	uint32_t v = 0;
	for (i = 0; i < 8; i++) {
		v += buf[i];
	}
#else
	uint64_t mask[8] = { uint64_t(-1), uint64_t(-1), uint64_t(-1), uint64_t(-1) };
	__m128i maskL, maskH;
	maskL = _mm_loadu_si128((const __m128i*)((const char*)mask + 32 - len));
	maskH = _mm_loadu_si128((const __m128i*)((const char*)mask + 48 - len));
	__m128i L = toLowerSSE(name);
	__m128i H = toLowerSSE(name + 16);
	L = _mm_and_si128(L, maskL);
	H = _mm_and_si128(H, maskH);

	__m128i t = _mm_add_epi32(L, H);
	t = _mm_hadd_epi32(t, t);
	t = _mm_hadd_epi32(t, t);
	uint32_t v = _mm_cvtsi128_si32(t);
#endif

	v ^= v >> 23;
	return v % 255;
}

const h2o_token_t *my_h2o_lookup_token(const char *name, size_t len)
{
	if (len > 27) return NULL;
	const int8_t hashTbl[] = {
-1, -1, -1, -1, -1, -1, -1, -1, -1, 45,
-1, -1, 28, -1, -1, -1, -1, -1, -1, -1,
-1, -1, -1, -1, -1, -1, -1, -1, -1, 30,
-1, -1, -1, -1, -1, -1, -1, -1, -1, 21,
-1, 20, -1, -1, -1, -1, 11, 27, -1, 13,
-1, -1, -1, -1, -1, 7, 43, -1, 32, -1,
18, -1, -1, -1, 10, 53, -1, 17, -1, -1,
-1, 50, -1, -1, -1, -1, 44, -1, 12, -1,
42, -1, -1, -1, -1, -1, -1, -1, 9, -1,
-1, -1, -1, -1, 41, 54, 3, -1, -1, -1,
-1, -1, 1, -1, -1, -1, -1, -1, 40, -1,
-1, 8, -1, -1, -1, -1, -1, 48, -1, -1,
-1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
-1, -1, 49, -1, -1, -1, -1, -1, -1, -1,
-1, -1, -1, -1, 2, 33, -1, -1, 15, 35,
-1, -1, -1, -1, -1, -1, -1, -1, -1, 4,
-1, -1, -1, 31, -1, -1, -1, 34, -1, -1,
-1, -1, -1, 51, 39, 14, -1, -1, -1, -1,
-1, -1, -1, -1, -1, -1, -1, 5, -1, -1,
-1, 0, 19, -1, -1, -1, 26, -1, 47, -1,
-1, 23, -1, -1, -1, -1, -1, -1, -1, 52,
-1, 6, -1, -1, -1, 29, -1, 36, -1, -1,
-1, -1, -1, -1, -1, 55, -1, 22, -1, -1,
-1, -1, 25, 24, 16, -1, -1, -1, -1, -1,
-1, -1, -1, -1, 46, -1, -1, -1, -1, -1,
-1, 38, -1, 37, -1,
};
#ifdef __AVX2__
	uint64_t maskTbl[8] = { uint64_t(-1), uint64_t(-1), uint64_t(-1), uint64_t(-1) };

	__m256i mask = _mm256_loadu_si256((const __m256i*)((const char*)maskTbl + 32 - len));
	__m256i x = toLowerAVX(name);
	x = _mm256_and_si256(x, mask);
	__m128i t = _mm_add_epi32(_mm256_castsi256_si128(x), _mm256_extracti128_si256(x, 1));
	t = _mm_hadd_epi32(t, t);
	t = _mm_hadd_epi32(t, t);
	uint32_t h = _mm_cvtsi128_si32(t);

	h ^= h >> 23;
	h %= 255;
	int8_t pos = hashTbl[h];
	if (pos < 0) return NULL;
	const st_h2o_buf_t *p = &h2o__tokens[pos].buf;
	if (len != p->len) return NULL;

	__m256i k = _mm256_loadu_si256((const __m256i*)p->base);
	k = _mm256_and_si256(k, mask);
	if (!_mm256_testc_si256(x, k)) return NULL;

	return h2o__tokens + pos;
#else
	uint32_t h = hash(name, len);
	int8_t pos = hashTbl[h];
	if (pos < 0) return NULL;
	const st_h2o_buf_t *p = &h2o__tokens[pos].buf;
	if (len != p->len) return NULL;
	if (!match_case_small_str(name, p->base, len)) return NULL;
	return h2o__tokens + pos;
#endif
}

