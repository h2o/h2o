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

inline bool is_same_short_str(__m128i x, const char *key, size_t keyLen)
{
    __m128i k = _mm_loadu_si128((const __m128i*)key);
#if 0
    return !_mm_cmpestrc(x, keyLen, k, keyLen, 24);
#else
    x = _mm_cmpeq_epi8(x, k);
    uint32_t m = _mm_movemask_epi8(x);
    uint32_t mask = (1 << keyLen) - 1;
    return (m & mask) == mask;
#endif
}
/*
	does text begin with [key, keyLen)?
	ignore case of text.
	@note key must not contain [A-Z].
*/
int is_same_long_str(const char *text, const char *key, size_t keyLen)
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
#if 1
	__m128i t1 = toLowerSSE(text);
	__m128i k1 = _mm_loadu_si128((const __m128i*)key);
	if (!_mm_testc_si128(t1, k1)) return 0;
	__m128i t2 = toLowerSSE(text + 16);
	__m128i k2 = _mm_loadu_si128((const __m128i*)(key + 16));
	return !_mm_cmpestrc(t2, keyLen - 16, k2, keyLen - 16, 8 + 16);
#else
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
#endif
}

const h2o_token_t *my_h2o_lookup_token(const char *name, size_t len)
{
    const char c0 = h2o_tolower(name[0]);
	if (len <= 16) {
        __m128i v = toLowerSSE(name);
        switch (len) {
        case 3:
            switch (c0) {
            case 'v':
                if (is_same_short_str(v, "via", 3)) return H2O_TOKEN_VIA;
                break;
            case 'a':
                if (is_same_short_str(v, "age", 3)) return H2O_TOKEN_AGE;
                break;
            }
            break;
        case 4:
            switch (c0) {
            case 'd':
                if (is_same_short_str(v, "date", 4)) return H2O_TOKEN_DATE;
                break;
            case 'e':
                if (is_same_short_str(v, "etag", 4)) return H2O_TOKEN_ETAG;
                break;
            case 'l':
                if (is_same_short_str(v, "link", 4)) return H2O_TOKEN_LINK;
                break;
            case 'f':
                if (is_same_short_str(v, "from", 4)) return H2O_TOKEN_FROM;
                break;
            case 'h':
                if (is_same_short_str(v, "host", 4)) return H2O_TOKEN_HOST;
                break;
            case 'v':
                if (is_same_short_str(v, "vary", 4)) return H2O_TOKEN_VARY;
                break;
            }
            break;
        case 5:
            switch (c0) {
            case 'r':
                if (is_same_short_str(v, "range", 5)) return H2O_TOKEN_RANGE;
                break;
            case ':':
                if (is_same_short_str(v, ":path", 5)) return H2O_TOKEN_PATH;
                break;
            case 'a':
                if (is_same_short_str(v, "allow", 5)) return H2O_TOKEN_ALLOW;
                break;
            }
            break;
        case 6:
            switch (c0) {
            case 'c':
                if (is_same_short_str(v, "cookie", 6)) return H2O_TOKEN_COOKIE;
                break;
            case 's':
                if (is_same_short_str(v, "server", 6)) return H2O_TOKEN_SERVER;
                break;
            case 'a':
                if (is_same_short_str(v, "accept", 6)) return H2O_TOKEN_ACCEPT;
                break;
            case 'e':
                if (is_same_short_str(v, "expect", 6)) return H2O_TOKEN_EXPECT;
                break;
            }
            break;
        case 7:
            switch (h2o_tolower(name[3])) {
            case 't':
                if (is_same_short_str(v, ":method", 7)) return H2O_TOKEN_METHOD;
                break;
            case 'h':
                if (is_same_short_str(v, ":scheme", 7)) return H2O_TOKEN_SCHEME;
                break;
            case 'r':
                if (is_same_short_str(v, "upgrade", 7)) return H2O_TOKEN_UPGRADE;
                if (is_same_short_str(v, "refresh", 7)) return H2O_TOKEN_REFRESH;
                break;
            case 'e':
                if (is_same_short_str(v, "referer", 7)) return H2O_TOKEN_REFERER;
                break;
            case 'a':
                if (is_same_short_str(v, ":status", 6)) return H2O_TOKEN_STATUS;
                break;
            case 'i':
                if (is_same_short_str(v, "expires", 6)) return H2O_TOKEN_EXPIRES;
                break;
            }
            break;
        case 8:
            switch (h2o_tolower(name[7])) {
            case 'e':
                if (is_same_short_str(v, "if-range", 8)) return H2O_TOKEN_IF_RANGE;
                break;
            case 'h':
                if (is_same_short_str(v, "if-match", 8)) return H2O_TOKEN_IF_MATCH;
                break;
            case 'n':
                if (is_same_short_str(v, "location", 8)) return H2O_TOKEN_LOCATION;
                break;
            }
            break;
        case 10:
            switch (c0) {
            case 's':
                if (is_same_short_str(v, "set-cookie", 10)) return H2O_TOKEN_SET_COOKIE;
                break;
            case 'c':
                if (is_same_short_str(v, "connection", 10)) return H2O_TOKEN_CONNECTION;
                break;
            case 'u':
                if (is_same_short_str(v, "user-agent", 10)) return H2O_TOKEN_USER_AGENT;
                break;
            case ':':
                if (is_same_short_str(v, ":authority", 10)) return H2O_TOKEN_AUTHORITY;
                break;
            }
            break;
        case 11:
            if (is_same_short_str(v, "retry-after", 11)) return H2O_TOKEN_RETRY_AFTER;
            break;
        case 12:
            switch (c0) {
            case 'c':
                if (is_same_short_str(v, "content-type", 12)) return H2O_TOKEN_CONTENT_TYPE;
                break;
            case 'm':
                if (is_same_short_str(v, "max-forwards", 12)) return H2O_TOKEN_MAX_FORWARDS;
                break;
            }
            break;
        case 13:
            switch (h2o_tolower(name[12])) {
            case 'd':
                if (is_same_short_str(v, "last-modified", 13)) return H2O_TOKEN_LAST_MODIFIED;
                break;
            case 'e':
                if (is_same_short_str(v, "content-range", 13)) return H2O_TOKEN_CONTENT_RANGE;
                break;
            case 'h':
                if (is_same_short_str(v, "if-none-match", 13)) return H2O_TOKEN_IF_NONE_MATCH;
                break;
            case 'l':
                if (is_same_short_str(v, "cache-control", 13)) return H2O_TOKEN_CACHE_CONTROL;
                if (is_same_short_str(v, "x-reproxy-url", 13)) return H2O_TOKEN_X_REPROXY_URL;
                break;
            case 'n':
                if (is_same_short_str(v, "authorization", 13)) return H2O_TOKEN_AUTHORIZATION;
                break;
            case 's':
                if (is_same_short_str(v, "accept-ranges", 13)) return H2O_TOKEN_ACCEPT_RANGES;
                break;
            }
            break;
        case 14:
            switch (c0) {
            case 'c':
                if (is_same_short_str(v, "content-length", 14)) return H2O_TOKEN_CONTENT_LENGTH;
                break;
            case 'h':
                if (is_same_short_str(v, "http2-settings", 14)) return H2O_TOKEN_HTTP2_SETTINGS;
                break;
            case 'a':
                if (is_same_short_str(v, "accept-charset", 13)) return H2O_TOKEN_ACCEPT_CHARSET;
                break;
            }
            break;
        case 15:
            switch (h2o_tolower(name[11])) {
            case 'u':
                if (is_same_short_str(v, "accept-language", 15)) return H2O_TOKEN_ACCEPT_LANGUAGE;
                break;
            case 'd':
                if (is_same_short_str(v, "accept-encoding", 15)) return H2O_TOKEN_ACCEPT_ENCODING;
                break;
            }
            break;
        case 16:
            switch (h2o_tolower(name[11])) {
            case 'g':
                if (is_same_short_str(v, "content-language", 16)) return H2O_TOKEN_CONTENT_LANGUAGE;
                break;
            case 'i':
                if (is_same_short_str(v, "www-authenticate", 16)) return H2O_TOKEN_WWW_AUTHENTICATE;
                break;
            case 'o':
                if (is_same_short_str(v, "content-encoding", 16)) return H2O_TOKEN_CONTENT_ENCODING;
                break;
            case 'a':
                if (is_same_short_str(v, "content-location", 16)) return H2O_TOKEN_CONTENT_LOCATION;
                break;
            }
            break;
        default:
            return NULL;
        }
    }
    switch (len) {
    case 17:
        switch (c0) {
        case 'i':
            if (is_same_long_str(name, "if-modified-since", 17)) return H2O_TOKEN_IF_MODIFIED_SINCE;
            break;
        case 't':
            if (is_same_long_str(name, "transfer-encoding", 17)) return H2O_TOKEN_TRANSFER_ENCODING;
            break;
        }
        break;
    case 18:
        if (is_same_long_str(name, "proxy-authenticate", 18)) return H2O_TOKEN_PROXY_AUTHENTICATE;
        break;
    case 19:
        switch (c0) {
        case 'i':
            if (is_same_long_str(name, "if-unmodified-since", 19)) return H2O_TOKEN_IF_UNMODIFIED_SINCE;
            break;
        case 'c':
            if (is_same_long_str(name, "content-disposition", 19)) return H2O_TOKEN_CONTENT_DISPOSITION;
            break;
        case 'p':
            if (is_same_long_str(name, "proxy-authorization", 19)) return H2O_TOKEN_PROXY_AUTHORIZATION;
            break;
        }
        break;
    case 25:
        if (is_same_long_str(name, "strict-transport-security", 25)) return H2O_TOKEN_STRICT_TRANSPORT_SECURITY;
        break;
    case 27:
        if (is_same_long_str(name, "access-control-allow-origin", 27)) return H2O_TOKEN_ACCESS_CONTROL_ALLOW_ORIGIN;
        break;
    }
    return NULL;
}

