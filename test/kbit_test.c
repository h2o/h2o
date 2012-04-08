#include <stdlib.h>
#include <stdio.h>
#include <time.h>
#include <emmintrin.h>
#include "kbit.h"

// from bowtie-0.9.8.1
inline static int bt1_pop64(uint64_t x) // the kbi_popcount64() equivalence; similar to popcount_2() in wiki
{
   x -= ((x >> 1) & 0x5555555555555555llu);
   x = (x & 0x3333333333333333llu) + ((x >> 2) & 0x3333333333333333llu);
   x = (x + (x >> 4)) & 0x0F0F0F0F0F0F0F0Fllu;
   x = x + (x >> 8);
   x = x + (x >> 16);
   x = x + (x >> 32);
   return x & 0x3F;
}

inline static int bt1_countInU64(uint64_t dw, int c) // the kbi_DNAcount64() equivalence
{
	uint64_t dwA  = dw &  0xAAAAAAAAAAAAAAAAllu;
	uint64_t dwNA = dw & ~0xAAAAAAAAAAAAAAAAllu;
	uint64_t tmp;
	switch (c) {
	case 0: tmp = (dwA >> 1) | dwNA; break;
	case 1: tmp = ~(dwA >> 1) & dwNA; break;
	case 2: tmp = (dwA >> 1) & ~dwNA; break;
	default: tmp = (dwA >> 1) & dwNA;
	}
	tmp = bt1_pop64(tmp);
	if (c == 0) tmp = 32 - tmp;
	return (int)tmp;
}

// from bigmagic
static uint32_t sse2_bit_count(const __m128i* block, const __m128i* block_end)
{
    const unsigned mu1 = 0x55555555;
    const unsigned mu2 = 0x33333333;
    const unsigned mu3 = 0x0F0F0F0F;
    const unsigned mu4 = 0x0000003F;

	uint32_t tcnt[4];

    // Loading masks
    __m128i m1 = _mm_set_epi32 (mu1, mu1, mu1, mu1);
    __m128i m2 = _mm_set_epi32 (mu2, mu2, mu2, mu2);
    __m128i m3 = _mm_set_epi32 (mu3, mu3, mu3, mu3);
    __m128i m4 = _mm_set_epi32 (mu4, mu4, mu4, mu4);
    __m128i mcnt;
    mcnt = _mm_xor_si128(m1, m1); // cnt = 0

    __m128i tmp1, tmp2;
    do
    {        
        __m128i b = _mm_load_si128(block);
        ++block;

        // b = (b & 0x55555555) + (b >> 1 & 0x55555555);
        tmp1 = _mm_srli_epi32(b, 1);                    // tmp1 = (b >> 1 & 0x55555555)
        tmp1 = _mm_and_si128(tmp1, m1); 
        tmp2 = _mm_and_si128(b, m1);                    // tmp2 = (b & 0x55555555)
        b    = _mm_add_epi32(tmp1, tmp2);               //  b = tmp1 + tmp2

        // b = (b & 0x33333333) + (b >> 2 & 0x33333333);
        tmp1 = _mm_srli_epi32(b, 2);                    // (b >> 2 & 0x33333333)
        tmp1 = _mm_and_si128(tmp1, m2); 
        tmp2 = _mm_and_si128(b, m2);                    // (b & 0x33333333)
        b    = _mm_add_epi32(tmp1, tmp2);               // b = tmp1 + tmp2

        // b = (b + (b >> 4)) & 0x0F0F0F0F;
        tmp1 = _mm_srli_epi32(b, 4);                    // tmp1 = b >> 4
        b = _mm_add_epi32(b, tmp1);                     // b = b + (b >> 4)
        b = _mm_and_si128(b, m3);                       //           & 0x0F0F0F0F

        // b = b + (b >> 8);
        tmp1 = _mm_srli_epi32 (b, 8);                   // tmp1 = b >> 8
        b = _mm_add_epi32(b, tmp1);                     // b = b + (b >> 8)

        // b = (b + (b >> 16)) & 0x0000003F;
        tmp1 = _mm_srli_epi32 (b, 16);                  // b >> 16
        b = _mm_add_epi32(b, tmp1);                     // b + (b >> 16)
        b = _mm_and_si128(b, m4);                       // (b >> 16) & 0x0000003F;

        mcnt = _mm_add_epi32(mcnt, b);                  // mcnt += b

    } while (block < block_end);

    _mm_store_si128((__m128i*)tcnt, mcnt);

    return tcnt[0] + tcnt[1] + tcnt[2] + tcnt[3];
}

int main(void)
{
	int i, j, N = 1000000, M = 200;
	uint64_t *x, cnt;
	clock_t t;
	int c = 1;

	x = (uint64_t*)calloc(N, 8);
	srand48(11);
	for (i = 0; i < N; ++i)
		x[i] = (uint64_t)lrand48() << 32 | lrand48();

	fprintf(stderr, "\n===> Calculate # of 1 in an integer (popcount) <===\n");

	t = clock();
	for (j = 0, cnt = 0; j < M; ++j)
		for (i = 0; i < N; ++i)
			cnt += kbi_popcount64(x[i]);
	fprintf(stderr, "%20s\t%20ld\t%10.3f\n", "kbit", (long)cnt, (double)(clock() - t) / CLOCKS_PER_SEC);

	t = clock();
	for (j = 0, cnt = 0; j < M; ++j)
		for (i = 0; i < N; ++i)
			cnt += bt1_pop64(x[i]);
	fprintf(stderr, "%20s\t%20ld\t%10.3f\n", "wiki-popcount_2", (long)cnt, (double)(clock() - t) / CLOCKS_PER_SEC);

	t = clock();
	for (j = 0, cnt = 0; j < M; ++j)
		for (i = 0; i < N; ++i)
			cnt += __builtin_popcountl(x[i]);
	fprintf(stderr, "%20s\t%20ld\t%10.3f\n", "__builtin_popcountl", (long)cnt, (double)(clock() - t) / CLOCKS_PER_SEC);

	t = clock();
	for (j = 0, cnt = 0; j < M; ++j)
		cnt += sse2_bit_count((__m128i*)x, (__m128i*)(x+N));
	fprintf(stderr, "%20s\t%20ld\t%10.3f\n", "SSE2-32bit", (long)cnt, (double)(clock() - t) / CLOCKS_PER_SEC);

	fprintf(stderr, "\n===> Count '%c' in 2-bit encoded integers <===\n", "ACGT"[c]);

	t = clock();
	for (j = 0, cnt = 0; j < M; ++j)
		for (i = 0; i < N; ++i)
			cnt += kbi_DNAcount64(x[i], c);
	fprintf(stderr, "%20s\t%20ld\t%10.3f\n", "kbit", (long)cnt, (double)(clock() - t) / CLOCKS_PER_SEC);

	t = clock();
	for (j = 0, cnt = 0; j < M; ++j)
		for (i = 0; i < N; ++i)
			cnt += bt1_countInU64(x[i], c);
	fprintf(stderr, "%20s\t%20ld\t%10.3f\n", "bowtie1", (long)cnt, (double)(clock() - t) / CLOCKS_PER_SEC);

	fprintf(stderr, "\n");
	free(x);
	return 0;
}
