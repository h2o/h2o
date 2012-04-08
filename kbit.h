#ifndef KBIT_H
#define KBIT_H

#include <stdint.h>

static inline uint64_t kbi_popcount64(uint64_t y) // standard popcount; from wikipedia
{
	y -= ((y >> 1) & 0x5555555555555555ull);
	y = (y & 0x3333333333333333ull) + (y >> 2 & 0x3333333333333333ull);
	return ((y + (y >> 4)) & 0xf0f0f0f0f0f0f0full) * 0x101010101010101ull >> 56;
}

static inline uint64_t kbi_DNAcount64(uint64_t y, int c) // count #A/C/G/T from a 2-bit encoded integer; from BWA
{
	// reduce nucleotide counting to bits counting
	y = ((c&2)? y : ~y) >> 1 & ((c&1)? y : ~y) & 0x5555555555555555ull;
	// count the number of 1s in y
	y = (y & 0x3333333333333333ull) + (y >> 2 & 0x3333333333333333ull);
	return ((y + (y >> 4)) & 0xf0f0f0f0f0f0f0full) * 0x101010101010101ull >> 56;
}

#ifndef kroundup32 // round a 32-bit integer to the next closet integer; from "bit twiddling hacks"
#define kroundup32(x) (--(x), (x)|=(x)>>1, (x)|=(x)>>2, (x)|=(x)>>4, (x)|=(x)>>8, (x)|=(x)>>16, ++(x))
#endif

#ifndef kbi_swap
#define kbi_swap(a, b) (((a) ^= (b)), ((b) ^= (a)), ((a) ^= (b))) // from "bit twiddling hacks"
#endif

#endif
