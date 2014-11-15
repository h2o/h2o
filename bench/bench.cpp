#include <string.h>
#include <string>
#include <stdio.h>
#include <fstream>
#include <unordered_set>
#include <vector>

typedef struct st_h2o_buf_t {
    const char *base;
    size_t len;
} h2o_buf_t;

typedef struct st_h2o_token_t {
    h2o_buf_t buf;
    int http2_static_table_name_index; /* non-zero if any */
    int is_connection_specific;
} h2o_token_t;
#define H2O_STRLIT(s) (s), sizeof(s) - 1
#include "h2o/token.h"

inline int h2o_tolower(int ch)
{
    return 'A' <= ch && ch <= 'Z' ? ch + 0x20 : ch;
}

int h2o__lcstris_core(const char *target, const char *test, size_t test_len)
{
    for (; test_len != 0; --test_len)
        if (h2o_tolower(*target++) != *test++)
            return 0;
    return 1;
}

#include "../lib/token_table.h"
#include "my_token_table.h"

typedef std::unordered_set<std::string> StrSet;
typedef std::vector<std::string> StrVec;

StrVec getWord(const std::string& fileName)
{
	StrSet ret;
	std::ifstream ifs(fileName.c_str(), std::ios::binary);
	std::string word;
	while (ifs >> word) {
		ret.insert(word);
	}
	StrVec sv;
	for (const std::string& w : ret) {
		sv.push_back(w);
	}
	return sv;
}

class Clock {
public:
	static inline uint64_t getRdtsc()
	{
#ifdef _MSC_VER
		return __rdtsc();
#else
		unsigned int eax, edx;
		__asm__ volatile("rdtsc" : "=a"(eax), "=d"(edx));
		return ((uint64_t)edx << 32) | eax;
#endif
	}
	Clock()
		: clock_(0)
		, count_(0)
	{
	}
	void begin()
	{
		clock_ -= getRdtsc();
	}
	void end()
	{
		clock_ += getRdtsc();
		count_++;
	}
	int getCount() const { return count_; }
	uint64_t getClock() const { return clock_; }
	void clear() { count_ = 0; clock_ = 0; }
private:
	uint64_t clock_;
	int count_;
};

void bench(const char *msg, const StrVec& sv, const h2o_token_t* f(const char*, size_t))
{
	const int N = 100000000;
	Clock clk;
	uint64_t sum = 0;
	for (int i = 0; i < N; i++) {
		const std::string& s = sv[i % sv.size()];
		clk.begin();
		const h2o_token_t *p = f(s.c_str(), s.size());
		clk.end();
		sum += p - h2o__tokens;
	}
	printf("%s clk=%7.2f sum=%016zx\n", msg, clk.getClock() / double(N), sum);
}
void test(const StrVec& sv)
{
	for (const std::string& s : sv) {
		const h2o_token_t *p = h2o_lookup_token(s.c_str(), s.size());
		const h2o_token_t *q = my_h2o_lookup_token(s.c_str(), s.size());
		if (p != q) {
			printf("ERR s=%s, org=%p, my=%p\n", s.c_str(), p, q);
			if (p) printf("org=%s\n", p->buf.base);
			if (q) printf("my =%s\n", q->buf.base);
			exit(1);
		}
	}
	puts("test ok");
}

int main(int argc, char *argv[])
{
	if (argc == 1) {
		printf("bench fileName (my|org)\n");
		return 1;
	}
	const std::string fileName = argv[1];
	const std::string mode = argc == 3 ? argv[2] : "";
	StrVec sv = getWord(fileName);
	if (sv.empty()) {
		printf("can't open %s, so use the fileName as word\n", fileName.c_str());
		sv.push_back(fileName);
	}
	test(sv);
	if (mode != "org") bench("my ", sv, my_h2o_lookup_token);
	if (mode != "my") bench("org", sv, h2o_lookup_token);
}

