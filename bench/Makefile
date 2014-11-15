bench: bench.cpp my_token_table.h
	$(CXX) -o bench -O3 -march=native bench.cpp -I ../include -std=c++11


test: ./bench
	./bench ./all_match.txt
	./bench ./data.txt

clean:
	rm -rf bench

MEM_OPT=-e L1-dcache-loads -e L1-dcache-load-misses -e L1-dcache-stores -e L1-dcache-store-misses -e L1-dcache-prefetch-misses -e L1-icache-load-misses -e LLC-loads -e LLC-stores -e LLC-prefetches -e dTLB-loads -e dTLB-load-misses -e dTLB-stores -e dTLB-store-misses -e iTLB-loads -e iTLB-load-misses -e branch-loads -e branch-load-misses
INST= -e cycles -e instructions -e cache-references -e cache-misses -e branches -e branch-misses -e bus-cycles -e ref-cycles

perf-inst:
	perf stat $(INST) ./bench data.txt org
	perf stat $(INST) ./bench data.txt my
perf-mem:
	perf stat $(MEM_OPT) ./bench data.txt org
	perf stat $(MEM_OPT) ./bench data.txt my
