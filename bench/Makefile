bench: bench.cpp my_token_table.h
	$(CXX) -o bench -O3 -march=native bench.cpp -I ../include -std=c++11


test: ./bench
	./bench ./all_match.txt
	./bench ./data.txt

clean:
	rm -rf bench
