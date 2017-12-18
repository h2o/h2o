ALL:
	cmake .
	make all
	make check
	sudo make check-as-root

fuzz:
	sudo apt-get install -y software-properties-common
	curl -L http://llvm.org/apt/llvm-snapshot.gpg.key | sudo apt-key add -
	sudo apt-add-repository -y 'deb http://llvm.org/apt/xenial llvm-toolchain-xenial-4.0 main'
	sudo apt-get install -y clang-4.0
	sudo ln -s /usr/bin/clang-4.0 /usr/bin/clang
	sudo ln -s /usr/bin/clang++-4.0 /usr/bin/clang++
	ASAN_OPTIONS=detect_leaks=0 CC=clang CXX=clang++ make -f misc/docker-ci/check.mk do-fuzz

do-fuzz:
	cmake -DBUILD_FUZZER=ON .
	make all
	make check
	sudo make check-as-root
	./h2o-fuzzer-http1 -close_fd_mask=3 -runs=1 -max_len=16384 fuzz/http1-corpus < /dev/null
	./h2o-fuzzer-http2 -close_fd_mask=3 -runs=1 -max_len=16384 fuzz/http2-corpus < /dev/null
	./h2o-fuzzer-url -close_fd_mask=3 -runs=1 -max_len=16384 fuzz/url-corpus < /dev/null

.PHONY: fuzz do-fuzz
