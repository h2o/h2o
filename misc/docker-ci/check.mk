CONTAINER_NAME=h2oserver/h2o-ci:ubuntu1604
SRC_DIR=/h2o
CHECK_MK=$(SRC_DIR)/misc/docker-ci/check.mk
CMAKE_ARGS=
BUILD_ARGS=
TEST_ENV=
FUZZ_ASAN=ASAN_OPTIONS=detect_leaks=0
DOCKER_RUN_OPTS=--privileged \
	--ulimit memlock=-1 \
	-v `pwd`:$(SRC_DIR):ro \
	-v /sys/kernel/debug:/sys/kernel/debug \
	-v /lib/modules:/lib/modules:ro \
	-v /usr/src:/usr/src:ro \
	--add-host=localhost.examp1e.net:127.0.0.1 \
	-it
TMP_SIZE=1G

ALL:
	docker run $(DOCKER_RUN_OPTS) $(CONTAINER_NAME) \
		make -f $(SRC_DIR)/misc/docker-ci/check.mk _check \
		BUILD_ARGS='$(BUILD_ARGS)' \
		TEST_ENV='$(TEST_ENV)' \
		TMP_SIZE='$(TMP_SIZE)'

ossl1.1.0+fuzz:
	docker run $(DOCKER_RUN_OPTS) $(CONTAINER_NAME) \
		env CC=clang CXX=clang++ \
		make -f $(SRC_DIR)/misc/docker-ci/check.mk _check \
		CMAKE_ARGS='-DOPENSSL_ROOT_DIR=/opt/openssl-1.1.0 -DBUILD_FUZZER=ON' \
		BUILD_ARGS='$(BUILD_ARGS)' \
		TEST_ENV='$(TEST_ENV)' \
		TMP_SIZE='$(TMP_SIZE)'

ossl1.1.1:
	docker run $(DOCKER_RUN_OPTS) $(CONTAINER_NAME) \
		make -f $(SRC_DIR)/misc/docker-ci/check.mk _check \
		CMAKE_ARGS='-DOPENSSL_ROOT_DIR=/opt/openssl-1.1.1' \
		BUILD_ARGS='$(BUILD_ARGS)' \
		TEST_ENV='$(TEST_ENV)' \
		TMP_SIZE='$(TMP_SIZE)'

ossl3.0:
	docker run $(DOCKER_RUN_OPTS) h2oserver/h2o-ci:ubuntu2204 \
		env DTRACE_TESTS=1 \
		make -f $(SRC_DIR)/misc/docker-ci/check.mk _check \
		CMAKE_ARGS='-DCMAKE_C_FLAGS=-Werror=format' \
		BUILD_ARGS='$(BUILD_ARGS)' \
		TEST_ENV='SKIP_PROG_EXISTS=1 $(TEST_ENV)' \
		TMP_SIZE='$(TMP_SIZE)'

boringssl:
	docker run $(DOCKER_RUN_OPTS) h2oserver/h2o-ci:ubuntu2204 \
		make -f $(SRC_DIR)/misc/docker-ci/check.mk _check \
		CMAKE_ARGS='-DOPENSSL_ROOT_DIR=/opt/boringssl' \
		BUILD_ARGS='$(BUILD_ARGS)' \
		TEST_ENV='SKIP_PROG_EXISTS=1 $(TEST_ENV)' \
		TMP_SIZE='$(TMP_SIZE)'

asan:
	docker run $(DOCKER_RUN_OPTS) h2oserver/h2o-ci:ubuntu2004 \
		make -f $(SRC_DIR)/misc/docker-ci/check.mk _check \
		CMAKE_ARGS='-DCMAKE_C_COMPILER=clang -DCMAKE_CXX_COMPILER=clang++ -DCMAKE_C_FLAGS=-fsanitize=address -DCMAKE_CXX_FLAGS=-fsanitize=address' \
		BUILD_ARGS='$(BUILD_ARGS)' \
		TEST_ENV='ASAN_OPTIONS=detect_leaks=0:alloc_dealloc_mismatch=0 $(TEST_ENV)' \
		TMP_SIZE='$(TMP_SIZE)'

# https://clang.llvm.org/docs/SourceBasedCodeCoverage.html
coverage:
	docker run $(DOCKER_RUN_OPTS) h2oserver/h2o-ci:ubuntu2204  \
		make -f $(SRC_DIR)/misc/docker-ci/check.mk _check _coverage_report \
		CMAKE_ARGS='-DCMAKE_C_COMPILER=clang -DCMAKE_CXX_COMPILER=clang++ -DCMAKE_C_FLAGS="-fprofile-instr-generate -fcoverage-mapping -mllvm -runtime-counter-relocation" -DCMAKE_CXX_FLAGS= -DCMAKE_BUILD_TYPE=Debug -DWITH_H2OLOG=OFF' \
		BUILD_ARGS='$(BUILD_ARGS)' \
		TEST_ENV='SKIP_PROG_EXISTS=1 LLVM_PROFILE_FILE=/home/ci/profraw/%c%p.profraw $(TEST_ENV)' \
		TMP_SIZE='$(TMP_SIZE)'

_coverage_report:
	llvm-profdata merge -sparse -o h2o.profdata /home/ci/profraw/*.profraw
	llvm-cov report -show-region-summary=0 -instr-profile h2o.profdata h2o $(SRC_DIR)/lib $(SRC_DIR)/src $(SRC_DIR)/deps/quicly/lib $(SRC_DIR)/deps/picotls/lib | tee /home/ci/summary.txt
	echo '~~~' > /home/ci/summary.md
	cat /home/ci/summary.txt >> /home/ci/summary.md
	echo '~~~' >> /home/ci/summary.md
	# TODO: send the coverage report to a coverage analyzing service

_check: _mount _do_check

_mount:
	uname -a
	sudo mount -t tmpfs tmpfs -o size=$(TMP_SIZE) /tmp
	sudo mkdir -p /sys/fs/bpf
	sudo mount -t bpf bpf -o mode=700 /sys/fs/bpf

_do_check:
	cmake $(CMAKE_ARGS) -H$(SRC_DIR) -B.
	time komake $(BUILD_ARGS) all checkdepends
	if [ -e h2o-fuzzer-http1 ] ; then export $(FUZZ_ASAN); fi; \
		ulimit -n 1024; \
		env $(TEST_ENV) make check

enter:
	docker run $(DOCKER_RUN_OPTS) -it $(CONTAINER_NAME) bash

pull:
	docker pull $(CONTAINER_NAME)

.PHONY: fuzz _check _do-check _fuzz _do-fuzz-extra enter pull
