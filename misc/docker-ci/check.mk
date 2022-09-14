CONTAINER_NAME=h2oserver/h2o-ci:ubuntu1604
SRC_DIR=/h2o
CHECK_MK=$(SRC_DIR)/misc/docker-ci/check.mk
CMAKE_ARGS=
BUILD_ARGS=
TEST_ENV=
FUZZ_ASAN=ASAN_OPTIONS=detect_leaks=0
DOCKER_RUN_OPTS=--privileged \
	--ulimit memlock=-1 \
	-v `pwd`:$(SRC_DIR).ro:ro \
	-v /sys/kernel/debug:/sys/kernel/debug \
	-v /lib/modules:/lib/modules:ro \
	-v /usr/src:/usr/src:ro \
	--add-host=localhost.examp1e.net:127.0.0.1 \
	-it

ALL:
	docker run $(DOCKER_RUN_OPTS) $(CONTAINER_NAME) \
		make -f $(SRC_DIR).ro/misc/docker-ci/check.mk _check \
		BUILD_ARGS='$(BUILD_ARGS)' \
		TEST_ENV='$(TEST_ENV)'

ossl1.1.0+fuzz:
	docker run $(DOCKER_RUN_OPTS) $(CONTAINER_NAME) \
		env CC=clang CXX=clang++ \
		make -f $(SRC_DIR).ro/misc/docker-ci/check.mk _check \
		CMAKE_ARGS='-DOPENSSL_ROOT_DIR=/opt/openssl-1.1.0 -DBUILD_FUZZER=ON' \
		BUILD_ARGS='$(BUILD_ARGS)' \
		TEST_ENV='$(TEST_ENV)'

ossl1.1.1:
	docker run $(DOCKER_RUN_OPTS) $(CONTAINER_NAME) \
		make -f $(SRC_DIR).ro/misc/docker-ci/check.mk _check \
		CMAKE_ARGS='-DOPENSSL_ROOT_DIR=/opt/openssl-1.1.1' \
		BUILD_ARGS='$(BUILD_ARGS)' \
		TEST_ENV='$(TEST_ENV)'

ossl3.0:
	docker run $(DOCKER_RUN_OPTS) h2oserver/h2o-ci:ubuntu2204 \
		env DTRACE_TESTS=1 \
		make -f $(SRC_DIR).ro/misc/docker-ci/check.mk _check \
		BUILD_ARGS='$(BUILD_ARGS)' \
		TEST_ENV='$(TEST_ENV)'

dtrace+asan:
	docker run $(DOCKER_RUN_OPTS) h2oserver/h2o-ci:ubuntu2004 \
		env DTRACE_TESTS=1 \
		make -f $(SRC_DIR).ro/misc/docker-ci/check.mk _check \
		CMAKE_ARGS='-DCMAKE_C_COMPILER=clang -DCMAKE_CXX_COMPILER=clang++ -DCMAKE_C_FLAGS=-fsanitize=address -DCMAKE_CXX_FLAGS=-fsanitize=address' \
		BUILD_ARGS='$(BUILD_ARGS)' \
		TEST_ENV='ASAN_OPTIONS=detect_leaks=0:alloc_dealloc_mismatch=0 $(TEST_ENV)'

# https://clang.llvm.org/docs/SourceBasedCodeCoverage.html
coverage:
	docker run $(DOCKER_RUN_OPTS) h2oserver/h2o-ci:ubuntu2204  \
		make -f $(SRC_DIR).ro/misc/docker-ci/check.mk _check _coverage_report \
		CMAKE_ARGS='-DCMAKE_C_COMPILER=clang -DCMAKE_CXX_COMPILER=clang++ -DCMAKE_C_FLAGS="-fprofile-instr-generate -fcoverage-mapping -mllvm -runtime-counter-relocation" -DCMAKE_CXX_FLAGS= -DCMAKE_BUILD_TYPE=Debug -DWITH_H2OLOG=OFF' \
		BUILD_ARGS='$(BUILD_ARGS)' \
		TEST_ENV='LLVM_PROFILE_FILE=/home/ci/profraw/%c%p.profraw $(TEST_ENV)'

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
	sudo mount -t tmpfs tmpfs -o size=1G /tmp
	sudo mkdir -p /sys/fs/bpf
	sudo mount -t bpf bpf -o mode=700 /sys/fs/bpf
	# create writable source directory using overlay
	sudo mkdir /tmp/src /tmp/src/upper /tmp/src/work $(SRC_DIR)
	sudo mount -t overlay overlay -o lowerdir=$(SRC_DIR).ro,upperdir=/tmp/src/upper,workdir=/tmp/src/work /tmp/src/upper
	sudo mount --bind /tmp/src/upper $(SRC_DIR)
	# allow overwrite of include/h2o/version.h
	sudo chown -R ci:ci $(SRC_DIR)/include/h2o
	# allow taking lock: mruby_config.rb.lock (which might or might not exist)
	sudo touch $(SRC_DIR)/misc/mruby_config.rb.lock $(SRC_DIR)/misc/h2get/misc/mruby_config.rb.lock
	sudo chown ci:ci $(SRC_DIR)/misc/mruby_config.rb.lock $(SRC_DIR)/misc/h2get/misc/mruby_config.rb.lock
	# allow write of mruby executables being generated (FIXME don't generate here)
	for i in deps/mruby/bin misc/h2get/deps/mruby/bin; do \
		sudo rm -rf $(SRC_DIR)/$$i; \
		sudo mkdir $(SRC_DIR)/$$i; \
		sudo chown -R ci:ci $(SRC_DIR)/$$i; \
	done

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
