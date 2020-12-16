CONTAINER_NAME=h2oserver/h2o-ci:ubuntu1604
SRC_DIR=/h2o
CHECK_MK=$(SRC_DIR)/misc/docker-ci/check.mk
CMAKE_ARGS=
FUZZ_ASAN=ASAN_OPTIONS=detect_leaks=0
DOCKER_RUN_OPTS=--privileged -v `pwd`:$(SRC_DIR) -v /sys/kernel/debug:/sys/kernel/debug --add-host=127.0.0.1.xip.io:127.0.0.1

ALL:
	docker run $(DOCKER_RUN_OPTS) $(CONTAINER_NAME) make -f $(SRC_DIR)/misc/docker-ci/check.mk _check

fuzz:
	docker run $(DOCKER_RUN_OPTS) $(CONTAINER_NAME) make -f $(SRC_DIR)/misc/docker-ci/check.mk _fuzz

ossl1.1.0:
	docker run $(DOCKER_RUN_OPTS) $(CONTAINER_NAME) make -f $(SRC_DIR)/misc/docker-ci/check.mk _check \
		CMAKE_ARGS='-DOPENSSL_ROOT_DIR=/opt/openssl-1.1.0'

ossl1.1.1:
	docker run $(DOCKER_RUN_OPTS) $(CONTAINER_NAME) make -f $(SRC_DIR)/misc/docker-ci/check.mk _check \
		CMAKE_ARGS='-DOPENSSL_ROOT_DIR=/opt/openssl-1.1.1'

dtrace:
	docker run $(DOCKER_RUN_OPTS) $(CONTAINER_NAME) env DTRACE_TESTS=1 make -f $(SRC_DIR)/misc/docker-ci/check.mk _check

_check:
	mkdir -p build
	sudo mount -t tmpfs tmpfs build -o size=3G
	sudo chown -R ci:ci build
	sudo chmod 0755 build
	$(MAKE) -f $(CHECK_MK) -C build _do-check CMAKE_ARGS=$(CMAKE_ARGS)

_do-check:
	cmake $(CMAKE_ARGS) -H$(SRC_DIR) -B.
	make all
	make check

_fuzz:
	$(FUZZ_ASAN) CC=clang CXX=clang++ $(MAKE) -f $(CHECK_MK) _check CMAKE_ARGS=-DBUILD_FUZZER=ON
	$(FUZZ_ASAN) $(MAKE) -f $(CHECK_MK) -C build _do-fuzz-extra

_do-fuzz-extra:
	./h2o-fuzzer-http1 -close_fd_mask=3 -runs=1 -max_len=16384 $(SRC_DIR)/fuzz/http1-corpus < /dev/null
	./h2o-fuzzer-http2 -close_fd_mask=3 -runs=1 -max_len=16384 $(SRC_DIR)/fuzz/http2-corpus < /dev/null
	./h2o-fuzzer-url -close_fd_mask=3 -runs=1 -max_len=16384 $(SRC_DIR)/fuzz/url-corpus < /dev/null

enter:
	docker run $(DOCKER_RUN_OPTS) -it $(CONTAINER_NAME) bash

pull:
	docker pull $(CONTAINER_NAME)

.PHONY: fuzz _check _do-check _fuzz _do-fuzz-extra enter pull
