CONTAINER_NAME=kazuho/h2o-ci:latest
SRC_DIR=/h2o
CHECK_MK=$(SRC_DIR)/misc/docker-ci/check.mk
CMAKE_ARGS=
FUZZ_ASAN=ASAN_OPTIONS=detect_leaks=0
DOCKER_RUN_OPTS=-v `pwd`:$(SRC_DIR) -e TRAVIS --add-host=127.0.0.1.xip.io:127.0.0.1 -it

ALL:
	docker run $(DOCKER_RUN_OPTS) $(CONTAINER_NAME) make -f /h2o/misc/docker-ci/check.mk _check

fuzz:
	docker run $(DOCKER_RUN_OPTS) $(CONTAINER_NAME) make -f /h2o/misc/docker-ci/check.mk _fuzz

ossl1.1.0:
	docker run $(DOCKER_RUN_OPTS) $(CONTAINER_NAME) make -f /h2o/misc/docker-ci/check.mk _ossl1.1.0

_check:
	mkdir -p build
	$(MAKE) -f $(CHECK_MK) -C build _do-check CMAKE_ARGS=$(CMAKE_ARGS)

_do-check:
	cmake $(CMAKE_ARGS) -H$(SRC_DIR) -B.
	make all
	make check
	sudo -E make check-as-root

_ossl1.1.0:
	$(MAKE) -f $(CHECK_MK) _check CMAKE_ARGS=-DOPENSSL_ROOT_DIR=/opt/openssl-1.1.0

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
