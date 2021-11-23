CONTAINER_NAME=h2oserver/h2o-ci:ubuntu1604
SRC_DIR=/h2o
CHECK_MK=$(SRC_DIR)/misc/docker-ci/check.mk
CMAKE_ARGS=
FUZZ_ASAN=ASAN_OPTIONS=detect_leaks=0
DOCKER_RUN_OPTS=--privileged \
	--ulimit memlock=-1 \
	-v `pwd`:$(SRC_DIR) \
	-v /sys/kernel/debug:/sys/kernel/debug \
	-v /lib/modules:/lib/modules:ro \
	-v /usr/src:/usr/src:ro \
	--add-host=localhost.examp1e.net:127.0.0.1 \
	-it

ALL:
	docker run $(DOCKER_RUN_OPTS) $(CONTAINER_NAME) \
		make -f $(SRC_DIR)/misc/docker-ci/check.mk _check

ossl1.1.0+fuzz:
	docker run $(DOCKER_RUN_OPTS) $(CONTAINER_NAME) \
		env CC=clang CXX=clang++ \
		make -f $(SRC_DIR)/misc/docker-ci/check.mk _check \
		CMAKE_ARGS='-DOPENSSL_ROOT_DIR=/opt/openssl-1.1.0\ -DBUILD_FUZZER=ON'

ossl1.1.1:
	docker run $(DOCKER_RUN_OPTS) $(CONTAINER_NAME) make -f $(SRC_DIR)/misc/docker-ci/check.mk _check \
		CMAKE_ARGS='-DOPENSSL_ROOT_DIR=/opt/openssl-1.1.1'

dtrace:
	docker run $(DOCKER_RUN_OPTS) $(CONTAINER_NAME) env DTRACE_TESTS=1 make -f $(SRC_DIR)/misc/docker-ci/check.mk _check

_check:
	uname -a
	sudo mkdir -p /sys/fs/bpf
	sudo mount -t bpf bpf /sys/fs/bpf -o mode=700
	mkdir -p build
	sudo mount -t tmpfs tmpfs build -o size=3G
	sudo chown -R ci:ci build
	sudo chmod 0755 build
	$(MAKE) -f $(CHECK_MK) -C build _do-check CMAKE_ARGS=$(CMAKE_ARGS)

_do-check:
	cmake $(CMAKE_ARGS) -H$(SRC_DIR) -B.
	time komake -j6 all checkdepends
	if [ -e h2o-fuzzer-http1 ] ; then export $(FUZZ_ASAN); fi; \
		ulimit -n 1024; \
		make check

enter:
	docker run $(DOCKER_RUN_OPTS) -it $(CONTAINER_NAME) bash

pull:
	docker pull $(CONTAINER_NAME)

.PHONY: fuzz _check _do-check _fuzz _do-fuzz-extra enter pull
