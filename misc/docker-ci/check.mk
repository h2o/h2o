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
	docker run $(DOCKER_RUN_OPTS) h2oserver/h2o-ci:ubuntu2004 \
		make -f $(SRC_DIR).ro/misc/docker-ci/check.mk _install_cmake3.22 _build_ossl3.0 _check \
		BUILD_ARGS='$(BUILD_ARGS)' \
		TEST_ENV='$(TEST_ENV)'

dtrace+asan:
	docker run $(DOCKER_RUN_OPTS) h2oserver/h2o-ci:ubuntu2004 \
		env DTRACE_TESTS=1 \
		make -f $(SRC_DIR).ro/misc/docker-ci/check.mk _check \
		CMAKE_ARGS='-DCMAKE_C_COMPILER=clang -DCMAKE_CXX_COMPILER=clang++ -DCMAKE_C_FLAGS=-fsanitize=address -DCMAKE_CXX_FLAGS=-fsanitize=address' \
		BUILD_ARGS='$(BUILD_ARGS)' \
		TEST_ENV='ASAN_OPTIONS=detect_leaks=0:alloc_dealloc_mismatch=0 $(TEST_ENV)'

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
	# allow write of mruby executables being generated (FIXME don't generate here)
	for i in deps/mruby/bin misc/h2get/deps/mruby-1.2.0/bin; do \
		sudo rm -rf $(SRC_DIR)/$$i; \
		sudo mkdir $(SRC_DIR)/$$i; \
		sudo chown ci:ci $(SRC_DIR)/$$i; \
	done

_do_check:
	cmake $(CMAKE_ARGS) -H$(SRC_DIR) -B.
	time komake $(BUILD_ARGS) all checkdepends
	if [ -e h2o-fuzzer-http1 ] ; then export $(FUZZ_ASAN); fi; \
		ulimit -n 1024; \
		env $(TEST_ENV) make check

_install_cmake3.22:
	sudo apt purge -y cmake
	sudo mkdir /usr/local/cmake-3.22
	wget -O - https://github.com/Kitware/CMake/releases/download/v3.22.1/cmake-3.22.1-linux-x86_64.tar.gz | sudo tar xzf - --strip-components 1 -C /usr/local/cmake-3.22
	sudo ln -s /usr/local/cmake-3.22/bin/cmake /usr/local/bin/cmake

_build_ossl3.0:
	curl -O https://www.openssl.org/source/openssl-3.0.0.tar.gz
	tar xf openssl-3.0.0.tar.gz
	cd openssl-3.0.0 && ./config --prefix=/opt/openssl-3.0 --openssldir=/opt/openssl-3.0 shared && make -j4 && sudo make install_sw install_ssldirs

enter:
	docker run $(DOCKER_RUN_OPTS) -it $(CONTAINER_NAME) bash

pull:
	docker pull $(CONTAINER_NAME)

.PHONY: fuzz _check _do-check _fuzz _install_cmake3.22 _build_ossl3.0 enter pull
