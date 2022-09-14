CONTAINER_NAME=h2oserver/h2o-ci:ubuntu2004
SRC_DIR=/picotls
CI_MK=$(SRC_DIR)/misc/docker-ci.mk
CMAKE_ARGS=
CHECK_ENVS=
DOCKER_RUN_OPTS=--privileged \
	-v `pwd`:$(SRC_DIR) \
	-it

ALL:
	docker run $(DOCKER_RUN_OPTS) $(CONTAINER_NAME) make -f $(CI_MK) _check CMAKE_ARGS='$(CMAKE_ARGS)' CHECK_ENVS='$(CHECK_ENVS)'

_check:
	uname -a
	mkdir -p build
	sudo mount -t tmpfs tmpfs build -o size=3G
	sudo chown -R ci:ci build
	sudo chmod 0755 build
	$(MAKE) -f $(CI_MK) -C build _do-check CMAKE_ARGS='$(CMAKE_ARGS)' CHECK_ENVS='$(CHECK_ENVS)'

_do-check:
	cmake $(CMAKE_ARGS) "-H$(SRC_DIR)" -B.
	$(MAKE) all VERBOSE=1
	env $(CHECK_ENVS) $(MAKE) check
