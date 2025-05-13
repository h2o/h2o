IMAGE_NAME=h2oserver/h2o-ci
VARIANT=unknown
DOCKER_OPTS=
PROJECT_DIR=$(shell pwd)

ALL:
	@echo 'Usage: make -f misc/docker-ci/build.mk <command> VARIANT=<variant>'
	@echo ''
	@echo 'Command is either `build` or `push`.'
	@echo 'Variant might be ubuntu1604, ubuntu2004 (corresponds to misc/docker-ci/Dockerfile.$$variant).'
	@echo ''
	@echo 'DOCKER_OPTS can also be set; e.g., DOCKER_OPTS=--network=host'
	@echo ''


build:
	cd misc/docker-ci/docker-root && docker build $(DOCKER_OPTS) --tag "$(IMAGE_NAME):$(VARIANT)" -f "../Dockerfile.$(VARIANT)" .

push: build
	docker push "$(IMAGE_NAME):$(VARIANT)"

.PHONY: build push
