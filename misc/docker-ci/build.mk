IMAGE_NAME=h2oserver/h2o-ci
VARIANT=unknown
PROJECT_DIR=$(shell pwd)

ALL:
	@echo 'Usage: make -f misc/docker-ci/build.mk <command> VARIANT=<variant>'
	@echo ''
	@echo 'Command is either `build` or `push`.'
	@echo 'Variant might be ubuntu1604, ubuntu2004 (corresponds to misc/docker-ci/Dockerfile.$$variant).'
	@echo ''


build:
	cd misc/docker-ci/docker-root && docker build --tag "$(IMAGE_NAME):$(VARIANT)" -f "../Dockerfile.$(VARIANT)" .

push: build
	docker push "$(IMAGE_NAME):$(VARIANT)"

.PHONY: build push
