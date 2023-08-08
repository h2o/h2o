IMAGE_NAME=h2oserver/h2o-ci
VARIANT=unknown
PROJECT_DIR=$(shell pwd)

ALL:
	@echo 'Usage: make -f misc/docker-ci/build.mk <command> VARIANT=<variant>'
	@echo ''
	@echo 'Command is either `build` or `push`.'
	@echo 'Variant might be ubuntu1604, ubuntu2004, or ubuntu2204 (corresponds to misc/docker-ci/Dockerfile.$$variant).'
	@echo ''

build:
	cd misc/docker-ci/docker-root && docker build --progress=plain --tag "$(IMAGE_NAME):$(VARIANT)" -f "../Dockerfile.$(VARIANT)" .

push: build
	docker push "$(IMAGE_NAME):$(VARIANT)"

# to test dockerfiles locally, it builds and tests a particular Dockerfile variant.
test:
	$(MAKE) -f $(firstword $(MAKEFILE_LIST)) build IMAGE_NAME=$(IMAGE_NAME) VARIANT=$(VARIANT)
	$(MAKE) -f $(dir $(firstword $(MAKEFILE_LIST)))/check.mk CINTAINER_NAME=$(IMAGE_NAME):$(VARIANT)

test-all:
	$(MAKE) -f $(firstword $(MAKEFILE_LIST)) test VARIANT=ubuntu1604
	$(MAKE) -f $(firstword $(MAKEFILE_LIST)) test VARIANT=ubuntu2004
	$(MAKE) -f $(firstword $(MAKEFILE_LIST)) test VARIANT=ubuntu2204

.PHONY: ALL build push
