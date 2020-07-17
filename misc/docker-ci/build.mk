DOCKER_HUB_NAMESPACE=h2oserver
MAKEFILE_DIR=$(dir $(realpath $(firstword $(MAKEFILE_LIST))))
PROJECT_ROOT_DIR=$(realpath $(MAKEFILE_DIR)/../..)

all: docker-login h2o-ci h2o-ci-dtrace
.PHONY: all

docker-login:
	docker login

h2o-ci: $(MAKEFILE_DIR)/Dockerfile
	docker build --tag $(DOCKER_HUB_NAMESPACE)/$@ -f $< "$(PROJECT_ROOT_DIR)"
	docker push $(DOCKER_HUB_NAMESPACE)/$@
.PHONY: h2o-ci

h2o-ci-dtrace: $(MAKEFILE_DIR)/Dockerfile.dtrace
	docker build --tag $(DOCKER_HUB_NAMESPACE)/$@ -f $< "$(PROJECT_ROOT_DIR)"
	docker push $(DOCKER_HUB_NAMESPACE)/$@
.PHONY: h2o-ci-dtrace
