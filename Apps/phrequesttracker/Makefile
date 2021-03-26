# Makefile for Phantom apps CI
#  created oct-2018 by michellel & jacobd at splunk
#
# Usage:
#   make local     - to bring up docker for local dev
#   make <target>  - pipeline targets build / upload
#   make secrets   - list any required secret values
#
# Credentials can be passed as environment variables or docker secret files
# under /run/secrets


# Variables set by GitLab
WORKSPACE                 ?= $(shell grep WORKSPACE: docker-compose.yml | cut -d : -f 2)
CI_COMMIT_REF_NAME        ?= $(shell git branch | grep "\*" | cut -d ' ' -f 2)

# Git variables
GIT_SERVER                ?= cd.splunkdev.com
RELEASE_GROUP             ?= phantom
RELEASE_REPO              ?= app_release
RELEASE_DIR               := $(WORKSPACE)/$(RELEASE_REPO)

# Docker variables
export IMAGE_TAG          ?= $(shell grep ^image: .gitlab-ci.yml | cut -d : -f 3)

# Variables sent to app_release for test/build/release scripts
export APP_DIR            ?= $(shell pwd)
export APP_REPO_NAME      ?= $(shell basename $(APP_DIR))
export APP_BRANCH         ?= $(CI_COMMIT_REF_NAME)
export TEST_BRANCH        ?= master

# Pipeline secrets
SECRETS = app_artf_token gitlab_api_token app_deploy_key
ifneq ($(wildcard /run/secrets/.),)
 # Load secrets if specified in filesystem rather than variables
 export GITLAB_API_TOKEN  ?= $(shell cat /run/secrets/gitlab_api_token)
 export APP_ARTF_TOKEN    ?= $(shell cat /run/secrets/app_artf_token)
 export APP_DEPLOY_KEY    ?= $(shell cat /run/secrets/app_deploy_key)
endif

APP_RELEASE_TARGETS = test upload build release
.PHONY: checkout local secrets list_secrets $(APP_RELEASE_TARGETS)

checkout: $(RELEASE_DIR)
$(RELEASE_DIR): /tmp/ssh-agent
	$(info Clone the $(RELEASE_REPO) repo into $(RELEASE_DIR))
	@git clone git@$(GIT_SERVER):$(RELEASE_GROUP)/$(RELEASE_REPO).git $(RELEASE_DIR)
	$(info Checkout the test branch: $(TEST_BRANCH))
	@cd $(RELEASE_DIR) && git checkout $(TEST_BRANCH)

$(APP_RELEASE_TARGETS): checkout
	@cd $(RELEASE_DIR) && make $@

local: secrets
	$(info Setting up local development instance)
	$(info Make sure you have run:)
	$(info   docker login repo.splunk.com)
	docker-compose up -d
	$(info Working directory is mapped to $(DOCKER_WORK). To connect:)
	$(info   docker exec -it -w $(DOCKER_WORK) local_qa-local_1 bash)

/tmp/ssh-agent:
	$(info Starting ssh agent)
	@mkdir -p -m 700 ~/.ssh
	@ssh-keyscan -p 22 $(GIT_SERVER) >> ~/.ssh/known_hosts
	@eval $(shell ssh-agent -s >$@)
	@if [ -s /run/secrets/app_deploy_key ]; then \
	  cp /run/secrets/app_deploy_key ~/.ssh/id_rsa && \
		source $@ && ssh-add ~/.ssh/id_rsa; \
	else \
	  cp ~/.ssh/app_deploy_key ~/.ssh/id_rsa && \
	  chmod 600 ~/.ssh/id_rsa && \
		cat $@ && \
		source $@ && ssh-add ~/.ssh/id_rsa; \
	fi

SECRET_FILES = $(foreach I,$(SECRETS),~/.docker/secrets/$I)
secrets: list_secrets $(SECRET_FILES)
list_secrets:
	$(info From .docker/secrets these files are loaded:)
	$(info   $(SECRETS))
