# Copyright (C) 2022 Fortanix, Inc. All Rights Reserved.
#
# Top-level Makefile logic for creating a tests Docker container along
# with a build. This stand-alone container has the deliverables and
# tests for a particular build. It can be used to run the tests independently
# from building the software.
#
# When you build a docker image using a Dockerfile, you need to have
# actual files or directories for the contents that you want to include
# in the new Docker image. Docker does not allow using symlinks to directories
# in the build context to include files from another location. To work with
# this system, we create a staging directory in our build directory with
# all of the build context. This contains copies of everything from the
# source and build trees that we want included in the tests docker container.
#

#
# tests-container: Top level (convenience) target for building the
# tests container.
tests-container: $(TESTS-CONTAINER)


# The run-tests-container target can be used to run the tests
# container. By default, this will do a full rebuild of the tests
# container (because we wipe the stage directory after builds
# to ensure the container is properly rebuilt), even if nothing
# has changed in your build tree. TESTS_CONTAINER_NO_REBUILD can
# be set to run with an already-built tests container.
# TESTS_CONTAINER_EXTRA_ARGS can also be set to pass additional
# arguments to the tests container when it's run. See
# make help-variables for more information about these settings.
#
# We assume that the user account running this command has configured
# AWS access with ~/.aws/config and ~/.aws/credentials. These are
# provided to the tests container via environment variables. To
# avoid the values being visible on the command-line, we use
# a docker environement variable file which we delete after running
# the container.
run-tests-container:  $(if $(TESTS_CONTAINER_NO_REBUILD),,$(TESTS-CONTAINER))
	[ $$(docker images -q $$(cat $(TESTS-CONTAINER-TAGFILE)) | wc -l) -gt 0 ] ||  docker load < $(BUILD_DIR)/$(TESTS-CONTAINER-BASE).tar.gz
	echo "AWS_CONFIG=$$($(BASE64) < ~/.aws/config)" > $(DOCKER-ENV-FILE)
	echo "AWS_CREDENTIALS=$$($(BASE64) < ~/.aws/credentials)" >> $(DOCKER-ENV-FILE)
	echo "ECR_PASSWORD=$$(aws ecr get-login-password)" >> $(DOCKER-ENV-FILE)
	$(RM) -rf /tmp/tests-container-tmp
	$(MKDIR) -p /tmp/tests-container-tmp
	docker run --security-opt "seccomp=unconfined" \
		--env-file $(DOCKER-ENV-FILE) \
		--network host \
		-v /var/run/docker.sock:/var/run/docker.sock \
		-v /tmp/tests-container-tmp:/tmp \
		$$($(CAT) $(TESTS-CONTAINER-TAGFILE)) $(TESTS_CONTAINER_EXTRA_ARGS) \
                || $$(rm -f $(DOCKER-ENV-FILE) && exit 1)
	$(RM) -f $(DOCKER-ENV-FILE)


$(SUBDIR)/PYTHON-LIB-FILES := $(call files-in-dir,$(REPO_ROOT)/tools/app-test-infra/python)

$(SUBDIR)/STAGED-PYTHON-LIB-FILES := $(subst $(REPO_ROOT),$(TESTS-STAGE-DIR)/tests,$($(SUBDIR)/PYTHON-LIB-FILES))

$(SUBDIR)/BIN-FILES := $(call files-in-dir,$(REPO_ROOT)/tools/app-test-infra/bin)
$(SUBDIR)/STAGED-BIN-FILES := $(subst $(REPO_ROOT),$(TESTS-STAGE-DIR)/tests,$($(SUBDIR)/BIN-FILES))

#
# This target defines everything that needs to be included in the tests
# container. There need to be Makefile rules for how to create everything
# included here.
#
# amzn-linux-nbd contains the updated nitro enclave kernel image
TESTS-STAGE-CONTENTS := \
	$(TESTS-STAGE-DIR)/Dockerfile-salmiac-ub20 \
	$(TESTS-STAGE-DIR)/requirements.txt \
	$(TESTS-STAGE-DIR)/requirements_frozen.txt \
	$(TESTS-STAGE-DIR)/generated_string_table.py \
	$(TESTS-STAGE-DIR)/docker-config.json \
	$(TESTS-STAGE-DIR)/container-converter \
	$(TESTS-STAGE-DIR)/$(ENCLAVE-KERNEL-TAR) \
	$(TESTS-STAGE-DIR)/amzn-linux-nbd \
	$($(SUBDIR)/STAGED-BIN-FILES) \
	$(TESTS-CONTAINER-APP-TESTS-FILE) \
	$($(SUBDIR)/STAGED-PYTHON-LIB-FILES) \
	$(TESTS-STAGE-DIR)/$(DOCKER-AWS-HELPER) \
	$(TESTS-CONTAINER-REGRESSION-TESTS)

#
# Rules for generating stage directory contents, mostly by copying files
# from the source or build directories.
#
$(eval $(call make-cp-rule,$(REPO_ROOT)/test/tests-container-salmiac/Dockerfile-salmiac-ub20,$(TESTS-STAGE-DIR)/Dockerfile-salmiac-ub20))
$(eval $(call make-cp-rule,$(REPO_ROOT)/test/tests-container-salmiac/requirements.txt,$(TESTS-STAGE-DIR)/requirements.txt))
$(eval $(call make-cp-rule,$(REPO_ROOT)/test/tests-container-salmiac/requirements_frozen.txt,$(TESTS-STAGE-DIR)/requirements_frozen.txt))
$(eval $(call make-cp-rule,$(REPO_ROOT)/strings/generated_string_table.py,$(TESTS-STAGE-DIR)/generated_string_table.py))
$(eval $(call make-cp-rule,$(REPO_ROOT)/tools/app-test-inrfa/bin/tests-container-entry.sh,$(TESTS-STAGE-DIR)/tests-container-entry.sh))
$(eval $(call make-cp-rule,$(REPO_ROOT)/tools/app-test-infra/bin/tests-container-run.py,$(TESTS-STAGE-DIR)/tests-container-run.py))
$(eval $(call make-cp-rule,$(REPO_ROOT)/test/tests-container-salmiac/docker-config.json,$(TESTS-STAGE-DIR)/docker-config.json))
$(eval $(call make-cp-rule,$(REPO_ROOT)/tools/container-converter/target/$(FLAVOR)/container-converter,$(TESTS-STAGE-DIR)/container-converter))
$(eval $(call pull-s3,s3\://fortanix-internal-artifact-repository/salmiac/$(ENCLAVE-KERNEL-TAR),$(TESTS-STAGE-DIR)/$(ENCLAVE-KERNEL-TAR)))
$(eval $(call untar-pkg,$(TESTS-STAGE-DIR)/$(ENCLAVE-KERNEL-TAR),$(TESTS-STAGE-DIR)/amzn-linux-nbd))

# This generates the rules for copying the contents of tools/app-test-infra/python
# tests-container-stage/tests/python.
$(foreach lib,$($(SUBDIR)/PYTHON-LIB-FILES) $($(SUBDIR)/BIN-FILES),$(eval $(call make-cp-rule,$(lib),$(subst $(REPO_ROOT),$(TESTS-STAGE-DIR)/tests,$(lib)))))

# This rule removes the image and staging directory after building,
# to force Make to run the docker build command each time. The Make rules
# should the container to be rebuilt if any of the inputs change.
# There isn't an easy way to force stage contents to be removed if
# an input is deleted (such as removing a test). Always forcing
# a clean build addresses this issue, but is not convenient for
# rapidly iterating on the container. We might want to add a Make
# option to skip the cleanup steps.
#
# The docker build step takes much longer than setting up the stage
# directory (at least right now), so forcing the stage directory
# to always be rebuilt isn't costing us much time. We can revisit
# if populating the stage directory starts taking longer.
$(TESTS-CONTAINER): $(TESTS-STAGE-CONTENTS)
	docker build \
		--tag $(TESTS-TAG) \
		--build-arg FLAVOR=$(FLAVOR) \
		--build-arg PLATFORM=$(PLATFORM) \
		-f $(TESTS-STAGE-DIR)/$(TESTS_CONTAINER_DOCKERFILE) \
		$(TESTS-STAGE-DIR)
	docker save $(TESTS-TAG) | gzip > $@
	echo "$(TESTS-TAG)" > $(TESTS-CONTAINER-TAGFILE)
	docker rmi -f $(TESTS-TAG)
	$(RM) -rf --preserve-root $(TESTS-STAGE-DIR)

$(TESTS-CONTAINER-APP-TESTS-FILE)::    | $(dir $(TESTS-CONTAINER-APP-TESTS-FILE))

$(eval $(call make-cp-rule,/usr/bin/$(DOCKER-AWS-HELPER),$(TESTS-STAGE-DIR)/$(DOCKER-AWS-HELPER)))
