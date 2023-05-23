#
# Make variable definitions.
#

# Values for BUILD_ROOT, FLAVOR, PLATFORM, FREQUENCY, and BUILD_DIR are set in
# defaults.make so they can be included earlier than this file.

DOCKER_REGISTRY := 513076507034.dkr.ecr.us-west-1.amazonaws.com

# Definitions related to string management
CODEGEN_DIR := $(BUILD_DIR)/codegen
PY_CODEGEN_DIR := $(BUILD_DIR)/codegen/python
PY_STRING_TABLE := $(PY_CODEGEN_DIR)/generated_string_table.py
PY_STRING_TABLE_WRAPPER :=  zircon/tools/app-test-infra/python/string_table.py
SHELL_CODEGEN_DIR := $(BUILD_DIR)/codegen/sh
SHELL_STRING_TABLE := $(SHELL_CODEGEN_DIR)/generated_string_table.sh

STRING_TABLE_SOURCE := $(REPO_ROOT)/zircon/strings/string-table
STRING_TABLE_SCRIPT := $(REPO_ROOT)/zircon/tools/bin/gen-string-tables.py
REPLACE_STRINGS_SCRIPT := $(REPO_ROOT)/zircon/tools/bin/replace-strings.py
EXTRA_STRINGS := --string PRODUCT_VERSION=$(VERSION) --string KERNEL_MODULE_VERSION=$(KERNEL_MODULE_VERSION)

# export FREQUENCY we get over make command line for tets to use.
export CI_FREQ=$(FREQUENCY)
$(info Building with FLAVOR=$(FLAVOR) PLATFORM=$(PLATFORM) FREQUENCY=$(FREQUENCY) BUILD_ROOT=$(BUILD_ROOT))
$(shell mkdir -p $(BUILD_DIR) && $(LN_S) $(BUILD_SUBDIR) $(BUILD_ROOT)/latest)

include $(REPO_ROOT)/make/Makefile.defs

# Usage: $(call dirname,/path/to/file)
# produces "/path/to"
# Make does have a builtin function, dir, to strip the filename portion from
# the path, but it doesn't strip the trailing slash. There are some situations
# where you need to strip the trailing slash so you can produce correct strings
# for rules or other reasons. The shell treats "dir", "dir/" and "dir//" as
# the same thing (if they're directories), but they're considered different
# for purposes of Makefile rules.
define dirname
$(patsubst %/,%,$(dir $1))
endef

# It's hard to represent whitespace in recipes.
null :=
space := $(null) $(null)
# The following line contains a literal tab.
tab := $(null)	$(null)

define newline

endef

# Usage: $(call pretty-print,list)
# Transforms list into something that will print more nicely.
define pretty-print
$(foreach thing,$1,$(info $(tab)$(thing)))
endef

# Get a test's frequency from the target name, for printing help. We have to
# do some string transformation because this isn't how the frequencies
# are usually generated.
define frequency-from-target
$(call test-frequency,$(subst run-test-,,$(patsubst %/run-app-test,%/app-test,$(test))))
endef

# Print a test along with its frequency.
define pretty-print-test
$(foreach test,$1,$(info $(tab)$(test) $(call frequency-from-target,$(test))))
endef

TMPDIR ?= /tmp

#
# Replace the call site with the list of files in the specified directory
# (but not directories or files in subdirectories). Files with '#' characters
# in their names can be a problem, so they're excluded. We don't normally
# use '#' characters in filenames, and various editors create temporary or
# backup files with '#' in the names. This can lead to difficult to debug
# intermittent problems with running make.
#
# When assinging the result to a variable, it's important to use a :=
# variable assignment rather than a = variable assignment. An = assignment
# will cause the find command to be executed each time that variable appears
# in the Makefiles, which will be very slow.
#
# Usage: $(call files-in-dir,path-to-directory)
#
define files-in-dir
$(shell $(FIND) $(1) -maxdepth 1 -regex '[^#]*' -type f)
endef

#
# Definition for the tests container build.
#
TESTS-CONTAINER-BASE := salmiac-tests-container
TESTS-CONTAINER := $(BUILD_DIR)/$(TESTS-CONTAINER-BASE).tar.gz

TESTS-CONTAINER-TAGFILE := $(BUILD_DIR)/tests-container-tag

DOCKER-ENV-FILE := $(BUILD_DIR)/docker-env

#
# Location of the stage directory for the tests container
#
TESTS-REGRESSION-TEST-SUBDIR := tests/regression-tests

TESTS-STAGE-DIR := $(BUILD_DIR)/tests-container-stage

TEST-CONTAINER-MOUNT := /opt/fortanix/ci/tests-container

#
# In-container test path.
#
TESTS-CONTAINER-HOME := /home/zircon-tests

#
# Variables for Python test runner.
#
PYTHONENV = \
	"PYTHONPATH=$(REPO_ROOT)/zircon/tools/python:$(REPO_ROOT)/zircon/tools/app-test-infra/python" \
	"TEST_BASE_DIR=$(BUILD_DIR)" \
	"FLAVOR=$(FLAVOR)" \
	"PLATFORM=$(PLATFORM)" \
	"ZIRCON_TMPDIR=$(TMPDIR)" \
	"FEMC_IMAGE_FILE=test_image_name.txt" \
	"CONVERTER_IMAGE=$(CONVERTER_IMAGE)" \
	"CONVERTER_FILE=$(CONVERTER_DOCKER_IMAGE)" \
	"DOCKER_REGISTRY=$(DOCKER_REGISTRY)"

TOOLSERVER_TAG_ARG := --no-tag

HOST_PKG_TAR := host_pkgs.tar.gz
HOST_PKG_PATH := $(BUILD_DIR)/$(HOST_PKG_TAR)

CA_BUNDLE_FILE := ca-certificates.crt
CA_BUNDLE_DIR := $(BUILD_DIR)/ca-certs
CA_BUNDLE_BUILD_PATH := $(CA_BUNDLE_DIR)/$(CA_BUNDLE_FILE)

#
# Package converter.
#
CONVERTER_TAR_GZ = converter-$(VERSION).tar.gz
CONVERTER_DOCKER_IMAGE = converter-docker-image-$(VERSION).tar.gz

TEST_BUNDLE := test-bundle.tar.gz
TEST_BUNDLE_DIRS := zircon/tools/bin zircon/tools/app-test-infra/bin zircon/tools/app-test-infra/python zircon/tools/app-test-infra/apps zircon/test/appcert
TEST_BUNDLE_FILES := $(shell $(FIND) $(TEST_BUNDLE_DIRS) -type f)



# In order to access the Fortanix Docker registry in AWS, we need this helper
# program. As a hack, to avoid having to fetch this program from S3 (which
# is how the chef recipes install it), we assume that the system building
# the tests container has already had the chef recipes applied, and we
# can just pick it up from /usr/local/bin.
DOCKER-AWS-HELPER := docker-credential-ecr-login


# Rule to specifically clean up the tests stage directory. The rule
# for building the tests container cleans up the staging directory on
# success, but it can't remove the staging directory on failure or if
# the build process gets killed. So this rule can be useful for cleaning up
# an old staging directory. The chmod is there in case the directories somehow
# end up without write or execute permissions permissions, which would prevent
# removing files in those directories or traversing those directories.
.PHONY: clean-tests-container
clean-tests-container-stage:
	$(CHMOD) --recursive +rwx $(TESTS-STAGE-DIR) > /dev/null 2> /dev/null || true
	$(RM) -rf --preserve-root $(TESTS-STAGE-DIR)


# Construct the various possible version strings.
TESTS-RELEASE-VERSION := $(MAJOR_MINOR_VERSION).$(FORTANIX_BUILD_NUMBER)
TESTS-JENKINS-VERSION := $(JOB_NAME)-$(BUILD_NUMBER)
TESTS-DEV-VERSION := dev-$(shell date +%Y%m%d)-$(shell openssl rand -hex 6)

# Choose the correct version string.
TESTS-VERSION := $(strip $(if $(filter zircon-release,$(JOB_NAME)),$(TESTS-RELEASE-VERSION),\
	$(if $(JOB_NAME),$(TESTS-JENKINS-VERSION),$(TESTS-DEV-VERSION))))

TESTS-TAG := $(TESTS-CONTAINER-BASE):$(TESTS-VERSION)

TESTS_CONTAINER_DOCKERFILE := Dockerfile-salmiac-ub20
