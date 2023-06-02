#
# Use bash as the shell for executing things. If not explicitly set, Make
# will use /bin/sh. On debian-based systems (including Ubuntu), this is
# dash.
#

SHELL := /bin/bash

# Disable python buffering, so the output from python test scripts gets
# printed to the console in a timely fashion. We used to use a utility
# called unbuffer (from the expect package), but this had issues with
# interrupting builds with control-C.
PYTHONUNBUFFERED=1
export PYTHONUNBUFFERED

# There is also the BUILD_DIR variable. This contains base directory for
# the current build target, which will be a subdirectory of the BUILD_ROOT.
# For example, the debug build for sgx will go under BUILD_ROOT/nitro-debug.
#

BUILD_ROOT ?= $(REPO_ROOT)/build

ifneq (1,$(words $(BUILD_ROOT)))
$(info Your BUILD_ROOT has whitespace in it. This will probably break.)
$(error Bad BUILD_ROOT)
endif

#
# Default values for PLATFORM, FLAVOR and FREQUENCY.
#

FLAVOR ?= debug
PLATFORM = nitro
FREQUENCY ?= smoke ci

#
# Check that FLAVOR and PLATFORM have valid values.
#

valid_flavors = debug release
ifneq (1,$(words $(FLAVOR)))
$(info Invalid FLAVOR value of "$(FLAVOR)")
$(info FLAVOR should be a single word)
$(info Valid values for FLAVOR are: $(valid_flavors))
endif

ifeq ($(filter $(FLAVOR),$(valid_flavors)),)
$(info Invalid FLAVOR value of "$(FLAVOR)")
$(info Valid values for FLAVOR are: $(valid_flavors))
$(error Invalid FLAVOR detected)
endif

# When a test should be run. ci stands for "continuous integration" and
# will always be run unless otherwise specified. Tests will automatically
# be given a frequency of ci unless specifically overridden.
valid_frequencies = smoke ci daily weekly
ifneq ($(filter-out $(valid_frequencies),$(FREQUENCY)),)
$(info Invalid frequency $(filter-out $(valid_frequencies),$(FREQUENCY)) requested)
$(info Valid values for FREQUENCY are: $(valid_frequencies))
$(error Invalid FREQUENCY detected)
endif

define frequency-help
Meanings for different FREQUENCY values:
smoke: Smoke tests are a small subset of tests run to verify that a build is
       not completely broken.
ci: CI stands for "continuous integration". The CI tests are run for each pull
    request submitted to Jenkins. They are run by the zircon_pr and
    zircon_sgx_pr test jobs.
daily: Tests marked as daily will be run as part of the daily zircon_soak and
       zircon_sgx_soak test jobs. They are not run as part of PR jobs.
weekly: Tests marked as weekly are run by the zircon_weekly test job once a
        week. Most of the tests in this category are extremely long running,
        so cannot complete even in the overnight daily test run.

Our jobs are configured so that when we run the less frequent tests, we also
run the more frequent tests. So running the CI tests will also include the
smoke tests, and running the daily tests will also include the smoke and ci
tests.
endef

BUILD_SUBDIR := $(PLATFORM)-$(FLAVOR)

BUILD_DIR := $(BUILD_ROOT)/$(BUILD_SUBDIR)
