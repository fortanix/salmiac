#
# Non-recursive make system.

# Disable implicit make rules. If you mess up your rules, make may find an
# implicit rule for building something, and instead of breaking the build,
# you can end up with things being built, but built wrong.
MAKEFLAGS += --no-builtin-rules

# This is the path to this Makefile, which must be in the root of the
# salmiac repository.
REPO_ROOT := $(abspath $(dir $(lastword $(MAKEFILE_LIST))))

-include Makefile.local
include $(REPO_ROOT)/make/defaults.make
include $(REPO_ROOT)/make/tools.make

ifneq ($(MAKEFILE_REINVOKED),1)

MAKE_OUTPUT_FILE := $(BUILD_DIR)/last-make-output

MAKEPROCS ?= $(shell /usr/bin/getconf _NPROCESSORS_ONLN)
STOP_ON_FAILURE := 1
ifeq ($(STOP_ON_FAILURE),1)
KEEP_GOING_OPTION :=
else
KEEP_GOING_OPTION := -k
endif

.PHONY: run_make
run_make:
	mkdir -p $(BUILD_DIR)
	(set -o pipefail ; $(CLANG_PREFIX) $(MAKE) $(MAKECMDGOALS) \
		MAKEFILE_REINVOKED=1 \
		$(KEEP_GOING_OPTION) \
		-C $(REPO_ROOT) \
		--no-print-directory \
		-j $(MAKEPROCS) 2>&1 | \
		$(TEE) -i "$(MAKE_OUTPUT_FILE)") || \
		($(ECHO) -e "\n\n\n--------- Build failed. Make output is in $(MAKE_OUTPUT_FILE). Greepping for failures: --------\n\n\n" && \
		$(GREP) --text -B 20 'make\[[[:digit:]]\+\]: \*\*\*' "$(MAKE_OUTPUT_FILE)" && \
		exit 1)

# Reinvoke ourselves with -j for parallelism.
%: run_make
	@:

# Don't try to build the Makefile with the run_make pattern rule. This
# silences a "Nothing to be done for 'run_make'" message
Makefile:
	@:

else

# Real Makefile starts here.

# If we're running tests, disable parallel make. Running tests in parallel
# is likely to cause timeoutes, especially on SGX.
ifneq ($(findstring run-test,$(MAKECMDGOALS))$(findstring run-converter,$(MAKECMDGOALS)),)
.NOTPARALLEL:
endif

# The first target in a Makefile is the default target (what gets built if
# you just type 'make'). So we need to set the default target here so it's
# before all of the other targets. But we don't actually know everything
# that we want to build until we've read in all of the subdir.make files,
# so the actual default rule goes at the bottom of the Makefile.
.PHONY: default
default: real_default

include $(REPO_ROOT)/make/defs.make
include $(REPO_ROOT)/make/rules.make
include $(REPO_ROOT)/make/strings.make

ifneq ($(MAKECMDGOALS),clean)
# Avoid (harmless) warnings about multiply-defined targets when make clean
# is performed. Our clean target just wipes the build directory, so we
# don't need any subdirectory rules for clean to work.
include $(REPO_ROOT)/make/subdirs.make
endif

all :=

# Add each subdirectory.
$(foreach SUBDIR,$(SUBDIRS),$(eval $(call process-subdir)))

include $(REPO_ROOT)/make/salmiac-tests-container.make

real_default: $(all)

clean:
	rm -rf --preserve-root $(BUILD_ROOT)

run-tests: $(all-tests)
endif
