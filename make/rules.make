
%/:
	$(MKDIR) -p $@

define make-app
$(BUILD_DIR)/$(1): $(BUILD_DIR)/$(1)/$(2)

$(call make-checking-build-command,$(BUILD_DIR)/$(1)/$(2),$$(patsubst %,$(BUILD_DIR)/%,$(3)) $(patsubst %,$(BUILD_DIR)/%,$(4)) $(6) | $(BUILD_DIR)/$(1)/,$(build-command))

$(call make-cp-rule,$(BUILD_DIR)/$(1)/$(2),$(TESTS-STAGE-REGRESSION-TEST-DIR)/$(1)/$(2))

endef

define add-special-test
$(SUBDIR)/run-test-targets += $(SUBDIR)/run-$(1)
$(SUBDIR)/run-tests: $(call test-enabled-by-frequency,$(SUBDIR)/$(1),$(SUBDIR)/run-$(1))

ifeq ($(1),app-test)
# Convenience target for running all of the app tests.
zircon/tools/app-test-infra/apps/run-tests: $(call test-enabled-by-frequency,$(SUBDIR)/app-test,$(SUBDIR)/run-app-test)
endif

endef

# Usage: $(eval $(call make-cp-rule,src,dst))
#
# Make a rule for copying src to dst. dst should be somewhere in the
# $(BUILD_DIR) directory tree. We try to specifically remove the target
# file first, to avoid problems like ZIRC-4069, where some of the files
# in the build or staging directories end up being not writable. We don't
# know why the files are ending up not writable, but we suspect it's
# a docker bug.
define make-cp-rule
$(2): $(1) | $$(dir $(2))
	$$(RM) -f $(2)
	$$(CP) $(1) $(2)

endef

define make-app-test-rule
$(eval $(call add-special-test,app-test))

.PHONY: $(SUBDIR)/run-nitro-app-test
$(SUBDIR)/run-nitro-app-test: SUBDIR := $(SUBDIR)
$(SUBDIR)/run-nitro-app-test: $($(SUBDIR)/copied-files)
$(SUBDIR)/run-nitro-app-test: | $(BUILD_DIR)/$(SUBDIR)/
	@echo
	@echo ==== Testing $(patsubst %.py,%,$(1)) ====
	@echo
	@date
	cd $$(BUILD_DIR)/$$(SUBDIR) && env "IS_NITRO=true" $$(PYTHONENV) ./$(1) \
		--toolserver $$(REPO_ROOT)/tools/container-converter/target/$$(FLAVOR)/container-converter \
		--container-env=nitro \
		--privileged \
		--no-results-db \
		$$(DOCKER_SECURITY_OPT) \
		$$(CONVERTER_KEY_ARG) \
		$$(EXTRA_APP_TEST_ARGS)
	@date

$(TESTS-CONTAINER-APP-TESTS-FILE):: force-rebuild | $(dir $(TESTS-CONTAINER-APP-TESTS-FILE))
	$$(ECHO) -E "$(SUBDIR)/$(1),$(call test-frequency,$(SUBDIR)/app-test)" >> $$@
endef

define make-subdir-default-rules
$(SUBDIR): $(BUILD_DIR)/$(1)
$(BUILD_DIR)/$(1): ;
all += $(1)
all-tests += $(1)/run-tests
.PHONY: $(1)/run-tests
$(1)/run-tests: ;

convenience_dir_targets += $(1)
.PHONY: $(1)/list-tests
$(1)/list-tests:
	$$(info Available tests in $(1):)
	$$(call pretty-print,$$(sort $$($(1)/test-targets)))
	$$(info Available run test targets in $(1):)
	$$(call pretty-print,$$(sort $$($(1)/run-test-targets)))
	@true

.PHONY: $(SUBDIR)/manifests
$(SUBDIR)/manifests: ;
manifests: $(SUBDIR)/manifests

.PHONY: $(SUBDIR)/tests
$(SUBDIR)/tests: ;
$(SUBDIR)/tests: $($(SUBDIR)/test-targets)
tests: $(SUBDIR)/tests

endef

# Usage: With SUBDIR set to the subdirectory, call:
# $(eval $(call process-subdir))
# This is done with a forall loop in the top-level Makefile.
define process-subdir
$(eval include $(SUBDIR)/subdir.make)
$(call make-subdir-default-rules,$(SUBDIR))

$(eval apps := $($(SUBDIR)/apps))
$(foreach app,$(apps),\
  $(call make-app,$(SUBDIR),$(app),\
  $($(SUBDIR)/$(app)-objs),\
  $($(SUBDIR)/$(app)/LIBS),\
  $($(SUBDIR)/$(app)/SYSTEM-SOLIBS),\
  $($(SUBDIR)/$(app)/PRECOMPILED-STATIC-LIBS)))

$(eval copy-files := $(strip $($(SUBDIR)/copy-files) $($(SUBDIR)/app-test)))
$(eval $(SUBDIR)/copied-files = $(foreach file,$(copy-files),$(BUILD_DIR)/$(SUBDIR)/$(file)))
$(foreach file,$(copy-files),$(call make-cp-rule,$(REPO_ROOT)/$(SUBDIR)/$(file),$(BUILD_DIR)/$(SUBDIR)/$(file)))
$(foreach file,$(copy-files),$(eval TESTS-CONTAINER-REGRESSION-TESTS += $(TESTS-STAGE-REGRESSION-TEST-DIR)/$(SUBDIR)/$(file)))
$(foreach file,$(copy-files),$(call make-cp-rule,$(REPO_ROOT)/$(SUBDIR)/$(file),$(TESTS-STAGE-REGRESSION-TEST-DIR)/$(SUBDIR)/$(file)))

$(if $($(SUBDIR)/app-test),$(call make-app-test-rule,$($(SUBDIR)/app-test)))

endef