#
# Generate string tables for various languages.
#

$(eval $(call make-checking-build-command,$(C_STRING_TABLE),\
  $(STRING_TABLE_SOURCE) $(STRING_TABLE_SCRIPT) $(REPO_ROOT)/strings/c.template,\
	$$(STRING_TABLE_SCRIPT) $$(EXTRA_STRINGS) --language c --output $$@ $$(STRING_TABLE_SOURCE)))

$(eval $(call make-checking-build-command,$(PY_STRING_TABLE),\
  $(STRING_TABLE_SOURCE) $(STRING_TABLE_SCRIPT) $(REPO_ROOT)/strings/python.template,\
	$$(STRING_TABLE_SCRIPT) $$(EXTRA_STRINGS) --language python --output $$@ $$(STRING_TABLE_SOURCE)))

$(eval $(call make-checking-build-command,$(SHELL_STRING_TABLE),\
  $(STRING_TABLE_SOURCE) $(STRING_TABLE-SCRIPT) $(REPO_ROOT)/strings/shell.template,\
	$$(STRING_TABLE_SCRIPT) $$(EXTRA_STRINGS) --language shell --output $$@ $$(STRING_TABLE_SOURCE)))

ZIRCON_SHELL_STRING_TABLE := $(SHELL_STRING_TABLE)

# Export this to child environments so shell scripts that want to use
# the string table can find it.
export ZIRCON_SHELL_STRING_TABLE
