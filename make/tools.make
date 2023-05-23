#
# Build tool definitions.
#

LD := /usr/bin/ld
STRIP := $(COMPILER_OUTPUT)/usr/bin/strip
TOUCH := $(COMPILER_OUTPUT)/usr/bin/touch
# The Make variable MAKE is special, so use this instead if you want a
# separate invocation of Make for recursive subbuilds.
MAKECMD := /usr/bin/make


# Google protobuf compiler. Used for generating source files from a protobuf
# definition file.
PROTOC := /usr/bin/protoc

AWK := /usr/bin/awk
# Base64 with no newlines in the output.
BASE64 := /usr/bin/base64 --wrap=0
BC := /usr/bin/bc
CAT := /bin/cat
CHMOD := /usr/bin/chmod
CMP := /usr/bin/cmp
CP := /bin/cp --preserve
# C preprocessor
CPP := /usr/bin/cpp
ECHO := /bin/echo
ENV := /usr/bin/env
FALSE := /bin/false
FIND := /usr/bin/find
GREP := /bin/grep
GZIP := /bin/gzip
LN := /bin/ln
LN_S := /bin/ln -sfn
MKDIR := /bin/mkdir
MV := /bin/mv
OBJCOPY := /usr/bin/objcopy
OPENSSL := /usr/bin/openssl
PYTHON := /usr/bin/python3
RM := /bin/rm
SED := /bin/sed
SHA256 := /usr/bin/sha256sum
TAR := /bin/tar
TEE := /usr/bin/tee
TIMEOUT_PROGRAM := /usr/bin/timeout
TRUE := /bin/true
UNZIP := /usr/bin/unzip
