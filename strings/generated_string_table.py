# Copyright 2023 Fortanix, Inc. All Rights Reserved.

#
# String definitions for Python code.
#
# Some of the definitions(like java options) may not be used right now but kept for future use

CONVERTER_DOCKER_LABEL = """com.fortanix.enclave-os.version"""
CONVERTER_MANIFEST_NAME = """app.manifest.sgx"""
INSTALL_BIN_DIR = """/opt/fortanix/enclave-os/bin"""
INSTALL_LOG_DIR = """/opt/fortanix/enclave-os/log"""
INSTALL_MANIFESTS_DIR = """/opt/fortanix/enclave-os/manifests"""
JAVA_OPTIONS_OPENJ9_JIT = """-Xdump:none -Xjit:disableSmartPlacementOfCodeCaches -Dcom.ibm.tools.attach.enable=no -XX:codecachetotal=10m"""
JAVA_OPTIONS_OPENJ9_NOJIT = """-Xdump:none -Xnojit -Xnoaot"""
JAVA_OPTIONS_OPENJDK = """-XX:CompressedClassSpaceSize=16m -XX:ReservedCodeCacheSize=16m -XX:-UseCompiler -XX:+UseSerialGC -XX:-UsePerfData"""
PACKAGE_INSTALL_ROOT = """/opt/fortanix/enclave-os"""
PRODUCT = """enclave-os"""
PRODUCT_UI_NAME = """EnclaveOS"""
PRODUCT_VERSION = """1.20.devel"""
STARTUP_BANNER_1 = """Fortanix(R) EnclaveOS Runtime Encryption Platform %s"""
STARTUP_BANNER_2 = """Copyright 2017-2023 Fortanix, Inc. All rights reserved."""
SUPPORT_EMAIL = """support@fortanix.com"""
ZIRCON_EXE_NAME = """enclaveos-runner"""
ZIRCON_LOG_FILE = """enclave-os.log"""