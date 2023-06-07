# Copyright 2023 Fortanix, Inc. All Rights Reserved.

#
# String definitions for Python code.
#

#
# String definitions for makefiles.
# TODO: Not all of these are needed. We should remove the unnecessary ones later. Also check
# salmiac/make/Makefile.defs
#


APPCONFIG_ENV_KEY = """APPCONFIG_ID"""
APPCONF_JSON_FILE = """appconfig.json"""
CHECKSUM_BINARY = """/opt/fortanix/enclave-os/bin/integrity-info"""
CHECKSUM_BINARY_NAME = """integrity-info"""
COMPANY = """fortanix"""
COMPANY_UI_NAME = """Fortanix"""
CONTAINER_CONVERTER = """enclave-os-container-converter"""
CONVERTER_DOCKER_LABEL = """com.fortanix.enclave-os.version"""
CONVERTER_HOST_PKG_PATH = """/opt/fortanix/converter/host_pkgs.tar.gz"""
CONVERTER_INSTALL_ROOT = """/opt/fortanix/converter"""
CONVERTER_MANIFEST_NAME = """app.manifest.sgx"""
CONVERTER_PRODUCT = """converter"""
CONVERTER_ZIRCON_OPENJ9_LABEL = """com.fortanix.zircon.guest.openj9-jit"""
CPUNUM_ENV_VAR = """ENCLAVEOS_CPUNUM"""
DISABLE_SGX2_ENV_VAR = """ENCLAVEOS_DISABLE_SGX2"""
FATAL_ERROR_1 = """%s has encountered an internal error and cannot continue."""
FATAL_ERROR_2 = """Your application may require functionality that is not yet implemented in %s."""
FATAL_ERROR_3 = """Please contact %s support <%s> for assistance"""
FORTANIX_MANAGER_UI_NAME = """Fortanix Manager"""
HOST_LIB_DIR = """/lib64"""
HOST_META_PACKAGE_DESCRIPTION = """Meta package depending on all packages required to run EnclaveOS images"""
HOST_PACKAGE_DESCRIPTION = """EnclaveOS System Settings"""
HOST_PKG_TAR = """host_pkgs.tar.gz"""
INSTALL_APPCONF_DIR = """/opt/fortanix/enclave-os/app-config"""
INSTALL_APPCONF_JSON_FILE = """/opt/fortanix/enclave-os/app-config/rw/appconfig.json"""
INSTALL_APPCONF_RO_DIR = """/opt/fortanix/enclave-os/app-config/ro"""
INSTALL_APPCONF_RW_DIR = """/opt/fortanix/enclave-os/app-config/rw"""
INSTALL_BIN_DIR = """/opt/fortanix/enclave-os/bin"""
INSTALL_BOOTSTRAP_DIR = """/opt/fortanix/enclave-os/bootstrap"""
INSTALL_EFS_DIR = """/opt/fortanix/enclave-os/default-efs-dirs"""
INSTALL_HASH_DIR = """/opt/fortanix/enclave-os/rofs-hashes"""
INSTALL_HOST_DIR = """/opt/fortanix/enclave-os/host"""
INSTALL_LIBOS_DIR = """/opt/fortanix/enclave-os/lib"""
INSTALL_LOG_DIR = """/opt/fortanix/enclave-os/log"""
INSTALL_MANIFESTS_DIR = """/opt/fortanix/enclave-os/manifests"""
INSTALL_ROOT_CA = """/opt/fortanix/enclave-os/certs/ca-certificates.crt"""
INSTALL_ROOT_CA_DIR = """/opt/fortanix/enclave-os/certs"""
JAVA_OPTIONS_OPENJ9_JIT = """-Xdump:none -Xjit:disableSmartPlacementOfCodeCaches -Dcom.ibm.tools.attach.enable=no -XX:codecachetotal=10m"""
JAVA_OPTIONS_OPENJ9_NOJIT = """-Xdump:none -Xnojit -Xnoaot"""
JAVA_OPTIONS_OPENJDK = """-XX:CompressedClassSpaceSize=16m -XX:ReservedCodeCacheSize=16m -XX:-UseCompiler -XX:+UseSerialGC -XX:-UsePerfData"""
KERNEL_MODULE_DESCRIPTION = """EnclaveOS SGX Driver"""
KERNEL_MODULE_VERSION = """1.20.devel"""
LOG_FILE_SIZE_ENV_VAR = """ENCLAVEOS_LOG_FILE_SIZE"""
LOG_LEVEL_ENV_VAR = """ENCLAVEOS_LOG_LEVEL"""
LOG_NUM_FILES_ENV_VAR = """ENCLAVEOS_LOG_NUM_FILES"""
LOG_TARGET_ENV_VAR = """ENCLAVEOS_LOG_TARGET"""
MANIFEST_DIR_ENV_VAR = """ENCLAVEOS_MANIFEST_DIR"""
PACKAGE_INSTALL_ROOT = """/opt/fortanix/enclave-os"""
PRODUCT = """enclave-os"""
PRODUCT_UI_NAME = """EnclaveOS"""
PRODUCT_VERSION = """1.20.devel"""
ROOT_CA_FILE = """ca-certificates.crt"""
RUNTIME_APPCONF_DIR = """app-config"""
RUNTIME_APPCONF_RO_DIR = """app-config/ro"""
RUNTIME_APPCONF_RW_DIR = """app-config/rw"""
RUNTIME_BIN_DIR = """bin"""
RUNTIME_BOOTSTRAP_DIR = """bootstrap"""
RUNTIME_DOC_DIR = """doc"""
RUNTIME_EFS_DIR = """default-efs-dirs"""
RUNTIME_EFS_KEYS_DIR = """efs-keys"""
RUNTIME_ENV_VAR = """ENCLAVEOS_RUNTIME"""
RUNTIME_GUEST_EFS_DIR = """ftx-efs"""
RUNTIME_HASH_DIR = """rofs-hashes"""
RUNTIME_HASH_EXT = """.hashes"""
RUNTIME_HOST_DIR = """host"""
RUNTIME_LIBOS_DIR = """lib"""
RUNTIME_LOG_DIR = """log"""
RUNTIME_MANIFEST_DIR = """manifests"""
RUNTIME_ROOT_CA_DIR = """certs"""
SIGNATURE_ENV_VAR = """ENCLAVEOS_SIGNATURE"""
SIGNATURE_ENV_VAR2 = """ENCLAVEOS_SIGNATURE2"""
SIGNING_KEY_ENV_VAR = """ENCLAVEOS_SIGNING_KEY"""
STARTUP_BANNER_1 = """Fortanix(R) EnclaveOS Runtime Encryption Platform %s"""
STARTUP_BANNER_2 = """Copyright 2017-2023 Fortanix, Inc. All rights reserved."""
SUPPORT_EMAIL = """support@fortanix.com"""
TROUBLE_SHOOTING_GUIDE = """<Work In Progress>"""
ZIRCON_CORE_DUMP_DISABLE_ENV_VAR = """ENCLAVEOS_CORE_DUMP_DISABLE"""
ZIRCON_CORE_DUMP_NAME = """enclaveos-runner.core.%p"""
ZIRCON_CORE_DUMP_PATH_ENV_VAR = """ENCLAVEOS_CORE_DUMP_FILE"""
ZIRCON_CORE_DUMP_SUFFIX = """.core.%p"""
ZIRCON_EXE_NAME = """enclaveos-runner"""
ZIRCON_HOST_LOADER_NAME = """ld-linux-x86-64.so.2"""
ZIRCON_LOG_FILE = """enclave-os.log"""
ZIRCON_PAL_SO_NAME = """libenclaveos-platform.so"""
ZIRCON_SHIM_SO_NAME = """libenclaveos-interface.so"""
ZIRCON_SIGNER_NAME = """enclaveos-signer"""
ZIRCON_TRUSTED_SHIM_ID = """enclaveos_shim"""
ZIRCON_TRUSTED_VDSO_ID = """enclaveos_vdso"""
ZIRCON_VDSO_NAME = """libenclaveos-vdso.so"""
