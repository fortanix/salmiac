Enclaveos Encrypted Filesystem
==============================

enclaveos-encrypted-filesystem is a small utility crate that helps you set up and manage a LUKS2 based encrypted filesystem.
It provides simple, safe Rust APIs for creating a LUKS2 based encrypted filesystem that can be setup before your application
runs in a TEE. It allows the usage of Fortanix Data Security Manager as an external key management service.

Pre-requisites
--------------

Ensure you have [cryptsetup](https://gitlab.com/cryptsetup/cryptsetup) installed on your system.

Environment variables
---------------
- DSM_APP_ID - Data Security Manager's Application ID where the passphrase resides. The application ID is used to authenticate with DSM using a client certificate. The passphrase in DSM is used to unlock the encrypted filesystem.

In example program only:
- DSM_ENDPOINT - Data Security Manager URL. Default endpoint used is https://amer.smartkey.io/ (in case of API key auth) or https://apps.amer.smartkey.io/ (in case of certificate auth). This environment variable can be used to override these defaults.
