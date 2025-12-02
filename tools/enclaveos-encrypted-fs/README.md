Enclaveos Encrypted Filesystem
==============================

enclaveos-encrypted-filesystem is a small utility crate that helps you set up and manage a LUKS2 based encrypted filesystem.
It provides simple, safe Rust APIs for creating a LUKS2 based encrypted filesystem that can be setup before your application
runs in a TEE. It allows the usage of Fortanix Data Security Manager as an external key management service.

Pre-requisites
--------------

Ensure you have [cryptsetup](https://gitlab.com/cryptsetup/cryptsetup) installed on your system.
