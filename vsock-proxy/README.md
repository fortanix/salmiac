# Overview

A salmiac converted image is conceptually split into two parts:

1. **Parent image**
2. **Enclave artifact**

The parent part remains a container image. It is based on `parent-base` and then
extended by the converter with more stuff.

The enclave part is based on `enclave-base` during conversion, but it does not
remain a normal runnable container image in the final output. Instead, the
converter extends/modifies it to produce the enclave runtime artifact that can
be launched by the parent. For example, in case of Nitro enclaves, this is the Enclave Image File (`.eif`).

In simpler terms, the parent image runs the parent `vsock-proxy` binary as
its entrypoint. This binary is responsible for launching the enclave and
managing parent side communication.

When the enclave starts, it first runs the enclave side `vsock-proxy` binary.
The enclave vsock-proxy reads the enclave settings that were placed during conversion,
sets up the enclave runtime environment, connects back to the parent proxy over vsock, and then
starts the original entrypoint/CMD from the input container image.

So the original application still runs inside the enclave, but it is started by
the enclave vsock-proxy after the proxy has completed the required setup.

## Build

For actual usage, `vsock-proxy` is built by the `container-converter`'s `build.rs`.

It can also be built independently:

```
SALMIAC_PLATFORM="<platform>" cargo build
```

`SALMIAC_PLATFORM` is used by build.rs to enable platform specific cfgs such as:
```rust
#[cfg(platform = "nitro")]
```
