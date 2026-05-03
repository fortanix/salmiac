Build script helper crate for salmiac crates that need platform specific
compilation.

This crate is intended to be used from another crate's `build.rs`. It reads the
`SALMIAC_PLATFORM` env var and emits the corresponding config for platform specific code.

## Usage

In another crate's `build.rs`:

```rust
use salmiac_build_support::Platform;

fn main() {
    if let Err(err) = Platform::emit_cfg_from_env() {
        panic!("{}", err);
    }
}
```

Then build with:
```
SALMIAC_PLATFORM=<platform> cargo build
```

This causes the consuming crate to be compiled with:

```rust
#[cfg(platform = "<platform>")]
```
