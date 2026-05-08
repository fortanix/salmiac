use salmiac_build_support::Platform;

fn main() {
    if let Err(err) = Platform::emit_cfg_from_env() {
        panic!("{}", err);
    }
}
