use salmiac_build_support::{Platform, DEFAULT_PLATFORM};

fn main() {
    Platform::emit_cfg_from_env_or(*DEFAULT_PLATFORM);
}
