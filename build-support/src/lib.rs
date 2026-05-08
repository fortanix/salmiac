use std::env;
use std::str::FromStr;

use strum::{AsRefStr, EnumString, VariantNames};

pub const PLATFORM_ENV: &str = "SALMIAC_PLATFORM";

#[derive(Clone, Copy, Debug, Eq, PartialEq, AsRefStr, EnumString, VariantNames)]
#[strum(serialize_all = "snake_case")]
pub enum Platform {
    Nitro,
    Simulator,
    Snp,
}

impl Platform {
    pub fn from_env() -> Result<Self, String> {
        match env::var(PLATFORM_ENV) {
            Ok(value) => Platform::from_str(&value)
                .map_err(|_| unsupported_platform_error(&value)),
            Err(err) => Err(format!("failed to read {PLATFORM_ENV}: {err}")),
        }
    }

    pub fn emit_cfg_from_env() -> Result<(), String> {
        println!("cargo::rerun-if-env-changed={PLATFORM_ENV}");

        let values = Self::VARIANTS
            .iter()
            .map(|value| format!("\"{value}\""))
            .collect::<Vec<_>>()
            .join(", ");

        println!("cargo::rustc-check-cfg=cfg(platform, values({values}))");

        let platform = Self::from_env()?;
        println!("cargo::rustc-cfg=platform=\"{}\"", platform.as_ref());

        Ok(())
    }
}

fn unsupported_platform_error(value: &str) -> String {
    format!(
        "unsupported {PLATFORM_ENV}={value}; supported values: {}",
        Platform::VARIANTS.join(", ")
    )
}
