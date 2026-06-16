use std::env;
use std::str::FromStr;

use strum::{AsRefStr, EnumString, VariantNames};

pub const PLATFORM_ENV: &str = "SALMIAC_PLATFORM";
pub const DEFAULT_PLATFORM: &Platform = &Platform::Nitro;

#[derive(Clone, Copy, Debug, Eq, PartialEq, AsRefStr, EnumString, VariantNames)]
#[strum(serialize_all = "snake_case")]
pub enum Platform {
    Nitro,
    Simulator,
    Snp,
    Tdx,
}

impl Platform {
    /// Detects the platform from the `SALMIAC_PLATFORM` environment variable.
    pub fn from_env() -> Result<Self, String> {
        match env::var(PLATFORM_ENV) {
            Ok(value) => Platform::from_str(&value).map_err(|_| unsupported_platform_error(&value)),
            Err(err) => Err(format!("failed to read {PLATFORM_ENV}: {err}")),
        }
    }

    /// Detects the platform from environment or falls back to `default`.
    pub fn from_env_or(default: Self) -> Self {
        Self::from_env().unwrap_or(default)
    }

    /// Configures `rustc-cfg` for the detected or default platform.
    pub fn emit_cfg_from_env_or(default: Self) -> Self {
        let platform = Self::from_env_or(default);
        Self::emit_cfg(platform);
        platform
    }

    /// Configures `rustc-cfg` for the platform detected from environment.
    pub fn emit_cfg_from_env() -> Result<Self, String> {
        let platform = Self::from_env()?;
        Self::emit_cfg(platform);

        Ok(platform)
    }

    /// Emits `cargo::rustc-cfg` and configuration checks for the platform.
    fn emit_cfg(platform: Self) {
        println!("cargo::rerun-if-env-changed={PLATFORM_ENV}");

        let values = Self::VARIANTS
            .iter()
            .map(|value| format!("\"{value}\""))
            .collect::<Vec<_>>()
            .join(", ");

        println!("cargo::rustc-check-cfg=cfg(platform, values({values}))");
        println!("cargo::rustc-cfg=platform=\"{}\"", platform.as_ref());
    }
}

fn unsupported_platform_error(value: &str) -> String {
    format!(
        "unsupported {PLATFORM_ENV}={value}; supported values: {}",
        Platform::VARIANTS.join(", ")
    )
}
