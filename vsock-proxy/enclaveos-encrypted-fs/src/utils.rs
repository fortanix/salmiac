/* Copyright (c) Fortanix, Inc.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */
use async_process::{Command, Stdio};
use log::debug;
use std::env;

#[derive(Default)]
pub struct CommandOutputConfig {
    pub stdout: Option<Stdio>,

    pub stderr: Option<Stdio>,
}

impl CommandOutputConfig {
    pub fn all_piped() -> Self {
        CommandOutputConfig {
            stdout: Some(Stdio::piped()),
            stderr: Some(Stdio::piped()),
        }
    }

    pub fn all_null() -> Self {
        CommandOutputConfig {
            stdout: Some(Stdio::null()),
            stderr: Some(Stdio::null()),
        }
    }
}

pub async fn run_subprocess(subprocess_path: &str, args: &[&str]) -> Result<(), String> {
    run_subprocess_with_output_setup(subprocess_path, args, CommandOutputConfig::default())
        .await
        .map(|_| ())
}

pub async fn run_subprocess_with_output_setup(
    subprocess_path: &str,
    args: &[&str],
    output_config: CommandOutputConfig,
) -> Result<async_process::Output, String> {
    let mut command = Command::new(subprocess_path);

    command.args(args);

    if let Some(stdout) = output_config.stdout {
        command.stdout(stdout);
    }

    if let Some(stderr) = output_config.stderr {
        command.stderr(stderr);
    }

    debug!("Running subprocess {} {:?}.", subprocess_path, args);
    let process = command
        .spawn()
        .map_err(|err| format!("Failed to run subprocess {}. {:?}. Args {:?}", subprocess_path, err, args))?;

    let output = process.output().await.map_err(|err| {
        format!(
            "Error while waiting for subprocess {} to finish: {:?}. Args {:?}",
            subprocess_path, err, args
        )
    })?;

    if output.status.success() {
        Ok(output)
    } else {
        Err(format!("Process exited with a negative return code. Output is: {:?}", output))
    }
}

pub fn find_env_or_err(key: &str) -> Result<String, String> {
    match env::var(key) {
        Ok(value) => Ok(value),
        Err(e) => Err(format!("Unable to find environment variable {}. Error: {}", key, e)),
    }
}