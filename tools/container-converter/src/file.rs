/* Copyright (c) Fortanix, Inc.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

use log::{debug, info};

use std::fs;
use std::fs::File;
use std::io::{BufRead, BufReader, Seek, Write};
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use tempfile::TempDir;

/// Describes a directory containing all dependencies needed to build a Docker image
/// The directory deletes itself after going out of scope!
pub(crate) struct BuildContext {
    temp_dir: TempDir,
}

impl BuildContext {
    pub(crate) fn new(dir: &Path) -> Result<Self, String> {
        let temp_dir =
            TempDir::new_in(dir).map_err(|err| format!("Cannot create build context in {}. {:?}", dir.display(), err))?;

        Ok(Self { temp_dir })
    }

    pub(crate) fn path(&self) -> &Path {
        self.temp_dir.path()
    }

    pub(crate) fn create_resource(&self, resource: Resource) -> Result<(), String> {
        self.create_resources(&[resource])
    }

    pub(crate) fn create_resources(&self, resources: &[Resource]) -> Result<(), String> {
        for resource in resources {
            let mut file = fs::File::create(self.path().join(&resource.name))
                .map_err(|err| format!("Failed to create resource {}, error: {:?}", &resource.name, err))?;

            file.write_all(&resource.data)
                .map_err(|err| format!("Failed to create resource {}, error: {:?}", &resource.name, err))?;

            if resource.is_executable {
                file.set_execute()
                    .map_err(|err| format!("Cannot change permissions for a file {:?}", err))?;
            }
        }

        Ok(())
    }

    pub(crate) fn create_docker_file(&self, docker_file_contents: &DockerFile) -> Result<(), String> {
        let docker_file_path = self.path().join("Dockerfile");

        let mut docker_file_handler = fs::OpenOptions::new()
            .create(true)
            .truncate(true)
            .write(true)
            .open(&docker_file_path)
            .map_err(|err| format!("Failed to create docker file at {}. {:?}", self.path().display(), err))?;

        let contents = docker_file_contents.to_string();
        docker_file_handler
            .write_all(contents.as_bytes())
            .map_err(|err| format!("Failed to write to Dockerfile {:?}", err))?;

        debug!("File contents of {}:\n {}", docker_file_path.display(), contents);

        Ok(())
    }

    pub(crate) fn package_into_archive(self, archive_path: &Path) -> Result<File, String> {
        let mut archive_file = std::fs::OpenOptions::new()
            .create(true)
            .write(true)
            .read(true)
            .open(archive_path)
            .map_err(|err| {
                format!(
                    "Failed creating an archive file at {} for Docker build context at {}. {:?}",
                    self.path().display(),
                    archive_path.display(),
                    err
                )
            })?;

        let dir_as_str = self
            .path()
            .to_str()
            .ok_or(format!("Failed to cast path {} to string", self.path().display()))?;

        info!(
            "Packaging build context {} into archive at {}.",
            self.path().display(),
            archive_path.display()
        );
        shiplift::tarball::dir(&mut archive_file, &dir_as_str, true).map_err(|err| {
            format!(
                "Failed packaging Docker build context at {} into an archive at {}. {:?}",
                self.path().display(),
                archive_path.display(),
                err
            )
        })?;

        archive_file
            .rewind()
            .map_err(|err| format!("Failed rewinding archive at {}. {:?}", archive_path.display(), err))?;

        Ok(archive_file)
    }
}

/// A type that describes an arbitrary file needed to build an image
#[derive(Clone)]
pub(crate) struct Resource<'a> {
    pub(crate) name: &'a str,

    pub(crate) data: &'a [u8],

    pub(crate) is_executable: bool,
}

pub(crate) fn log_file(path: &Path) -> Result<(), String> {
    let file_name = path.file_name().and_then(|e| e.to_str()).unwrap_or("<Unknown file>");

    let file = fs::OpenOptions::new()
        .read(true)
        .open(path)
        .map_err(|err| format!("Failed to open file {} {:?}", file_name, err))?;

    let reader = BufReader::new(file);

    debug!("File contents of {}:\n", file_name);
    for line in reader.lines() {
        if let Ok(l) = line {
            println!("{}", l)
        }
    }

    Ok(())
}

/// A type that describes docker file contents by section
pub(crate) struct DockerFile {
    pub(crate) from: String,

    pub(crate) add: Option<DockerCopyArgs>,

    pub(crate) env: Vec<String>,

    pub(crate) run: Option<String>,

    pub(crate) cmd: Option<String>,

    pub(crate) entrypoint: Option<String>,
}

impl ToString for DockerFile {
    fn to_string(&self) -> String {
        let mut result = format!("FROM {} \n", self.from);

        if let Some(add) = &self.add {
            result.push_str(&format!("ADD {} \n", add.to_string()));
        }

        if !self.env.is_empty() {
            result.push_str(&format!("ENV {} \n", self.env.join(" ")));
        }

        if let Some(run) = &self.run {
            result.push_str(&format!("RUN {} \n", run));
        }

        if let Some(cmd) = &self.cmd {
            result.push_str(&format!("CMD {} \n", cmd));
        }

        if let Some(entrypoint) = &self.entrypoint {
            result.push_str(&format!("ENTRYPOINT [\"{}\"] \n", entrypoint));
        }

        result
    }
}

pub(crate) struct DockerCopyArgs {
    pub(crate) items: Vec<String>,

    pub(crate) destination: String,
}

impl ToString for DockerCopyArgs {
    fn to_string(&self) -> String {
        format!("{} {}", self.items.join(" "), self.destination)
    }
}

pub(crate) trait UnixFile {
    fn set_execute(&mut self) -> std::io::Result<()>;
}

impl UnixFile for fs::File {
    fn set_execute(&mut self) -> std::io::Result<()> {
        self.set_permissions(fs::Permissions::from_mode(0o755))
    }
}
