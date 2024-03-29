/* Copyright (c) Fortanix, Inc.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

use std::ffi::OsString;
use std::io::{self, Error, ErrorKind};
use std::path::{Path, PathBuf};
use std::{env, fs, str};

use mbedtls::x509::Certificate;
use pkix::pem;

fn read_certificates(path: PathBuf) -> io::Result<Vec<Vec<u8>>> {
    // todo: Allow all valid certificate formats according to https://datatracker.ietf.org/doc/html/rfc7468
    let begin = "-----BEGIN CERTIFICATE-----\n";
    let end = "-----END CERTIFICATE-----\n";
    let mut certs = Vec::new();
    let content = fs::read(path.clone())?;
    let content = str::from_utf8(&content).map_err(|e| Error::new(ErrorKind::InvalidData, e))?;

    let pems = content.char_indices().filter_map(|(idx, _c)| {
        let sub = &content[idx..];
        if sub.starts_with(begin) {
            sub.split_inclusive(end).next()
        } else {
            None
        }
    });

    for pem in pems {
        if let Some(der) = pem::pem_to_der(pem, None) {
            match Certificate::from_der(&der) {
                Ok(_) => {
                    certs.push(der);
                }
                Err(err) => {
                    println!("WARN: invalid certificate found in file {}. {:?}", path.display(), err)
                }
            }
        }
    }

    if 0 < certs.len() {
        println!("Collected {} root certificates", certs.len());
        Ok(certs)
    } else {
        Err(Error::new(
            ErrorKind::NotFound,
            "Failed to collect any root certificates, please specify `ROOT_CERTIFICATE_DIR` correctly",
        ))
    }
}

fn main() -> io::Result<()> {
    let out_dir = env::var_os("OUT_DIR").unwrap();
    let mut cert_list = Vec::new();
    let dir_location = if let Some(path) = env::var_os("ROOT_CERTIFICATE_DIR") {
        path
    } else {
        OsString::from("/usr/share/ca-certificates/mozilla")
    };
    let ca_certificates = fs::read_dir(&dir_location).expect("Directory does not exist");
    for cert_file in ca_certificates.filter_map(|f| f.ok()) {
        match read_certificates(cert_file.path()) {
            Ok(mut cert) => cert_list.append(&mut cert),
            Err(e) => eprintln!(
                "Failed to read certificate {}: {}",
                cert_file
                    .path()
                    .into_os_string()
                    .into_string()
                    .unwrap_or(String::from("<parse error>")),
                e
            ),
        }
    }
    if cert_list.len() != 0 {
        println!("{} root certificates found", cert_list.len());
    } else {
        eprintln!(
            "No root certificates found in \"{}\"",
            dir_location.into_string().unwrap_or(String::from("<parse error>"))
        );
        return Err(Error::new(ErrorKind::NotFound, "Didn't find any root certificates"));
    }
    let serialized_data: Vec<u8> = serde_cbor::to_vec(&cert_list).expect("Serialization Failed");

    let output_file = Path::new(&out_dir).join("cert_list");
    fs::write(output_file.as_path(), serialized_data).expect("Could not write root certificates to build directory");
    Ok(())
}
