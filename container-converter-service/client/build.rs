#![deny(warnings)]
use nitro_enclaves_converter_client_generator::NitroEnclavesConverterApiSource;
use webservice_client_generator::api_definition::ApiSource;
use webservice_client_generator::languages::Rust;
use webservice_client_generator::code_generator::{CodeGenerator, SingleFileCodeGenerator};

use std::env;
use std::error::Error;
use std::path::Path;
use std::result::Result;

fn main() -> Result<(), Box<dyn Error>> {
    let output_directory = env::var_os("OUT_DIR").unwrap().into_string().unwrap();

    let output_file = Path::new(&output_directory).join("generated_models.rs").into();
    let api = NitroEnclavesConverterApiSource.api_definition();
    let lang = Box::new(Rust { operations_mutate_client: false }) as _;
    let generator = SingleFileCodeGenerator { output_file };
    Ok(generator.generate_code(&lang, &api)?)
}
