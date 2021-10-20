#![deny(warnings)]
use nitro_enclaves_converter_client_generator::NitroEnclavesConverterApiSource;
use webservice_client_generator;

fn main() -> std::io::Result<()> {
    webservice_client_generator::main(NitroEnclavesConverterApiSource)
}