#![deny(warnings)]
use api_model::*;

use client_generator_base::reflection::types::TypeDef;
use model_types::*;
use webservice_client_generator::api_definition::{ApiDefinition, ApiSource};
use webservice_client_generator::{parse_route_groups, parse_types};

use model_types::AccountApprovalPolicyRepr as AccountApprovalPolicy;
use model_types::GroupApprovalPolicyRepr as GroupApprovalPolicy;
use model_types::QuorumPolicyRepr as QuorumPolicy;

pub struct NitroEnclavesConverterApiSource;

impl ApiSource for NitroEnclavesConverterApiSource {
    const NAME: &'static str = "NITRO_ENCLAVES_CONVERTER";
    const VERSION: &'static str = "0.1.0";

    fn api_definition(&self) -> ApiDefinition {
        let type_defs = Self::all_type_defs();
        let routes = parse_route_groups! {
            converter: [
                api_model::ConvertImage,
            ]
        };
        ApiDefinition {
            name: String::from(Self::NAME),
            type_defs,
            routes,
        }
    }
}

impl NitroEnclavesConverterApiSource {
    fn all_type_defs() -> Vec<TypeDef> {
        parse_types! {
            api_model_nitro_enclaves_converter_types,
            model_types_types,
        }
    }
}