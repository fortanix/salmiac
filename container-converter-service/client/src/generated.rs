#![allow(unused_imports, non_snake_case)]
use crate::{NitroEnclavesConverterClient, Result};
use crate::api_model::*;
use crate::operations::*;
use hyper::method::Method;
use serde::{Deserialize, Serialize, Deserializer};
use uuid::Uuid;

use std::collections::{HashMap, HashSet};
use std::fmt;

include!(concat!(env!("OUT_DIR"), "/generated_models.rs"));