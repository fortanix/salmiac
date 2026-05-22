/// This name macro is used in `build.rs` file, so that it does not have to be changed in more than one
/// location in the event of a binary name change.
/// A macro is used due to the requirements of compile time concatenation.

// #[macro_export]
macro_rules! attestation_client_bin_name {
    () => {
        "ccm-attestation-client-sevsnp"
    };
}

pub(crate) use attestation_client_bin_name;
