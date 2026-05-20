use embedded_attestation_client::EmbeddedSnpAttestationClient;

fn main() {
    let client = EmbeddedSnpAttestationClient::new()
        .expect("Could not set up embedded SNP attestation client");
    client.run().expect("Attestation client execution failed")
}
