use std::{collections::HashMap, env};

use ironcore_alloy::{
    standalone::config::{StandaloneConfiguration, StandaloneSecret, StandardSecrets},
    standard::StandardDocumentOps,
    AlloyMetadata, Secret, Standalone, TenantId,
};
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize)]
struct Contact<'a> {
    pub name: &'a str,
    pub adddress: &'a str,
    pub ssn: &'a str,
}

#[tokio::main]
async fn main() {
    let standalone_secret =
        env::var("STANDALONE_SECRET").expect("STANDALONE_SECRET env variable must be set.");

    let config = StandaloneConfiguration::new(
        StandardSecrets::new(
            Some(1),
            vec![StandaloneSecret::new(
                1,
                Secret::new(standalone_secret.as_bytes().to_vec()).unwrap(),
            )],
        )
        .unwrap(),
        HashMap::new(),
        HashMap::new(),
    );

    let standalone = Standalone::new(&config);
    let metadata = AlloyMetadata::new_simple(TenantId("Tenant".to_string()));
    let jim_original = Contact {
        name: "Jim Bridger",
        adddress: "2825-519 Stone Creek Rd, Bozeman, MT 59715",
        ssn: "000-12-2345",
    };
    let jim_string = "jim".to_string();

    // Encrypt the Jim's personal information.
    let encrypted = standalone
        .standard()
        .encrypt(
            [(
                jim_string.clone(),
                serde_json::to_vec(&jim_original).unwrap(),
            )]
            .into(),
            &metadata,
        )
        .await
        .unwrap();

    // Decrypt Jim's personal information.
    let decrypted = standalone
        .standard()
        .decrypt(encrypted, &metadata)
        .await
        .unwrap();
    let parsed_jim: Contact =
        serde_json::from_slice(&decrypted.get(&jim_string).unwrap()[..]).unwrap();

    // Print the decrypted record.
    println!("Decrypted SSN: {}", parsed_jim.ssn);
    println!("Decrypted address: {}", parsed_jim.adddress);
    println!("Decrypted name: {}", parsed_jim.name);
}
