use std::collections::HashMap;

use anyhow::Result;
use base64::Engine;
use ironcore_alloy::standalone::config::{
    RotatableSecret, StandaloneConfiguration, StandaloneSecret, StandardSecrets, VectorSecret,
};
use ironcore_alloy::standard_attached::StandardAttachedDocumentOps;
use ironcore_alloy::vector::{PlaintextVector, VectorOps};
use ironcore_alloy::{AlloyMetadata, DerivationPath, Secret, SecretPath, Standalone, TenantId};
use qdrant_client::prelude::*;
use qdrant_client::qdrant::vectors_config::Config;
use qdrant_client::qdrant::{CreateCollection, SearchPoints, VectorParams, VectorsConfig};
use serde_json::{self, json};

const ENCRYPTED_DOC_KEY: &str = "_encrypted_document";

#[tokio::main]
async fn main() -> Result<()> {
    // Example of top level client
    let client = QdrantClient::from_url("http://localhost:6334").build()?;
    let base64_engine = base64::engine::general_purpose::STANDARD_NO_PAD;
    let alloy_client = create_alloy_client()?;
    let tenant_name = "tenant1";
    let tenant_id = TenantId(tenant_name.to_string());
    let alloy_metadata = AlloyMetadata::new_simple(tenant_id);
    client.delete_collection(tenant_name).await?;

    client
        .create_collection(&CreateCollection {
            collection_name: tenant_name.into(),
            vectors_config: Some(VectorsConfig {
                config: Some(Config::Params(VectorParams {
                    size: 10,
                    distance: Distance::Cosine.into(),
                    ..Default::default()
                })),
            }),
            ..Default::default()
        })
        .await?;

    let json = json!(
        {
            "foo": "Bar",
            "bar": 12,
            "baz": {
                "qux": "quux"
            }
        }
    );

    // Since the embedding is sensitive, we'll encrypt the text as well. We can encrypt it as a single blob since we don't
    // need to match on pieces for this example. If we wanted to match on some fields we could instead deterministically encrypt those fields.
    let encrypted_json = alloy_client
        .standard_attached()
        .encrypt(
            serde_json::to_string(&json).unwrap().as_bytes().to_vec(),
            &alloy_metadata,
        )
        .await?;

    // Encrypt the embedding as well.
    let encrypted_vector = alloy_client
        .vector()
        .encrypt(create_plaintext_vector(vec![12.; 10]), &alloy_metadata)
        .await?;

    let payload: Payload = {
        let mut inner = Payload::new();
        inner.insert(ENCRYPTED_DOC_KEY, base64_engine.encode(encrypted_json.0));
        inner
    };

    let points = vec![PointStruct::new(
        0,
        encrypted_vector.encrypted_vector,
        payload,
    )];
    client
        .upsert_points_blocking(tenant_name, None, points, None)
        .await?;

    // Later we want to query, but because the embeddings are encrypted, we need to encrypt the query.
    let query_vector = alloy_client
        .vector()
        .encrypt(create_plaintext_vector(vec![11.; 10]), &alloy_metadata)
        .await?;
    let search_result = client
        .search_points(&SearchPoints {
            collection_name: tenant_name.into(),
            vector: query_vector.encrypted_vector,
            filter: None,
            limit: 10,
            with_payload: Some(true.into()),
            ..Default::default()
        })
        .await?;
    // Note that the encrypted result will not be deterministic because of a different IV each run.
    dbg!(&search_result);
    // &search_result = SearchResponse {
    //     result: [
    //         ScoredPoint {
    //             id: Some(
    //                 PointId {
    //                     point_id_options: Some(
    //                         Num(
    //                             0,
    //                         ),
    //                     ),
    //                 },
    //             ),
    //             payload: {
    //                 "_encrypted_document": Value {
    //                     kind: Some(
    //                         StringValue(
    //                             "AAAAAYIAAG8KJAograI69h2cKUS97PbwJEgbjYbZbQLrQD2I9BHTq2a38X8QARJHEkUaQwoMQ54URzJDiUNW7G5JEjCPhU1WpnaD8cMkmr+zRjbya+QHvAh5lNwIucUgEiOFCxmwixy0t3tAN6dyhf+OPx4aATGHaBVZrqZ6GwALR9HOoc2sOMyvQXyEMwZLRWfUcO25pKkIGuNLf02zAqijyDH2YXJ5TJsAAxsUcDXBUkY9qEJui8qIAQQlLA",
    //                         ),
    //                     ),
    //                 },
    //             },
    //             score: 0.9999996,
    //             version: 0,
    //             vectors: None,
    //             shard_key: None,
    //         },
    //     ],
    //     time: 0.000914,
    // }

    let found_point = search_result.result.into_iter().next().unwrap();
    let mut payload = found_point.payload;
    let encrypted_payload = payload.remove(ENCRYPTED_DOC_KEY).unwrap();
    // Since the payload has the encrypted, get the encrypted bytes.
    let encrypted_bytes = base64_engine
        .decode(encrypted_payload.as_str().unwrap())
        .unwrap();
    let decrypted_document = alloy_client
        .standard_attached()
        .decrypt(
            ironcore_alloy::standard_attached::EncryptedAttachedDocument(encrypted_bytes),
            &alloy_metadata,
        )
        .await?;
    println!(
        "Decrypted document: {}",
        std::str::from_utf8(&decrypted_document)?
    );

    Ok(())
}

fn create_plaintext_vector(v: Vec<f32>) -> PlaintextVector {
    PlaintextVector {
        plaintext_vector: v,
        secret_path: SecretPath("".to_string()),
        derivation_path: DerivationPath("".to_string()),
    }
}

fn create_alloy_client() -> Result<std::sync::Arc<Standalone>> {
    // An example key, obviously this would come from a secure location in a real situation.
    let standalone_secret = "f8cba200fb44b891d6a389858ae699d57b7ff48572cdcb9e5ed1d4364bf531b8";
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
        HashMap::from([(
            SecretPath("".to_string()),
            VectorSecret::new(
                0.1,
                RotatableSecret::new(
                    Some(StandaloneSecret::new(
                        1,
                        Secret::new(standalone_secret.as_bytes().to_vec())?,
                    )),
                    None,
                )?,
            ),
        )]),
    );

    Ok(ironcore_alloy::Standalone::new(&config))
}
