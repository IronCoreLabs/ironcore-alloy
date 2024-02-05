use std::collections::HashMap;
use std::sync::Arc;

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
use serde_json::{self, json, Value};

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

    let data = vec![
        (
            json!(
                {
                    "title": "Fellowship of the ring",
                    "description": "The Fellowship of the Ring is the first of three volumes of the epic novel The Lord of the Rings by the English author J. R. R. Tolkien.",
                }
            ),
            vec![12.0f32; 10],
        ),
        (
            json!(
            {
                "title": "The Two Towers",
                "description": "The Two Towers is the second volume of J. R. R. Tolkien's high fantasy novel The Lord of the Rings."
            }),
            vec![1., 2., 3., 4., 5., 6., 7., 8., 9., 10.],
        ),
    ];

    let point_futures = data.into_iter().map(|(book_json, embedding)| {
        encrypt_to_point(alloy_client.clone(), &alloy_metadata, book_json, embedding)
    });
    let points: Vec<_> = futures::future::join_all(point_futures)
        .await
        .into_iter()
        .collect::<Result<Vec<_>, _>>()?;

    client
        .upsert_points_blocking(tenant_name, None, points, None)
        .await?;

    // Later we want to query, but because the embeddings are encrypted, we need to encrypt the query.
    let mut query_vectors = alloy_client
        .vector()
        .generate_query_vectors(
            HashMap::from([("".to_string(), create_plaintext_vector(&[11.; 10]))]),
            &alloy_metadata,
        )
        .await?;

    // Since we don't have keys in rotation we can just get the first vector.
    let query_vector = query_vectors
        .remove("")
        .unwrap()
        .into_iter()
        .next()
        .unwrap();

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
    //  &search_result = SearchResponse {
    //     result: [
    //         ScoredPoint {
    //             id: Some(
    //                 PointId {
    //                     point_id_options: Some(
    //                         Uuid(
    //                             "efdb2820-7029-4673-befa-db7b6fc75792",
    //                         ),
    //                     ),
    //                 },
    //             ),
    //             payload: {
    //                 "_encrypted_document": Value {
    //                     kind: Some(
    //                         StringValue(
    //                             "AAAAAYIAAG8KJAogWrZV+lcmyjAGxiWMmAWy6cV8d8771H2c69AC0cQVd6YQARJHEkUaQwoMBkK2FY4SJzYKWQ9fEjBwzIhVF4oSpWz+C16n4Iho+LJzODItu2oy9TxtO29Vj2F+2hHbeRARAwA1F357SZwaATF8R2dw6WFjMAcWdmzMFCD/ytazUlHAqVkH6Qngfv40HbQ14FM8ohN0I+3fwjUMgC2v3Hlu0SGfTLuvUAW6Q/khe7ID9d10R/In+m0L6V9ebwEFutLuk94/QxcGMUVq7AIPIkDsP0C9cd1iIGe0DF8W2aZTOiKxKbKk1P0QqfNV+e97tg8x4tMGkCzyC+VJjNzOJYA4z7f7YYJOhwEj82RUqAZOAs4E4UK/PjC3IYUU0+WZksrRCWmf5J1JDnSbXb6T5vXBz4S49sIdkofn2hKTWyQfppTAeg",
    //                         ),
    //                     ),
    //                 },
    //             },
    //             score: 0.99995387,
    //             version: 0,
    //             vectors: None,
    //             shard_key: None,
    //         },
    //         ScoredPoint {
    //             id: Some(
    //                 PointId {
    //                     point_id_options: Some(
    //                         Uuid(
    //                             "a358f199-df59-4dc9-9259-85dc81d7a43d",
    //                         ),
    //                     ),
    //                 },
    //             ),
    //             payload: {
    //                 "_encrypted_document": Value {
    //                     kind: Some(
    //                         StringValue(
    //                             "AAAAAYIAAG8KJAog6zeP2sTpd2ySI8szpMdTdcKxUEPAj6z6tSQOPXFNRd8QARJHEkUaQwoMxOUFUmR4fCStyfQvEjDwhGCXE7hbPijhJQcK5BYrFIol5AOl8xwD8p7GfKDFKcpZhC9W4a4sPjkm6oGoWycaATH3mMssblX4OH2xk1Lmcj3k19ptPqGoErPmgXce6x6ojIWg8G9CSbY81C2v4yLEkj9/RkqU0nIf2of+7g34rxmgCThideXMdYr+p72zyNYAy6j2no1OxpbcH8l6KFwFb4AVUplUiYS7bGwnIh7Wj3DQOi/Ooc7PVq3+h3TtcmxaH5m3IPri/BEExFFpdTrgyEFZpAsM3rSXMktP7+Iicoz9GN1nwHi6aBhQLw",
    //                         ),
    //                     ),
    //                 },
    //             },
    //             score: 0.8886131,
    //             version: 0,
    //             vectors: None,
    //             shard_key: None,
    //         },
    //     ],
    //     time: 0.000709083,
    // }

    let found_point = search_result.result.into_iter().next().unwrap();
    let mut payload = found_point.payload;
    let encrypted_payload = payload.remove(ENCRYPTED_DOC_KEY).unwrap();
    // Since the payload is encrypted, get the encrypted bytes.
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

fn create_plaintext_vector(v: &[f32]) -> PlaintextVector {
    PlaintextVector {
        plaintext_vector: v.to_vec(),
        secret_path: SecretPath("".to_string()),
        derivation_path: DerivationPath("".to_string()),
    }
}

fn create_alloy_client() -> Result<std::sync::Arc<Standalone>> {
    // An example key, obviously this would come from a secure location in a real situation.
    let standalone_secret =
        hex_literal::hex!("f8cba200fb44b891d6a389858ae699d57b7ff48572cdcb9e5ed1d4364bf531b8");
    let config = StandaloneConfiguration::new(
        StandardSecrets::new(
            Some(1),
            vec![StandaloneSecret::new(
                1,
                Secret::new(standalone_secret.to_vec()).unwrap(),
            )],
        )
        .unwrap(),
        Default::default(),
        HashMap::from([(
            SecretPath("".to_string()),
            VectorSecret::new(
                2.0,
                RotatableSecret::new(
                    Some(StandaloneSecret::new(
                        1,
                        Secret::new(standalone_secret.to_vec())?,
                    )),
                    None,
                )?,
            ),
        )]),
    );

    Ok(ironcore_alloy::Standalone::new(&config))
}

async fn encrypt_to_point(
    alloy_client: Arc<Standalone>,
    alloy_metadata: &AlloyMetadata,
    book_json: Value,
    embedding: Vec<f32>,
) -> Result<PointStruct> {
    // Encrypt the whole book using probabilistic encryption
    let encrypted_json = alloy_client
        .standard_attached()
        .encrypt(
            serde_json::to_string(&book_json)
                .unwrap()
                .as_bytes()
                .to_vec(),
            &alloy_metadata,
        )
        .await?;

    // Encrypt the embedding as well.
    let encrypted_vector = alloy_client
        .vector()
        .encrypt(create_plaintext_vector(&embedding), &alloy_metadata)
        .await?;

    let payload: Payload = {
        let mut inner = Payload::new();
        inner.insert(
            ENCRYPTED_DOC_KEY,
            base64::engine::general_purpose::STANDARD_NO_PAD.encode(encrypted_json.0),
        );
        inner
    };

    Ok(PointStruct::new(
        uuid::Uuid::new_v4().to_string(),
        encrypted_vector.encrypted_vector,
        payload,
    ))
}
