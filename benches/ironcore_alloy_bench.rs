use std::env;
use std::time::Duration;

use criterion::{criterion_group, criterion_main, BatchSize, Criterion};
use ironcore_alloy::saas_shield::config::SaasShieldConfiguration;
use ironcore_alloy::standalone::config::{
    RotatableSecret, StandaloneConfiguration, StandaloneSecret, StandardSecrets, VectorSecret,
};
use ironcore_alloy::standard::{EncryptedDocument, PlaintextDocument, StandardDocumentOps};
use ironcore_alloy::vector::{PlaintextVector, VectorOps};
use ironcore_alloy::{
    AlloyMetadata, PlaintextBytes, SaasShield, Secret, SecretPath, Standalone, TenantId,
};
use ironcore_alloy::{DerivationPath, FieldId};
use itertools::Itertools;
use rand::rngs::ThreadRng;
use rand::{Rng, RngCore};
use rand_distr::{Alphanumeric, Uniform};
use tokio::runtime::Runtime;

fn benches(c: &mut Criterion) {
    let mut rng = rand::thread_rng();
    let mut key_bytes = [0u8; 64];
    rng.fill_bytes(&mut key_bytes);
    let secret = Secret::new([1u8; 64].to_vec()).unwrap();
    let standalone_secret = StandaloneSecret::new(1, secret.clone());
    let rotatable_secret = RotatableSecret::new(Some(standalone_secret), None).unwrap();

    let standard_secrets =
        StandardSecrets::new(Some(1), vec![StandaloneSecret::new(1, secret.clone())]).unwrap();
    let deterministic_secrets = [(
        SecretPath("secret_path".to_string()),
        rotatable_secret.clone(),
    )]
    .into();
    let vector_secrets = [(
        SecretPath("secret_path".to_string()),
        VectorSecret::new(1.23, rotatable_secret),
    )]
    .into();

    let config =
        StandaloneConfiguration::new(standard_secrets, deterministic_secrets, vector_secrets);
    let sdk = Standalone::new(&config);
    let metadata = AlloyMetadata::new_simple(TenantId("tenant".to_string()));

    let range = Uniform::from(-1.0..1.0);
    c.bench_function("encrypt d=1k", |b| {
        b.to_async(Runtime::new().unwrap()).iter_batched(
            || rng.clone().sample_iter(&range).take(1000).collect_vec(),
            |values| async {
                let vector = PlaintextVector {
                    plaintext_vector: values,
                    secret_path: SecretPath("secret_path".to_string()),
                    derivation_path: DerivationPath("derivation_path".to_string()),
                };
                sdk.vector().encrypt(vector, &metadata).await.unwrap();
            },
            BatchSize::SmallInput,
        )
    });

    fn random_word(rng: ThreadRng, length: usize) -> Vec<u8> {
        rng.sample_iter(&Alphanumeric)
            .take(length)
            .map(char::from)
            .collect::<String>()
            .into_bytes()
    }
    let roundtrip = |value: Vec<u8>| async {
        let encrypted = sdk
            .standard()
            .encrypt(
                PlaintextDocument([(FieldId("foo".to_string()), value.into())].into()),
                &metadata,
            )
            .await
            .unwrap();
        sdk.standard().decrypt(encrypted, &metadata).await.unwrap();
    };
    c.bench_function(
        format!("Standalone - encrypt/decrypt roundtrip 10B").as_str(),
        |b| {
            b.to_async(Runtime::new().unwrap()).iter_batched(
                || random_word(rng.clone(), 10),
                roundtrip,
                BatchSize::SmallInput,
            )
        },
    );
    c.bench_function(
        format!("Standalone - encrypt/decrypt roundtrip 10KB").as_str(),
        |b| {
            b.to_async(Runtime::new().unwrap()).iter_batched(
                || random_word(rng.clone(), 10_000),
                roundtrip,
                BatchSize::SmallInput,
            )
        },
    );
    c.bench_function(
        format!("Standalone - encrypt/decrypt roundtrip 100KB").as_str(),
        |b| {
            b.to_async(Runtime::new().unwrap()).iter_batched(
                || random_word(rng.clone(), 100_000),
                roundtrip,
                BatchSize::SmallInput,
            )
        },
    );
    // This test requires `computer_auth_hash` to be `pub`, so only
    // briefly un-comment and test, then re-comment.
    // {
    //     let mut iv: [u8; 12] = [0u8; 12];
    //     rng.fill_bytes(&mut iv);
    //     let approximation_factor: f32 = u16::MAX as f32;
    //     test_function(c, &mut rng, "authentication", |values| {
    //         ironcore_alloy::util::compute_auth_hash(&key, &approximation_factor, iv, values.iter());
    //     })
    // }
}

fn tsp_benches(c: &mut Criterion) {
    let rng = rand::thread_rng();
    let tsp_uri = env::var("TSP_ADDRESS").unwrap_or("http://localhost".to_string());
    let tsp_port = env::var("TSP_PORT").unwrap_or("32804".to_string());
    let tenant_id = env::var("TENANT_ID").unwrap_or("tenant-gcp-l".to_string());
    let api_key = env::var("API_KEY").unwrap_or("0WUaXesNgbTAuLwn".to_string());

    let config =
        SaasShieldConfiguration::new(format!("{tsp_uri}:{tsp_port}"), api_key, true, None).unwrap();
    let sdk = SaasShield::new(&config);
    let metadata = AlloyMetadata::new_simple(TenantId(tenant_id));

    let encrypt = |plaintext: PlaintextDocument| async {
        sdk.standard().encrypt(plaintext, &metadata).await.unwrap()
    };

    let decrypt = |encrypted: EncryptedDocument| async {
        sdk.standard().decrypt(encrypted, &metadata).await.unwrap()
    };

    let roundtrip = |plaintext: PlaintextDocument| async {
        let encrypted = encrypt(plaintext).await;
        decrypt(encrypted).await
    };

    fn random_word(rng: ThreadRng, length: usize) -> PlaintextBytes {
        PlaintextBytes(
            rng.sample_iter(&Alphanumeric)
                .take(length)
                .map(char::from)
                .collect::<String>()
                .into_bytes(),
        )
    }

    c.bench_function(
        format!("TSP - encrypt/decrypt roundtrip fixed document from TSC tests").as_str(),
        |b| {
            b.to_async(Runtime::new().unwrap()).iter_batched(
                || {
                    PlaintextDocument(
                        [(
                            FieldId("doc1".to_string()),
                            PlaintextBytes("Encrypt these bytes!".as_bytes().to_vec()),
                        )]
                        .into(),
                    )
                },
                roundtrip,
                BatchSize::SmallInput,
            )
        },
    );

    c.bench_function(format!("TSP - encrypt 10KB").as_str(), |b| {
        b.to_async(Runtime::new().unwrap()).iter_batched(
            || {
                PlaintextDocument(
                    [(
                        FieldId("doc1".to_string()),
                        random_word(rng.clone(), 10_000),
                    )]
                    .into(),
                )
            },
            encrypt,
            BatchSize::SmallInput,
        )
    });

    c.bench_function(format!("TSP - encrypt 100KB").as_str(), |b| {
        b.to_async(Runtime::new().unwrap()).iter_batched(
            || {
                PlaintextDocument(
                    [(
                        FieldId("doc1".to_string()),
                        random_word(rng.clone(), 100_000),
                    )]
                    .into(),
                )
            },
            encrypt,
            BatchSize::SmallInput,
        )
    });
}

criterion_group! {
    name = standalone_benchmarks;
    config = Criterion::default().measurement_time(Duration::from_secs(10));
    targets = benches
}

criterion_group! {
    name = tsp_benchmarks;
    config = Criterion::default().sample_size(10);
    targets = tsp_benches
}
criterion_main!(standalone_benchmarks, tsp_benchmarks);
