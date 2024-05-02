use criterion::{criterion_group, criterion_main, BatchSize, Criterion};
use ironcore_alloy::saas_shield::config::SaasShieldConfiguration;
use ironcore_alloy::standalone::config::{
    RotatableSecret, StandaloneConfiguration, StandaloneSecret, StandardSecrets, VectorSecret,
};
use ironcore_alloy::standard::{
    EncryptedDocument, PlaintextDocument, PlaintextDocuments, StandardDocumentOps,
};
use ironcore_alloy::vector::{PlaintextVector, VectorOps};
use ironcore_alloy::{
    AlloyMetadata, DocumentId, PlaintextBytes, SaasShield, Secret, SecretPath, Standalone, TenantId,
};
use ironcore_alloy::{DerivationPath, FieldId};
use itertools::Itertools;
use rand::rngs::ThreadRng;
use rand::{Rng, RngCore};
use rand_distr::Uniform;
use std::collections::HashMap;
use std::env;
use std::sync::Arc;
use std::time::Duration;
use tokio::runtime::{Handle, Runtime};

fn random_bytes(rng: &mut ThreadRng, length: usize) -> PlaintextBytes {
    let random_bytes = {
        let mut vec = vec![0; length];
        rng.fill_bytes(&mut vec);
        vec
    };
    PlaintextBytes(random_bytes)
}

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
    c.bench_function("vector_encrypt d=1k", |b| {
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

    let roundtrip = |value: PlaintextBytes| async {
        let encrypted = sdk
            .standard()
            .encrypt(
                PlaintextDocument([(FieldId("foo".to_string()), value)].into()),
                &metadata,
            )
            .await
            .unwrap();
        sdk.standard().decrypt(encrypted, &metadata).await.unwrap();
    };

    c.bench_function("Standalone - roundtrip 10B", |b| {
        b.to_async(Runtime::new().unwrap()).iter_batched(
            || random_bytes(&mut rng, 10),
            roundtrip,
            BatchSize::SmallInput,
        )
    });
    c.bench_function("Standalone - roundtrip 10KB", |b| {
        b.to_async(Runtime::new().unwrap()).iter_batched(
            || random_bytes(&mut rng, 10_000),
            roundtrip,
            BatchSize::SmallInput,
        )
    });
    c.bench_function("Standalone - roundtrip 100KB", |b| {
        b.to_async(Runtime::new().unwrap()).iter_batched(
            || random_bytes(&mut rng, 100_000),
            roundtrip,
            BatchSize::SmallInput,
        )
    });

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
    let mut rng = rand::thread_rng();
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

    c.bench_function("TSP - encrypt 1B", |b| {
        b.to_async(Runtime::new().unwrap()).iter_batched(
            || generate_plaintext(1, 1, &mut rng),
            encrypt,
            BatchSize::SmallInput,
        )
    });

    c.bench_function("TSP - encrypt 100B", |b| {
        b.to_async(Runtime::new().unwrap()).iter_batched(
            || generate_plaintext(100, 1, &mut rng),
            encrypt,
            BatchSize::SmallInput,
        )
    });

    c.bench_function("TSP - encrypt 10KB", |b| {
        b.to_async(Runtime::new().unwrap()).iter_batched(
            || generate_plaintext(10_000, 1, &mut rng),
            encrypt,
            BatchSize::SmallInput,
        )
    });

    c.bench_function("TSP - encrypt 1MB", |b| {
        b.to_async(Runtime::new().unwrap()).iter_batched(
            || generate_plaintext(1_000_000, 1, &mut rng),
            encrypt,
            BatchSize::SmallInput,
        )
    });

    c.bench_function("TSP - decrypt 1B", |b| {
        b.to_async(Runtime::new().unwrap()).iter_batched(
            || preencrypt(1, sdk.clone(), metadata.clone(), &mut rng),
            decrypt,
            BatchSize::SmallInput,
        )
    });

    c.bench_function("TSP - decrypt 100B", |b| {
        b.to_async(Runtime::new().unwrap()).iter_batched(
            || preencrypt(100, sdk.clone(), metadata.clone(), &mut rng),
            decrypt,
            BatchSize::SmallInput,
        )
    });

    c.bench_function("TSP - decrypt 10KB", |b| {
        b.to_async(Runtime::new().unwrap()).iter_batched(
            || preencrypt(10_000, sdk.clone(), metadata.clone(), &mut rng),
            decrypt,
            BatchSize::LargeInput,
        )
    });

    c.bench_function("TSP - decrypt 1MB", |b| {
        b.to_async(Runtime::new().unwrap()).iter_batched(
            || preencrypt(1_000_000, sdk.clone(), metadata.clone(), &mut rng),
            decrypt,
            BatchSize::SmallInput,
        )
    });

    c.bench_function("TSP - batch encrypt 10 documents, 10 fields, 10B", |b| {
        b.to_async(Runtime::new().unwrap()).iter_batched(
            || {
                let num_documents = 10;
                let num_fields = 10;
                let field_size = 10;
                PlaintextDocuments((0..num_documents).fold(HashMap::new(), |mut acc, i| {
                    let doc = generate_plaintext(field_size, num_fields, &mut rng);
                    acc.insert(DocumentId(format!("doc{}", i)), doc);
                    acc
                }))
            },
            |documents: PlaintextDocuments| async {
                sdk.standard()
                    .encrypt_batch(documents, &metadata)
                    .await
                    .unwrap()
            },
            BatchSize::SmallInput,
        )
    });
}

fn generate_plaintext(
    bytes_per_field: usize,
    num_fields: usize,
    rng: &mut ThreadRng,
) -> PlaintextDocument {
    PlaintextDocument((0..num_fields).fold(HashMap::new(), |mut acc, i| {
        acc.insert(
            FieldId(format!("field{}", i)),
            random_bytes(rng, bytes_per_field),
        );
        acc
    }))
}

/// Generate a random word of the provided size and encrypt it using the SDK/metadata.
/// This should then be passed in to the `setup` stage of `iter_batched`.
fn preencrypt(
    size: usize,
    sdk: Arc<SaasShield>,
    metadata: Arc<AlloyMetadata>,
    rng: &mut ThreadRng,
) -> EncryptedDocument {
    let plaintext =
        PlaintextDocument([(FieldId("doc1".to_string()), random_bytes(rng, size))].into());
    let handle = Handle::try_current().unwrap();
    std::thread::spawn(move || {
        // Using Handle::block_on to run async code in the new thread.
        handle
            .block_on(sdk.standard().encrypt(plaintext, &metadata))
            .unwrap()
    })
    .join()
    .unwrap()
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
