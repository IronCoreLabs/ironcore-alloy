use criterion::{criterion_group, criterion_main, BatchSize, Criterion};
use ironcore_alloy::standalone::config::{
    RotatableSecret, StandaloneConfiguration, StandaloneSecret, StandardSecrets, VectorSecret,
};
use ironcore_alloy::vector::{PlaintextVector, VectorOps};
use ironcore_alloy::DerivationPath;
use ironcore_alloy::{AlloyMetadata, Secret, SecretPath, Standalone, TenantId};
use itertools::Itertools;
use rand::{Rng, RngCore};
use rand_distr::Uniform;
use tokio::runtime::Runtime;
// // Test the function F with inputs of dimensionality 1,000 and 1,000,000
// async fn test_function<F, Fut>(c: &mut Criterion, rng: &mut ThreadRng, name: &str, mut f: F)
// where
//     F: FnMut(Vec<f32>) -> Fut,
//     Fut: Future<Output = ()>,
// {
//     let range = Uniform::from(-1.0..1.0);
//     c.bench_function(format!("{name} d=1k").as_str(), |b| {
//         b.to_async(Runtime::new().unwrap()).iter_batched(
//             || rng.sample_iter(&range).take(1000).collect_vec(),
//             |values| async { &mut f(values) },
//             BatchSize::SmallInput,
//         );
//     });

//     // c.bench_function(format!("{name} d=1M").as_str(), |b| {
//     //     b.iter_batched(
//     //         || rng.sample_iter(&range).take(1000000).collect_vec(),
//     //         &mut f,
//     //         BatchSize::LargeInput,
//     //     )
//     // });
// }

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
    c.bench_function(format!("encrypt d=1k").as_str(), |b| {
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

    // test_function(c, &mut rng, "encrypt/decrypt roundtrip", |values| {
    //     sdk.encrypt(values, &doc_metadata)
    //         .and_then(|encrypted| sdk.decrypt(encrypted, &doc_metadata))
    //         .unwrap();
    // });

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

criterion_group!(benchmarks, benches);
criterion_main!(benchmarks);
