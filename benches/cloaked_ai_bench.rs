// use cloaked_ai::{
//     CloakedAiDecryptOps, CloakedAiEncryptOps, CloakedAiStandalone, DocumentMetadata, EncryptionKey,
//     Key, ScalingFactor, TenantId,
// };
use criterion::{criterion_group, criterion_main, Criterion};
// use itertools::Itertools;
// use rand::{rngs::ThreadRng, Rng, RngCore};
// use rand_distr::Uniform;

// // Test the function F with inputs of dimensionality 1,000 and 1,000,000
// fn test_function<F>(c: &mut Criterion, rng: &mut ThreadRng, name: &str, mut f: F)
// where
//     F: FnMut(Vec<f32>) -> (),
// {
//     let range = Uniform::from(-1.0..1.0);
//     c.bench_function(format!("{name} d=1k").as_str(), |b| {
//         b.iter_batched(
//             || rng.sample_iter(&range).take(1000).collect_vec(),
//             &mut f,
//             BatchSize::SmallInput,
//         )
//     });

//     c.bench_function(format!("{name} d=1M").as_str(), |b| {
//         b.iter_batched(
//             || rng.sample_iter(&range).take(1000000).collect_vec(),
//             &mut f,
//             BatchSize::LargeInput,
//         )
//     });
// }

fn benches(_c: &mut Criterion) {
    // let mut rng = rand::thread_rng();
    // let mut key_bytes = [0u8; 64];
    // rng.fill_bytes(&mut key_bytes);
    // let key = Key {
    //     scaling_factor: ScalingFactor(11.),
    //     key: EncryptionKey(key_bytes.to_vec().into()),
    // };
    // let sdk = CloakedAiStandalone::new(key, 1.0);
    // let doc_metadata = DocumentMetadata {
    //     tenant_id: TenantId("tenant".to_string()),
    // };

    // test_function(c, &mut rng, "encrypt", |values| {
    //     sdk.encrypt(values, &doc_metadata).unwrap();
    // });

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
    //         cloaked_ai_sdk::util::compute_auth_hash(&key, &approximation_factor, iv, values.iter());
    //     })
    // }
}

criterion_group!(benchmarks, benches);
criterion_main!(benchmarks);
