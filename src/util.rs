use crate::{errors::AlloyError, AlloyMetadata, FieldId, TenantId, VectorEncryptionKey};
use ironcore_documents::v5::key_id_header::KeyId;
use itertools::Itertools;
use protobuf::Message;
use rand::{
    rngs::{adapter::ReseedingRng, OsRng},
    CryptoRng, RngCore, SeedableRng,
};
use rand_chacha::{ChaCha20Core, ChaCha20Rng};
use ring::hmac::{Key as HMACKey, HMAC_SHA256, HMAC_SHA512};
use std::{
    collections::HashMap,
    sync::{Arc, Mutex, MutexGuard},
};

/// number of bytes that can be read from before it rngs are reseeded. 1 MiB
const BYTES_BEFORE_RESEEDING: u64 = 1024 * 1024;

pub(crate) type OurReseedingRng = ReseedingRng<ChaCha20Core, OsRng>;

#[derive(Debug, PartialEq)]
pub(crate) struct AuthHash(pub(crate) [u8; 32]);

/// Helper function to avoid `Mutex` noise at each call site. Must be derefed to use.
pub(crate) fn get_rng<R: RngCore + CryptoRng>(rng: &Arc<Mutex<R>>) -> MutexGuard<'_, R> {
    // should be safe... panics if the current thread holds the lock, we'll need to test to see how the FFI makes
    // threads appear. Also panics if poisoned, which I don't think we care about cause everything is dying then.
    rng.lock().unwrap()
}

pub(crate) fn hash256<K: AsRef<[u8]>, T: AsRef<[u8]>>(key: K, payload: T) -> [u8; 32] {
    let hmac_key = HMACKey::new(HMAC_SHA256, key.as_ref());
    ring::hmac::sign(&hmac_key, payload.as_ref())
        .as_ref()
        // this is safe because digest output len (SHA256_OUTPUT_LEN) == 32
        .try_into()
        .unwrap()
}

pub(crate) fn hash512<K: AsRef<[u8]>, T: AsRef<[u8]>>(key: K, payload: T) -> [u8; 64] {
    let hmac_key = HMACKey::new(HMAC_SHA512, key.as_ref());
    ring::hmac::sign(&hmac_key, payload.as_ref())
        .as_ref()
        // this is safe because digest output len (SHA256_OUTPUT_LEN) == 32
        .try_into()
        .unwrap()
}

pub(crate) fn compute_auth_hash<'a, A: AsRef<[u8]>, B: Iterator<Item = &'a f32>>(
    key: &VectorEncryptionKey,
    approximation_factor: &f32,
    iv: A,
    encrypted_embedding: B,
) -> AuthHash {
    let hmac_key = HMACKey::new(HMAC_SHA256, &key.key.0);
    let mut ctx = ring::hmac::Context::with_key(&hmac_key);
    ctx.update(key.scaling_factor.0.to_be_bytes().as_ref());
    ctx.update(approximation_factor.to_be_bytes().as_ref());
    ctx.update(iv.as_ref());
    for embedding in encrypted_embedding {
        ctx.update(embedding.to_be_bytes().as_ref());
    }
    let signature: [u8; 32] = ctx
        .sign()
        .as_ref()
        .try_into() // this is safe because digest output len (SHA256_OUTPUT_LEN) == 32
        .unwrap();
    AuthHash(signature)
}

pub(crate) fn check_auth_hash<'a, A: AsRef<[u8]>, B: Iterator<Item = &'a f32>>(
    key: &VectorEncryptionKey,
    approximation_factor: &f32,
    iv: A,
    encrypted_embedding: B,
    auth_hash: AuthHash,
) -> bool {
    compute_auth_hash(key, approximation_factor, iv, encrypted_embedding) == auth_hash
}

pub(crate) fn create_reseeding_rng() -> Arc<Mutex<OurReseedingRng>> {
    Arc::new(Mutex::new(ReseedingRng::new(
        ChaCha20Core::from_entropy(),
        BYTES_BEFORE_RESEEDING,
        OsRng,
    )))
}

/// Creates a seeded RNG that won't actually ever reseed to use in test functions from the FFI.
#[cfg(test)]
pub(crate) fn create_test_seeded_rng(seed: u64) -> Arc<Mutex<OurReseedingRng>> {
    //Note that this will never actually reseed because the threshold is 0.
    Arc::new(Mutex::new(ReseedingRng::new(
        ChaCha20Core::seed_from_u64(seed),
        0,
        OsRng,
    )))
}

pub(crate) fn create_rng<K: AsRef<[u8]>, T: AsRef<[u8]>>(key: K, hash_payload: T) -> ChaCha20Rng {
    ChaCha20Rng::from_seed(hash256(key, hash_payload))
}

pub(crate) struct BatchResult<U> {
    pub successes: HashMap<FieldId, U>,
    pub failures: HashMap<FieldId, AlloyError>,
}

/// Applies the function `func` to all the values of `collection`, then partitions them into
/// success and failure hashmaps. Note that the value type for failures is currently `String`
/// because of an issue with uniffi exporting errors.
pub(crate) fn collection_to_batch_result<T, U, F, I>(collection: I, func: F) -> BatchResult<U>
where
    F: Fn(T) -> Result<U, AlloyError>,
    I: IntoIterator<Item = (FieldId, T)>,
{
    let (successes, failures) = collection
        .into_iter()
        .map(|(key, value)| match func(value) {
            Ok(x) => Ok((key, x)),
            Err(x) => Err((key, x)),
        })
        .partition_result();
    BatchResult {
        successes,
        failures,
    }
}

/// Returns `true` if the key IDs and tenant IDs are identical, otherwise `false`.
pub(crate) fn check_rotation_no_op(
    encrypted_key_id: KeyId,
    maybe_current_key: &Option<u32>,
    new_tenant_id: &TenantId,
    metadata: &AlloyMetadata,
) -> bool {
    maybe_current_key == &Some(encrypted_key_id.0) && new_tenant_id == &metadata.tenant_id
}

pub(crate) fn v4_proto_from_bytes<B: AsRef<[u8]>>(
    b: B,
) -> Result<ironcore_documents::icl_header_v4::V4DocumentHeader, AlloyError> {
    Ok(Message::parse_from_bytes(b.as_ref())?)
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::{vector::EncryptionKey, vector::ScalingFactor};
    use base64::Engine;
    use bytes::Bytes;
    use itertools::Itertools;
    use proptest::prelude::*;
    use std::collections::HashSet;

    // Test to show that an empty key produces a reasonable signature.
    #[test]
    fn test_hash_empty_key() {
        assert_eq!(
            hash256(&Bytes::default(), &[1u8]).to_vec(),
            vec![
                61, 122, 251, 102, 49, 36, 236, 191, 44, 149, 63, 134, 61, 79, 200, 121, 110, 235,
                45, 55, 43, 100, 170, 213, 134, 151, 236, 82, 100, 100, 156, 219
            ]
        );
    }

    proptest! {
        // This is to test that values written out and read by serde_json work the same as
        // just generic f32 values.
        #[test]
        fn roundtrip(arb_msg: Vec<f32>, key: [u8; 32], iv: [u8; 12], scaling_factor: u32) {
            let f32_scaling_factor = if scaling_factor == 0 {
                1.
            } else {
                scaling_factor as f32
            };
            let key = VectorEncryptionKey {
                scaling_factor: ScalingFactor(f32_scaling_factor),
                key: EncryptionKey(key.to_vec().into()),
            };

            let first_hash = compute_auth_hash(&key, &1.2f32, iv, arb_msg.iter());
            let roundtrip: Vec<f32> =
                serde_json::from_str(serde_json::to_string(&arb_msg).unwrap().as_str()).unwrap();
            let second_hash = compute_auth_hash(&key, &1.2f32, iv, roundtrip.iter());

            proptest::prop_assert_eq!(first_hash, second_hash);
        }

        #[test]
        fn ascii85_encoding_produces_consistent_prefix(arb_msg: [u8; 2], id in 1..u32::MAX) {

            let prefix_func = |prefix_bytes:&[u8]| {
                // When we calculate the prefix, we need to pad out to the full 4 byte width
                // so that the algorithm produces the correct character in the 2nd position.
                // This is due to the way 85 bit encodings change the last character if you don't
                // have a full 4 byte input.
                // Note that this test is different because it's using 2 random bytes as the padding
                // here showing that it's not relevant what the padding was, just that it's present.
                let prefix_padded = [&prefix_bytes[..], &arb_msg[..]].concat();
                let mut starting = ascii85::encode(prefix_padded.as_slice());
                // drop the last 2 chars as they're the padding `~>` in the case of ascii85
                starting.pop();
                starting.pop();
                // drop the last 3 characters of the produced string
                // as they could be affected by the random bytes
                starting.pop();
                starting.pop();
                starting.pop();
                starting
            };

            let encode_func = |whole:&[u8]| ascii85::encode(whole);
            encoding_produces_consistent_prefix(id,&arb_msg[..], prefix_func, encode_func)?
        }

        // Generating 4 bytes for arb_msg since I want to test padding cases without a full chunk
        #[test]
        fn z85_encoding_produces_consistent_prefix(arb_msg: [u8; 4], id in 1..u32::MAX) {

            let prefix_func = |prefix_bytes:&[u8]| {
                // When we calculate the prefix, we need to pad out to the full 4 byte width
                // so that the algorithm produces the correct character in the 2nd position.
                // This is due to the way 85 bit encodings change the last character if you don't
                // have a full 4 byte input.
                let prefix_padded = [&prefix_bytes[..], &[0,0]].concat();
                let mut starting = z85::encode(prefix_padded.as_slice());
                // drop the last 3 characters of the produced string
                // as they could be affected by the random bytes
                starting.pop();
                starting.pop();
                starting.pop();
                starting
            };

            let encode_func = |whole:&[u8]| z85::encode(whole);
            encoding_produces_consistent_prefix(id,&arb_msg[..], prefix_func, encode_func)?
        }

        // Generating 4 bytes for arb_msg since I want to test padding cases without a full chunk
        #[test]
        fn base85_encoding_produces_consistent_prefix(arb_msg: [u8; 4], id in 1..u32::MAX) {

            let prefix_func = |prefix_bytes:&[u8]| {
                // When we calculate the prefix, we need to pad out to the full 4 byte width
                // so that the algorithm produces the correct character in the 2nd position.
                // This is due to the way 85 bit encodings change the last character if you don't
                // have a full 4 byte input.
                let prefix_padded = [&prefix_bytes[..], &[0, 0]].concat();
                let mut starting = base85::encode(prefix_padded.as_slice());
                // drop the last 3 characters of the produced string
                // as they could be affected by the random bytes
                starting.pop();
                starting.pop();
                starting.pop();
                starting
            };

            let encode_func = |whole:&[u8]| base85::encode(whole);
            encoding_produces_consistent_prefix(id,&arb_msg[..], prefix_func, encode_func)?
        }
        // Generating 4 bytes for arb_msg since I want to test padding cases without a full chunk
        #[test]
        fn base64_encoding_produces_consistent_prefix(arb_msg: [u8; 4], id in 1..u32::MAX) {

            let prefix_func = |prefix_bytes:&[u8]| {
                base64::engine::general_purpose::STANDARD_NO_PAD.encode(prefix_bytes)
            };

            let encode_func = |whole:&[u8]| base64::engine::general_purpose::STANDARD.encode(whole);
            encoding_produces_consistent_prefix(id,&arb_msg[..], prefix_func, encode_func)?
        }

        // Generating 4 bytes for arb_msg since I want to test padding cases without a full chunk
        #[test]
        fn base64_url_encoding_produces_consistent_prefix(arb_msg: [u8; 4], id in 1..u32::MAX) {

            let prefix_func = |prefix_bytes:&[u8]| {
                base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(prefix_bytes)
            };

            let encode_func = |whole:&[u8]| base64::engine::general_purpose::URL_SAFE.encode(whole);
            encoding_produces_consistent_prefix(id,&arb_msg[..], prefix_func, encode_func)?
        }
    }

    // Note that this does _not_ work if you allow an id of 0
    fn encoding_produces_consistent_prefix<F, G>(
        id: u32,
        arb_msg: &[u8],
        encode_prefix: F,
        encode_message: G,
    ) -> Result<(), TestCaseError>
    where
        F: Fn(&[u8]) -> String,
        G: Fn(&[u8]) -> String,
    {
        let second_byte_padding = 0u8;

        // We want to check that if each of the bits of the first padding byte were set
        // that the resulting
        let unique_padding_byte_vec = vec![128, 64, 32, 16, 8, 4, 2, 1, 0u8];
        let unique_padding_count = unique_padding_byte_vec.len();
        // A place to collect all the prefixes we calculate using the above vec.
        let mut prefixes: HashSet<String> = HashSet::new();
        for first_byte_padding in unique_padding_byte_vec {
            // These are the bytes we'll put on the encrypted data.
            let prefix_bytes = [
                &u32::to_be_bytes(id)[..],
                &[first_byte_padding],
                &[second_byte_padding],
            ]
            .concat();
            // This is the string representation of the prefix bytes.
            let prefix = encode_prefix(prefix_bytes.as_slice());
            let full_vec = prefix_bytes
                .into_iter()
                .chain(arb_msg.to_vec().into_iter())
                .collect_vec();
            // String encoded prefix + arbitrary bytes.
            let encoded_string = encode_message(full_vec.as_slice());
            // Our calculated prefix should always be on the front of the encoded message.
            prop_assert!(encoded_string.starts_with(&prefix));
            prefixes.insert(prefix);
        }
        prop_assert_eq!(prefixes.len(), unique_padding_count);
        Ok(())
    }
}
