use super::{EncryptionKey, ScalingFactor, VectorEncryptionKey};
use crate::util;
use crate::util::{compute_auth_hash, create_rng, AuthHash};
use itertools::Itertools;
use ndarray::Array1;
use ndarray_rand::RandomExt;
use rand::{CryptoRng, RngCore};
use rand_chacha::ChaCha20Rng;
use rand_distr::{Distribution, StandardNormal, Uniform};
use std::{error::Error, fmt::Display};

const SHUFFLE_KEY:&str = "One Ring to rule them all, One Ring to find them, One Ring to bring them all, and in the darkness bind them";

#[derive(Debug)]
pub(crate) struct EncryptResult {
    pub(crate) ciphertext: Array1<f32>, // c
    pub(crate) iv: [u8; 12],            // n
    pub(crate) auth_hash: AuthHash,
}

#[derive(Debug)]
pub(crate) enum EncryptError {
    InvalidKey(String),
    OverflowError,
}

impl Display for EncryptError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            EncryptError::InvalidKey(msg) => write!(f, "{}", msg),
            EncryptError::OverflowError => {
                write!(f, "Embedding or approximation factor too large.")
            }
        }
    }
}

impl Error for EncryptError {}

#[derive(Debug, PartialEq)]
pub(crate) enum DecryptError {
    InvalidKey(String),
    InvalidAuthHash,
}

impl Display for DecryptError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DecryptError::InvalidKey(msg) => write!(f, "{}", msg),
            DecryptError::InvalidAuthHash => write!(f, "Auth Hash verification failed."),
        }
    }
}

impl Error for DecryptError {}

/// Get a vector sample the same length as the message from a multivariate normal distribution
/// with a mean of zero and a covariance matrix of identity. Step 3 in the paper's encrypt, step 2 in decrypt
/// u <-- N(0, I_d; coin_1)
fn sample_normal_vector(
    coin_rng: &mut rand_chacha::ChaCha20Rng,
    message_dimensionality: usize,
) -> Array1<f32> {
    // Because the multivariate normal distribution we need has mean 0 and an identity variance,
    // we don't have to do any decomposition for sampling, we can just sample straight from
    // the standard normal distribution.
    Array1::random_using(message_dimensionality, StandardNormal, coin_rng)
}

/// Get a uniform point. Later expanded on to be a uniform point normalized within our ball defined
/// by our approximation factor. Step 4 in encrypt, step 3 in decrypt.
/// x' <-- U(0, 1; coin_2)
fn sample_uniform_point(coin_rng: &mut rand_chacha::ChaCha20Rng) -> f32 {
    let uniform = Uniform::from(0.0..1.);
    // x' in the paper
    uniform.sample(coin_rng)
}
/// Step 5 in encrypt, step 4 in decrypt
/// x <-- (sB/4)(x')(1/d);
fn calculate_uniform_point_in_ball(
    scaling_factor: ScalingFactor,
    approximation_factor: f32,
    uniform_point: f32,
    message_dimensionality: usize,
) -> f32 {
    // with scaling factor 2^30 and approximation_factor 2^16, we fit under 2^53
    let d_dimensional_ball_radius = scaling_factor.0 / 4. * approximation_factor;
    // x in the paper
    d_dimensional_ball_radius * uniform_point.powf(1. / message_dimensionality as f32)
}

/// Calculate our normalized sampled vector, which acts as a fudge factor added to each encrypted message field. Step
/// 6 in encrypt, step 5 in decrypt.
/// λ_m <-- ux/||u||;
fn calculate_normalized_vector(
    multivariate_normal_sample: Array1<f32>, // u
    uniform_point_in_ball: f32,              // x
) -> Array1<f32> {
    let norm: f32 = multivariate_normal_sample.map(|x| x.powi(2)).sum().sqrt(); // ||u||
    multivariate_normal_sample * uniform_point_in_ball / norm
}

fn generate_normalized_vector(
    key: &VectorEncryptionKey,
    iv: [u8; 12],
    approximation_factor: f32,
    message_dimensionality: usize,
) -> Array1<f32> {
    let mut coin_rng = create_rng(&key.key.0, iv);
    // u
    let multivariate_normal_sample = sample_normal_vector(&mut coin_rng, message_dimensionality);
    // x'
    let uniform_point = sample_uniform_point(&mut coin_rng);
    // x
    let uniform_point_in_ball = calculate_uniform_point_in_ball(
        key.scaling_factor,
        approximation_factor,
        uniform_point,
        message_dimensionality,
    );
    // λ_m
    calculate_normalized_vector(multivariate_normal_sample, uniform_point_in_ball)
}

pub(crate) fn encrypt<R: RngCore + CryptoRng>(
    key: &VectorEncryptionKey, // K + s in the paper, key and scaling factor
    approximation_factor: f32,
    message: Array1<f32>, // m in the paper, vector
    rng: &mut R,
) -> Result<EncryptResult, EncryptError> {
    if key.scaling_factor.0 == 0. || key.scaling_factor.0 == -0. {
        return Err(EncryptError::InvalidKey(
            "Scaling factor cannot be zero".to_string(),
        ));
    }
    // d in the paper
    let message_dimensionality = message.len();
    // n <-$- {0,1}^l
    // iv length is an unanswered question. Using 12 because that's what we frequently use in other cases.
    // The paper doesn't define good values for l (which is the length)
    // n in the paper
    let iv: [u8; 12] = {
        let mut iv_internal = [0u8; 12];
        rng.fill_bytes(&mut iv_internal);
        iv_internal
    };

    // if we were given nothing to encrypt, hand them back their iv now
    let ciphertext = if message_dimensionality == 0 {
        Array1::zeros(message.raw_dim())
    } else {
        // λ_m
        let ball_normalized_vector =
            generate_normalized_vector(key, iv, approximation_factor, message_dimensionality);
        // c <-- sm + λ_m
        key.scaling_factor.0 * message + ball_normalized_vector
    };
    if ciphertext.iter().any(|f| !f.is_finite()) {
        Err(EncryptError::OverflowError)
    } else {
        let auth_hash = compute_auth_hash(key, &approximation_factor, iv, ciphertext.iter());
        Ok(EncryptResult {
            ciphertext,
            iv,
            auth_hash,
        })
    }
}

pub(crate) fn decrypt(
    key: &VectorEncryptionKey, // K + s
    approximation_factor: f32,
    encrypted_result: EncryptResult, // n + c
) -> Result<Array1<f32>, DecryptError> {
    if key.scaling_factor.0 == 0. || key.scaling_factor.0 == -0. {
        return Err(DecryptError::InvalidKey(
            "Scaling factor cannot be zero".to_string(),
        ));
    }

    if util::check_auth_hash(
        key,
        &approximation_factor,
        encrypted_result.iv,
        encrypted_result.ciphertext.iter(),
        encrypted_result.auth_hash,
    ) {
        // d in the paper
        let message_dimensionality = encrypted_result.ciphertext.len();
        // if we were given nothing to decrypt, hand them back their empty array now
        if message_dimensionality == 0 {
            return Ok(Array1::zeros(encrypted_result.ciphertext.raw_dim()));
        }
        // λ_m
        let ball_normalized_vector = generate_normalized_vector(
            key,
            encrypted_result.iv,
            approximation_factor,
            message_dimensionality,
        );
        // m <-- (c - λ_m) / s
        let message = (encrypted_result.ciphertext - ball_normalized_vector) / key.scaling_factor.0;
        Ok(message)
    } else {
        Err(DecryptError::InvalidAuthHash)
    }
}

fn create_rng_for_shuffle(key: &EncryptionKey) -> ChaCha20Rng {
    util::create_rng(&key.0, SHUFFLE_KEY.as_bytes())
}

pub(crate) fn shuffle<T: IntoIterator<Item = A>, A>(key: &EncryptionKey, input: T) -> Vec<A> {
    let mut rng: ChaCha20Rng = create_rng_for_shuffle(key);
    input
        .into_iter()
        .map(|i| (rng.next_u32(), i))
        .sorted_unstable_by_key(|(key, _)| *key)
        .map(|(_, v)| v)
        .collect()
}

pub(crate) fn unshuffle<T: IntoIterator<Item = A>, A>(key: &EncryptionKey, input: T) -> Vec<A> {
    let mut rng: ChaCha20Rng = create_rng_for_shuffle(key);
    // Because we're working with iterators, we get the indexes via enumerate and then unzip
    let (indexes_with_rand, values): (Vec<_>, Vec<_>) = input
        .into_iter()
        .enumerate()
        .map(|(src_index, a)| ((src_index, rng.next_u32()), a))
        .unzip();

    indexes_with_rand
        .into_iter()
        // Sort the values by the deterministic RNG values.
        .sorted_unstable_by_key(|(_, rng_value)| *rng_value)
        // Throw away the rng values, now that the indices are sorted by them.
        .map(|(src_index, _)| src_index)
        .zip(values)
        // Unshuffle the data by sorting by the src_index we randomized above
        .sorted_unstable_by_key(|(src_index, _)| *src_index)
        .map(|(_, a)| a)
        .collect()
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::vector::ScalingFactor;
    use approx::assert_ulps_eq;
    use proptest::proptest;
    use rand::SeedableRng;

    const ORIGINAL_APPROX_FACTOR: f32 = u16::MAX as f32;
    // sqrt(5), assuming plaintext embedding N = 5
    const NEW_APPROX_FACTOR: f32 = 2.236;
    #[test]
    fn encrypt_produces_known_value() {
        let mut k = rand_chacha::ChaCha20Rng::seed_from_u64(1u64);
        let result = encrypt(
            &VectorEncryptionKey {
                scaling_factor: ScalingFactor(1235.),
                key: EncryptionKey(
                    vec![
                        69, 96, 99, 158, 198, 112, 183, 161, 125, 73, 43, 39, 62, 7, 123, 10, 150,
                        190, 245, 139, 167, 118, 7, 121, 229, 68, 84, 110, 0, 14, 254, 200,
                    ]
                    .into(),
                ),
            },
            NEW_APPROX_FACTOR,
            vec![1., 2., 3., 4., 5.].into(),
            &mut k,
        )
        .unwrap();
        assert_eq!(
            result.ciphertext.to_vec(),
            vec![1415.0125, 2964.8154, 3906.9604, 4702.6606, 6102.1367]
        );
        assert_eq!(
            result.iv,
            [154, 55, 68, 80, 69, 96, 99, 158, 198, 112, 183, 161]
        );
        assert_eq!(
            result.auth_hash,
            AuthHash([
                217, 138, 3, 49, 185, 112, 93, 193, 40, 13, 87, 35, 129, 35, 135, 150, 118, 42,
                135, 181, 146, 137, 232, 138, 133, 160, 29, 212, 161, 205, 52, 246
            ])
        )
    }

    #[test]
    fn encrypt_works_with_empty_key() {
        let mut k = rand_chacha::ChaCha20Rng::seed_from_u64(1u64);
        let result = encrypt(
            &VectorEncryptionKey {
                scaling_factor: ScalingFactor(1235.),
                key: EncryptionKey(
                    vec![
                        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                        0, 0, 0, 0, 0, 0, 0,
                    ]
                    .into(),
                ),
            },
            ORIGINAL_APPROX_FACTOR,
            vec![1., 2., 3., 4., 5.].into(),
            &mut k,
        )
        .unwrap();
        assert_eq!(
            result.ciphertext.to_vec(),
            vec![-3591613.5, -439214.0, 7322809.0, 4174419.3, -4583661.0]
        );
        assert_eq!(
            result.iv,
            [154, 55, 68, 80, 69, 96, 99, 158, 198, 112, 183, 161]
        );
        assert_eq!(
            result.auth_hash,
            AuthHash([
                105, 50, 225, 168, 209, 144, 135, 250, 101, 123, 30, 134, 160, 214, 110, 30, 244,
                88, 226, 29, 65, 114, 211, 70, 194, 186, 180, 20, 72, 22, 99, 37
            ])
        )
    }

    #[test]
    fn encrypt_works_with_empty_key_and_message() {
        let mut k = rand_chacha::ChaCha20Rng::seed_from_u64(1u64);
        let result = encrypt(
            &VectorEncryptionKey {
                scaling_factor: ScalingFactor(1235.),
                key: EncryptionKey(
                    vec![
                        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                        0, 0, 0, 0, 0, 0, 0,
                    ]
                    .into(),
                ),
            },
            ORIGINAL_APPROX_FACTOR,
            vec![].into(),
            &mut k,
        )
        .unwrap();
        assert_eq!(result.ciphertext.len(), 0);
        assert_eq!(
            result.iv,
            [154, 55, 68, 80, 69, 96, 99, 158, 198, 112, 183, 161]
        );
    }

    fn encrypt_with_scaling_factor(s: f32) -> Result<EncryptResult, EncryptError> {
        let mut k = rand_chacha::ChaCha20Rng::seed_from_u64(1u64);
        encrypt(
            &VectorEncryptionKey {
                scaling_factor: ScalingFactor(s),
                key: EncryptionKey(
                    vec![
                        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                        0, 0, 0, 0, 0, 0, 0,
                    ]
                    .into(),
                ),
            },
            ORIGINAL_APPROX_FACTOR,
            vec![].into(),
            &mut k,
        )
    }

    #[test]
    fn encrypt_errors_zero_scaling_factor() {
        let result = encrypt_with_scaling_factor(0.0).unwrap_err();
        assert!(matches!(result, EncryptError::InvalidKey(_)));
        assert!(format!("{:?}", result).contains("Scaling factor"));
    }

    #[test]
    fn encrypt_errors_neg_zero_scaling_factor() {
        let result = encrypt_with_scaling_factor(0.0).unwrap_err();
        assert!(matches!(result, EncryptError::InvalidKey(_)));
        assert!(format!("{:?}", result).contains("Scaling factor"));
    }

    #[test]
    fn decrypt_fails_for_invalid_auth_hash() {
        let result = decrypt(
            &VectorEncryptionKey {
                scaling_factor: ScalingFactor(1235.),
                key: EncryptionKey(
                    vec![
                        69, 96, 99, 158, 198, 112, 183, 161, 125, 73, 43, 39, 62, 7, 123, 10, 150,
                        190, 245, 139, 167, 118, 7, 121, 229, 68, 84, 110, 0, 14, 254, 200,
                    ]
                    .into(),
                ),
            },
            ORIGINAL_APPROX_FACTOR,
            EncryptResult {
                ciphertext: vec![
                    4451592050750.542,
                    -2317609296247.8955,
                    1764294206720.3362,
                    884855869588.2513,
                    -18808007603170.01,
                ]
                .into(),
                iv: [154, 69, 198, 125, 62, 150, 167, 229, 0, 124, 17, 14],
                auth_hash: AuthHash([0u8; 32]),
            },
        )
        .unwrap_err();
        assert_eq!(result, DecryptError::InvalidAuthHash);
    }
    #[test]
    fn decrypt_reveals_known_value() {
        // This ciphertext and icl_metadata comes from `encrypt_produces_known_value()`
        let result = decrypt(
            &VectorEncryptionKey {
                scaling_factor: ScalingFactor(1235.),
                key: EncryptionKey(
                    vec![
                        69, 96, 99, 158, 198, 112, 183, 161, 125, 73, 43, 39, 62, 7, 123, 10, 150,
                        190, 245, 139, 167, 118, 7, 121, 229, 68, 84, 110, 0, 14, 254, 200,
                    ]
                    .into(),
                ),
            },
            NEW_APPROX_FACTOR,
            EncryptResult {
                ciphertext: vec![1390.5643, 2388.8906, 3766.532, 4970.743, 5517.305].into(),
                iv: [154, 69, 198, 125, 62, 150, 167, 229, 0, 124, 17, 14],
                auth_hash: AuthHash([
                    156, 177, 147, 169, 125, 110, 188, 61, 7, 69, 127, 189, 182, 191, 208, 203, 57,
                    155, 49, 52, 152, 171, 74, 80, 216, 8, 171, 249, 21, 162, 101, 59,
                ]),
            },
        )
        .unwrap();
        assert_eq!(result.to_vec(), vec![1., 2., 3., 4., 5.]);
    }

    fn decrypt_with_scaling_factor(s: f32) -> Result<Array1<f32>, DecryptError> {
        decrypt(
            &VectorEncryptionKey {
                scaling_factor: ScalingFactor(s),
                key: EncryptionKey(
                    vec![
                        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                        0, 0, 0, 0, 0, 0, 0,
                    ]
                    .into(),
                ),
            },
            ORIGINAL_APPROX_FACTOR,
            EncryptResult {
                ciphertext: vec![].into(),
                iv: [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
                auth_hash: AuthHash([0u8; 32]),
            },
        )
    }

    #[test]
    fn decrypt_errors_zero_scaling_factor() {
        let result = decrypt_with_scaling_factor(0.0).unwrap_err();
        assert!(matches!(result, DecryptError::InvalidKey(_)));
        assert!(format!("{:?}", result).contains("Scaling factor"));
    }
    #[test]
    fn decrypt_errors_neg_zero_scaling_factor() {
        let result = decrypt_with_scaling_factor(-0.0).unwrap_err();
        assert!(matches!(result, DecryptError::InvalidKey(_)));
        assert!(format!("{:?}", result).contains("Scaling factor"));
    }

    #[ignore]
    #[test]
    fn roundtrip_small_value() {
        let key = VectorEncryptionKey {
            scaling_factor: ScalingFactor(1.),
            key: EncryptionKey(
                vec![
                    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                    0, 0, 0, 0, 0, 0,
                ]
                .into(),
            ),
        };
        // let mut prf_rng = rand_chacha::ChaCha20Rng::seed_from_u64(1u64);
        let message: Array1<f32> = vec![-6.593513538421856e-163].into();
        let encrypt_result = encrypt(
            &key,
            ORIGINAL_APPROX_FACTOR,
            message.clone(),
            &mut rand::thread_rng(),
        )
        .unwrap();
        let decrypt_result = decrypt(&key, ORIGINAL_APPROX_FACTOR, encrypt_result).unwrap();

        assert_eq!(message, decrypt_result);
    }

    proptest!(
        #[test]
        fn roundtrip(arb_msg: Vec<u16>, key: [u8; 32], scaling_factor in 1..16777215) {
            let key = VectorEncryptionKey {
                scaling_factor: ScalingFactor(scaling_factor as f32),
                key: EncryptionKey(key.to_vec().into()),
            };
            let approximation_factor = 5.;
            let message: Array1<f32> = arb_msg.into_iter().map(|u| u as f32).collect();
            let encrypt_result = encrypt(&key, approximation_factor, message.clone(), &mut rand::thread_rng()).unwrap();
            let decrypt_result = decrypt(&key, approximation_factor, encrypt_result).unwrap();
            assert_ulps_eq!(message.as_slice().unwrap(), decrypt_result.as_slice().unwrap());
        }
    );

    fn get_key() -> VectorEncryptionKey {
        VectorEncryptionKey {
            scaling_factor: ScalingFactor(1235.),
            key: EncryptionKey(
                vec![
                    69, 96, 99, 158, 198, 112, 183, 161, 125, 73, 43, 39, 62, 7, 123, 10, 150, 190,
                    245, 139, 167, 118, 7, 121, 229, 68, 84, 110, 0, 14, 254, 200,
                ]
                .into(),
            ),
        }
    }
    fn shuffle_with_static_key<A>(values: Array1<A>) -> Array1<A> {
        shuffle(&get_key().key, values).into()
    }
    fn unshuffle_with_static_key<A>(values: Array1<A>) -> Array1<A> {
        unshuffle(&get_key().key, values).into()
    }
    #[test]
    fn shuffle_reorders_consistently() {
        let one: Array1<f64> = vec![0.1, -0.3, 0.5, -1.9, -100.0, -1.0, 30.0, -99.0].into();
        assert_eq!(
            shuffle_with_static_key(one.clone()),
            shuffle_with_static_key(one)
        );
    }

    fn manual_shuffle<A>(v: Vec<A>) -> Vec<A> {
        let indexes = vec![2, 0, 4, 3, 5, 6, 1, 7]; // Calculated manually
        v.into_iter()
            .zip(indexes)
            .sorted_unstable_by_key(|(_, index)| *index)
            .map(|(value, _)| value)
            .collect_vec()
    }

    #[test]
    fn shuffle_reorders_in_known_way() {
        let one: Array1<_> = vec![0.1, -0.3, 0.5, -1.9, -100.0, -1.0, 30.0, -99.0].into();
        assert_eq!(
            shuffle_with_static_key(one.clone()).to_vec(),
            manual_shuffle(one.to_vec())
        );

        let two: Array1<_> = (1..7).collect_vec().into();
        assert_eq!(
            shuffle_with_static_key(two.clone()).to_vec(),
            manual_shuffle(two.to_vec())
        );

        let three: Array1<_> = vec!["one", "two", "three", "four", "five", "six", "seven"].into();
        assert_eq!(
            shuffle_with_static_key(three.clone()).to_vec(),
            manual_shuffle(three.to_vec())
        );
    }

    #[test]
    fn shuffle_unshuffle_is_identity() {
        let one: Array1<_> = vec![0.1, -0.3, 0.5, -1.9, -100.0, -1.0, 30.0, -99.0].into();
        assert_eq!(
            unshuffle_with_static_key(shuffle_with_static_key(one.clone())).to_vec(),
            one.to_vec()
        );
        let two: Array1<_> = vec!["one", "two", "three", "four", "five", "six", "seven"].into();
        assert_eq!(
            unshuffle_with_static_key(shuffle_with_static_key(two.clone())).to_vec(),
            two.to_vec()
        );

        // Shuffle twice and unshuffle twice
        let one: Array1<_> = (1..100).into_iter().collect();
        assert_eq!(
            unshuffle_with_static_key(unshuffle_with_static_key(shuffle_with_static_key(
                shuffle_with_static_key(one.clone())
            )))
            .to_vec(),
            one.to_vec()
        );
    }
}
