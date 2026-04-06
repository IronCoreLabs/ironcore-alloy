use rand::rngs::SysRng;
use rand::{CryptoRng, SeedableRng, TryCryptoRng, TryRng};
use rand_chacha::ChaCha20Rng;
use std::convert::Infallible;
use std::sync::{Arc, Mutex};

use super::hash256;

/// Default reseed threshold in bytes. Matches ThreadRng's 64 KiB interval.
const RESEED_THRESHOLD: usize = 64 * 1024;

/// A CSPRNG wrapper that automatically reseeds from system entropy periodically.
/// Implements [`CryptoRng`] so it can be used anywhere a `CryptoRng` is expected.
///
/// Set `reseed_threshold` to `None` to disable reseeding, which preserves
/// deterministic output for test RNGs.
pub(crate) struct ReseedingRng<T: CryptoRng + SeedableRng> {
    inner: T,
    bytes_generated: usize,
    reseed_threshold: Option<usize>,
}

impl<T: CryptoRng + SeedableRng> ReseedingRng<T> {
    fn new(rng: T) -> Self {
        ReseedingRng {
            inner: rng,
            bytes_generated: 0,
            reseed_threshold: Some(RESEED_THRESHOLD),
        }
    }

    fn new_seeded(seed: u64) -> Self {
        ReseedingRng {
            inner: T::seed_from_u64(seed),
            bytes_generated: 0,
            reseed_threshold: None,
        }
    }

    fn reseed_if_needed(&mut self) {
        if let Some(threshold) = self.reseed_threshold {
            if self.bytes_generated >= threshold {
                if let Ok(reseeded) = T::try_from_rng(&mut SysRng) {
                    self.inner = reseeded;
                }
                // On reseed failure, continue with existing state rather than panicking.
                // The current state is still cryptographically valid and the likelihood of
                // SysRng erroring is very low.
                self.bytes_generated = 0;
            }
        }
    }
}

impl<T: CryptoRng + SeedableRng> TryRng for ReseedingRng<T> {
    type Error = Infallible;

    fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
        self.reseed_if_needed();
        let val = self.inner.next_u32();
        self.bytes_generated = self.bytes_generated.saturating_add(4);
        Ok(val)
    }

    fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
        self.reseed_if_needed();
        let val = self.inner.next_u64();
        self.bytes_generated = self.bytes_generated.saturating_add(8);
        Ok(val)
    }

    fn try_fill_bytes(&mut self, dst: &mut [u8]) -> Result<(), Self::Error> {
        self.reseed_if_needed();
        self.inner.fill_bytes(dst);
        self.bytes_generated = self.bytes_generated.saturating_add(dst.len());
        Ok(())
    }
}

impl<T: CryptoRng + SeedableRng> TryCryptoRng for ReseedingRng<T> {}

pub(crate) type OurReseedingRng = ReseedingRng<ChaCha20Rng>;

pub(crate) fn create_reseeding_rng() -> Arc<Mutex<OurReseedingRng>> {
    let inner =
        ChaCha20Rng::try_from_rng(&mut SysRng).expect("Failed to seed RNG from system entropy");
    Arc::new(Mutex::new(ReseedingRng::new(inner)))
}

/// Creates a seeded RNG to use in test functions from the FFI and in the case
/// that users are creating a client for testing
pub(crate) fn create_test_seeded_rng(seed: u64) -> Arc<Mutex<OurReseedingRng>> {
    Arc::new(Mutex::new(ReseedingRng::new_seeded(seed)))
}

pub(crate) fn create_rng_maybe_seeded(maybe_seed: Option<i32>) -> Arc<Mutex<OurReseedingRng>> {
    maybe_seed
        //We don't care that the negative numbers turn into giant numbers for the seed we just need a static value.
        .map(|seed| create_test_seeded_rng(seed as u64))
        .unwrap_or_else(create_reseeding_rng)
}

pub(crate) fn create_rng<K: AsRef<[u8]>, T: AsRef<[u8]>>(key: K, hash_payload: T) -> ChaCha20Rng {
    ChaCha20Rng::from_seed(hash256(key, hash_payload))
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::Rng;

    #[test]
    fn seeded_rng_is_deterministic() {
        let rng1 = create_test_seeded_rng(42);
        let rng2 = create_test_seeded_rng(42);
        let val1: u64 = rng1.lock().unwrap().next_u64();
        let val2: u64 = rng2.lock().unwrap().next_u64();
        assert_eq!(val1, val2);
    }

    #[test]
    fn different_seeds_produce_different_output() {
        let rng1 = create_test_seeded_rng(1);
        let rng2 = create_test_seeded_rng(2);
        let val1: u64 = rng1.lock().unwrap().next_u64();
        let val2: u64 = rng2.lock().unwrap().next_u64();
        assert_ne!(val1, val2);
    }

    #[test]
    fn seeded_rng_does_not_reseed() {
        let rng = create_test_seeded_rng(99);
        let mut guard = rng.lock().unwrap();
        // Generate more than RESEED_THRESHOLD bytes
        let mut buf = [0u8; 1024];
        for _ in 0..100 {
            guard.fill_bytes(&mut buf);
        }
        // If reseeding happened, the bytes_generated counter would have reset.
        // With no reseeding, it should be at least 100 * 1024.
        assert!(guard.bytes_generated >= 100 * 1024);
        assert!(guard.reseed_threshold.is_none());
    }

    #[test]
    fn production_rng_reseeds_after_threshold() {
        let rng = create_reseeding_rng();
        let mut guard = rng.lock().unwrap();
        assert_eq!(guard.reseed_threshold, Some(RESEED_THRESHOLD));
        // Generate exactly the threshold number of bytes
        let mut buf = [0u8; 1024];
        for _ in 0..64 {
            guard.fill_bytes(&mut buf);
        }
        // bytes_generated should be at or above threshold
        assert!(guard.bytes_generated >= RESEED_THRESHOLD);
        // Next call should trigger a reseed, resetting the counter
        let _ = guard.next_u32();
        assert!(guard.bytes_generated < RESEED_THRESHOLD);
    }

    #[test]
    fn create_rng_produces_deterministic_output() {
        let rng1 = create_rng("key", "payload");
        let rng2 = create_rng("key", "payload");
        let val1: [u8; 32] = rng1.get_seed();
        let val2: [u8; 32] = rng2.get_seed();
        assert_eq!(val1, val2);
    }

    #[test]
    fn create_rng_different_inputs_differ() {
        let rng1 = create_rng("key1", "payload");
        let rng2 = create_rng("key2", "payload");
        assert_ne!(rng1.get_seed(), rng2.get_seed());
    }
}
