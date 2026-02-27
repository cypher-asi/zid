//! Root secret (NeuralKey) from which all keys are derived.

use rand_core::{CryptoRng, RngCore};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::error::CryptoError;

/// A 256-bit root secret from which all identity and machine keys are derived.
///
/// Generated via CSPRNG. Must be stored securely (e.g. encrypted at rest,
/// Shamir-split for recovery). Zeroized on drop.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct NeuralKey([u8; 32]);

impl NeuralKey {
    /// Generate a new NeuralKey from a cryptographically secure RNG.
    pub fn generate(rng: &mut (impl RngCore + CryptoRng)) -> Self {
        let mut bytes = [0u8; 32];
        rng.fill_bytes(&mut bytes);
        Self(bytes)
    }

    /// Access the raw key material (for HKDF derivation only).
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Copy the raw key material (needed by Shamir split).
    pub fn to_bytes(&self) -> [u8; 32] {
        self.0
    }

    /// Reconstruct a NeuralKey from raw bytes (e.g. after Shamir recovery).
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Validate that the NeuralKey has sufficient entropy.
    ///
    /// Uses multiple statistical tests inspired by NIST SP 800-90B:
    /// - Shannon entropy estimation (minimum 3.5 bits/byte for 32-byte sample)
    /// - Unique byte count (minimum 16 unique values)
    /// - Run length test for sequential patterns (max run <= 10)
    /// - Two-byte and four-byte repeating pattern detection
    pub fn validate_entropy(&self) -> Result<(), CryptoError> {
        if self.0.iter().all(|&b| b == 0) {
            return Err(CryptoError::InsufficientEntropy(
                "NeuralKey cannot be all zeros".into(),
            ));
        }

        let first = self.0[0];
        if self.0.iter().all(|&b| b == first) {
            return Err(CryptoError::InsufficientEntropy(
                "repeated single-byte pattern".into(),
            ));
        }

        let entropy = shannon_entropy(&self.0);
        if entropy < 3.5 {
            return Err(CryptoError::InsufficientEntropy(format!(
                "Shannon entropy {entropy:.2} bits/byte (minimum 3.5)"
            )));
        }

        let unique = count_unique_bytes(&self.0);
        if unique < 16 {
            return Err(CryptoError::InsufficientEntropy(format!(
                "only {unique} unique bytes (minimum 16)"
            )));
        }

        let max_run = max_run_length(&self.0);
        if max_run > 10 {
            return Err(CryptoError::InsufficientEntropy(format!(
                "suspicious sequential pattern (run length {max_run})"
            )));
        }

        if has_repeating_pattern(&self.0) {
            return Err(CryptoError::InsufficientEntropy(
                "short repeating pattern detected".into(),
            ));
        }

        Ok(())
    }

    /// Compute a BLAKE3 commitment of the NeuralKey.
    ///
    /// Store this alongside encrypted Shamir shares to verify that
    /// reconstruction produced the correct secret. The commitment is
    /// a one-way hash and cannot be reversed.
    #[cfg(feature = "commitment")]
    pub fn compute_commitment(&self) -> [u8; 32] {
        blake3::hash(&self.0).into()
    }

    /// Verify that this NeuralKey matches a previously stored commitment.
    ///
    /// Uses constant-time comparison to prevent timing attacks.
    /// Returns `Ok(())` on match, [`CryptoError::CommitmentMismatch`] otherwise.
    #[cfg(feature = "commitment")]
    pub fn verify_commitment(&self, expected: &[u8; 32]) -> Result<(), CryptoError> {
        let actual = self.compute_commitment();
        if constant_time_eq(&actual, expected) {
            Ok(())
        } else {
            Err(CryptoError::CommitmentMismatch)
        }
    }
}

impl core::fmt::Debug for NeuralKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_tuple("NeuralKey").field(&"[REDACTED]").finish()
    }
}

// ---------------------------------------------------------------------------
// Entropy helpers (pure functions, no allocations beyond a 256-byte array)
// ---------------------------------------------------------------------------

fn shannon_entropy(data: &[u8; 32]) -> f64 {
    let mut freq = [0u32; 256];
    for &b in data {
        freq[b as usize] += 1;
    }
    let len = data.len() as f64;
    let mut h = 0.0f64;
    for &c in &freq {
        if c > 0 {
            let p = c as f64 / len;
            h -= p * p.log2();
        }
    }
    h
}

fn count_unique_bytes(data: &[u8; 32]) -> usize {
    let mut seen = [false; 256];
    for &b in data {
        seen[b as usize] = true;
    }
    seen.iter().filter(|&&b| b).count()
}

fn max_run_length(data: &[u8; 32]) -> usize {
    if data.len() < 2 {
        return 0;
    }
    let mut max_run = 1usize;
    let mut cur = 1usize;
    let mut last_dir: Option<i16> = None;

    for i in 1..data.len() {
        let diff = data[i] as i16 - data[i - 1] as i16;
        let dir = Some(diff.signum());
        if dir == last_dir || last_dir.is_none() {
            cur += 1;
        } else {
            max_run = max_run.max(cur);
            cur = 1;
        }
        last_dir = dir;
    }
    max_run.max(cur)
}

fn has_repeating_pattern(data: &[u8; 32]) -> bool {
    for pat_len in [2, 4] {
        if data.len() >= pat_len * 2 {
            let pattern = &data[..pat_len];
            if data.chunks(pat_len).all(|c| c.len() < pat_len || c == pattern) {
                return true;
            }
        }
    }
    false
}

#[cfg(feature = "commitment")]
fn constant_time_eq(a: &[u8; 32], b: &[u8; 32]) -> bool {
    let mut acc = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        acc |= x ^ y;
    }
    acc == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validate_entropy_rejects_all_zeros() {
        let nk = NeuralKey::from_bytes([0u8; 32]);
        assert!(nk.validate_entropy().is_err());
    }

    #[test]
    fn validate_entropy_rejects_repeated_byte() {
        let nk = NeuralKey::from_bytes([0x42; 32]);
        assert!(nk.validate_entropy().is_err());
    }

    #[test]
    fn validate_entropy_rejects_sequential() {
        let mut buf = [0u8; 32];
        for (i, b) in buf.iter_mut().enumerate() {
            *b = i as u8;
        }
        assert!(NeuralKey::from_bytes(buf).validate_entropy().is_err());
    }

    #[test]
    fn validate_entropy_rejects_two_byte_pattern() {
        let mut buf = [0u8; 32];
        for i in 0..32 {
            buf[i] = if i % 2 == 0 { 0xAB } else { 0xCD };
        }
        assert!(NeuralKey::from_bytes(buf).validate_entropy().is_err());
    }

    #[test]
    fn validate_entropy_accepts_random() {
        let nk = NeuralKey::generate(&mut rand::thread_rng());
        assert!(nk.validate_entropy().is_ok());
    }

    #[cfg(feature = "commitment")]
    #[test]
    fn commitment_roundtrip() {
        let nk = NeuralKey::generate(&mut rand::thread_rng());
        let c = nk.compute_commitment();
        assert!(nk.verify_commitment(&c).is_ok());
    }

    #[cfg(feature = "commitment")]
    #[test]
    fn commitment_mismatch() {
        let nk = NeuralKey::generate(&mut rand::thread_rng());
        let wrong = [0xFFu8; 32];
        assert!(nk.verify_commitment(&wrong).is_err());
    }

    #[cfg(feature = "commitment")]
    #[test]
    fn commitment_differs_for_different_keys() {
        let mut rng = rand::thread_rng();
        let a = NeuralKey::generate(&mut rng);
        let b = NeuralKey::generate(&mut rng);
        assert_ne!(a.compute_commitment(), b.compute_commitment());
    }
}
