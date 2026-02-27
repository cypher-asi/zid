//! Error types for cryptographic operations.

use thiserror::Error;

/// Errors that can occur during cryptographic operations.
#[derive(Debug, Error)]
pub enum CryptoError {
    /// HKDF expand produced an invalid output length.
    #[error("HKDF expand failed: output length invalid")]
    HkdfExpandFailed,

    /// Ed25519 signature did not verify.
    #[error("Ed25519 signature verification failed")]
    Ed25519VerifyFailed,

    /// ML-DSA-65 signature did not verify.
    #[error("ML-DSA-65 signature verification failed")]
    MlDsaVerifyFailed,

    /// One or both components of a hybrid signature failed verification.
    #[error("hybrid signature verification failed: {0}")]
    HybridVerifyFailed(
        /// Reason for failure.
        &'static str,
    ),

    /// ML-KEM-768 decapsulation failed (ciphertext may be invalid).
    #[error("ML-KEM-768 decapsulation failed")]
    MlKemDecapFailed,

    /// X25519 Diffie-Hellman produced a degenerate all-zero shared secret.
    #[error("X25519 key agreement produced all-zero shared secret")]
    X25519ZeroSharedSecret,

    /// A DID string could not be parsed or did not match the expected format.
    #[error("invalid DID key: {0}")]
    InvalidDid(
        /// Detail message.
        String,
    ),

    /// A key or signature buffer had an unexpected length.
    #[error("invalid key length: expected {expected}, got {got}")]
    InvalidKeyLength {
        /// Expected byte count.
        expected: usize,
        /// Actual byte count.
        got: usize,
    },

    /// A ciphertext buffer had an unexpected length.
    #[error("invalid ciphertext length: expected {expected}, got {got}")]
    InvalidCiphertextLength {
        /// Expected byte count.
        expected: usize,
        /// Actual byte count.
        got: usize,
    },

    /// Shamir secret splitting failed.
    #[error("Shamir split failed: {0}")]
    ShamirSplitFailed(
        /// Detail message.
        String,
    ),

    /// Shamir secret recovery failed.
    #[error("Shamir recovery failed: {0}")]
    ShamirRecoveryFailed(
        /// Detail message.
        String,
    ),

    /// NeuralKey has insufficient entropy (weak randomness detected).
    #[error("insufficient entropy: {0}")]
    InsufficientEntropy(
        /// Detail message.
        String,
    ),

    /// NeuralKey commitment mismatch after Shamir reconstruction.
    #[error("Neural Key commitment mismatch: reconstructed key does not match stored commitment")]
    CommitmentMismatch,
}
