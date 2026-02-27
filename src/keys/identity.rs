//! Identity signing and verifying keys (Ed25519 + ML-DSA-65 hybrid).

use ml_dsa::{KeyGen, MlDsa65};
use zeroize::ZeroizeOnDrop;

use crate::error::CryptoError;
use crate::ops::signing::{arr_from_bytes, hybrid_sign, hybrid_verify, HybridSignature};

/// Identity Signing Key — Ed25519 + ML-DSA-65 hybrid.
///
/// Derived from a NeuralKey via HKDF. Produces hybrid signatures that
/// require both classical and post-quantum components to verify.
#[derive(ZeroizeOnDrop)]
pub struct IdentitySigningKey {
    #[zeroize(skip)]
    ed25519: ed25519_dalek::SigningKey,
    #[zeroize(skip)]
    ml_dsa_signing: ml_dsa::SigningKey<MlDsa65>,
    #[zeroize(skip)]
    ml_dsa_verifying: ml_dsa::VerifyingKey<MlDsa65>,
}

impl IdentitySigningKey {
    /// Construct from pre-derived Ed25519 and ML-DSA-65 seed material.
    pub fn from_seeds(ed25519_seed: [u8; 32], ml_dsa_seed: [u8; 32]) -> Self {
        let ed25519 = ed25519_dalek::SigningKey::from_bytes(&ed25519_seed);

        let ml_dsa_b32 = arr_from_bytes(ml_dsa_seed);
        let kp = MlDsa65::key_gen_internal(&ml_dsa_b32);
        let ml_dsa_verifying = kp.verifying_key().clone();
        let ml_dsa_signing = kp.signing_key().clone();

        Self {
            ed25519,
            ml_dsa_signing,
            ml_dsa_verifying,
        }
    }

    /// Produce a hybrid signature over `msg`.
    pub fn sign(&self, msg: &[u8]) -> HybridSignature {
        hybrid_sign(&self.ed25519, &self.ml_dsa_signing, msg)
    }

    /// Extract the corresponding verifying key.
    pub fn verifying_key(&self) -> IdentityVerifyingKey {
        IdentityVerifyingKey {
            ed25519: self.ed25519.verifying_key(),
            ml_dsa: self.ml_dsa_verifying.clone(),
        }
    }

    /// Access the raw Ed25519 public key bytes (for DID encoding).
    pub fn ed25519_public_bytes(&self) -> [u8; 32] {
        self.ed25519.verifying_key().to_bytes()
    }
}

impl core::fmt::Debug for IdentitySigningKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("IdentitySigningKey")
            .field("ed25519_public", &self.ed25519.verifying_key())
            .finish_non_exhaustive()
    }
}

/// Identity Verifying Key — Ed25519 + ML-DSA-65 public keys.
#[derive(Debug, Clone)]
pub struct IdentityVerifyingKey {
    ed25519: ed25519_dalek::VerifyingKey,
    ml_dsa: ml_dsa::VerifyingKey<MlDsa65>,
}

impl IdentityVerifyingKey {
    /// Verify a hybrid signature: both Ed25519 and ML-DSA-65 must pass.
    pub fn verify(&self, msg: &[u8], sig: &HybridSignature) -> Result<(), CryptoError> {
        hybrid_verify(&self.ed25519, &self.ml_dsa, msg, sig)
    }

    /// Access the raw Ed25519 public key bytes (for DID encoding).
    pub fn ed25519_bytes(&self) -> [u8; 32] {
        self.ed25519.to_bytes()
    }
}
