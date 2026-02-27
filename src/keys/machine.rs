//! Machine key pairs and capabilities (Ed25519 + ML-DSA-65 signing,
//! X25519 + ML-KEM-768 encryption).

use bitflags::bitflags;
use ml_dsa::{KeyGen, MlDsa65};
use ml_kem::{KemCore, MlKem768};

use crate::error::CryptoError;
use crate::ops::signing::{arr_from_bytes, hybrid_sign, hybrid_verify, HybridSignature};

bitflags! {
    /// Capability flags for a machine key pair.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct MachineKeyCapabilities: u8 {
        /// Machine may produce signatures.
        const SIGN    = 0x01;
        /// Machine may encrypt/decapsulate.
        const ENCRYPT = 0x02;
        /// Machine may write to storage.
        const STORE   = 0x04;
        /// Machine may read from storage.
        const FETCH   = 0x08;
    }
}

/// Machine Key Pair — full hybrid key set for a single machine/device.
///
/// Contains Ed25519 + ML-DSA-65 for signing and X25519 + ML-KEM-768 for
/// encryption/key encapsulation. All four key types are always present.
pub struct MachineKeyPair {
    pub(crate) ed25519_signing: ed25519_dalek::SigningKey,
    pub(crate) x25519_secret: x25519_dalek::StaticSecret,
    pub(crate) ml_dsa_signing: ml_dsa::SigningKey<MlDsa65>,
    pub(crate) ml_dsa_verifying: ml_dsa::VerifyingKey<MlDsa65>,
    pub(crate) ml_kem_decap: <MlKem768 as KemCore>::DecapsulationKey,
    pub(crate) ml_kem_encap: <MlKem768 as KemCore>::EncapsulationKey,
    pub(crate) capabilities: MachineKeyCapabilities,
    pub(crate) epoch: u64,
}

impl MachineKeyPair {
    /// Construct from pre-derived seed material.
    pub(crate) fn from_seeds(
        sign_seed: [u8; 32],
        encrypt_seed: [u8; 32],
        pq_sign_seed: [u8; 32],
        pq_encrypt_seed: [u8; 32],
        capabilities: MachineKeyCapabilities,
        epoch: u64,
    ) -> Result<Self, CryptoError> {
        let ed25519_signing = ed25519_dalek::SigningKey::from_bytes(&sign_seed);
        let x25519_secret = x25519_dalek::StaticSecret::from(encrypt_seed);

        let ml_dsa_kp = MlDsa65::key_gen_internal(&arr_from_bytes(pq_sign_seed));
        let ml_dsa_verifying = ml_dsa_kp.verifying_key().clone();
        let ml_dsa_signing = ml_dsa_kp.signing_key().clone();

        let (ml_kem_decap, ml_kem_encap) = generate_mlkem_deterministic(&pq_encrypt_seed)?;

        Ok(Self {
            ed25519_signing,
            x25519_secret,
            ml_dsa_signing,
            ml_dsa_verifying,
            ml_kem_decap,
            ml_kem_encap,
            capabilities,
            epoch,
        })
    }

    /// Produce a hybrid signature (Ed25519 + ML-DSA-65) over `msg`.
    pub fn sign(&self, msg: &[u8]) -> HybridSignature {
        hybrid_sign(&self.ed25519_signing, &self.ml_dsa_signing, msg)
    }

    /// Extract the corresponding public key.
    pub fn public_key(&self) -> MachinePublicKey {
        use ml_kem::EncodedSizeUser as _;

        let ek_bytes = self.ml_kem_encap.as_bytes();
        let ek_clone =
            <<MlKem768 as KemCore>::EncapsulationKey as ml_kem::EncodedSizeUser>::from_bytes(
                &ek_bytes,
            );

        MachinePublicKey {
            ed25519_verifying: self.ed25519_signing.verifying_key(),
            x25519_public: x25519_dalek::PublicKey::from(&self.x25519_secret),
            ml_dsa_verifying: self.ml_dsa_verifying.clone(),
            ml_kem_encap: ek_clone,
            capabilities: self.capabilities,
            epoch: self.epoch,
        }
    }

    /// The capability flags granted to this machine.
    pub fn capabilities(&self) -> MachineKeyCapabilities {
        self.capabilities
    }

    /// The epoch (rotation counter) for this machine key set.
    pub fn epoch(&self) -> u64 {
        self.epoch
    }
}

impl core::fmt::Debug for MachineKeyPair {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("MachineKeyPair")
            .field("capabilities", &self.capabilities)
            .field("epoch", &self.epoch)
            .finish_non_exhaustive()
    }
}

/// Machine Public Key — all four public key components for a machine.
///
/// Used for signature verification and hybrid key encapsulation.
/// Total size: ~3,200 bytes (32 + 32 + 1,952 + 1,184).
#[derive(Debug)]
pub struct MachinePublicKey {
    pub(crate) ed25519_verifying: ed25519_dalek::VerifyingKey,
    pub(crate) x25519_public: x25519_dalek::PublicKey,
    pub(crate) ml_dsa_verifying: ml_dsa::VerifyingKey<MlDsa65>,
    pub(crate) ml_kem_encap: <MlKem768 as KemCore>::EncapsulationKey,
    pub(crate) capabilities: MachineKeyCapabilities,
    pub(crate) epoch: u64,
}

impl MachinePublicKey {
    /// Verify a hybrid signature: both Ed25519 and ML-DSA-65 must pass.
    pub fn verify(&self, msg: &[u8], sig: &HybridSignature) -> Result<(), CryptoError> {
        hybrid_verify(&self.ed25519_verifying, &self.ml_dsa_verifying, msg, sig)
    }

    /// Access the raw Ed25519 public key bytes (for DID encoding).
    pub fn ed25519_bytes(&self) -> [u8; 32] {
        self.ed25519_verifying.to_bytes()
    }

    /// The capability flags granted to this machine.
    pub fn capabilities(&self) -> MachineKeyCapabilities {
        self.capabilities
    }

    /// The epoch (rotation counter) for this machine key set.
    pub fn epoch(&self) -> u64 {
        self.epoch
    }
}

/// Deterministically generate ML-KEM-768 keys from a 32-byte seed.
fn generate_mlkem_deterministic(
    seed: &[u8; 32],
) -> Result<
    (
        <MlKem768 as KemCore>::DecapsulationKey,
        <MlKem768 as KemCore>::EncapsulationKey,
    ),
    CryptoError,
> {
    let d = crate::ops::derivation::hkdf_derive_32(seed, b"mlkem768:d")?;
    let z = crate::ops::derivation::hkdf_derive_32(seed, b"mlkem768:z")?;

    let d_b32 = mlkem_b32_from_bytes(d);
    let z_b32 = mlkem_b32_from_bytes(z);

    Ok(MlKem768::generate_deterministic(&d_b32, &z_b32))
}

fn mlkem_b32_from_bytes(bytes: [u8; 32]) -> ml_kem::B32 {
    let mut arr = ml_kem::B32::default();
    arr.copy_from_slice(&bytes);
    arr
}
