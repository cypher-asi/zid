#![doc = include_str!("../README.md")]
#![forbid(unsafe_code)]
#![warn(missing_docs)]
#![deny(rustdoc::broken_intra_doc_links)]

#[cfg(feature = "did")]
pub mod did;
pub mod error;
pub(crate) mod keys;
pub(crate) mod ops;
#[cfg(feature = "shamir")]
pub(crate) mod sharing;
pub mod types;

#[cfg(feature = "did")]
pub use did::{did_key_to_ed25519, ed25519_to_did_key, verify_did_ed25519};
pub use error::CryptoError;
pub use keys::identity::{IdentitySigningKey, IdentityVerifyingKey};
pub use keys::machine::{MachineKeyCapabilities, MachineKeyPair, MachinePublicKey};
pub use ops::encapsulation::{EncapBundle, SharedSecret};
pub use ops::signing::HybridSignature;
#[cfg(feature = "shamir")]
pub use sharing::shamir::ShamirShare;
#[cfg(feature = "shamir")]
pub use sharing::shares_api::{
    derive_machine_keypair_from_shares, generate_identity, sign_with_shares, verify_shares,
    IdentityBundle, IdentityInfo,
};
pub use types::{IdentityId, MachineId};

/// Test-only helpers for deterministic key derivation from raw seeds.
///
/// External crates enable via `zid = { ..., features = ["testkit"] }` in
/// `[dev-dependencies]`.
#[cfg(feature = "testkit")]
pub mod testkit {
    use crate::error::CryptoError;
    use crate::keys::identity::IdentitySigningKey;
    use crate::keys::machine::{MachineKeyCapabilities, MachineKeyPair};
    use crate::keys::neural::NeuralKey;
    use crate::types::{IdentityId, MachineId};

    /// Derive an identity signing key from a raw 32-byte seed (deterministic).
    pub fn derive_identity_signing_key_from_seed(
        seed: [u8; 32],
        identity_id: IdentityId,
    ) -> Result<IdentitySigningKey, CryptoError> {
        let nk = NeuralKey::from_bytes(seed);
        crate::ops::derivation::derive_identity_signing_key(&nk, identity_id)
    }

    /// Derive a machine keypair from a raw 32-byte seed (deterministic).
    pub fn derive_machine_keypair_from_seed(
        seed: [u8; 32],
        identity_id: IdentityId,
        machine_id: MachineId,
        epoch: u64,
        capabilities: MachineKeyCapabilities,
    ) -> Result<MachineKeyPair, CryptoError> {
        let nk = NeuralKey::from_bytes(seed);
        crate::ops::derivation::derive_machine_keypair(
            &nk,
            identity_id,
            machine_id,
            epoch,
            capabilities,
        )
    }
}
