//! High-level threshold API: generate identities, sign, and derive machine keys
//! using Shamir shares.

use rand_core::{CryptoRng, RngCore};
use zeroize::Zeroize;

use crate::error::CryptoError;
use crate::keys::identity::IdentityVerifyingKey;
use crate::keys::machine::{MachineKeyCapabilities, MachineKeyPair};
use crate::keys::neural::NeuralKey;
use crate::ops::derivation::{derive_identity_signing_key, derive_machine_keypair};
use crate::ops::signing::HybridSignature;
use crate::sharing::shamir::{self, ShamirShare};
use crate::types::{IdentityId, MachineId};

/// Everything returned after generating a new identity.
pub struct IdentityBundle {
    /// Shamir shares of the root secret.
    pub shares: Vec<ShamirShare>,
    /// Number of shares required for recovery.
    pub threshold: usize,
    /// Public verifying key for the identity.
    pub verifying_key: IdentityVerifyingKey,
    /// `did:key` encoding of the Ed25519 public key (requires `did` feature).
    #[cfg(feature = "did")]
    pub did: String,
}

/// Public identity info recovered from shares (no secret material).
pub struct IdentityInfo {
    /// Public verifying key for the identity.
    pub verifying_key: IdentityVerifyingKey,
    /// `did:key` encoding of the Ed25519 public key (requires `did` feature).
    #[cfg(feature = "did")]
    pub did: String,
}

/// Generate a new identity. Returns shares + public identity info.
/// The NeuralKey is created, split, and immediately zeroized.
pub fn generate_identity(
    threshold: usize,
    total: usize,
    identity_id: IdentityId,
    rng: &mut (impl RngCore + CryptoRng),
) -> Result<IdentityBundle, CryptoError> {
    let nk = NeuralKey::generate(rng);
    let mut secret = nk.to_bytes();

    let shares = shamir::split(&secret, total, threshold, rng)?;

    let isk = derive_identity_signing_key(&nk, identity_id)?;
    let vk = isk.verifying_key();
    #[cfg(feature = "did")]
    let did = crate::did::ed25519_to_did_key(&isk.ed25519_public_bytes());

    secret.zeroize();
    drop(nk);

    Ok(IdentityBundle {
        shares,
        threshold,
        verifying_key: vk,
        #[cfg(feature = "did")]
        did,
    })
}

/// Verify shares are valid by reconstructing and checking. Returns public identity info.
pub fn verify_shares(
    shares: &[ShamirShare],
    identity_id: IdentityId,
) -> Result<IdentityInfo, CryptoError> {
    with_neural_key(shares, |nk| {
        let isk = derive_identity_signing_key(nk, identity_id)?;
        let vk = isk.verifying_key();
        #[cfg(feature = "did")]
        let did = crate::did::ed25519_to_did_key(&isk.ed25519_public_bytes());
        Ok(IdentityInfo {
            verifying_key: vk,
            #[cfg(feature = "did")]
            did,
        })
    })
}

/// Sign a message using threshold shares. Ephemeral reconstruction + zeroize.
pub fn sign_with_shares(
    shares: &[ShamirShare],
    identity_id: IdentityId,
    msg: &[u8],
) -> Result<HybridSignature, CryptoError> {
    with_neural_key(shares, |nk| {
        let isk = derive_identity_signing_key(nk, identity_id)?;
        Ok(isk.sign(msg))
    })
}

/// Derive a machine keypair using threshold shares. Ephemeral reconstruction + zeroize.
pub fn derive_machine_keypair_from_shares(
    shares: &[ShamirShare],
    identity_id: IdentityId,
    machine_id: MachineId,
    epoch: u64,
    capabilities: MachineKeyCapabilities,
) -> Result<MachineKeyPair, CryptoError> {
    with_neural_key(shares, |nk| {
        derive_machine_keypair(nk, identity_id, machine_id, epoch, capabilities)
    })
}

/// Reconstruct a NeuralKey from shares, run `f`, then zeroize.
fn with_neural_key<T>(
    shares: &[ShamirShare],
    f: impl FnOnce(&NeuralKey) -> Result<T, CryptoError>,
) -> Result<T, CryptoError> {
    let mut secret = shamir::combine(shares)?;
    let nk = NeuralKey::from_bytes(secret);
    secret.zeroize();
    let result = f(&nk);
    drop(nk);
    result
}
