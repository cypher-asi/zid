//! HKDF-SHA256 key derivation with domain separation.

use hkdf::Hkdf;
use sha2::Sha256;

use crate::error::CryptoError;
use crate::keys::identity::IdentitySigningKey;
use crate::keys::machine::MachineKeyCapabilities;
use crate::keys::neural::NeuralKey;
use crate::types::{IdentityId, MachineId};

/// Derive an [`IdentitySigningKey`] (Ed25519 + ML-DSA-65) from a NeuralKey.
///
/// Domain separation follows zero-id conventions so that the same NeuralKey
/// produces identical Ed25519 keys in both systems.
pub fn derive_identity_signing_key(
    nk: &NeuralKey,
    identity_id: IdentityId,
) -> Result<IdentitySigningKey, CryptoError> {
    let ed25519_seed = hkdf_derive_32(
        nk.as_bytes(),
        &build_info(b"cypher:id:identity:v1", &[identity_id.as_bytes()]),
    )?;
    let ml_dsa_seed = hkdf_derive_32(
        nk.as_bytes(),
        &build_info(b"cypher:id:identity:pq-sign:v1", &[identity_id.as_bytes()]),
    )?;

    Ok(IdentitySigningKey::from_seeds(ed25519_seed, ml_dsa_seed))
}

/// Derive a [`MachineKeyPair`](crate::keys::machine::MachineKeyPair)
/// (Ed25519 + ML-DSA-65 signing, X25519 + ML-KEM-768 encryption) from a
/// NeuralKey.
///
/// Two-level derivation:
/// 1. Machine seed from NeuralKey with identity\_id, machine\_id, epoch
/// 2. Individual key seeds from machine seed with algorithm-specific info
pub fn derive_machine_keypair(
    nk: &NeuralKey,
    identity_id: IdentityId,
    machine_id: MachineId,
    epoch: u64,
    capabilities: MachineKeyCapabilities,
) -> Result<crate::keys::machine::MachineKeyPair, CryptoError> {
    let machine_seed = hkdf_derive_32(
        nk.as_bytes(),
        &build_info(
            b"cypher:shared:machine:v1",
            &[
                identity_id.as_bytes(),
                machine_id.as_bytes(),
                &epoch.to_be_bytes(),
            ],
        ),
    )?;

    let mid = machine_id.as_bytes();
    let sign_seed = hkdf_derive_32(
        &machine_seed,
        &build_info(b"cypher:shared:machine:sign:v1", &[mid]),
    )?;
    let encrypt_seed = hkdf_derive_32(
        &machine_seed,
        &build_info(b"cypher:shared:machine:encrypt:v1", &[mid]),
    )?;
    let pq_sign_seed = hkdf_derive_32(
        &machine_seed,
        &build_info(b"cypher:shared:machine:pq-sign:v1", &[mid]),
    )?;
    let pq_encrypt_seed = hkdf_derive_32(
        &machine_seed,
        &build_info(b"cypher:shared:machine:pq-encrypt:v1", &[mid]),
    )?;

    crate::keys::machine::MachineKeyPair::from_seeds(
        sign_seed,
        encrypt_seed,
        pq_sign_seed,
        pq_encrypt_seed,
        capabilities,
        epoch,
    )
}

/// HKDF-SHA256 extract-then-expand to produce 32 bytes.
pub(crate) fn hkdf_derive_32(ikm: &[u8], info: &[u8]) -> Result<[u8; 32], CryptoError> {
    let hk = Hkdf::<Sha256>::new(None, ikm);
    let mut out = [0u8; 32];
    hk.expand(info, &mut out)
        .map_err(|_| CryptoError::HkdfExpandFailed)?;
    Ok(out)
}

fn build_info(prefix: &[u8], parts: &[&[u8]]) -> Vec<u8> {
    let len = prefix.len() + parts.iter().map(|p| p.len()).sum::<usize>();
    let mut info = Vec::with_capacity(len);
    info.extend_from_slice(prefix);
    for part in parts {
        info.extend_from_slice(part);
    }
    info
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_info_concatenates_prefix_and_parts() {
        let info = build_info(b"prefix:", &[b"aaa", b"bbb"]);
        assert_eq!(info, b"prefix:aaabbb");
    }

    #[test]
    fn build_info_empty_parts() {
        let info = build_info(b"only-prefix", &[]);
        assert_eq!(info, b"only-prefix");
    }

    #[test]
    fn hkdf_derive_32_produces_deterministic_output() {
        let a = hkdf_derive_32(b"ikm", b"info").unwrap();
        let b = hkdf_derive_32(b"ikm", b"info").unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn hkdf_derive_32_different_info_different_output() {
        let a = hkdf_derive_32(b"ikm", b"info-a").unwrap();
        let b = hkdf_derive_32(b"ikm", b"info-b").unwrap();
        assert_ne!(a, b);
    }

    #[test]
    fn identity_key_derivation_deterministic() {
        let seed = [0xABu8; 32];
        let nk = NeuralKey::from_bytes(seed);
        let id = IdentityId::new([0x01u8; 16]);

        let k1 = derive_identity_signing_key(&nk, id).unwrap();
        let nk2 = NeuralKey::from_bytes(seed);
        let k2 = derive_identity_signing_key(&nk2, id).unwrap();

        assert_eq!(k1.ed25519_public_bytes(), k2.ed25519_public_bytes());
    }

    #[test]
    fn different_identity_ids_produce_different_keys() {
        let seed = [0xABu8; 32];
        let nk = NeuralKey::from_bytes(seed);
        let id_a = IdentityId::new([0x01u8; 16]);
        let id_b = IdentityId::new([0x02u8; 16]);

        let k1 = derive_identity_signing_key(&nk, id_a).unwrap();
        let nk2 = NeuralKey::from_bytes(seed);
        let k2 = derive_identity_signing_key(&nk2, id_b).unwrap();

        assert_ne!(k1.ed25519_public_bytes(), k2.ed25519_public_bytes());
    }
}
