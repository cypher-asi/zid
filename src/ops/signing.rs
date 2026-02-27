//! Hybrid signature type and signing/verification helpers.
//!
//! Every signature produced by this crate contains both an Ed25519 and an
//! ML-DSA-65 component. Both must verify for the signature to be accepted.

use ml_dsa::MlDsa65;

use crate::error::CryptoError;

/// PQ-Hybrid signature: always contains both Ed25519 and ML-DSA-65 components.
/// Both must verify for the signature to be considered valid.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct HybridSignature {
    /// Ed25519 signature bytes.
    #[cfg_attr(feature = "serde", serde(with = "serde_bytes"))]
    pub ed25519: [u8; 64],
    /// ML-DSA-65 signature bytes (fixed 3 309 bytes per FIPS 204).
    #[cfg_attr(feature = "serde", serde(with = "serde_bytes"))]
    pub ml_dsa: [u8; 3_309],
}

impl HybridSignature {
    /// Length of the Ed25519 component.
    pub const ED25519_LEN: usize = 64;
    /// Length of the ML-DSA-65 component.
    pub const ML_DSA_65_LEN: usize = 3_309;

    /// Serialize to bytes: ed25519 (64) || ml\_dsa (3309).
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(Self::ED25519_LEN + Self::ML_DSA_65_LEN);
        out.extend_from_slice(&self.ed25519);
        out.extend_from_slice(&self.ml_dsa);
        out
    }

    /// Deserialize from bytes: ed25519 (64) || ml\_dsa (3309).
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, CryptoError> {
        if bytes.len() < Self::ED25519_LEN + Self::ML_DSA_65_LEN {
            return Err(CryptoError::InvalidKeyLength {
                expected: Self::ED25519_LEN + Self::ML_DSA_65_LEN,
                got: bytes.len(),
            });
        }
        let mut ed25519 = [0u8; 64];
        ed25519.copy_from_slice(&bytes[..64]);
        let mut ml_dsa = [0u8; 3_309];
        ml_dsa.copy_from_slice(&bytes[64..64 + 3_309]);
        Ok(Self { ed25519, ml_dsa })
    }
}

/// Produce a PQ-Hybrid signature (Ed25519 + ML-DSA-65) over `msg`.
pub(crate) fn hybrid_sign(
    ed_key: &ed25519_dalek::SigningKey,
    pq_key: &ml_dsa::SigningKey<MlDsa65>,
    msg: &[u8],
) -> HybridSignature {
    use ed25519_dalek::Signer as _;
    use ml_dsa::signature::SignatureEncoding as _;

    let ed_sig = ed_key.sign(msg);
    let pq_sig: ml_dsa::Signature<MlDsa65> = ml_dsa::signature::Signer::sign(pq_key, msg);

    let pq_bytes = pq_sig.to_bytes();
    let mut ml_dsa = [0u8; HybridSignature::ML_DSA_65_LEN];
    ml_dsa.copy_from_slice(pq_bytes.as_ref());

    HybridSignature {
        ed25519: ed_sig.to_bytes(),
        ml_dsa,
    }
}

/// Verify a PQ-Hybrid signature: both Ed25519 and ML-DSA-65 must pass.
pub(crate) fn hybrid_verify(
    ed_key: &ed25519_dalek::VerifyingKey,
    pq_key: &ml_dsa::VerifyingKey<MlDsa65>,
    msg: &[u8],
    sig: &HybridSignature,
) -> Result<(), CryptoError> {
    use ed25519_dalek::Verifier as _;

    let ed_sig = ed25519_dalek::Signature::from_bytes(&sig.ed25519);
    ed_key
        .verify(msg, &ed_sig)
        .map_err(|_| CryptoError::Ed25519VerifyFailed)?;

    let pq_sig = <ml_dsa::Signature<MlDsa65>>::try_from(&sig.ml_dsa[..])
        .map_err(|_| CryptoError::MlDsaVerifyFailed)?;
    ml_dsa::signature::Verifier::verify(pq_key, msg, &pq_sig)
        .map_err(|_| CryptoError::MlDsaVerifyFailed)?;

    Ok(())
}

/// Construct a `B32` (`Array<u8, U32>`) from a `[u8; 32]`.
pub(crate) fn arr_from_bytes(bytes: [u8; 32]) -> ml_dsa::B32 {
    let mut arr = ml_dsa::B32::default();
    arr.copy_from_slice(&bytes);
    arr
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hybrid_signature_to_bytes_length() {
        let sig = HybridSignature {
            ed25519: [0xAA; 64],
            ml_dsa: [0xBB; 3_309],
        };
        let bytes = sig.to_bytes();
        assert_eq!(bytes.len(), 64 + 3_309);
    }

    #[test]
    fn hybrid_signature_from_bytes_round_trip() {
        let sig = HybridSignature {
            ed25519: [0xAA; 64],
            ml_dsa: [0xBB; 3_309],
        };
        let bytes = sig.to_bytes();
        let sig2 = HybridSignature::from_bytes(&bytes).unwrap();
        assert_eq!(sig, sig2);
    }

    #[test]
    fn hybrid_signature_from_bytes_too_short() {
        let bytes = [0u8; 100];
        let err = HybridSignature::from_bytes(&bytes).unwrap_err();
        assert!(matches!(
            err,
            crate::error::CryptoError::InvalidKeyLength { .. }
        ));
    }

    #[test]
    fn hybrid_signature_from_bytes_exact_length() {
        let bytes = vec![0u8; 64 + 3_309];
        let sig = HybridSignature::from_bytes(&bytes).unwrap();
        assert_eq!(sig.ed25519, [0u8; 64]);
        assert_eq!(sig.ml_dsa, [0u8; 3_309]);
    }
}
