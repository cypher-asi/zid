//! Shamir secret sharing: split a 32-byte secret into threshold shares.

use rand_core::RngCore;

use crate::error::CryptoError;

/// Opaque Shamir share with a 1-based index. Hex-serializable for UI display.
#[derive(Clone)]
pub struct ShamirShare {
    index: u8,
    data: Vec<u8>,
}

impl ShamirShare {
    /// The 1-based share index.
    pub fn index(&self) -> u8 {
        self.index
    }

    /// Encode this share as a hex string (index byte prepended).
    pub fn to_hex(&self) -> String {
        let mut raw = vec![self.index];
        raw.extend_from_slice(&self.data);
        hex::encode(raw)
    }

    /// Encode this share as raw bytes (index byte prepended).
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut raw = vec![self.index];
        raw.extend_from_slice(&self.data);
        raw
    }

    /// Decode a share from raw bytes produced by [`to_bytes`](Self::to_bytes).
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, CryptoError> {
        if bytes.is_empty() {
            return Err(CryptoError::ShamirRecoveryFailed("share is empty".into()));
        }
        Ok(Self {
            index: bytes[0],
            data: bytes[1..].to_vec(),
        })
    }

    /// Decode a share from a hex string produced by [`to_hex`](Self::to_hex).
    pub fn from_hex(h: &str) -> Result<Self, CryptoError> {
        let raw = hex::decode(h)
            .map_err(|e| CryptoError::ShamirRecoveryFailed(format!("hex decode: {e}")))?;
        if raw.is_empty() {
            return Err(CryptoError::ShamirRecoveryFailed("share is empty".into()));
        }
        Ok(Self {
            index: raw[0],
            data: raw[1..].to_vec(),
        })
    }
}

impl core::fmt::Debug for ShamirShare {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("ShamirShare")
            .field("index", &self.index)
            .field("len", &self.data.len())
            .finish()
    }
}

/// Split a 32-byte secret into `total` shares with `threshold` required for reconstruction.
pub fn split(
    secret: &[u8; 32],
    total: usize,
    threshold: usize,
    rng: &mut dyn RngCore,
) -> Result<Vec<ShamirShare>, CryptoError> {
    if threshold == 0 {
        return Err(CryptoError::ShamirSplitFailed(
            "threshold must be > 0".into(),
        ));
    }
    if threshold > total {
        return Err(CryptoError::ShamirSplitFailed(format!(
            "threshold ({threshold}) must be <= total ({total})"
        )));
    }
    if total > 255 {
        return Err(CryptoError::ShamirSplitFailed(format!(
            "total ({total}) must be <= 255"
        )));
    }

    let raw_shares = shamir_vault::split(secret.as_slice(), total, threshold, rng)
        .map_err(|e| CryptoError::ShamirSplitFailed(format!("{e}")))?;

    Ok(raw_shares
        .into_iter()
        .enumerate()
        .map(|(i, data)| ShamirShare {
            index: (i + 1) as u8,
            data,
        })
        .collect())
}

/// Combine threshold-or-more shares back into a 32-byte secret.
pub fn combine(shares: &[ShamirShare]) -> Result<[u8; 32], CryptoError> {
    if shares.is_empty() {
        return Err(CryptoError::ShamirRecoveryFailed(
            "no shares provided".into(),
        ));
    }
    let raw: Vec<Vec<u8>> = shares.iter().map(|s| s.data.clone()).collect();
    let secret = shamir_vault::combine(&raw)
        .map_err(|e| CryptoError::ShamirRecoveryFailed(format!("{e}")))?;

    if secret.len() != 32 {
        return Err(CryptoError::ShamirRecoveryFailed(format!(
            "expected 32 bytes, got {}",
            secret.len()
        )));
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&secret);
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn split_and_combine_round_trip() {
        let secret = [0x42u8; 32];
        let mut rng = rand::thread_rng();
        let shares = split(&secret, 5, 3, &mut rng).unwrap();
        assert_eq!(shares.len(), 5);

        let recovered = combine(&shares[0..3]).unwrap();
        assert_eq!(recovered, secret);
    }

    #[test]
    fn split_threshold_zero_rejected() {
        let secret = [0u8; 32];
        let mut rng = rand::thread_rng();
        let err = split(&secret, 5, 0, &mut rng).unwrap_err();
        assert!(matches!(err, CryptoError::ShamirSplitFailed(_)));
    }

    #[test]
    fn split_threshold_exceeds_total_rejected() {
        let secret = [0u8; 32];
        let mut rng = rand::thread_rng();
        let err = split(&secret, 3, 5, &mut rng).unwrap_err();
        assert!(matches!(err, CryptoError::ShamirSplitFailed(_)));
    }

    #[test]
    fn split_total_exceeds_255_rejected() {
        let secret = [0u8; 32];
        let mut rng = rand::thread_rng();
        let err = split(&secret, 256, 3, &mut rng).unwrap_err();
        assert!(matches!(err, CryptoError::ShamirSplitFailed(_)));
    }

    #[test]
    fn combine_empty_shares_rejected() {
        let err = combine(&[]).unwrap_err();
        assert!(matches!(err, CryptoError::ShamirRecoveryFailed(_)));
    }

    #[test]
    fn share_hex_round_trip() {
        let secret = [0xFFu8; 32];
        let mut rng = rand::thread_rng();
        let shares = split(&secret, 3, 2, &mut rng).unwrap();

        for share in &shares {
            let hex = share.to_hex();
            let recovered = ShamirShare::from_hex(&hex).unwrap();
            assert_eq!(recovered.index(), share.index());
        }
    }

    #[test]
    fn from_hex_empty_string_rejected() {
        let err = ShamirShare::from_hex("").unwrap_err();
        assert!(matches!(err, CryptoError::ShamirRecoveryFailed(_)));
    }

    #[test]
    fn from_hex_invalid_hex_rejected() {
        let err = ShamirShare::from_hex("zzzz").unwrap_err();
        assert!(matches!(err, CryptoError::ShamirRecoveryFailed(_)));
    }
}
