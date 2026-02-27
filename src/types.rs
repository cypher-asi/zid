//! Strongly-typed identifiers to prevent accidental parameter swapping.

/// 128-bit identity identifier.
///
/// Prevents accidental parameter swapping with [`MachineId`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct IdentityId([u8; 16]);

impl IdentityId {
    /// Create an `IdentityId` from raw bytes.
    pub const fn new(bytes: [u8; 16]) -> Self {
        Self(bytes)
    }

    /// Access the underlying bytes.
    pub fn as_bytes(&self) -> &[u8; 16] {
        &self.0
    }
}

impl From<[u8; 16]> for IdentityId {
    fn from(bytes: [u8; 16]) -> Self {
        Self(bytes)
    }
}

/// 128-bit machine/device identifier.
///
/// Prevents accidental parameter swapping with [`IdentityId`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct MachineId([u8; 16]);

impl MachineId {
    /// Create a `MachineId` from raw bytes.
    pub const fn new(bytes: [u8; 16]) -> Self {
        Self(bytes)
    }

    /// Access the underlying bytes.
    pub fn as_bytes(&self) -> &[u8; 16] {
        &self.0
    }
}

impl From<[u8; 16]> for MachineId {
    fn from(bytes: [u8; 16]) -> Self {
        Self(bytes)
    }
}
