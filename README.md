# zid

A post-quantum identity library for identity and machine key management.

## Core Terminology

### Root & Recovery

- **NeuralKey** — 256-bit root secret (CSPRNG), from which all keys are deterministically derived via HKDF-SHA256. Zeroized on drop.
- **ShamirShare** — Opaque threshold share of the NeuralKey; hex-serializable for transport/storage.

### Identity

- **IdentityId** — 128-bit identifier that scopes an identity's key derivation domain.
- **IdentitySigningKey / IdentityVerifyingKey** — Ed25519 + ML-DSA-65 hybrid keypair for signing and verification.
- **DID** — `did:key` encoding of an Ed25519 public key (multicodec `0xed01` + base58btc).

### Machine

- **MachineId** — 128-bit identifier for a device/machine.
- **MachineKeyPair / MachinePublicKey** — Full hybrid key set per machine: Ed25519 + ML-DSA-65 (signing) and X25519 + ML-KEM-768 (encryption).
- **MachineKeyCapabilities** — Bitflags (`SIGN`, `ENCRYPT`, `STORE`, `FETCH`) controlling what a machine key may do.
- **Epoch** — Rotation counter; changing epoch produces a fresh machine key set from the same NeuralKey.

### Signing & Encryption

- **HybridSignature** — Signature containing both Ed25519 (64 B) and ML-DSA-65 (3 309 B) components; both must verify.
- **Hybrid KEM** — Key encapsulation combining X25519 DH + ML-KEM-768, with shared secrets HKDF-combined.

## Key Structure

```
NeuralKey (256-bit root secret)
│
├── HKDF("cypher:id:identity:v1")        → Ed25519 seed ──┐
├── HKDF("cypher:id:identity:pq-sign:v1")→ ML-DSA-65 seed ┘→ IdentitySigningKey
│
├── HKDF("cypher:shared:machine:v1")     → Machine Seed
│   ├── HKDF(":sign:v1")                 → Ed25519 machine sign key
│   ├── HKDF(":encrypt:v1")              → X25519 machine encrypt key
│   ├── HKDF(":pq-sign:v1")              → ML-DSA-65 machine sign key
│   └── HKDF(":pq-encrypt:v1")           → ML-KEM-768 machine encrypt key
│                                           └→ MachineKeyPair
│
└── Shamir split                          → ShamirShares (t-of-n)
```

## File Structure

```
zid/
  Cargo.toml          # Crate manifest, feature flags, dependencies
  README.md
  src/
    lib.rs            # Public API re-exports, testkit module
    types.rs          # IdentityId, MachineId newtypes
    error.rs          # CryptoError enum (thiserror)
    keys/
      mod.rs          # Key module root
      neural.rs       # NeuralKey (root secret, zeroize)
      identity.rs     # IdentitySigningKey, IdentityVerifyingKey
      machine.rs      # MachineKeyPair, MachinePublicKey, MachineKeyCapabilities
    ops/
      mod.rs          # Operations module root
      derivation.rs   # HKDF-SHA256 key derivation with domain separation
      signing.rs      # HybridSignature, hybrid_sign, hybrid_verify
      encapsulation.rs# Hybrid KEM: X25519 + ML-KEM-768 encap/decap
    sharing/          # (feature = "shamir")
      mod.rs
      shamir.rs       # ShamirShare, split, combine
      shares_api.rs   # generate_identity, sign_with_shares, derive_machine_keypair_from_shares
    did.rs            # (feature = "did") did:key encode/decode/verify
```

## Usage

### Cargo Features

| Feature  | Default | Description |
|----------|---------|-------------|
| `serde`  | yes     | Serde `Serialize`/`Deserialize` on signature types |
| `did`    | yes     | DID key encoding/decoding (`bs58` dep) |
| `shamir` | yes     | Shamir secret sharing (`shamir-vault` + `hex` deps) |
| `testkit`| no      | Deterministic key derivation helpers for tests |

Disable defaults for a minimal build:

```toml
zid = { version = "0.2", default-features = false }
```

### Identity Generation and Signing

```rust,no_run
use zid::*;

let identity_id = IdentityId::new([0x01u8; 16]);
let mut rng = rand::thread_rng();

// Generate an identity split into 5 shares (3 needed to recover)
let bundle = generate_identity(3, 5, identity_id, &mut rng).unwrap();

// Sign with threshold shares
let sig = sign_with_shares(&bundle.shares[..3], identity_id, b"hello").unwrap();

// Verify
assert!(bundle.verifying_key.verify(b"hello", &sig).is_ok());
```

### Machine Key Derivation

```rust,no_run
use zid::*;

let identity_id = IdentityId::new([0x01u8; 16]);
let machine_id = MachineId::new([0x02u8; 16]);
let mut rng = rand::thread_rng();

let bundle = generate_identity(3, 5, identity_id, &mut rng).unwrap();

let caps = MachineKeyCapabilities::SIGN | MachineKeyCapabilities::ENCRYPT;
let mkp = derive_machine_keypair_from_shares(
    &bundle.shares[..3],
    identity_id,
    machine_id,
    1,    // epoch
    caps,
).unwrap();

let sig = mkp.sign(b"machine msg");
assert!(mkp.public_key().verify(b"machine msg", &sig).is_ok());
```

### Hybrid KEM

```rust,no_run
use zid::*;

let id = IdentityId::new([0x01u8; 16]);
let mut rng = rand::thread_rng();
let bundle = generate_identity(3, 5, id, &mut rng).unwrap();

let caps = MachineKeyCapabilities::SIGN | MachineKeyCapabilities::ENCRYPT;
let sender = derive_machine_keypair_from_shares(
    &bundle.shares[..3], id, MachineId::new([0xAA; 16]), 1, caps,
).unwrap();
let receiver = derive_machine_keypair_from_shares(
    &bundle.shares[..3], id, MachineId::new([0xBB; 16]), 1, caps,
).unwrap();

// Encapsulate to receiver
let (ss_send, encap_bundle) = receiver.public_key().encapsulate(&sender).unwrap();

// Decapsulate on receiver side
let ss_recv = receiver.decapsulate(&encap_bundle, &sender.public_key()).unwrap();

assert_eq!(ss_send.as_bytes(), ss_recv.as_bytes());
```

### Shamir Shares

```rust,no_run
use zid::*;

let identity_id = IdentityId::new([0x01u8; 16]);
let mut rng = rand::thread_rng();
let bundle = generate_identity(3, 5, identity_id, &mut rng).unwrap();

// Serialize shares to hex for transport/storage
let hex_strings: Vec<String> = bundle.shares.iter().map(|s| s.to_hex()).collect();

// Reconstruct from hex
let recovered: Vec<ShamirShare> = hex_strings
    .iter()
    .map(|h| ShamirShare::from_hex(h).unwrap())
    .collect();
```

### DID Encoding

```rust,no_run
use zid::*;

let identity_id = IdentityId::new([0x01u8; 16]);
let mut rng = rand::thread_rng();
let bundle = generate_identity(3, 5, identity_id, &mut rng).unwrap();

// The bundle includes the did:key string
println!("DID: {}", bundle.did);

// Manual round-trip
let pk = [0u8; 32]; // some Ed25519 public key bytes
let did = ed25519_to_did_key(&pk);
let recovered = did_key_to_ed25519(&did).unwrap();
assert_eq!(pk, recovered);
```

## License

Licensed under the [MIT License](LICENSE-MIT).
