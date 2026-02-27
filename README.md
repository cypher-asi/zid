# zid

Post-quantum hybrid cryptography library for identity and machine key management.

## Features

- **Hybrid signatures** — Ed25519 + ML-DSA-65 (FIPS 204). Both components must
  verify for a signature to be accepted.
- **Hybrid key encapsulation** — X25519 + ML-KEM-768 (FIPS 203). Shared secrets
  are derived by HKDF-combining both KEM outputs.
- **Deterministic derivation** — All keys are derived from a single 256-bit root
  secret (NeuralKey) via HKDF-SHA256 with domain separation.
- **Shamir secret sharing** — Split the root secret into threshold shares for
  secure backup and recovery.
- **DID encoding** — `did:key` representation of Ed25519 public keys.

## Cargo Features

| Feature  | Default | Description |
|----------|---------|-------------|
| `serde`  | yes     | Serde `Serialize`/`Deserialize` on signature types |
| `did`    | yes     | DID key encoding/decoding (`bs58` dep) |
| `shamir` | yes     | Shamir secret sharing (`shamir-vault` + `hex` deps) |

Disable defaults for a minimal build:

```toml
zid = { version = "0.2", default-features = false }
```

## Quick Start

```rust,no_run
use zid::*;

// Generate an identity split into 5 shares (3 needed to recover)
let identity_id = IdentityId::new([0x01u8; 16]);
let mut rng = rand::thread_rng();
let bundle = generate_identity(3, 5, identity_id, &mut rng).unwrap();

// Sign with threshold shares
let sig = sign_with_shares(&bundle.shares[..3], identity_id, b"hello").unwrap();

// Verify
assert!(bundle.verifying_key.verify(b"hello", &sig).is_ok());
```

## License

Licensed under either of [Apache License, Version 2.0](LICENSE-APACHE) or
[MIT License](LICENSE-MIT) at your option.
