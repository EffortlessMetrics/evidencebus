# evidencebus-digest

SHA-256 digest computation and verification for evidencebus.

## Purpose

This crate provides deterministic digest operations for computing and verifying SHA-256 digests. It is a core primitive used throughout the evidencebus workspace for integrity checking and reproducible evidence validation.

## Key Functions

### `compute_sha256`

Computes the SHA-256 digest of given data.

```rust
use evidencebus_digest::compute_sha256;

let digest = compute_sha256(b"hello world");
assert_eq!(digest.len(), 64);
```

### `verify_digest`

Verifies that data matches an expected digest.

```rust
use evidencebus_digest::{compute_sha256, verify_digest};

let data = b"hello world";
let expected = compute_sha256(data);
assert!(verify_digest(data, &expected).is_ok());
```

## Error Types

### `DigestError`

- `VerificationFailed` - Expected and actual digests don't match
- `InvalidFormat` - Digest format is invalid (wrong length or invalid hex characters)

## Usage Examples

### Computing a File Digest

```rust
use evidencebus_digest::compute_sha256;
use std::fs;

let content = fs::read("path/to/file")?;
let digest = compute_sha256(&content);
println!("SHA-256: {}", digest);
```

### Verifying Data Integrity

```rust
use evidencebus_digest::verify_digest;

let data = get_data();
let expected_digest = "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9";

match verify_digest(&data, expected_digest) {
    Ok(_) => println!("Data integrity verified"),
    Err(e) => println!("Verification failed: {}", e),
}
```

## Design Principles

- **Deterministic** - Same input always produces the same digest
- **Secure** - Uses SHA-256 cryptographic hash
- **Simple** - Minimal API surface area
- **No I/O** - Pure computation, no filesystem operations

## Dependencies

- `sha2` - SHA-256 implementation
- `hex` - Hex encoding/decoding
- `thiserror` - Error handling

## Testing

The crate includes comprehensive tests for:

- Known digest values
- Verification success/failure
- Invalid digest formats
- Edge cases

Run tests with:

```bash
cargo test -p evidencebus-digest
```

## Related Documentation

- [ADR-0005: Determinism and Digest Rules](../../docs/adrs/0005-determinism-and-digest-rules.md)
- [Architecture Guide](../../docs/architecture.md)
- [API Reference](../../docs/api-reference.md)

## License

MIT License - see [LICENSE](../../LICENSE) for details.
