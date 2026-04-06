# evidencebus-canonicalization

Deterministic JSON canonicalization for evidencebus.

## Purpose

This crate provides functions for canonicalizing JSON values to ensure deterministic serialization. Canonicalization ensures that semantically equivalent JSON values always produce the same byte representation, regardless of original key ordering or whitespace.

This is essential for reproducible digest computation and consistent evidence validation per [ADR-0005](../../docs/adrs/0005-determinism-and-digest-rules.md).

## Key Functions

### `canonicalize_json`

Canonicalizes a value to deterministic JSON by:

- Sorting object keys in lexicographic order
- Removing extraneous whitespace
- Producing compact output (no pretty-printing)

```rust
use evidencebus_canonicalization::canonicalize_json;
use serde_json::json;

let data = json!({
    "z": 1,
    "a": 2,
    "m": 3
});

let result = canonicalize_json(&data).unwrap();
// Keys are sorted: "a", "m", "z"
assert_eq!(result, r#"{"a":2,"m":3,"z":1}"#);
```

## Error Types

### `CanonicalizationError`

- `SerializationFailed` - JSON serialization failed

## Usage Examples

### Canonicalizing a Packet

```rust
use evidencebus_canonicalization::canonicalize_json;
use evidencebus_types::Packet;

let packet = create_packet();
let canonical = canonicalize_json(&packet)?;
println!("Canonical JSON: {}", canonical);
```

### Computing Deterministic Digests

```rust
use evidencebus_canonicalization::canonicalize_json;
use evidencebus_digest::compute_sha256;

let data = json!({"b": 2, "a": 1});
let canonical = canonicalize_json(&data)?;
let digest = compute_sha256(canonical.as_bytes());
println!("Deterministic digest: {}", digest);
```

### Comparing JSON Values

```rust
use evidencebus_canonicalization::canonicalize_json;
use serde_json::json;

let data1 = json!({"z": 1, "a": 2});
let data2 = json!({"a": 2, "z": 1});

let canon1 = canonicalize_json(&data1)?;
let canon2 = canonicalize_json(&data2)?;

assert_eq!(canon1, canon2); // Same canonical form
```

## Design Principles

- **Deterministic** - Same semantic JSON always produces same bytes
- **Recursive** - Sorts keys at all nesting levels
- **Compact** - No unnecessary whitespace
- **No I/O** - Pure transformation, no filesystem operations

## Canonicalization Rules

Per ADR-0005, canonicalization follows these rules:

1. **Object Keys** - Sorted lexicographically (UTF-8 code point order)
2. **No Whitespace** - Compact JSON with no spaces or newlines
3. **Recursive** - All nested objects are canonicalized
4. **Arrays Preserved** - Array order is maintained (not sorted)
5. **Numbers** - Preserved as-is (no normalization)

## Dependencies

- `serde` - Serialization framework
- `serde_json` - JSON implementation
- `thiserror` - Error handling

## Testing

The crate includes comprehensive tests for:

- Key sorting at multiple levels
- Nested object canonicalization
- Array handling
- Edge cases (empty objects, arrays)
- Error handling

Run tests with:

```bash
cargo test -p evidencebus-canonicalization
```

## Related Documentation

- [ADR-0005: Determinism and Digest Rules](../../docs/adrs/0005-determinism-and-digest-rules.md)
- [Architecture Guide](../../docs/architecture.md)
- [API Reference](../../docs/api-reference.md)

## License

MIT License - see [LICENSE](../../LICENSE) for details.
