# evidencebus-validation

Packet and bundle validation for evidencebus.

## Purpose

This crate provides validation functions for packets, bundles, and artifacts, with comprehensive error reporting for validation failures. It ensures that all evidence conforms to the schema and maintains data integrity.

## Key Functions

### `validate_packet`

Validates a packet structure and content.

```rust
use evidencebus_validation::validate_packet;
use evidencebus_types::Packet;

let packet = create_packet();
match validate_packet(&packet) {
    Ok(_) => println!("Packet is valid"),
    Err(e) => println!("Validation failed: {}", e),
}
```

### `validate_bundle`

Validates a bundle and all its packets.

```rust
use evidencebus_validation::validate_bundle;
use evidencebus_types::Bundle;

let bundle = create_bundle();
match validate_bundle(&bundle) {
    Ok(_) => println!("Bundle is valid"),
    Err(e) => println!("Validation failed: {}", e),
}
```

### `validate_attachment`

Validates an attachment's structure and references.

```rust
use evidencebus_validation::validate_attachment;
use evidencebus_types::Attachment;

let attachment = create_attachment();
match validate_attachment(&attachment) {
    Ok(_) => println!("Attachment is valid"),
    Err(e) => println!("Validation failed: {}", e),
}
```

## Error Types

### `ValidationError`

Errors that can occur when validating packets:

- `SchemaInvalid` - Schema version is invalid
- `MissingRequiredField` - Required field is missing
- `InvalidEnum` - Enum value is invalid
- `ReferenceInvalid` - Reference is invalid
- `DigestMismatch` - Digest doesn't match content
- `DuplicatePacketId` - Duplicate packet ID detected
- `PathTraversal` - Path traversal detected
- `UnsafePath` - Unsafe path detected

### `BundleValidationError`

Errors that can occur when validating bundles:

- `ManifestInvalid` - Bundle manifest is invalid
- `MissingArtifact` - Referenced artifact is missing
- `ConflictingPacket` - Packet conflict detected
- `InventoryMismatch` - Bundle inventory doesn't match
- `DigestMismatch` - Digest doesn't match content
- `InvalidDigest` - Digest format is invalid

## Usage Examples

### Validating a Packet

```rust
use evidencebus_validation::validate_packet;
use evidencebus_types::Packet;

fn process_packet(packet: &Packet) -> Result<(), Box<dyn std::error::Error>> {
    validate_packet(packet)?;
    println!("Packet is valid");
    Ok(())
}
```

### Validating a Bundle

```rust
use evidencebus_validation::validate_bundle;
use evidencebus_types::Bundle;

fn process_bundle(bundle: &Bundle) -> Result<(), Box<dyn std::error::Error>> {
    validate_bundle(bundle)?;
    println!("Bundle is valid");
    Ok(())
}
```

### Handling Validation Errors

```rust
use evidencebus_validation::{validate_packet, ValidationError};

let packet = create_packet();

match validate_packet(&packet) {
    Ok(_) => println!("Valid"),
    Err(ValidationError::DigestMismatch { expected, actual }) => {
        println!("Digest mismatch:");
        println!("  Expected: {}", expected);
        println!("  Actual:   {}", actual);
    }
    Err(ValidationError::PathTraversal(path)) => {
        println!("Path traversal detected: {}", path);
    }
    Err(e) => println!("Validation error: {}", e),
}
```

### Custom Validation Logic

```rust
use evidencebus_validation::validate_packet;
use evidencebus_types::Packet;

fn validate_with_custom_rules(packet: &Packet) -> Result<(), String> {
    // Run standard validation
    validate_packet(packet).map_err(|e| e.to_string())?;

    // Add custom rules
    if packet.labels.get("category").is_none() {
        return Err("Packet must have a 'category' label".to_string());
    }

    Ok(())
}
```

## Validation Rules

### Packet Validation

1. **Schema Version** - Must be valid version format
2. **Packet ID** - Must be non-empty and valid
3. **Producer** - Must have tool_name, tool_version, invocation_id
4. **Subject** - Must have vcs_kind, repo_identifier, commit
5. **Summary** - Must have status, title, short_summary
6. **Projections** - Must have valid assertions, findings, metrics
7. **Attachments** - Must have valid paths and digests
8. **Provenance** - Must have command, environment_fingerprint
9. **Labels** - Optional, but must be valid key-value pairs
10. **Created At** - Must be valid ISO 8601 timestamp

### Bundle Validation

1. **Manifest** - Must have valid packets and artifacts entries
2. **Packet Digests** - Must match actual packet content
3. **Artifact Digests** - Must match actual artifact content
4. **No Conflicts** - No duplicate packet IDs with different content
5. **Inventory Match** - All listed files must exist

### Attachment Validation

1. **Path Safety** - No path traversal, relative only
2. **Digest Format** - Must be valid 64-character hex string
3. **Size** - Must be positive integer
4. **Media Type** - Must be valid MIME type

## Design Principles

- **Comprehensive** - Validates all aspects of packets and bundles
- **Clear Errors** - Descriptive error messages for failures
- **Early Detection** - Fails fast on obvious issues
- **Extensible** - Easy to add custom validation rules

## Dependencies

- `evidencebus-codes` - Shared error codes
- `evidencebus-digest` - Digest computation
- `evidencebus-path` - Path validation
- `evidencebus-types` - Core data structures
- `thiserror` - Error handling

## Testing

The crate includes comprehensive BDD-style tests for:

- Packet validation rules
- Bundle validation rules
- Attachment validation
- Error handling
- Edge cases

Run tests with:

```bash
cargo test -p evidencebus-validation
```

## Related Documentation

- [Architecture Guide](../../docs/architecture.md)
- [API Reference](../../docs/api-reference.md)
- [Schema Documentation](../../docs/schema.md)
- [Validation Tutorial](../../docs/tutorials/validating-packets-bundles.md)

## License

MIT License - see [LICENSE](../../LICENSE) for details.
