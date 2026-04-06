# evidencebus-fs

Filesystem I/O for evidencebus packets and bundles.

## Purpose

This crate provides functions for reading and writing packets and bundles with safe path handling to prevent path traversal attacks. It handles all filesystem operations for evidencebus, including loading packets, building bundles, and validating file integrity.

## Key Functions

### `read_packet`

Reads and deserializes a packet JSON file.

```rust
use evidencebus_fs::read_packet;
use std::path::Path;

let packet = read_packet(Path::new("packet.eb.json"))?;
```

### `write_packet`

Writes a packet to JSON with canonical formatting.

```rust
use evidencebus_fs::write_packet;
use std::path::Path;

write_packet(Path::new("packet.eb.json"), &packet)?;
```

### `load_target`

Loads a target (packet or bundle) from the filesystem.

```rust
use evidencebus_fs::load_target;
use std::path::Path;

let target = load_target(Path::new("./bundle"))?;

match target {
    LoadedTarget::Packet(packet) => println!("Loaded packet"),
    LoadedTarget::Bundle { manifest, packets } => println!("Loaded bundle"),
}
```

### `validate_target`

Validates a loaded target.

```rust
use evidencebus_fs::{load_target, validate_target};
use std::path::Path;

let target = load_target(Path::new("./bundle"))?;
validate_target(&target)?;
```

### `build_bundle`

Creates a bundle from packet files.

```rust
use evidencebus_fs::build_bundle;
use std::path::Path;

let packets = vec![
    PathBuf::from("packet1.eb.json"),
    PathBuf::from("packet2.eb.json"),
];

build_bundle(&packets, Path::new("./output-bundle"))?;
```

## Data Structures

### `LoadedBundle`

A loaded bundle with manifest and packets.

```rust
pub struct LoadedBundle {
    pub manifest: BundleManifest,
    pub packets: Vec<Packet>,
}
```

### `LoadedTarget`

A loaded target (either a packet or a bundle).

```rust
pub enum LoadedTarget {
    Packet(Packet),
    Bundle(LoadedBundle),
}
```

## Error Types

### `FsError`

- `IoError` - Filesystem I/O error
- `InvalidJson` - JSON parsing failed
- `PathError` - Path validation failed
- `BundleCreationFailed` - Bundle creation failed
- `ArtifactCopyFailed` - Artifact copy failed
- `ValidationError` - Packet validation failed
- `BundleValidationError` - Bundle validation failed
- `CanonicalizationError` - JSON canonicalization failed
- `DigestError` - Digest operation failed
- `CoreError` - Core operation failed
- `InvalidInput` - Invalid input provided

## Usage Examples

### Loading a Packet

```rust
use evidencebus_fs::read_packet;
use std::path::Path;

fn load_and_process(path: &Path) -> Result<(), Box<dyn std::error::Error>> {
    let packet = read_packet(path)?;
    println!("Loaded packet: {}", packet.packet_id);
    Ok(())
}
```

### Creating a Bundle

```rust
use evidencebus_fs::build_bundle;
use std::path::PathBuf;

fn create_bundle_from_packets() -> Result<(), Box<dyn std::error::Error>> {
    let packets = vec![
        PathBuf::from("packets/packet1.eb.json"),
        PathBuf::from("packets/packet2.eb.json"),
    ];

    build_bundle(&packets, PathBuf::from("./output-bundle"))?;
    println!("Bundle created successfully");
    Ok(())
}
```

### Loading and Validating a Bundle

```rust
use evidencebus_fs::{load_target, validate_target};
use std::path::Path;

fn load_and_validate(path: &Path) -> Result<(), Box<dyn std::error::Error>> {
    let target = load_target(path)?;
    validate_target(&target)?;
    println!("Bundle is valid");
    Ok(())
}
```

### Writing a Packet

```rust
use evidencebus_fs::write_packet;
use std::path::Path;

fn save_packet(packet: &Packet, path: &Path) -> Result<(), Box<dyn std::error::Error>> {
    write_packet(path, packet)?;
    println!("Packet saved to {}", path.display());
    Ok(())
}
```

## Design Principles

- **Safe Path Handling** - Prevents path traversal attacks
- **Canonical Output** - Writes packets in canonical JSON format
- **Validation Integration** - Validates packets and bundles during operations
- **Explicit Errors** - Clear error messages for failures

## Bundle Creation Process

When creating a bundle, the crate:

1. **Loads Packets** - Reads and validates all packet files
2. **Detects Conflicts** - Checks for duplicate packet IDs
3. **Builds Manifest** - Creates bundle manifest with digests
4. **Creates Directory Structure** - Creates canonical bundle layout
5. **Copies Artifacts** - Copies artifacts with integrity checks
6. **Writes Manifest** - Writes `bundle.eb.json` with canonical JSON

## Path Safety

All path operations enforce:

- **No Traversal** - Rejects paths with `..` components
- **Relative Only** - Rejects absolute paths
- **Forward Slashes** - Normalizes to forward slashes
- **Sanitization** - Sanitizes path components

## Dependencies

- `evidencebus-canonicalization` - JSON canonicalization
- `evidencebus-codes` - Validation modes
- `evidencebus-core` - Bundle construction
- `evidencebus-digest` - Digest computation
- `evidencebus-path` - Path validation
- `evidencebus-types` - Core data structures
- `evidencebus-validation` - Packet and bundle validation
- `thiserror` - Error handling

## Testing

The crate includes comprehensive BDD-style tests for:

- Packet reading and writing
- Bundle creation
- Target loading
- Validation
- Path safety
- Error handling

Run tests with:

```bash
cargo test -p evidencebus-fs
```

## Related Documentation

- [Architecture Guide](../../docs/architecture.md)
- [Building a Bundle](../../docs/tutorials/building-a-bundle.md)
- [Validating Packets and Bundles](../../docs/tutorials/validating-packets-bundles.md)
- [API Reference](../../docs/api-reference.md)

## License

MIT License - see [LICENSE](../../LICENSE) for details.
