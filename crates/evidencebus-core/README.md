# evidencebus-core

Core bundle construction and semantics for evidencebus.

## Purpose

This crate provides pure functions for building bundles, manifests, and summaries, as well as deduplicating packets and detecting conflicts. It contains the core business logic for bundle creation without any filesystem operations.

## Key Functions

### `dedupe_packets`

Deduplicates packets by digest, keeping the first occurrence.

```rust
use evidencebus_core::dedupe_packets;
use evidencebus_types::Packet;

let packets = vec![packet1, packet2, packet3];
let deduped = dedupe_packets(packets)?;
```

### `detect_conflicts`

Detects conflicts between packets (same ID, different content).

```rust
use evidencebus_core::detect_conflicts;
use evidencebus_types::Packet;

let packets = vec![packet1, packet2];
let conflicts = detect_conflicts(&packets);

for conflict in conflicts {
    println!("Conflict: {} has different digests", conflict.packet_id);
}
```

### `build_bundle_manifest`

Builds a bundle manifest from packets and artifacts.

```rust
use evidencebus_core::build_bundle_manifest;
use evidencebus_types::{Packet, Artifact};

let manifest = build_bundle_manifest(&packets, &artifacts)?;
```

### `build_bundle_summary`

Builds a summary of a bundle.

```rust
use evidencebus_core::build_bundle_summary;
use evidencebus_types::Packet;

let summary = build_bundle_summary(&packets);
println!("Total packets: {}", summary.total_packets);
println!("Status counts: {:?}", summary.status_counts);
```

## Error Types

### `CoreError`

- `Conflict` - Conflict detected between packets
- `Canonicalization` - JSON canonicalization failed
- `InvalidDigest` - Digest format is invalid
- `Serialization` - JSON serialization failed

## Usage Examples

### Creating a Bundle Manifest

```rust
use evidencebus_core::build_bundle_manifest;
use evidencebus_types::{Packet, Artifact};

fn create_manifest(packets: &[Packet], artifacts: &[Artifact]) -> Result<(), Box<dyn std::error::Error>> {
    let manifest = build_bundle_manifest(packets, artifacts)?;
    println!("Manifest: {:?}", manifest);
    Ok(())
}
```

### Detecting Packet Conflicts

```rust
use evidencebus_core::detect_conflicts;
use evidencebus_types::Packet;

fn check_conflicts(packets: &[Packet]) -> Result<(), String> {
    let conflicts = detect_conflicts(packets);

    if !conflicts.is_empty() {
        return Err(format!("Found {} conflicts", conflicts.len()));
    }

    Ok(())
}
```

### Building a Bundle Summary

```rust
use evidencebus_core::build_bundle_summary;
use evidencebus_types::Packet;

fn summarize_bundle(packets: &[Packet]) {
    let summary = build_bundle_summary(packets);

    println!("Bundle Summary:");
    println!("  Total packets: {}", summary.total_packets);
    println!("  Total artifacts: {}", summary.total_artifacts);
    println!("  Status: {:?}", summary.status_counts);
    println!("  Severity: {:?}", summary.severity_counts);
}
```

## Design Principles

- **Pure Functions** - No I/O, deterministic behavior
- **Conflict Detection** - Identifies duplicate packet IDs with different content
- **Deduplication** - Removes duplicate packets by digest
- **Manifest Building** - Creates bundle manifests with integrity metadata

## Bundle Manifest Structure

The bundle manifest includes:

1. **Packets** - List of packet entries with IDs, paths, and digests
2. **Artifacts** - List of artifact entries with packet IDs, paths, roles, and digests
3. **Integrity** - Manifest digest, packet digests, and artifact digests

## Bundle Summary Structure

The bundle summary includes:

1. **Total Packets** - Count of packets in bundle
2. **Total Artifacts** - Count of artifacts in bundle
3. **Status Counts** - Breakdown by packet status (passed, failed, etc.)
4. **Severity Counts** - Breakdown by finding severity (error, warning, etc.)

## Conflict Detection

Conflicts are detected when:

1. Two packets have the same `packet_id`
2. The packets have different content (different digests)

Identical packets (same ID, same digest) are automatically deduplicated.

## Dependencies

- `evidencebus-canonicalization` - JSON canonicalization
- `evidencebus-digest` - Digest computation
- `evidencebus-types` - Core data structures
- `thiserror` - Error handling

## Testing

The crate includes comprehensive BDD-style tests for:

- Packet deduplication
- Conflict detection
- Manifest building
- Summary generation
- Edge cases

Run tests with:

```bash
cargo test -p evidencebus-core
```

## Related Documentation

- [Architecture Guide](../../docs/architecture.md)
- [Building a Bundle](../../docs/tutorials/building-a-bundle.md)
- [API Reference](../../docs/api-reference.md)

## License

MIT License - see [LICENSE](../../LICENSE) for details.
