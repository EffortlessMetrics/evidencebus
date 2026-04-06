# evidencebus-export

Evidence export for Markdown and SARIF formats.

## Purpose

This crate provides a unified interface for exporting evidence packets and bundles to different formats. It acts as a facade, delegating to format-specific crates (`evidencebus-export-markdown` and `evidencebus-export-sarif`).

## Key Functions

### `export_packet_markdown`

Exports a single packet to Markdown format.

```rust
use evidencebus_export::export_packet_markdown;
use evidencebus_types::Packet;

let packet = create_packet();
let markdown = export_packet_markdown(&packet, true, false)?;
println!("{}", markdown);
```

### `export_bundle_markdown`

Exports multiple packets to a combined Markdown summary.

```rust
use evidencebus_export::export_bundle_markdown;
use evidencebus_types::Packet;

let packets = vec![packet1, packet2];
let markdown = export_bundle_markdown(&packets, true, false)?;
println!("{}", markdown);
```

### `export_packets_sarif`

Exports multiple packets to SARIF format.

```rust
use evidencebus_export::export_packets_sarif;
use evidencebus_types::Packet;

let packets = vec![packet1, packet2];
let sarif = export_packets_sarif(&packets)?;
println!("{}", serde_json::to_string_pretty(&sarif)?);
```

## Configuration

### `ExportOptions`

Controls export behavior:

```rust
use evidencebus_export::{ExportOptions, LossyMode};

let options = ExportOptions::new()
    .with_include_details(true)
    .with_include_artifacts(true)
    .with_lossy_mode(LossyMode::Permissive);
```

### `LossyMode`

Controls how lossy exports are handled:

- `Strict` - Error on lossy export
- `Permissive` - Warn on lossy export
- `Silent` - Don't report lossiness

## Error Types

### `ExportError`

- `UnsupportedFormat` - Requested format is not supported
- `LossyExport` - Export is lossy and mode is strict
- `SerializationFailed` - JSON serialization failed
- `InvalidInput` - Invalid input data provided

## Usage Examples

### Exporting with Options

```rust
use evidencebus_export::{export_packet_markdown, ExportOptions};
use evidencebus_types::Packet;

fn export_with_options(packet: &Packet) -> Result<String, Box<dyn std::error::Error>> {
    let options = ExportOptions::new()
        .with_include_details(true)
        .with_include_artifacts(false);

    let markdown = export_packet_markdown(packet, options.include_details, options.include_artifacts)?;
    Ok(markdown)
}
```

### Handling Lossy Exports

```rust
use evidencebus_export::{export_packets_sarif, LossyMode};
use evidencebus_types::Packet;

fn export_strict(packets: &[Packet]) -> Result<String, Box<dyn std::error::Error>> {
    // SARIF export is lossy, so this would fail in strict mode
    // For now, use permissive mode
    let sarif = export_packets_sarif(packets)?;
    Ok(serde_json::to_string_pretty(&sarif)?)
}
```

### Exporting to File

```rust
use evidencebus_export::{export_bundle_markdown, ExportOptions};
use evidencebus_types::Packet;
use std::fs;

fn write_bundle_summary(packets: &[Packet], path: &str) -> Result<(), Box<dyn std::error::Error>> {
    let options = ExportOptions::new()
        .with_include_details(true)
        .with_include_artifacts(true);

    let markdown = export_bundle_markdown(packets, options.include_details, options.include_artifacts)?;
    fs::write(path, markdown)?;
    Ok(())
}
```

## Design Principles

- **Facade Pattern** - Provides unified interface to format-specific crates
- **Delegation** - Delegates to specialized crates for format-specific logic
- **Configuration** - Provides options for controlling export behavior
- **Lossy Awareness** - Explicitly handles lossy exports

## Export Formats

### Markdown

- **Purpose**: Human-readable reports
- **Use Cases**: Documentation, PR reviews, summaries
- **Lossiness**: Minimal (all information preserved)
- **Implementation**: `evidencebus-export-markdown`

### SARIF

- **Purpose**: Tool integration (GitHub code scanning, IDEs)
- **Use Cases**: CI/CD integration, security scanning
- **Lossiness**: High (metrics, relations omitted)
- **Implementation**: `evidencebus-export-sarif`

## Dependencies

- `evidencebus-codes` - Shared enums (status, severity)
- `evidencebus-export-markdown` - Markdown export implementation
- `evidencebus-export-sarif` - SARIF export implementation
- `evidencebus-types` - Core data structures
- `thiserror` - Error handling

## Testing

The crate includes comprehensive tests for:

- Export options
- Lossy mode handling
- Format delegation
- Error handling

Run tests with:

```bash
cargo test -p evidencebus-export
```

## Related Documentation

- [Exporting to Different Formats](../../docs/tutorials/exporting-formats.md)
- [ADR-0004: Lossy Export Policy](../../docs/adrs/0004-lossy-export-policy.md)
- [Architecture Guide](../../docs/architecture.md)
- [API Reference](../../docs/api-reference.md)

## License

MIT License - see [LICENSE](../../LICENSE) for details.
