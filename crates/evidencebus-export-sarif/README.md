# evidencebus-export-sarif

SARIF (Static Analysis Results Interchange Format) export for evidencebus.

## Purpose

This crate provides functions to convert evidence packets and bundles into SARIF 2.1.0 format for integration with tools like GitHub code scanning, IDE integrations, and other static analysis consumers.

## Key Functions

### `export_packet`

Exports a single packet to SARIF format.

```rust
use evidencebus_export_sarif::export_packet;
use evidencebus_types::Packet;

let packet = create_packet();
let sarif = export_packet(&packet)?;
println!("{}", serde_json::to_string_pretty(&sarif)?);
```

### `export_packets`

Exports multiple packets to a single SARIF document.

```rust
use evidencebus_export_sarif::export_packets;
use evidencebus_types::Packet;

let packets = vec![packet1, packet2, packet3];
let sarif = export_packets(&packets)?;
println!("{}", serde_json::to_string_pretty(&sarif)?);
```

## Helper Functions

### `sarif_level`

Maps finding severity to SARIF level.

```rust
use evidencebus_export_sarif::sarif_level;
use evidencebus_codes::FindingSeverity;

let level = sarif_level(&FindingSeverity::Error);
assert_eq!(level, "error");
```

### `sarif_result_kind`

Maps packet status to SARIF result kind.

```rust
use evidencebus_export_sarif::sarif_result_kind;
use evidencebus_codes::PacketStatus;

let kind = sarif_result_kind(&PacketStatus::Pass);
assert_eq!(kind, "pass");
```

## Error Types

### `SarifExportError`

- `SerializationFailed` - JSON serialization failed
- `InvalidInput` - Invalid input data provided

## Usage Examples

### Exporting a Packet to SARIF

```rust
use evidencebus_export_sarif::export_packet;
use evidencebus_types::Packet;

fn create_sarif_report(packet: &Packet) -> Result<String, Box<dyn std::error::Error>> {
    let sarif = export_packet(packet)?;
    Ok(serde_json::to_string_pretty(&sarif)?)
}
```

### Exporting a Bundle to SARIF

```rust
use evidencebus_export_sarif::export_packets;
use evidencebus_types::Packet;

fn create_bundle_sarif(packets: &[Packet]) -> Result<String, Box<dyn std::error::Error>> {
    let sarif = export_packets(packets)?;
    Ok(serde_json::to_string_pretty(&sarif)?)
}
```

### Writing to File

```rust
use evidencebus_export_sarif::export_packets;
use std::fs;

fn write_sarif_file(packets: &[Packet], path: &str) -> Result<(), Box<dyn std::error::Error>> {
    let sarif = export_packets(packets)?;
    fs::write(path, serde_json::to_string_pretty(&sarif)?)?;
    Ok(())
}
```

## SARIF Output Format

The SARIF export follows the SARIF 2.1.0 standard with:

1. **Version** - Always "2.1.0"
2. **Schema** - References official SARIF schema
3. **Runs** - One run per export (or per packet for single packet export)
4. **Tool** - evidencebus as the driver
5. **Results** - Findings and assertions converted to SARIF results
6. **Locations** - File locations from findings

### Example Output

```json
{
  "version": "2.1.0",
  "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
  "runs": [
    {
      "tool": {
        "driver": {
          "name": "evidencebus",
          "version": "0.1.0",
          "informationUri": "https://github.com/EffortlessMetrics/evidencebus"
        }
      },
      "results": [
        {
          "ruleId": "faultline.suspect_window",
          "level": "warning",
          "message": {
            "text": "Suspect window remains"
          },
          "locations": [
            {
              "physicalLocation": {
                "artifactLocation": {
                  "uri": "crates/parser/src/lib.rs"
                }
              }
            }
          ]
        }
      ]
    }
  ]
}
```

## Lossy Export

SARIF export is inherently lossy because SARIF is designed for static analysis results, not general evidence. The following fields are omitted:

- **Metrics** - Not applicable to SARIF
- **Relations** - Not applicable to SARIF
- **Native payloads** - Referenced but not embedded
- **Attachments without locations** - No location to report

This is intentional and documented per [ADR-0004](../../docs/adrs/0004-lossy-export-policy.md).

## Design Principles

- **SARIF Compliant** - Follows SARIF 2.1.0 specification
- **Tool Integration** - Designed for GitHub code scanning and IDE integrations
- **Explicitly Lossy** - Clear about what information is omitted
- **Standard Format** - Uses industry-standard SARIF format

## Severity Mapping

| evidencebus Severity | SARIF Level |
|-------------------|--------------|
| Note | note |
| Warning | warning |
| Error | error |

## Status Mapping

| evidencebus Status | SARIF Result Kind |
|-------------------|-------------------|
| Pass | pass |
| Fail | fail |
| Warn | review |
| Indeterminate | notApplicable |
| Error | fail |

## Dependencies

- `evidencebus-codes` - Shared enums (status, severity)
- `evidencebus-types` - Core data structures
- `serde_json` - JSON serialization
- `thiserror` - Error handling

## Testing

The crate includes comprehensive tests for:

- Packet export
- Bundle export
- Severity mapping
- Status mapping
- SARIF compliance

Run tests with:

```bash
cargo test -p evidencebus-export-sarif
```

## Related Documentation

- [ADR-0004: Lossy Export Policy](../../docs/adrs/0004-lossy-export-policy.md)
- [Exporting to Different Formats](../../docs/tutorials/exporting-formats.md)
- [Architecture Guide](../../docs/architecture.md)
- [API Reference](../../docs/api-reference.md)

## License

MIT License - see [LICENSE](../../LICENSE) for details.
