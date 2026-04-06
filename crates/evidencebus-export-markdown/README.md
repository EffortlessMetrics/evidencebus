# evidencebus-export-markdown

Markdown export for evidencebus packets and bundles.

## Purpose

This crate provides functions to convert evidence packets and bundles into human-readable Markdown summaries. Markdown exports are ideal for documentation, pull request reviews, and human consumption.

## Key Functions

### `export_packet`

Exports a single packet to Markdown format.

```rust
use evidencebus_export_markdown::export_packet;
use evidencebus_types::Packet;

let packet = create_packet();
let markdown = export_packet(&packet)?;
println!("{}", markdown);
```

### `export_bundle`

Exports multiple packets to a combined Markdown summary.

```rust
use evidencebus_export_markdown::export_bundle;
use evidencebus_types::Packet;

let packets = vec![packet1, packet2, packet3];
let markdown = export_bundle(&packets, true, false)?;
println!("{}", markdown);
```

## Helper Functions

### `status_emoji`

Returns an emoji for a packet status.

```rust
use evidencebus_export_markdown::status_emoji;
use evidencebus_codes::PacketStatus;

let emoji = status_emoji(&PacketStatus::Pass);
assert_eq!(emoji, "✅");
```

### `severity_emoji`

Returns an emoji for a finding severity.

```rust
use evidencebus_export_markdown::severity_emoji;
use evidencebus_codes::FindingSeverity;

let emoji = severity_emoji(&FindingSeverity::Error);
assert_eq!(emoji, "🔴");
```

### `attachment_role_emoji`

Returns an emoji for an attachment role.

```rust
use evidencebus_export_markdown::attachment_role_emoji;
use evidencebus_types::AttachmentRole;

let emoji = attachment_role_emoji(&AttachmentRole::NativePayload);
assert_eq!(emoji, "📦");
```

## Error Types

### `MarkdownExportError`

- `InvalidInput` - Invalid input data provided

## Usage Examples

### Exporting a Packet to Markdown

```rust
use evidencebus_export_markdown::export_packet;
use evidencebus_types::Packet;

fn create_summary(packet: &Packet) -> Result<String, Box<dyn std::error::Error>> {
    let markdown = export_packet(packet)?;
    Ok(markdown)
}
```

### Exporting a Bundle to Markdown

```rust
use evidencebus_export_markdown::export_bundle;
use evidencebus_types::Packet;

fn create_bundle_summary(packets: &[Packet]) -> Result<String, Box<dyn std::error::Error>> {
    let markdown = export_bundle(packets, true, true)?;
    Ok(markdown)
}
```

### Writing to File

```rust
use evidencebus_export_markdown::export_packet;
use std::fs;

fn write_packet_summary(packet: &Packet, path: &str) -> Result<(), Box<dyn std::error::Error>> {
    let markdown = export_packet(packet)?;
    fs::write(path, markdown)?;
    Ok(())
}
```

## Markdown Output Format

The Markdown export includes:

1. **Packet Header** - Packet ID with status emoji
2. **Metadata** - Producer, subject, timestamps
3. **Summary** - Status, title, short summary
4. **Assertions** - List of assertions with status
5. **Findings** - List of findings with severity and location
6. **Metrics** - Table of metrics with values and units
7. **Attachments** - List of attachments with roles and sizes
8. **Provenance** - Command, environment, platform info
9. **Labels** - Key-value labels

### Example Output

```markdown
# Evidence Packet: pkt-faultline

## Metadata
- **Tool**: faultline v0.1.0
- **Subject**: EffortlessMetrics/example @ bad456
- **Created**: 2024-01-15T10:30:00Z

## Summary
❓ **Indeterminate**: Suspect window narrowed

Skipped midpoint prevented exact first-bad localization.

## Assertions
✅ **faultline.localization**: Localization outcome
- Status: indeterminate
- Summary: A suspect window of three commits remains.

## Findings
⚠️ **faultline.suspect_window**: Suspect window remains
Read parser changes and workflow changes first.
- Location: crates/parser/src/lib.rs

## Metrics
| Metric | Value | Unit |
|--------|-------|------|
| suspect_window_commits | 3 | count |

## Attachments
📦 **native_payload**: faultline/analysis.json (151 bytes)
📊 **report_html**: faultline/index.html (208 bytes)
⚠️ **stderr_log**: logs/stderr.log (22 bytes)

## Provenance
- **Command**: faultline --good good123 --bad bad456 --cmd 'cargo test parser_regression'
- **Environment**: linux-x86_64
- **Platform**: linux/x86_64

## Labels
- category: localization
```

## Design Principles

- **Human-Readable** - Clear, well-formatted output
- **Complete** - Includes all relevant information
- **Structured** - Uses standard Markdown formatting
- **Emoji-Enhanced** - Uses emojis for visual clarity

## Dependencies

- `evidencebus-codes` - Shared enums (status, severity)
- `evidencebus-types` - Core data structures
- `thiserror` - Error handling

## Testing

The crate includes comprehensive tests for:

- Packet export
- Bundle export
- Emoji mapping
- Edge cases

Run tests with:

```bash
cargo test -p evidencebus-export-markdown
```

## Related Documentation

- [Exporting to Different Formats](../../docs/tutorials/exporting-formats.md)
- [Architecture Guide](../../docs/architecture.md)
- [API Reference](../../docs/api-reference.md)

## License

MIT License - see [LICENSE](../../LICENSE) for details.
