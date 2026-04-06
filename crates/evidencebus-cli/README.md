# evidencebus-cli

CLI (Command Line Interface) for evidencebus.

## Purpose

This crate provides the command-line interface for evidencebus, serving as the composition root that brings together all other crates. It exposes operator-facing commands for validating, bundling, inspecting, and exporting evidence.

## Commands

### `validate`

Validates a packet or bundle.

```bash
evidencebus validate packet.eb.json
evidencebus validate ./bundle
evidencebus validate packet.eb.json --schema-only
```

### `bundle`

Creates a bundle from packet files.

```bash
evidencebus bundle packet1.eb.json packet2.eb.json --out ./my-bundle
```

### `inspect`

Inspects a packet or bundle.

```bash
evidencebus inspect packet.eb.json
evidencebus inspect ./bundle --format json
```

### `emit`

Exports a packet or bundle to different formats.

```bash
# Markdown export
evidencebus emit markdown ./bundle --out ./summary.md

# SARIF export
evidencebus emit sarif ./bundle --out ./results.sarif

# With details and artifacts
evidencebus emit markdown ./bundle --out ./full.md --details --artifacts
```

### `schema`

Displays schema information.

```bash
# Pretty format
evidencebus schema packet --format pretty

# JSON format
evidencebus schema bundle --format json
```

## Usage Examples

### Basic Workflow

```bash
# Validate a packet
evidencebus validate packet.eb.json

# Create a bundle
evidencebus bundle packet1.eb.json packet2.eb.json --out ./bundle

# Inspect the bundle
evidencebus inspect ./bundle

# Export to Markdown
evidencebus emit markdown ./bundle --out ./summary.md

# Export to SARIF
evidencebus emit sarif ./bundle --out ./results.sarif
```

### CI/CD Integration

```bash
#!/bin/bash
set -e

# Validate all packets
for packet in evidence/packets/*.eb.json; do
  evidencebus validate "$packet"
done

# Create bundle
evidencebus bundle evidence/packets/*.eb.json --out ./evidence-bundle

# Export for review
evidencebus emit markdown ./evidence-bundle --out ./evidence-summary.md

# Export for GitHub
evidencebus emit sarif ./evidence-bundle --out ./results.sarif
```

### GitHub Actions Integration

```yaml
name: Evidence Report

on:
  pull_request:

jobs:
  evidence:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3

      - name: Install evidencebus
        run: cargo install --path .

      - name: Run evidence tools
        run: |
          ./run-faultline.sh
          ./run-perfgate.sh

      - name: Create evidence bundle
        run: |
          evidencebus bundle \
            packets/*.eb.json \
            --out ./evidence-bundle

      - name: Export to SARIF
        run: |
          evidencebus emit sarif ./evidence-bundle --out ./results.sarif

      - name: Upload SARIF
        uses: github/codeql-action/upload-sarif@v2
        with:
          sarif_file: ./results.sarif
```

## Command Reference

### validate

Validates a packet or bundle.

**Arguments:**
- `target` - Path to packet file or bundle directory

**Options:**
- `-s, --schema-only` - Validate schema only, skip file existence checks

**Examples:**
```bash
evidencebus validate packet.eb.json
evidencebus validate ./bundle --schema-only
```

### bundle

Creates a bundle from packet files.

**Arguments:**
- `packets` - Packet files to include in bundle (required)

**Options:**
- `-o, --out <path>` - Output directory for bundle (default: `./evidence-bundle`)

**Examples:**
```bash
evidencebus bundle packet1.eb.json packet2.eb.json --out ./my-bundle
```

### inspect

Inspects a packet or bundle.

**Arguments:**
- `target` - Path to packet file or bundle directory

**Options:**
- `-f, --format <format>` - Output format: `text` or `json` (default: `text`)

**Examples:**
```bash
evidencebus inspect packet.eb.json
evidencebus inspect ./bundle --format json
```

### emit

Exports a packet or bundle to different formats.

**Arguments:**
- `target` - Path to packet file or bundle directory

**Options:**
- `-f, --format <format>` - Output format: `markdown` or `sarif` (required)
- `-o, --out <path>` - Output file (optional, prints to stdout if not specified)
- `-d, --details` - Include detailed output
- `-a, --artifacts` - Include artifacts in output

**Examples:**
```bash
evidencebus emit markdown ./bundle --out ./summary.md
evidencebus emit sarif ./bundle --out ./results.sarif
evidencebus emit markdown ./bundle --out ./full.md --details --artifacts
```

### schema

Displays schema information.

**Arguments:**
- `schema` - Schema to display: `packet` or `bundle`

**Options:**
- `-f, --format <format>` - Output format: `json` or `pretty` (default: `pretty`)

**Examples:**
```bash
evidencebus schema packet --format pretty
evidencebus schema bundle --format json
```

## Exit Codes

The CLI uses the following exit codes:

| Code | Name | Description |
|------|------|-------------|
| 0 | Success | Operation completed successfully |
| 1 | Io | I/O error occurred |
| 2 | InvalidInput | Invalid input provided |
| 3 | ValidationFailed | Validation failed |
| 4 | ExportFailed | Export operation failed |
| 5 | BundleCreationFailed | Bundle creation failed |

## Design Principles

- **Composition Root** - Brings together all evidencebus crates
- **Operator-Facing** - Designed for command-line use
- **Clear Errors** - Provides helpful error messages
- **Structured Output** - Supports multiple output formats

## Dependencies

The CLI depends on all evidencebus crates:

- `evidencebus-codes` - Shared enums and exit codes
- `evidencebus-export` - Export functionality
- `evidencebus-fs` - Filesystem operations
- `evidencebus-types` - Core data structures

Plus:
- `clap` - Command-line argument parsing
- `miette` - Diagnostic error reporting
- `serde_json` - JSON serialization
- `termcolor` - Colored terminal output

## Testing

The crate includes comprehensive BDD-style tests for:

- CLI commands
- Error handling
- Output formatting
- Integration scenarios

Run tests with:

```bash
cargo test -p evidencebus-cli
```

Run the CLI directly:

```bash
cargo run -p evidencebus-cli -- --help
```

## Related Documentation

- [Getting Started](../../docs/getting-started.md)
- [Architecture Guide](../../docs/architecture.md)
- [API Reference](../../docs/api-reference.md)

## License

MIT License - see [LICENSE](../../LICENSE) for details.
