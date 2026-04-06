# Getting Started

This guide will help you get up and running with evidencebus, the schema-first evidence backplane for repo operations.

## What is evidencebus?

evidencebus is a neutral evidence transport and validation system that takes outputs from tools like `faultline`, `proofrun`, `repropack`, `stackcut`, `perfgate`, and similar tools and transforms them into:

- **Validated packets** - Structured evidence with schema validation
- **Deterministic bundles** - Stable, reproducible evidence collections
- **Portable artifact inventories** - File manifests with integrity checking
- **Neutral exports** - Markdown and SARIF formats for downstream tools

evidencebus is deliberately **not** a merge cockpit. It moves evidence; downstream tools like `cockpitctl` decide what that evidence means for merge decisions.

## Installation

### Prerequisites

- **Rust 1.78 or later** - evidencebus requires Rust 1.78 or newer
- **Git** - For cloning the repository

### Installing from Source

1. Clone the repository:

```bash
git clone https://github.com/EffortlessMetrics/evidencebus.git
cd evidencebus
```

2. Build the CLI:

```bash
cargo build --release
```

3. The `evidencebus` binary will be available at `target/release/evidencebus`. You can optionally add it to your PATH:

```bash
# On Linux/macOS
export PATH="$PATH:$(pwd)/target/release"

# On Windows (PowerShell)
$env:PATH += ";$(Get-Location)\target\release"
```

### Installing via Cargo (when published)

Once published to crates.io, you can install directly:

```bash
cargo install evidencebus-cli
```

## Quick Start

Let's walk through a basic workflow: validating a packet, creating a bundle, and exporting to different formats.

### Step 1: Validate a Packet

First, let's validate an existing packet to ensure it conforms to the schema:

```bash
evidencebus validate fixtures/packets/perfgate/pkt-perfgate.eb.json
```

This command checks:
- JSON schema validation
- Required field presence
- Digest integrity
- Path safety and traversal prevention

### Step 2: Create a Bundle

Combine multiple packets into a deterministic bundle:

```bash
evidencebus bundle \
  fixtures/packets/perfgate/pkt-perfgate.eb.json \
  fixtures/packets/faultline/pkt-faultline.eb.json \
  --out ./my-evidence-bundle
```

This creates a directory structure:

```
my-evidence-bundle/
  bundle.eb.json
  packets/
    pkt-perfgate/
      packet.eb.json
      artifacts/
    pkt-faultline/
      packet.eb.json
      artifacts/
```

### Step 3: Inspect a Bundle

View the contents of a bundle:

```bash
evidencebus inspect ./my-evidence-bundle
```

Or get JSON output:

```bash
evidencebus inspect ./my-evidence-bundle --format json
```

### Step 4: Export to Markdown

Generate a human-readable Markdown summary:

```bash
evidencebus emit markdown ./my-evidence-bundle --out ./SUMMARY.md
```

### Step 5: Export to SARIF

Generate a SARIF report for tool integration:

```bash
evidencebus emit sarif ./my-evidence-bundle --out ./results.sarif
```

## Common Use Cases

### Use Case 1: Creating Your First Packet

See [Creating Your First Packet](tutorials/creating-your-first-packet.md) for a detailed tutorial on creating packets programmatically.

### Use Case 2: Validating Evidence Before Merge

Integrate evidencebus into your CI/CD pipeline to validate evidence before merge:

```bash
#!/bin/bash
# In your CI pipeline

# Validate all packets
for packet in evidence/packets/*.eb.json; do
  evidencebus validate "$packet" || exit 1
done

# Create a bundle
evidencebus bundle evidence/packets/*.eb.json --out ./evidence-bundle

# Export for review
evidencebus emit markdown ./evidence-bundle --out ./evidence-summary.md
```

### Use Case 3: Integrating with Existing Tools

If you have an existing tool that produces evidence, you can:

1. Create a packet structure that matches your tool's output
2. Use the [`evidencebus-types`](../crates/evidencebus-types) crate to build packets
3. Validate against the schema: `evidencebus schema packet`

Example schema reference:

```bash
evidencebus schema packet --format pretty
```

### Use Case 4: Digest Verification

Verify the integrity of packets and bundles:

```bash
# Validate with digest checking (default)
evidencebus validate packet.eb.json

# Skip file existence checks, only validate schema
evidencebus validate packet.eb.json --schema-only
```

## CLI Reference

The evidencebus CLI provides several commands:

| Command | Description |
|---------|-------------|
| `validate` | Validate a packet or bundle |
| `bundle` | Create a bundle from packet files |
| `inspect` | Inspect a packet or bundle |
| `emit` | Export a packet or bundle to Markdown or SARIF |
| `schema` | Display schema information |

For detailed help on any command:

```bash
evidencebus <command> --help
```

## Next Steps

- Read the [Architecture Guide](architecture.md) to understand the system design
- Follow the [Tutorials](tutorials/) for hands-on learning
- Check the [Producer Guide](producer-guide.md) for creating evidence
- Review the [Consumer Guide](consumer-guide.md) for consuming evidence
- Explore the [API Reference](api-reference.md) for programmatic usage

## Troubleshooting

### "Digest mismatch" error

This error occurs when the SHA-256 digest in the packet doesn't match the actual file content. Ensure:

1. All referenced artifacts exist
2. Files haven't been modified after packet creation
3. Digests were computed correctly

### "Path traversal detected" error

evidencebus prevents path traversal attacks for security. Ensure:

1. All paths are relative (no absolute paths)
2. Paths don't contain `..` sequences
3. Paths use forward slashes (even on Windows)

### "Schema validation failed" error

Your packet doesn't conform to the schema. Check:

1. Required fields are present
2. Field types match the schema
3. Enum values are valid
4. Use `evidencebus schema packet` to view the schema

## Getting Help

- **Documentation**: Check the [docs/](.) directory for comprehensive guides
- **Examples**: See the [examples/](../examples/) directory for sample bundles
- **Issues**: Report bugs or request features on GitHub
- **Discussions**: Join community discussions on GitHub
