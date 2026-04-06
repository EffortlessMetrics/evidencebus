# Building a Bundle

This tutorial will guide you through creating evidence bundles from multiple packets.

## What is a Bundle?

A bundle is a deterministic collection of packets with:

- A manifest file (`bundle.eb.json`) listing all packets and artifacts
- Stable directory layout for reproducibility
- SHA-256 digests for integrity verification
- Conflict detection for duplicate packet IDs
- Automatic deduplication of identical packets

## Prerequisites

Before building a bundle, ensure you have:

1. One or more valid packet files (`.eb.json`)
2. Any referenced artifact files in the correct locations
3. The evidencebus CLI installed

## Using the CLI

### Step 1: Prepare Your Packets

Ensure your packets are valid:

```bash
evidencebus validate packet1.eb.json
evidencebus validate packet2.eb.json
```

### Step 2: Create a Bundle

Use the `bundle` command to combine packets:

```bash
evidencebus bundle \
  packet1.eb.json \
  packet2.eb.json \
  packet3.eb.json \
  --out ./my-bundle
```

This creates a directory structure:

```
my-bundle/
  bundle.eb.json
  packets/
    pkt-tool1/
      packet.eb.json
      artifacts/
    pkt-tool2/
      packet.eb.json
      artifacts/
    pkt-tool3/
      packet.eb.json
      artifacts/
```

### Step 3: Verify the Bundle

Inspect the bundle to verify it was created correctly:

```bash
evidencebus inspect ./my-bundle
```

### Step 4: Validate the Bundle

Validate the bundle's integrity:

```bash
evidencebus validate ./my-bundle
```

## Programmatic Bundle Creation

### Step 1: Set Up Dependencies

Add to your `Cargo.toml`:

```toml
[dependencies]
evidencebus-core = { path = "../evidencebus/crates/evidencebus-core" }
evidencebus-fs = { path = "../evidencebus/crates/evidencebus-fs" }
evidencebus-types = { path = "../evidencebus/crates/evidencebus-types" }
evidencebus-digest = { path = "../evidencebus/crates/evidencebus-digest" }
```

### Step 2: Create Bundles Programmatically

```rust
use evidencebus_fs::{build_bundle, FsError};
use evidencebus_types::Packet;
use std::path::PathBuf;

fn main() -> Result<(), FsError> {
    // Define packet files to include
    let packets = vec![
        PathBuf::from("packet1.eb.json"),
        PathBuf::from("packet2.eb.json"),
        PathBuf::from("packet3.eb.json"),
    ];

    // Build the bundle
    let bundle_path = PathBuf::from("./my-bundle");
    build_bundle(&packets, &bundle_path)?;

    println!("Bundle created at: {:?}", bundle_path);

    Ok(())
}
```

### Step 3: Load and Inspect a Bundle

```rust
use evidencebus_fs::{load_target, LoadedTarget};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let bundle_path = PathBuf::from("./my-bundle");

    // Load the bundle
    let target = load_target(&bundle_path)?;

    match target {
        LoadedTarget::Bundle { manifest, packets } => {
            println!("Bundle contains {} packets", packets.len());
            println!("Manifest: {}", serde_json::to_string_pretty(&manifest)?);
        }
        _ => println!("Not a bundle"),
    }

    Ok(())
}
```

## Bundle Structure

### Manifest File

The `bundle.eb.json` file contains:

```json
{
  "packets": [
    {
      "packet_id": "pkt-tool1",
      "relative_path": "packets/pkt-tool1/packet.eb.json",
      "sha256": "..."
    }
  ],
  "artifacts": [
    {
      "packet_id": "pkt-tool1",
      "relative_path": "packets/pkt-tool1/artifacts/output.txt",
      "role": "output",
      "sha256": "..."
    }
  ],
  "integrity": {
    "manifest_digest": "...",
    "packet_digests": {
      "pkt-tool1": "..."
    },
    "artifact_digests": {
      "packets/pkt-tool1/artifacts/output.txt": "..."
    }
  }
}
```

### Directory Layout

```
bundle/
  bundle.eb.json              # Bundle manifest
  packets/                    # All packets
    pkt-tool1/               # Packet directory (named by packet_id)
      packet.eb.json         # Packet metadata
      artifacts/             # Packet-local artifacts
        tool1/output.txt
        tool1/report.html
    pkt-tool2/
      packet.eb.json
      artifacts/
        tool2/data.json
```

## Conflict Detection

evidencebus automatically detects and handles conflicts:

### Duplicate Packet IDs

If two packets have the same ID:

1. **Identical packets**: Deduplicated automatically
2. **Different packets**: Error raised - you must resolve the conflict

```bash
# Example error
Error: Bundle validation failed: Duplicate packet ID 'pkt-tool1' with different content
```

### Resolution Strategies

**Option 1: Rename Packets**

Modify the `packet_id` in one of the packets before bundling:

```json
{
  "packet_id": "pkt-tool1-alternative",
  ...
}
```

**Option 2: Merge Content**

Combine the content into a single packet if appropriate.

**Option 3: Use Different Bundles**

Create separate bundles for different contexts.

## Best Practices

### 1. Use Descriptive Packet IDs

```json
// Good
{
  "packet_id": "faultline-parser-2024-01-15-001"
}

// Avoid
{
  "packet_id": "packet1"
}
```

### 2. Organize Artifacts Logically

```
packets/pkt-tool1/artifacts/
  tool1/              # Tool-specific directory
    output.txt
    report.html
  logs/               # Common directory
    stderr.log
    stdout.log
```

### 3. Include Complete Provenance

Each packet should document:
- Tool name and version
- Invocation ID
- Command line used
- Environment fingerprint

### 4. Validate Before Bundling

```bash
# Validate all packets first
for packet in *.eb.json; do
  evidencebus validate "$packet" || exit 1
done

# Then create bundle
evidencebus bundle *.eb.json --out ./bundle
```

### 5. Use Deterministic Ordering

evidencebus automatically sorts packets and artifacts for deterministic output. Don't rely on input order.

## Common Use Cases

### Use Case 1: CI/CD Evidence Collection

```bash
#!/bin/bash
set -e

# Run various tools
./run-faultline.sh
./run-perfgate.sh
./run-stackcut.sh

# Collect all packets
evidencebus bundle \
  packets/faultline-*.eb.json \
  packets/perfgate-*.eb.json \
  packets/stackcut-*.eb.json \
  --out ./evidence-bundle

# Export for review
evidencebus emit markdown ./evidence-bundle --out ./evidence-summary.md
```

### Use Case 2: Multi-Tool Evidence

Combine evidence from different tools into a single bundle:

```bash
evidencebus bundle \
  security-analysis.eb.json \
  performance-test.eb.json \
  code-coverage.eb.json \
  --out ./full-evidence-bundle
```

### Use Case 3: Historical Comparison

Create bundles for different commits and compare:

```bash
# Bundle for commit A
evidencebus bundle commit-a/*.eb.json --out ./bundle-a

# Bundle for commit B
evidencebus bundle commit-b/*.eb.json --out ./bundle-b

# Compare exports
evidencebus emit markdown ./bundle-a --out ./summary-a.md
evidencebus emit markdown ./bundle-b --out ./summary-b.md
```

## Troubleshooting

### Issue: "Digest mismatch" Error

**Cause**: File content doesn't match the digest in the packet.

**Solution**:
1. Ensure files haven't been modified after packet creation
2. Recompute digests if files were legitimately updated
3. Verify all referenced artifacts exist

### Issue: "Path traversal detected" Error

**Cause**: Packet contains paths with `..` or absolute paths.

**Solution**:
1. Use only relative paths
2. Ensure paths don't contain `..` sequences
3. Use forward slashes (even on Windows)

### Issue: "Duplicate packet ID" Error

**Cause**: Multiple packets have the same ID.

**Solution**:
1. Rename one of the packets
2. Merge packet content if appropriate
3. Use separate bundles if needed

### Issue: "Missing artifact" Error

**Cause**: Referenced artifact file doesn't exist.

**Solution**:
1. Ensure all artifacts are in the correct location
2. Verify paths in the packet are correct
3. Check file permissions

## Next Steps

- Learn about [Exporting to Different Formats](exporting-formats.md)
- Read about [Validating Packets and Bundles](validating-packets-bundles.md)
- Explore the [Architecture Guide](../architecture.md) for deeper understanding
