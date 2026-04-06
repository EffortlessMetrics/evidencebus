# Validating Packets and Bundles

This tutorial will guide you through validating packets and bundles to ensure data integrity and schema compliance.

## Why Validation Matters

Validation ensures:

1. **Schema Compliance** - Packets conform to the expected structure
2. **Data Integrity** - Digests match file contents
3. **Security** - No path traversal or unsafe operations
4. **Consistency** - Required fields are present and valid
5. **Reproducibility** - Deterministic output for reliable processing

## Validation Levels

evidencebus provides two validation levels:

### 1. Schema-Only Validation

Validates JSON structure without checking file existence:

```bash
evidencebus validate packet.eb.json --schema-only
```

Use this when:
- You want to validate structure before creating files
- You're working with incomplete data
- You need fast validation for CI gates

### 2. Full Validation

Validates schema, digests, and file existence (default):

```bash
evidencebus validate packet.eb.json
```

Use this when:
- You're ready to finalize evidence
- You need to ensure all artifacts exist
- You're preparing for distribution

## Validating Packets

### Basic Packet Validation

```bash
evidencebus validate ./packet.eb.json
```

### Validating Multiple Packets

```bash
for packet in packets/*.eb.json; do
  evidencebus validate "$packet" || exit 1
done
```

### Programmatic Packet Validation

```rust
use evidencebus_fs::{load_target, validate_target, LoadedTarget};
use std::path::PathBuf;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let packet_path = PathBuf::from("./packet.eb.json");

    // Load the packet
    let target = load_target(&packet_path)?;

    // Validate the packet
    validate_target(&target)?;

    println!("Packet is valid!");

    Ok(())
}
```

### What Packet Validation Checks

1. **Schema Validation**
   - Required fields present
   - Field types correct
   - Enum values valid
   - No unknown fields (strict mode)

2. **Packet ID Validation**
   - Not empty
   - No path traversal (`..`)
   - No backslashes (`\`)
   - No leading slashes (`/`)

3. **Digest Validation**
   - SHA-256 digest format correct (64 hex characters)
   - Digest matches file content (for full validation)

4. **Path Validation**
   - All paths are relative
   - No path traversal sequences
   - Forward slashes only

5. **Status Validation**
   - Status is one of: `passed`, `failed`, `indeterminate`, `skipped`

6. **Severity Validation**
   - Severity is one of: `error`, `warning`, `info`, `note`

## Validating Bundles

### Basic Bundle Validation

```bash
evidencebus validate ./my-bundle
```

### Validating Bundle Schema Only

```bash
evidencebus validate ./my-bundle --schema-only
```

### Programmatic Bundle Validation

```rust
use evidencebus_fs::{load_target, validate_target, LoadedTarget};
use std::path::PathBuf;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let bundle_path = PathBuf::from("./my-bundle");

    // Load the bundle
    let target = load_target(&bundle_path)?;

    // Validate the bundle
    validate_target(&target)?;

    println!("Bundle is valid!");

    Ok(())
}
```

### What Bundle Validation Checks

1. **Manifest Validation**
   - `bundle.eb.json` exists and is valid
   - All packet entries are valid
   - All artifact entries are valid

2. **Packet Validation**
   - All listed packets exist
   - Packet digests match
   - Packets are individually valid

3. **Artifact Validation**
   - All listed artifacts exist
   - Artifact digests match
   - Paths are safe and relative

4. **Integrity Validation**
   - Manifest digest is correct
   - Packet digests match manifest
   - Artifact digests match manifest

5. **Conflict Detection**
   - No duplicate packet IDs with different content
   - No duplicate artifact paths with different content

## Common Validation Errors

### Error: "Schema validation failed"

**Cause**: Packet doesn't conform to the schema.

**Examples**:
- Missing required field
- Invalid field type
- Invalid enum value

**Solution**:
```bash
# View the schema
evidencebus schema packet --format pretty

# Compare your packet
cat packet.eb.json | jq .
```

### Error: "Digest mismatch"

**Cause**: File content doesn't match the digest in the packet.

**Examples**:
- File was modified after packet creation
- Digest was computed incorrectly
- Wrong file referenced

**Solution**:
```bash
# Recompute digest
evidencebus digest compute ./artifacts/output.txt

# Update packet with correct digest
# Or restore original file content
```

### Error: "Path traversal detected"

**Cause**: Packet contains unsafe paths.

**Examples**:
- Path contains `..`
- Path is absolute
- Path contains backslashes

**Solution**:
```json
// Bad
{
  "relative_path": "../secret.txt"
}

// Good
{
  "relative_path": "artifacts/output.txt"
}
```

### Error: "Packet ID contains invalid characters"

**Cause**: Packet ID has invalid characters.

**Examples**:
- Empty string
- Contains `..`
- Contains `\`
- Starts with `/`

**Solution**:
```json
// Bad
{
  "packet_id": "../packet"
}

// Good
{
  "packet_id": "my-tool-001"
}
```

### Error: "Duplicate packet ID"

**Cause**: Multiple packets have the same ID.

**Examples**:
- Two packets with same ID in a bundle
- Packet ID collision during bundling

**Solution**:
```bash
# Rename one of the packets
# Or merge content into a single packet
# Or use separate bundles
```

### Error: "Missing artifact"

**Cause**: Referenced artifact file doesn't exist.

**Examples**:
- File was deleted
- Path is incorrect
- File wasn't created

**Solution**:
```bash
# Check if file exists
ls -la packets/pkt-tool1/artifacts/output.txt

# Verify path in packet
cat packet.eb.json | jq '.projections.attachments[].relative_path'
```

## Validation in CI/CD

### GitHub Actions Example

```yaml
name: Evidence Validation

on:
  pull_request:

jobs:
  validate:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3

      - name: Install evidencebus
        run: |
          cargo install --path .

      - name: Validate evidence packets
        run: |
          for packet in evidence/packets/*.eb.json; do
            evidencebus validate "$packet" || exit 1
          done

      - name: Validate evidence bundle
        run: |
          evidencebus validate evidence/bundle
```

### GitLab CI Example

```yaml
validate-evidence:
  stage: test
  script:
    - cargo install --path .
    - for packet in evidence/packets/*.eb.json; do
        evidencebus validate "$packet" || exit 1;
      done
    - evidencebus validate evidence/bundle
```

### Jenkins Pipeline Example

```groovy
pipeline {
  agent any
  stages {
    stage('Validate Evidence') {
      steps {
        sh 'cargo install --path .'
        sh '''
          for packet in evidence/packets/*.eb.json; do
            evidencebus validate "$packet" || exit 1
          done
        '''
        sh 'evidencebus validate evidence/bundle'
      }
    }
  }
}
```

## Best Practices

### 1. Validate Early and Often

```bash
# Validate after creating each packet
./create-packet.sh
evidencebus validate packet.eb.json

# Validate before bundling
for packet in packets/*.eb.json; do
  evidencebus validate "$packet" || exit 1
done
evidencebus bundle packets/*.eb.json --out ./bundle
```

### 2. Use Schema-Only for Fast Checks

```bash
# Fast schema check in CI
evidencebus validate packet.eb.json --schema-only

# Full validation before deployment
evidencebus validate packet.eb.json
```

### 3. Validate Before Exporting

```bash
# Always validate before export
evidencebus validate ./bundle
evidencebus emit markdown ./bundle --out ./summary.md
```

### 4. Handle Validation Errors Gracefully

```bash
#!/bin/bash
set -e

validate_packet() {
  local packet="$1"
  if ! evidencebus validate "$packet"; then
    echo "Validation failed for $packet"
    echo "Please review the packet and fix any issues"
    exit 1
  fi
}

# Validate all packets
for packet in packets/*.eb.json; do
  validate_packet "$packet"
done

echo "All packets validated successfully"
```

### 5. Log Validation Results

```bash
#!/bin/bash

# Create validation log
mkdir -p logs

# Validate and log
for packet in packets/*.eb.json; do
  echo "Validating $packet" | tee -a logs/validation.log
  evidencebus validate "$packet" 2>&1 | tee -a logs/validation.log
done
```

## Advanced Validation

### Custom Validation Rules

You can add custom validation logic:

```rust
use evidencebus_types::Packet;

fn validate_custom_rules(packet: &Packet) -> Result<(), String> {
    // Check for required labels
    if !packet.labels.contains_key("category") {
        return Err("Packet must have a 'category' label".to_string());
    }

    // Check for required metrics
    let has_execution_time = packet.projections.metrics
        .iter()
        .any(|m| m.name == "execution_time_ms");

    if !has_execution_time {
        return Err("Packet must include execution_time_ms metric".to_string());
    }

    Ok(())
}
```

### Validation Report Generation

```rust
use evidencebus_fs::{load_target, validate_target};
use std::path::PathBuf;

fn generate_validation_report(path: &PathBuf) -> Result<String, Box<dyn std::error::Error>> {
    let target = load_target(path)?;
    let result = validate_target(&target);

    let report = match result {
        Ok(_) => format!("✓ Validation passed: {:?}", path),
        Err(e) => format!("✗ Validation failed: {:?}\n  Error: {}", path, e),
    };

    Ok(report)
}
```

## Next Steps

- Learn about [Creating Your First Packet](creating-your-first-packet.md)
- Explore [Building a Bundle](building-a-bundle.md)
- Read the [Testing Strategy](../testing-strategy.md) for testing approaches
