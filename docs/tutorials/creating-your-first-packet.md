# Creating Your First Packet

This tutorial will guide you through creating your first evidence packet from scratch.

## What is a Packet?

A packet is a structured container for evidence produced by a tool. It includes:

- **Producer metadata** - Information about the tool that created the packet
- **Subject information** - What the evidence is about (commit, repository, etc.)
- **Summary** - High-level status and description
- **Projections** - Structured findings, assertions, metrics, and attachments
- **Provenance** - How the evidence was produced
- **Labels** - Custom metadata for categorization

## Prerequisites

Before creating a packet, ensure you have:

1. Rust 1.78 or later installed
2. The evidencebus source code cloned
3. Basic familiarity with JSON and Rust

## Approach 1: Creating a Packet Programmatically

### Step 1: Set Up a New Project

Create a new Rust project:

```bash
cargo new my-evidence-producer
cd my-evidence-producer
```

### Step 2: Add Dependencies

Add evidencebus types to your `Cargo.toml`:

```toml
[dependencies]
evidencebus-types = { path = "../evidencebus/crates/evidencebus-types" }
evidencebus-codes = { path = "../evidencebus/crates/evidencebus-codes" }
evidencebus-canonicalization = { path = "../evidencebus/crates/evidencebus-canonicalization" }
evidencebus-digest = { path = "../evidencebus/crates/evidencebus-digest" }
serde_json = "1.0"
chrono = { version = "0.4", features = ["serde"] }
```

### Step 3: Create a Basic Packet

Update `src/main.rs`:

```rust
use evidencebus_types::{
    Packet, PacketId, Producer, Subject, Summary, Projections,
    Provenance, Labels, SchemaVersion, FindingSeverity, PacketStatus,
    Assertion, Finding, Metric, Attachment, NativePayload
};
use evidencebus_codes::FindingSeverityCode;
use chrono::Utc;
use std::collections::HashMap;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Create a packet ID
    let packet_id = PacketId::new("my-tool-001")?;

    // Create producer metadata
    let producer = Producer {
        tool_name: "my-tool".to_string(),
        tool_version: "1.0.0".to_string(),
        invocation_id: "run-001".to_string(),
    };

    // Create subject information
    let subject = Subject {
        vcs_kind: "git".to_string(),
        repo_identifier: "my-org/my-repo".to_string(),
        commit: "abc123".to_string(),
        base: Some("def456".to_string()),
        head: Some("abc123".to_string()),
        path_scope: Some("src/main.rs".to_string()),
        workspace_scope: None,
    };

    // Create a summary
    let summary = Summary {
        status: PacketStatus::Passed,
        title: "All checks passed".to_string(),
        short_summary: "Tool completed successfully".to_string(),
    };

    // Create projections
    let projections = Projections {
        assertions: vec![
            Assertion {
                id: "my-tool.check1".to_string(),
                status: PacketStatus::Passed,
                summary: Some(Summary {
                    status: PacketStatus::Passed,
                    title: "Check 1 passed".to_string(),
                    short_summary: "No issues found".to_string(),
                }),
            }
        ],
        findings: vec![
            Finding {
                id: "my-tool.info".to_string(),
                severity: FindingSeverityCode::Info,
                title: "Information".to_string(),
                message: "Tool ran successfully".to_string(),
                location: None,
            }
        ],
        metrics: vec![
            Metric {
                name: "execution_time_ms".to_string(),
                value: 1500,
                unit: "milliseconds".to_string(),
            }
        ],
        relations: vec![],
        attachments: vec![],
    };

    // Create provenance
    let provenance = Provenance {
        command: "my-tool --run".to_string(),
        environment_fingerprint: "linux-x86_64".to_string(),
        platform_info: evidencebus_types::PlatformInfo {
            os: "linux".to_string(),
            arch: "x86_64".to_string(),
        },
    };

    // Create labels
    let mut labels = HashMap::new();
    labels.insert("category".to_string(), "quality".to_string());

    // Create the packet
    let packet = Packet {
        eb_version: SchemaVersion::new("0.1.0"),
        packet_id,
        producer,
        subject,
        summary,
        projections,
        native_payloads: vec![],
        artifacts: vec![],
        provenance,
        labels,
        created_at: Utc::now(),
    };

    // Serialize to JSON
    let json = serde_json::to_string_pretty(&packet)?;
    println!("{}", json);

    Ok(())
}
```

### Step 4: Run Your Program

```bash
cargo run
```

You should see JSON output representing your packet.

## Approach 2: Creating a Packet from JSON

### Step 1: Create a JSON File

Create `packet.json`:

```json
{
  "eb_version": "0.1.0",
  "packet_id": "my-tool-001",
  "producer": {
    "tool_name": "my-tool",
    "tool_version": "1.0.0",
    "invocation_id": "run-001"
  },
  "subject": {
    "vcs_kind": "git",
    "repo_identifier": "my-org/my-repo",
    "commit": "abc123",
    "base": "def456",
    "head": "abc123",
    "path_scope": "src/main.rs"
  },
  "summary": {
    "status": "passed",
    "title": "All checks passed",
    "short_summary": "Tool completed successfully"
  },
  "projections": {
    "assertions": [
      {
        "id": "my-tool.check1",
        "status": "passed",
        "summary": {
          "status": "passed",
          "title": "Check 1 passed",
          "short_summary": "No issues found"
        }
      }
    ],
    "findings": [
      {
        "id": "my-tool.info",
        "severity": "info",
        "title": "Information",
        "message": "Tool ran successfully"
      }
    ],
    "metrics": [
      {
        "name": "execution_time_ms",
        "value": 1500,
        "unit": "milliseconds"
      }
    ],
    "relations": [],
    "attachments": []
  },
  "native_payloads": [],
  "artifacts": [],
  "provenance": {
    "command": "my-tool --run",
    "environment_fingerprint": "linux-x86_64",
    "platform_info": {
      "os": "linux",
      "arch": "x86_64"
    }
  },
  "labels": {
    "category": "quality"
  },
  "created_at": "2024-01-15T10:30:00Z"
}
```

### Step 2: Validate Your Packet

Use the evidencebus CLI to validate:

```bash
evidencebus validate packet.json
```

## Adding Attachments

Attachments allow you to include additional files with your packet.

### Step 1: Create an Attachment Directory

```bash
mkdir -p artifacts
echo "Sample output" > artifacts/output.txt
```

### Step 2: Compute the Digest

You'll need to compute the SHA-256 digest of your attachment:

```rust
use evidencebus_digest::{compute_digest, DigestError};
use std::path::Path;

fn add_attachment(packet: &mut Packet, path: &Path) -> Result<(), DigestError> {
    let digest = compute_digest(path)?;
    let size = std::fs::metadata(path)?.len();

    packet.projections.attachments.push(Attachment {
        role: "output".to_string(),
        media_type: "text/plain".to_string(),
        relative_path: "artifacts/output.txt".to_string(),
        sha256: digest,
        size: size as u64,
        schema_id: None,
    });

    Ok(())
}
```

### Step 3: Add to Artifacts List

```rust
packet.artifacts.push("artifacts/output.txt".to_string());
```

## Best Practices

1. **Use Descriptive Packet IDs**: Make them unique and meaningful
   - Good: `faultline-2024-01-15-run-001`
   - Bad: `packet1`

2. **Include Complete Provenance**: Document how evidence was produced
   - Command line invocation
   - Environment fingerprint
   - Platform information

3. **Use Appropriate Severity Levels**:
   - `error` - Critical issues that must be addressed
   - `warning` - Issues that should be reviewed
   - `info` - Informational messages
   - `note` - Additional context

4. **Provide Clear Summaries**:
   - Title should be concise but descriptive
   - Short summary should explain the outcome

5. **Use Labels for Categorization**:
   - Add labels like `category: security`, `priority: high`
   - Helps with filtering and organization

## Common Pitfalls

### Pitfall 1: Invalid Packet IDs

Packet IDs cannot contain:
- Empty strings
- Path traversal sequences (`..`)
- Backslashes (`\`)
- Leading slashes (`/`)

### Pitfall 2: Missing Required Fields

Ensure all required fields are present:
- `eb_version`
- `packet_id`
- `producer`
- `subject`
- `summary`
- `projections`
- `provenance`
- `created_at`

### Pitfall 3: Invalid Status Values

Status must be one of:
- `passed`
- `failed`
- `indeterminate`
- `skipped`

### Pitfall 4: Invalid Severity Values

Severity must be one of:
- `error`
- `warning`
- `info`
- `note`

## Next Steps

- Learn how to [Build a Bundle](building-a-bundle.md)
- Explore [Exporting to Different Formats](exporting-formats.md)
- Read about [Validating Packets and Bundles](validating-packets-bundles.md)
- Check the [API Reference](../api-reference.md) for detailed type information
