# Exporting to Different Formats

This tutorial will guide you through exporting packets and bundles to various formats for different use cases.

## Supported Export Formats

evidencebus supports two primary export formats:

1. **Markdown** - Human-readable reports for documentation and review
2. **SARIF** - Static Analysis Results Interchange Format for tool integration

## Prerequisites

Before exporting, ensure you have:

1. A valid packet file or bundle directory
2. The evidencebus CLI installed

## Exporting to Markdown

### Basic Export

Export a bundle to Markdown:

```bash
evidencebus emit markdown ./my-bundle --out ./summary.md
```

Export a single packet:

```bash
evidencebus emit markdown ./packet.eb.json --out ./packet-summary.md
```

### Detailed Export

Include detailed information:

```bash
evidencebus emit markdown ./my-bundle --out ./detailed-summary.md --details
```

### Include Artifacts

Include artifact references in the output:

```bash
evidencebus emit markdown ./my-bundle --out ./full-summary.md --artifacts
```

### Programmatic Export

```rust
use evidencebus_export::{export_packet_markdown, export_bundle_markdown};
use evidencebus_fs::{load_target, LoadedTarget};
use std::path::PathBuf;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let target_path = PathBuf::from("./my-bundle");
    let target = load_target(&target_path)?;

    let markdown = match target {
        LoadedTarget::Packet(packet) => {
            export_packet_markdown(&packet, false, false)?
        }
        LoadedTarget::Bundle { packets, .. } => {
            export_bundle_markdown(&packets, false, false)?
        }
        _ => return Err("Invalid target".into()),
    };

    std::fs::write("./summary.md", markdown)?;
    println!("Exported to summary.md");

    Ok(())
}
```

### Markdown Output Format

The Markdown export includes:

```markdown
# Evidence Summary

## Bundle Overview
- **Packets**: 2
- **Status**: Mixed (1 passed, 1 failed)
- **Created**: 2024-01-15T10:30:00Z

## Packets

### pkt-faultline
- **Status**: indeterminate
- **Tool**: faultline v0.1.0
- **Subject**: EffortlessMetrics/example @ bad456

#### Summary
Suspect window narrowed

#### Findings
- [WARNING] Suspect window remains
  Read parser changes and workflow changes first.

#### Metrics
- suspect_window_commits: 3 count

---

### pkt-perfgate
- **Status**: passed
- **Tool**: perfgate v0.1.0
- **Subject**: EffortlessMetrics/example @ bad456

#### Summary
Performance within acceptable range

#### Findings
- [INFO] Performance check completed
  All metrics within thresholds.

#### Metrics
- execution_time_ms: 1500 milliseconds
```

## Exporting to SARIF

### Basic Export

Export a bundle to SARIF:

```bash
evidencebus emit sarif ./my-bundle --out ./results.sarif
```

Export a single packet:

```bash
evidencebus emit sarif ./packet.eb.json --out ./packet-results.sarif
```

### Programmatic Export

```rust
use evidencebus_export::export_packets_sarif;
use evidencebus_fs::{load_target, LoadedTarget};
use std::path::PathBuf;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let target_path = PathBuf::from("./my-bundle");
    let target = load_target(&target_path)?;

    let packets = match target {
        LoadedTarget::Bundle { packets, .. } => packets,
        LoadedTarget::Packet(packet) => vec![packet],
        _ => return Err("Invalid target".into()),
    };

    let sarif = export_packets_sarif(&packets)?;
    std::fs::write("./results.sarif", serde_json::to_string_pretty(&sarif)?)?;

    println!("Exported to results.sarif");

    Ok(())
}
```

### SARIF Output Format

The SARIF export follows the SARIF 2.1.0 standard:

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

## Use Cases

### Use Case 1: Pull Request Documentation

Generate a Markdown summary for pull request reviews:

```bash
#!/bin/bash

# Create bundle from CI evidence
evidenceus bundle \
  ci/packets/*.eb.json \
  --out ./pr-evidence-bundle

# Export to Markdown for PR description
evidencebus emit markdown ./pr-evidence-bundle --out ./pr-evidence.md

# Append to PR description
cat ./pr-evidence.md >> ./pr-description.md
```

### Use Case 2: GitHub Actions Integration

Use SARIF for GitHub Advanced Security:

```yaml
name: Evidence Report

on:
  pull_request:

jobs:
  evidence:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3

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

### Use Case 3: CI/CD Gate Integration

Export to Markdown for CI gate documentation:

```bash
#!/bin/bash

# Run all evidence tools
make run-evidence

# Create bundle
evidencebus bundle \
  evidence/packets/*.eb.json \
  --out ./evidence-bundle

# Export summary
evidencebus emit markdown ./evidence-bundle --out ./evidence-summary.md

# Check for failures
if grep -q "Status: failed" ./evidence-summary.md; then
  echo "Evidence check failed"
  cat ./evidence-summary.md
  exit 1
fi
```

### Use Case 4: Historical Analysis

Export multiple bundles for comparison:

```bash
#!/bin/bash

# Export each commit's evidence
for commit in $(git log --oneline -10 | cut -d' ' -f1); do
  git checkout $commit
  evidencebus emit markdown ./evidence-bundle --out ./history/$commit.md
done

# Generate comparison report
git checkout main
```

## Custom Export Formats

You can create custom export formats by implementing the export logic:

```rust
use evidencebus_types::Packet;

pub fn export_custom(packets: &[Packet]) -> Result<String, Box<dyn std::error::Error>> {
    let mut output = String::new();

    for packet in packets {
        output.push_str(&format!("Packet: {}\n", packet.packet_id));
        output.push_str(&format!("Status: {:?}\n", packet.summary.status));
        output.push_str(&format!("Tool: {}\n", packet.producer.tool_name));
        output.push_str("\n");
    }

    Ok(output)
}
```

## Best Practices

### 1. Choose the Right Format

- **Markdown**: For human review, documentation, PR descriptions
- **SARIF**: For tool integration, CI/CD platforms, security scanning

### 2. Include Context

Use the `--details` flag for comprehensive exports:

```bash
evidencebus emit markdown ./bundle --out ./full-report.md --details
```

### 3. Preserve Artifacts

Use the `--artifacts` flag to include artifact references:

```bash
evidencebus emit markdown ./bundle --out ./full-report.md --artifacts
```

### 4. Validate Before Export

Always validate before exporting:

```bash
evidencebus validate ./bundle
evidencebus emit markdown ./bundle --out ./summary.md
```

### 5. Use Deterministic Output

evidencebus exports are deterministic. The same input always produces the same output, making them suitable for caching and comparison.

## Troubleshooting

### Issue: "Export failed" Error

**Cause**: Invalid packet or bundle structure.

**Solution**:
1. Validate the target first: `evidencebus validate ./target`
2. Check file permissions
3. Ensure all referenced artifacts exist

### Issue: "Empty output" Error

**Cause**: Bundle contains no packets or packets have no findings.

**Solution**:
1. Verify the bundle contains packets: `evidencebus inspect ./bundle`
2. Check packet content for findings and metrics

### Issue: "Invalid format" Error

**Cause**: Invalid format specification.

**Solution**:
1. Use valid format names: `markdown` or `sarif`
2. Check spelling: `evidencebus emit markdown ./bundle`

## Next Steps

- Learn about [Validating Packets and Bundles](validating-packets-bundles.md)
- Read the [Producer Guide](../producer-guide.md) for creating evidence
- Explore the [Consumer Guide](../consumer-guide.md) for consuming evidence
