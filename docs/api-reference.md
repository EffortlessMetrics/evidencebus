# API Reference

This document provides detailed API documentation for all evidencebus microcrates.

## Table of Contents

- [evidencebus-digest](#evidencebus-digest)
- [evidencebus-canonicalization](#evidencebus-canonicalization)
- [evidencebus-validation](#evidencebus-validation)
- [evidencebus-path](#evidencebus-path)
- [evidencebus-core](#evidencebus-core)
- [evidencebus-fs](#evidencebus-fs)
- [evidencebus-export-markdown](#evidencebus-export-markdown)
- [evidencebus-export-sarif](#evidencebus-export-sarif)
- [evidencebus-export](#evidencebus-export)

---

## evidencebus-digest

**Purpose**: Cryptographic digest computation and verification

### Dependencies

```toml
[dependencies]
evidencebus-digest = "0.1.0"
```

### Types

#### `Digest`

A wrapper around a SHA-256 digest hex string.

```rust
pub struct Digest {
    // Private hex string representation
}
```

**Methods**:
- `pub fn as_str(&self) -> &str` — Returns the digest as a hex string
- `pub fn from_hex(hex: &str) -> Result<Self, DigestError>` — Creates a Digest from a hex string

#### `DigestError`

Errors that can occur during digest operations.

```rust
pub enum DigestError {
    InvalidHex(String),
    VerificationFailed { expected: Digest, actual: Digest },
}
```

### Functions

#### `compute_sha256`

Computes the SHA-256 digest of the provided data.

```rust
pub fn compute_sha256(data: &[u8]) -> Digest
```

**Parameters**:
- `data` — The data to digest

**Returns**: A `Digest` containing the SHA-256 hash

**Example**:
```rust
use evidencebus_digest::compute_sha256;

let data = b"hello world";
let digest = compute_sha256(data);
println!("SHA-256: {}", digest.as_str());
```

#### `verify_digest`

Verifies that data matches an expected digest.

```rust
pub fn verify_digest(data: &[u8], expected: &Digest) -> Result<(), DigestError>
```

**Parameters**:
- `data` — The data to verify
- `expected` — The expected digest

**Returns**: `Ok(())` if the digest matches, `Err(DigestError)` otherwise

**Example**:
```rust
use evidencebus_digest::{compute_sha256, verify_digest};

let data = b"hello world";
let expected = compute_sha256(data);
verify_digest(data, &expected).unwrap();
```

---

## evidencebus-canonicalization

**Purpose**: Deterministic JSON serialization and ordering

### Dependencies

```toml
[dependencies]
evidencebus-canonicalization = "0.1.0"
```

### Types

#### `CanonicalizationError`

Errors that can occur during canonicalization.

```rust
pub enum CanonicalizationError {
    SerializationError(String),
}
```

### Functions

#### `canonicalize_json`

Canonicalizes a serializable value to JSON with sorted keys.

```rust
pub fn canonicalize_json<T: Serialize>(value: &T) -> Result<String, CanonicalizationError>
```

**Parameters**:
- `value` — The value to canonicalize

**Returns**: A JSON string with sorted keys

**Example**:
```rust
use evidencebus_canonicalization::canonicalize_json;
use serde_json::json;

let data = json!({"z": 1, "a": 2, "nested": {"b": 3, "a": 4}});
let canonical = canonicalize_json(&data).unwrap();
// Result: {"a":2,"nested":{"a":4,"b":3},"z":1}
```

#### `canonicalize_bundle_order`

Sorts packets in place by packet_id for deterministic ordering.

```rust
pub fn canonicalize_bundle_order(packets: &mut Vec<Packet>)
```

**Parameters**:
- `packets` — The packets to sort (modified in place)

**Example**:
```rust
use evidencebus_canonicalization::canonicalize_bundle_order;
use evidencebus_types::Packet;

let mut packets = vec![
    create_packet("z-packet"),
    create_packet("a-packet"),
];
canonicalize_bundle_order(&mut packets);
// packets[0].packet_id == "a-packet"
// packets[1].packet_id == "z-packet"
```

---

## evidencebus-validation

**Purpose**: Packet and bundle validation rules

### Dependencies

```toml
[dependencies]
evidencebus-validation = "0.1.0"
```

### Types

#### `ValidationError`

Errors that can occur during packet validation.

```rust
pub enum ValidationError {
    MissingRequiredField(String),
    InvalidStatus(String),
    PathTraversal(String),
    UnsafePath(String),
    InvalidDigest(String),
    ReferenceInvalid { path: String, digest: String },
}
```

#### `BundleValidationError`

Errors that can occur during bundle validation.

```rust
pub enum BundleValidationError {
    PacketValidation(String, ValidationError),
    MissingArtifact { packet_id: String, path: String },
    DigestMismatch { packet_id: String, path: String, expected: Digest, actual: Digest },
    Conflict { packet_id: String },
}
```

#### `ValidationMode`

The strictness level for validation.

```rust
pub enum ValidationMode {
    SchemaOnly,  // Only validate JSON schema
    Strict,      // Validate schema and verify all digests
}
```

### Functions

#### `validate_packet`

Validates a packet according to schema and semantic rules.

```rust
pub fn validate_packet(packet: &Packet) -> Result<(), ValidationError>
```

**Parameters**:
- `packet` — The packet to validate

**Returns**: `Ok(())` if valid, `Err(ValidationError)` otherwise

**Example**:
```rust
use evidencebus_validation::validate_packet;
use evidencebus_types::Packet;

let packet = Packet::new("test-packet", "tool", "1.0");
match validate_packet(&packet) {
    Ok(()) => println!("Packet is valid"),
    Err(e) => eprintln!("Validation error: {:?}", e),
}
```

#### `validate_bundle`

Validates a bundle according to schema and semantic rules.

```rust
pub fn validate_bundle(bundle: &Bundle, mode: ValidationMode) -> Result<(), BundleValidationError>
```

**Parameters**:
- `bundle` — The bundle to validate
- `mode` — The validation mode (SchemaOnly or Strict)

**Returns**: `Ok(())` if valid, `Err(BundleValidationError)` otherwise

**Example**:
```rust
use evidencebus_validation::{validate_bundle, ValidationMode};
use evidencebus_types::Bundle;

let bundle = load_bundle("path/to/bundle");
validate_bundle(&bundle, ValidationMode::Strict)?;
```

---

## evidencebus-path

**Purpose**: Path validation and sanitization utilities

### Dependencies

```toml
[dependencies]
evidencebus-path = "0.1.0"
```

### Types

#### `PathError`

Errors that can occur during path operations.

```rust
pub enum PathError {
    AbsolutePath(String),
    PathTraversal(String),
    InvalidComponent(String),
    EmptyComponent,
}
```

### Functions

#### `validate_bundle_path`

Validates that a path is safe for bundle operations.

```rust
pub fn validate_bundle_path(path: &Path) -> Result<(), PathError>
```

**Parameters**:
- `path` — The path to validate

**Returns**: `Ok(())` if safe, `Err(PathError)` otherwise

**Example**:
```rust
use evidencebus_path::validate_bundle_path;
use std::path::Path;

let path = Path::new("safe/path/to/file.txt");
validate_bundle_path(path)?;
```

#### `sanitize_path_component`

Sanitizes a single path component for safe use.

```rust
pub fn sanitize_path_component(component: &str) -> Result<String, PathError>
```

**Parameters**:
- `component` — The component to sanitize

**Returns**: A sanitized component string

**Example**:
```rust
use evidencebus_path::sanitize_path_component;

let safe = sanitize_path_component("file name.txt").unwrap();
// Result: "file_name.txt"
```

#### `normalize_relative_path`

Normalizes a relative path, resolving `.` and `..` components.

```rust
pub fn normalize_relative_path(path: &Path) -> Result<PathBuf, PathError>
```

**Parameters**:
- `path` — The path to normalize

**Returns**: A normalized `PathBuf`

**Example**:
```rust
use evidencebus_path::normalize_relative_path;
use std::path::Path;

let path = Path::new("a/b/../c");
let normalized = normalize_relative_path(path)?;
// Result: "a/c"
```

#### `to_forward_slash`

Converts a path to use forward slashes (cross-platform).

```rust
pub fn to_forward_slash(path: &Path) -> String
```

**Parameters**:
- `path` — The path to convert

**Returns**: A string with forward slashes

**Example**:
```rust
use evidencebus_path::to_forward_slash;
use std::path::Path;

let path = Path::new("a\\b\\c");
let forward = to_forward_slash(path);
// Result: "a/b/c"
```

---

## evidencebus-core

**Purpose**: Bundle construction, conflict detection, and deduplication

### Dependencies

```toml
[dependencies]
evidencebus-core = "0.1.0"
```

### Types

#### `DedupeError`

Errors that can occur during deduplication.

```rust
pub enum DedupeError {
    Conflict { packet_id: String },
}
```

#### `Conflict`

Represents a conflict between packets.

```rust
pub struct Conflict {
    pub packet_id: String,
    pub reason: String,
}
```

### Functions

#### `dedupe_packets`

Deduplicates packets, removing exact duplicates and detecting conflicts.

```rust
pub fn dedupe_packets(packets: Vec<Packet>) -> Result<Vec<Packet>, DedupeError>
```

**Parameters**:
- `packets` — The packets to deduplicate

**Returns**: Deduplicated packets, or error if conflicts exist

**Example**:
```rust
use evidencebus_core::dedupe_packets;

let packets = vec![packet1, packet2, packet3];
let deduped = dedupe_packets(packets)?;
```

#### `detect_conflicts`

Detects conflicts between packets with the same ID but different content.

```rust
pub fn detect_conflicts(packets: &[Packet]) -> Vec<Conflict>
```

**Parameters**:
- `packets` — The packets to check for conflicts

**Returns**: A list of detected conflicts

**Example**:
```rust
use evidencebus_core::detect_conflicts;

let conflicts = detect_conflicts(&packets);
for conflict in conflicts {
    eprintln!("Conflict in packet: {}", conflict.packet_id);
}
```

#### `build_bundle_manifest`

Builds a bundle manifest from packets and artifacts.

```rust
pub fn build_bundle_manifest(packets: &[Packet], artifacts: &[Artifact]) -> BundleManifest
```

**Parameters**:
- `packets` — The packets to include
- `artifacts` — The artifacts to include

**Returns**: A `BundleManifest` with sorted entries

**Example**:
```rust
use evidencebus_core::build_bundle_manifest;

let manifest = build_bundle_manifest(&packets, &artifacts);
```

#### `build_bundle_summary`

Builds a bundle summary from packets.

```rust
pub fn build_bundle_summary(packets: &[Packet]) -> BundleSummary
```

**Parameters**:
- `packets` — The packets to summarize

**Returns**: A `BundleSummary` with counts and statistics

**Example**:
```rust
use evidencebus_core::build_bundle_summary;

let summary = build_bundle_summary(&packets);
println!("Total packets: {}", summary.total_packets);
```

---

## evidencebus-fs

**Purpose**: Filesystem I/O for packets and bundles

### Dependencies

```toml
[dependencies]
evidencebus-fs = "0.1.0"
```

### Types

#### `FsError`

Errors that can occur during filesystem operations.

```rust
pub enum FsError {
    IoError(std::io::Error),
    JsonError(serde_json::Error),
    ValidationError(ValidationError),
    PathError(PathError),
    NotFound(String),
}
```

#### `BundleBuilder`

Builder for constructing bundles on the filesystem.

```rust
pub struct BundleBuilder {
    output_dir: PathBuf,
}
```

**Methods**:
- `pub fn new(output_dir: &Path) -> Self` — Creates a new builder
- `pub fn add_packet(&mut self, packet_path: &Path) -> Result<(), FsError>` — Adds a packet
- `pub fn build(self) -> Result<BundleManifest, FsError>` — Builds the bundle

#### `LoadedBundle`

A loaded bundle with its packets and manifest.

```rust
pub struct LoadedBundle {
    pub manifest: BundleManifest,
    pub packets: Vec<Packet>,
}
```

### Functions

#### `read_packet`

Reads a packet from a JSON file.

```rust
pub fn read_packet(path: &Path) -> Result<Packet, FsError>
```

**Parameters**:
- `path` — The path to the packet file

**Returns**: The loaded `Packet`

**Example**:
```rust
use evidencebus_fs::read_packet;

let packet = read_packet(Path::new("packet.eb.json"))?;
```

#### `write_packet`

Writes a packet to a JSON file.

```rust
pub fn write_packet(path: &Path, packet: &Packet) -> Result<(), FsError>
```

**Parameters**:
- `path` — The path to write the packet
- `packet` — The packet to write

**Returns**: `Ok(())` on success

**Example**:
```rust
use evidencebus_fs::write_packet;

write_packet(Path::new("packet.eb.json"), &packet)?;
```

#### `build_bundle`

Builds a bundle from packet files.

```rust
pub fn build_bundle(packet_paths: &[PathBuf], output_dir: &Path) -> Result<BundleManifest, FsError>
```

**Parameters**:
- `packet_paths` — Paths to packet files
- `output_dir` — Directory to create the bundle

**Returns**: The bundle manifest

**Example**:
```rust
use evidencebus_fs::build_bundle;

let packets = vec![
    PathBuf::from("pkt1.eb.json"),
    PathBuf::from("pkt2.eb.json"),
];
let manifest = build_bundle(&packets, Path::new("output/bundle"))?;
```

#### `load_bundle`

Loads a bundle from a directory.

```rust
pub fn load_bundle(dir: &Path) -> Result<LoadedBundle, FsError>
```

**Parameters**:
- `dir` — The bundle directory

**Returns**: The loaded bundle

**Example**:
```rust
use evidencebus_fs::load_bundle;

let bundle = load_bundle(Path::new("evidence-bundle"))?;
```

---

## evidencebus-export-markdown

**Purpose**: Markdown format export

### Dependencies

```toml
[dependencies]
evidencebus-export-markdown = "0.1.0"
```

### Types

#### `MarkdownExportOptions`

Options for Markdown export.

```rust
pub struct MarkdownExportOptions {
    pub include_artifacts: bool,
    pub include_provenance: bool,
    pub include_links: bool,
}

impl Default for MarkdownExportOptions {
    fn default() -> Self {
        Self {
            include_artifacts: true,
            include_provenance: true,
            include_links: true,
        }
    }
}
```

### Functions

#### `export_packet_markdown`

Exports a packet to Markdown format.

```rust
pub fn export_packet_markdown(
    packet: &Packet,
    options: &MarkdownExportOptions
) -> Result<String, ExportError>
```

**Parameters**:
- `packet` — The packet to export
- `options` — Export options

**Returns**: Markdown string

**Example**:
```rust
use evidencebus_export_markdown::{export_packet_markdown, MarkdownExportOptions};

let options = MarkdownExportOptions::default();
let markdown = export_packet_markdown(&packet, &options)?;
println!("{}", markdown);
```

#### `export_bundle_markdown`

Exports a bundle to Markdown format.

```rust
pub fn export_bundle_markdown(
    bundle: &Bundle,
    options: &MarkdownExportOptions
) -> Result<String, ExportError>
```

**Parameters**:
- `bundle` — The bundle to export
- `options` — Export options

**Returns**: Markdown string

**Example**:
```rust
use evidencebus_export_markdown::{export_bundle_markdown, MarkdownExportOptions};

let options = MarkdownExportOptions::default();
let markdown = export_bundle_markdown(&bundle, &options)?;
```

---

## evidencebus-export-sarif

**Purpose**: SARIF format export

### Dependencies

```toml
[dependencies]
evidencebus-export-sarif = "0.1.0"
```

### Types

#### `SarifExportOptions`

Options for SARIF export.

```rust
pub struct SarifExportOptions {
    pub tool_name: String,
    pub tool_version: String,
    pub lossy_mode: LossyMode,
}

impl Default for SarifExportOptions {
    fn default() -> Self {
        Self {
            tool_name: "evidencebus".to_string(),
            tool_version: env!("CARGO_PKG_VERSION").to_string(),
            lossy_mode: LossyMode::Permissive,
        }
    }
}
```

#### `LossyMode`

How to handle data that cannot be represented in SARIF.

```rust
pub enum LossyMode {
    Strict,      // Error on lossy export
    Permissive,  // Warn on lossy export
    Silent,      // Silently drop lossy data
}
```

### Functions

#### `export_packet_sarif`

Exports a packet to SARIF format.

```rust
pub fn export_packet_sarif(
    packet: &Packet,
    options: &SarifExportOptions
) -> Result<serde_json::Value, ExportError>
```

**Parameters**:
- `packet` — The packet to export
- `options` — Export options

**Returns**: SARIF JSON value

**Example**:
```rust
use evidencebus_export_sarif::{export_packet_sarif, SarifExportOptions};

let options = SarifExportOptions::default();
let sarif = export_packet_sarif(&packet, &options)?;
println!("{}", serde_json::to_string_pretty(&sarif)?);
```

#### `export_packets_sarif`

Exports multiple packets to SARIF format.

```rust
pub fn export_packets_sarif(
    packets: &[Packet],
    options: &SarifExportOptions
) -> Result<serde_json::Value, ExportError>
```

**Parameters**:
- `packets` — The packets to export
- `options` — Export options

**Returns**: SARIF JSON value with multiple runs

**Example**:
```rust
use evidencebus_export_sarif::{export_packets_sarif, SarifExportOptions};

let options = SarifExportOptions::default();
let sarif = export_packets_sarif(&packets, &options)?;
```

---

## evidencebus-export

**Purpose**: Common export types and re-exports (facade)

### Dependencies

```toml
[dependencies]
evidencebus-export = "0.1.0"
```

### Types

This crate re-exports all types from `evidencebus-export-markdown` and `evidencebus-export-sarif`:

```rust
// Re-exports from evidencebus-export-markdown
pub use evidencebus_export_markdown::{
    export_packet_markdown,
    export_bundle_markdown,
    MarkdownExportOptions,
};

// Re-exports from evidencebus-export-sarif
pub use evidencebus_export_sarif::{
    export_packet_sarif,
    export_packets_sarif,
    SarifExportOptions,
    LossyMode,
};

// Common types
pub enum ExportError {
    MarkdownError(String),
    SarifError(String),
    IoError(String),
}
```

### Usage

Use this crate as a convenience facade for all export functionality:

```rust
use evidencebus_export::{
    export_packet_markdown,
    export_packet_sarif,
    MarkdownExportOptions,
    SarifExportOptions,
};

// Export to Markdown
let markdown = export_packet_markdown(&packet, &MarkdownExportOptions::default())?;

// Export to SARIF
let sarif = export_packet_sarif(&packet, &SarifExportOptions::default())?;
```
