# Migration Guide

This guide helps you migrate to the new microcrate architecture introduced in the evidencebus refactoring.

## Overview

The microcrate refactoring reorganized the codebase into smaller, focused crates with clear responsibilities. This was an **internal** refactoring that:

- **Did not change** the public Packet and Bundle data structures
- **Did not change** the JSON schemas (`schemas/packet.schema.json`, `schemas/bundle.schema.json`)
- **Did not change** the CLI interface
- **Did change** internal module organization for better separation of concerns

## Breaking Changes

### For Library Users

If you are using evidencebus as a library (not via the CLI), you may need to update your imports:

#### Before

```rust
use evidencebus_core::{validate_packet, validate_bundle};
use evidencebus_export::{export_packet_markdown, export_packet_sarif};
```

#### After

```rust
// Validation is now in a dedicated crate
use evidencebus_validation::{validate_packet, validate_bundle};

// Export functions are now in format-specific crates
use evidencebus_export_markdown::export_packet_markdown;
use evidencebus_export_sarif::export_packet_sarif;

// Or use the facade for convenience
use evidencebus_export::{export_packet_markdown, export_packet_sarif};
```

### For Contributors

If you are contributing to the codebase, you need to understand the new crate structure:

#### Moved Functions

| Old Location | New Crate | Function |
|--------------|-----------|----------|
| `evidencebus_core::compute_sha256()` | `evidencebus_digest` | Digest computation |
| `evidencebus_core::verify_digest()` | `evidencebus_digest` | Digest verification |
| `evidencebus_core::canonicalize_json()` | `evidencebus_canonicalization` | JSON canonicalization |
| `evidencebus_core::validate_packet()` | `evidencebus_validation` | Packet validation |
| `evidencebus_core::validate_bundle()` | `evidencebus_validation` | Bundle validation |
| `evidencebus_fs::validate_bundle_path()` | `evidencebus_path` | Path validation |
| `evidencebus_fs::sanitize_path_component()` | `evidencebus_path` | Path sanitization |
| `evidencebus_fs::normalize_relative_path()` | `evidencebus_path` | Path normalization |
| `evidencebus_export::export_packet_markdown()` | `evidencebus_export_markdown` | Markdown export |
| `evidencebus_export::export_packet_sarif()` | `evidencebus_export_sarif` | SARIF export |

#### New Crates

The following crates are new and should be used for their specific responsibilities:

- `evidencebus-digest` — Use for all digest operations
- `evidencebus-canonicalization` — Use for JSON canonicalization
- `evidencebus-validation` — Use for all validation logic
- `evidencebus-path` — Use for path utilities
- `evidencebus-export-markdown` — Use for Markdown-specific export
- `evidencebus-export-sarif` — Use for SARIF-specific export

## Migration Steps

### Step 1: Update Imports

Update your `Cargo.toml` dependencies:

```toml
[dependencies]
evidencebus-types = "0.1.0"
evidencebus-validation = "0.1.0"
evidencebus-export = "0.1.0"
```

Update your code imports:

```rust
// Old
use evidencebus_core::{validate_packet, validate_bundle};
use evidencebus_export::{export_packet_markdown, export_packet_sarif};

// New
use evidencebus_validation::{validate_packet, validate_bundle};
use evidencebus_export::{export_packet_markdown, export_packet_sarif};
```

### Step 2: Update Test Code

If you have tests that use internal functions, update them to use the new crate locations:

```rust
// Old
use evidencebus_core::tests::*;

// New
use evidencebus_validation::tests::*;
```

### Step 3: Review Dependencies

Check your `Cargo.toml` and remove any dependencies on crates that no longer export the functions you need. Add dependencies on the new, more focused crates.

## No Changes Required

The following do NOT require changes:

- **Packet and Bundle JSON schemas** — No changes to `schemas/packet.schema.json` or `schemas/bundle.schema.json`
- **CLI interface** — All CLI commands work exactly as before
- **Packet and Bundle data structures** — `evidencebus_types` types remain unchanged
- **JSON format** — The canonical JSON format is identical
- **Bundle directory layout** — The filesystem layout is unchanged

## Testing Your Migration

After updating your code, run the tests:

```bash
# Run all tests
cargo test --workspace --all-targets

# Run BDD tests to verify behavior
cargo test --workspace bdd

# Run CLI smoke tests
just smoke
```

## Getting Help

If you encounter issues during migration:

1. Check the [`docs/architecture.md`](docs/architecture.md) for the new crate structure
2. Review the crate-specific documentation in each crate's `src/lib.rs`
3. Look at the BDD tests in each crate for usage examples
4. Open an issue with details about what you're trying to migrate

## Summary

| Category | Changed? | Action Required |
|----------|----------|----------------|
| JSON schemas | No | None |
| Data structures | No | None |
| CLI interface | No | None |
| Bundle layout | No | None |
| Internal module organization | Yes | Update imports if using as library |
| Test code | Yes | Update test imports |
