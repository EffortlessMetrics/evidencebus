# Building evidencebus

## Prerequisites

- Rust stable
- Cargo
- `just` for the convenience command surface (optional)

## Common commands

```bash
cargo build
cargo test
cargo run -p evidencebus-cli -- --help
```

Or via `just`:

```bash
just ci-fast
just smoke
```

## Workspace shape

### Core Primitives

- `evidencebus-codes` — shared enums and exit codes
- `evidencebus-types` — packet and bundle value objects

### Functional Crates

- `evidencebus-digest` — SHA-256 digest computation and verification
- `evidencebus-canonicalization` — deterministic JSON serialization and ordering
- `evidencebus-validation` — packet and bundle validation rules
- `evidencebus-path` — path validation and sanitization utilities
- `evidencebus-core` — bundle construction, conflict detection, and deduplication

### Filesystem and I/O

- `evidencebus-fs` — filesystem IO and directory bundle creation

### Export Formats

- `evidencebus-export-markdown` — Markdown format export
- `evidencebus-export-sarif` — SARIF format export
- `evidencebus-export` — common export types and re-exports (facade)

### Testing and Tooling

- `evidencebus-fixtures` — reusable packet constructors for tests
- `evidencebus-cli` — operator-facing CLI

## Building individual crates

```bash
# Build a specific crate
cargo build -p evidencebus-digest

# Build with all features
cargo build --all-features

# Build in release mode
cargo build --release
```

## Testing

```bash
# Run all tests
cargo test --workspace --all-targets

# Run tests for a specific crate
cargo test -p evidencebus-validation

# Run BDD tests only
cargo test --workspace bdd

# Run tests with output
cargo test --workspace -- --nocapture
```

## Important note

The canonical artifact formats live in `schemas/packet.schema.json` and
`schemas/bundle.schema.json`. Those files are product surfaces and should be
versioned deliberately.

## BDD Testing

evidencebus uses Behavior-Driven Development with scenario-based tests. See
[`docs/testing-strategy.md`](docs/testing-strategy.md) for the complete testing
approach and guidelines for writing new BDD tests.
