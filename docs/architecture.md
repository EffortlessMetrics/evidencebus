# Architecture

evidencebus follows a lean, seam-driven workspace layout.

## Crates

### Core Primitives

- `evidencebus-codes` — stable enums and exit codes
- `evidencebus-types` — packet, bundle, and validation report types

### Functional Crates

- `evidencebus-digest` — SHA-256 digest computation and verification
- `evidencebus-canonicalization` — deterministic JSON serialization and ordering
- `evidencebus-validation` — packet and bundle validation rules
- `evidencebus-path` — path validation and sanitization utilities
- `evidencebus-core` — bundle construction, conflict detection, and deduplication

### Filesystem and I/O

- `evidencebus-fs` — packet loading, bundle writing, strict filesystem checks

### Export Formats

- `evidencebus-export-markdown` — Markdown format export
- `evidencebus-export-sarif` — SARIF format export
- `evidencebus-export` — common export types and re-exports (facade)

### Testing and Tooling

- `evidencebus-fixtures` — reusable sample packets and builders for tests
- `evidencebus-cli` — composition root and operator-facing commands

## Dependency Graph

```
evidencebus-codes (leaf)
    ↑
evidencebus-types
    ↑
┌─────────────────────────────────────────────────────────────┐
│ evidencebus-digest                                          │
│ evidencebus-canonicalization                                │
│ evidencebus-path                                           │
└─────────────────────────────────────────────────────────────┘
    ↑
┌─────────────────────────────────────────────────────────────┐
│ evidencebus-validation                                      │
└─────────────────────────────────────────────────────────────┘
    ↑
┌─────────────────────────────────────────────────────────────┐
│ evidencebus-core                                            │
└─────────────────────────────────────────────────────────────┘
    ↑
┌─────────────────────────────────────────────────────────────┐
│ evidencebus-fs                                              │
└─────────────────────────────────────────────────────────────┘
    ↑
┌─────────────────────────────────────────────────────────────┐
│ evidencebus-export-markdown                                 │
│ evidencebus-export-sarif                                    │
└─────────────────────────────────────────────────────────────┘
    ↑
┌─────────────────────────────────────────────────────────────┐
│ evidencebus-export (facade)                                 │
│ evidencebus-fixtures                                        │
└─────────────────────────────────────────────────────────────┘
    ↑
evidencebus-cli
```

## Flow

1. Producer writes a packet JSON file plus attachments.
2. evidencebus validates the packet using `evidencebus-validation`.
3. evidencebus bundles one or more packets into a deterministic directory layout using `evidencebus-fs` and `evidencebus-core`.
4. Downstream tools read the bundle manifest and packet files.
5. Packet-local artifacts live beneath each packet directory.
6. Exports derive from the canonical packet or bundle using format-specific crates, never the other way around.

## Core design rules

- keep bundle layout deterministic
- use relative paths and digests
- preserve native payloads through typed attachments
- keep exports explicitly lossy where formats cannot express the full model
- maintain clear separation of concerns across microcrates
- test observable behaviors using BDD-style tests

## Bundle shape

```text
evidence-bundle/
  bundle.eb.json
  packets/
    <packet-id>/
      packet.eb.json
      artifacts/
```

## Microcrate Responsibilities

### evidencebus-digest

Cryptographic digest computation and verification. Provides SHA-256 digest operations used throughout the codebase for integrity verification.

### evidencebus-canonicalization

Deterministic JSON serialization and ordering. Ensures consistent representation of packets and bundles for digest computation and comparison.

### evidencebus-validation

Packet and bundle validation rules. Centralizes all validation logic including schema validation, semantic validation, and integrity checks.

### evidencebus-path

Path validation and sanitization utilities. Provides security-focused path operations to prevent path traversal and ensure safe filesystem operations.

### evidencebus-core

Bundle construction, conflict detection, and deduplication. Handles the semantic operations for building bundles from packets.

### evidencebus-fs

Filesystem I/O for packets and bundles. Manages reading and writing packets, building bundle directory structures, and artifact copying.

### evidencebus-export-markdown

Markdown format export. Converts packets and bundles to human-readable Markdown format.

### evidencebus-export-sarif

SARIF format export. Converts packets and bundles to SARIF format for tool integration.

### evidencebus-export

Common export types and re-exports. Provides a facade for export functionality with shared types and lossy export modes.
