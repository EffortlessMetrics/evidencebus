# Changelog

All notable changes to evidencebus will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Comprehensive documentation suite including:
  - Getting Started guide
  - Tutorial series (creating packets, building bundles, exporting, validating)
  - Contributing guide
  - FAQ
  - Crate-specific README files

### Changed
- Improved documentation organization and cross-references
- Enhanced code examples throughout documentation

## [0.1.0] - 2024-01-15

### Added
- Initial release of evidencebus as a microcrate workspace
- Core primitives:
  - `evidencebus-codes` - Stable enums and exit codes
  - `evidencebus-types` - Core data structures for packets, bundles, and validation reports
- Functional crates:
  - `evidencebus-digest` - SHA-256 digest computation and verification
  - `evidencebus-canonicalization` - Deterministic JSON serialization and ordering
  - `evidencebus-validation` - Packet and bundle validation rules
  - `evidencebus-path` - Path validation and sanitization utilities
  - `evidencebus-core` - Bundle construction, conflict detection, and deduplication
- Filesystem and I/O:
  - `evidencebus-fs` - Packet loading, bundle writing, and strict filesystem checks
- Export formats:
  - `evidencebus-export-markdown` - Markdown format export
  - `evidencebus-export-sarif` - SARIF format export
  - `evidencebus-export` - Common export types and re-exports (facade pattern)
- Testing and tooling:
  - `evidencebus-fixtures` - Reusable sample packets and builders for tests
  - `evidencebus-cli` - Composition root and operator-facing CLI commands
- CLI commands:
  - `validate` - Validate packets and bundles
  - `bundle` - Create bundles from packet files
  - `inspect` - Inspect packet and bundle contents
  - `emit` - Export to Markdown and SARIF formats
  - `schema` - Display schema information
- JSON schemas for packets and bundles
- BDD-style testing framework
- Comprehensive example bundles and fixtures
- Documentation:
  - Architecture guide
  - Consumer guide
  - Producer guide
  - API reference
  - Schema documentation
  - Testing strategy
  - Migration guide
  - Mission and vision
  - Non-goals
  - Architecture Decision Records (ADRs)

### Design Principles
- **Schema-first** - Checked-in JSON Schemas define the public contract
- **Artifact-first** - Packets and bundles are the product
- **Deterministic** - Stable ordering, stable digests, stable manifests
- **Local-first** - No daemon, service, or network requirement
- **Neutral** - Evidence transport and validation only, never merge policy
- **Explicit filesystem behavior** - Clear, predictable file operations
- **Lossy exports** - Exports are explicitly marked where formats cannot express the full model
- **Canonical bundle truth** - JSON + attached artifacts is the canonical representation

## [0.0.1] - 2023-12-01

### Added
- Initial project setup
- Workspace configuration
- Basic crate structure
- Initial documentation

---

## Versioning Guidelines

### Major Version (X.0.0)
- Breaking changes to packet or bundle schemas
- Removal of public APIs
- Changes to canonical bundle layout
- Changes to digest computation method

### Minor Version (0.X.0)
- New features (backward compatible)
- New export formats
- New validation rules (non-breaking)
- Performance improvements

### Patch Version (0.0.X)
- Bug fixes
- Documentation updates
- Internal refactoring (no public API changes)
- Test improvements

### Schema Changes

When updating schemas:

1. Update the JSON schema files in `schemas/`
2. Update the `docs/schema.md` documentation
3. Add migration notes to `docs/migration-guide.md`
4. Update example packets and bundles
5. Consider version bumping based on impact

### Migration Guide

For users upgrading between versions, see the [Migration Guide](docs/migration-guide.md) for detailed instructions.

---

## Release Process

1. Update version in `Cargo.toml` workspace
2. Update version in individual crate `Cargo.toml` files
3. Update CHANGELOG.md with release notes
4. Tag the release: `git tag -a v0.1.0 -m "Release v0.1.0"`
5. Push tag: `git push origin v0.1.0`
6. Create GitHub release with changelog
7. Publish to crates.io (when available)
