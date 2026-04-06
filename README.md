# evidencebus

**Schema-first evidence backplane for repo operations.**

evidencebus takes outputs from tools like `faultline`, `proofrun`, `repropack`,
`stackcut`, `perfgate`, and similar repos and turns them into:

- validated packets
- deterministic bundles
- portable artifact inventories
- neutral exports such as Markdown and SARIF

It is deliberately **not** the merge cockpit. evidencebus moves evidence.
`cockpitctl` should decide what that evidence means for merge.

## Core commands

```bash
evidencebus validate fixtures/packets/perfgate/pkt-perfgate.eb.json
evidencebus bundle \
  fixtures/packets/perfgate/pkt-perfgate.eb.json \
  fixtures/packets/faultline/pkt-faultline.eb.json \
  --out ./out/evidence-bundle

evidencebus inspect ./out/evidence-bundle
evidencebus emit markdown ./out/evidence-bundle --out ./out/SUMMARY.md
evidencebus emit sarif ./out/evidence-bundle --out ./out/results.sarif
evidencebus schema packet
```

## Workspace doctrine

- **artifact-first** — packets and bundles are the product
- **schema-first** — checked-in JSON Schemas define the public contract
- **deterministic** — stable ordering, stable digests, stable manifests
- **local-first** — no daemon, service, or network requirement
- **neutral** — evidence transport and validation only, never merge policy

## Crate Architecture

evidencebus is organized as a workspace of focused microcrates, each with a single, well-defined responsibility:

### Core Primitives

- **`evidencebus-codes`** — Stable enums and exit codes shared across the workspace

- **`evidencebus-types`** — Core data structures for packets, bundles, and validation reports

### Functional Crates

- **`evidencebus-digest`** — SHA-256 digest computation and verification for integrity checking

- **`evidencebus-canonicalization`** — Deterministic JSON serialization and ordering for stable digests

- **`evidencebus-validation`** — Packet and bundle validation rules, centralized for consistency

- **`evidencebus-path`** — Path validation and sanitization utilities for security

- **`evidencebus-core`** — Bundle construction, conflict detection, and deduplication

### Filesystem and I/O

- **`evidencebus-fs`** — Packet loading, bundle writing, and strict filesystem checks

### Export Formats

- **`evidencebus-export-markdown`** — Markdown format export for human-readable reports

- **`evidencebus-export-sarif`** — SARIF format export for tool integration

- **`evidencebus-export`** — Common export types and re-exports (facade pattern)

### Testing and Tooling

- **`evidencebus-fixtures`** — Reusable sample packets and builders for tests

- **`evidencebus-cli`** — Composition root and operator-facing CLI commands

## Canonical layout

evidencebus writes directory bundles in this shape:

```text
evidence-bundle/
  bundle.eb.json
  packets/
    pkt-faultline/
      packet.eb.json
      artifacts/
        faultline/analysis.json
        faultline/index.html
        logs/stderr.log
    pkt-perfgate/
      packet.eb.json
      artifacts/
        report.json
```

## Testing

evidencebus uses Behavior-Driven Development (BDD) with scenario-based tests that serve as living documentation. Each crate includes comprehensive BDD tests covering observable behaviors rather than implementation details.

See [`docs/testing-strategy.md`](docs/testing-strategy.md) for the complete testing approach.

```bash
# Run all tests
cargo test --workspace --all-targets

# Run tests for a specific crate
cargo test -p evidencebus-validation

# Run BDD tests only
cargo test --workspace bdd
```

## Documents

- [`requirements.md`](requirements.md)
- [`design.md`](design.md)
- [`tasks.md`](tasks.md)
- [`docs/architecture.md`](docs/architecture.md) — Detailed crate architecture and responsibilities
- [`docs/testing-strategy.md`](docs/testing-strategy.md) — BDD testing approach
- [`docs/api-reference.md`](docs/api-reference.md) — Complete API reference for all microcrates
- [`docs/migration-guide.md`](docs/migration-guide.md) — Guide for migrating to the new microcrate architecture
- [`docs/producer-guide.md`](docs/producer-guide.md)
- [`docs/consumer-guide.md`](docs/consumer-guide.md)
- [`docs/schema.md`](docs/schema.md)

## Building

```bash
cargo build
cargo test
cargo run -p evidencebus-cli -- --help
```

See [`BUILDING.md`](BUILDING.md) for more build details.

## Schemas

The canonical artifact formats are defined in:

- [`schemas/packet.schema.json`](schemas/packet.schema.json) — Packet JSON schema
- [`schemas/bundle.schema.json`](schemas/bundle.schema.json) — Bundle JSON schema

These schemas are product surfaces and should be versioned deliberately.
