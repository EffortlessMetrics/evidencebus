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

- `evidencebus-codes` — shared enums and exit codes
- `evidencebus-types` — packet and bundle value objects
- `evidencebus-core` — validation, canonicalization, and bundling rules
- `evidencebus-fs` — filesystem IO and directory bundle creation
- `evidencebus-export` — Markdown and SARIF rendering
- `evidencebus-fixtures` — reusable packet constructors for tests
- `evidencebus-cli` — operator-facing CLI

## Important note

The canonical artifact formats live in `schemas/packet.schema.json` and
`schemas/bundle.schema.json`. Those files are product surfaces and should be
versioned deliberately.
