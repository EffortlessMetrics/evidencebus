# Architecture

evidencebus follows a lean, seam-driven workspace layout.

## Crates

- `evidencebus-codes` — stable enums and exit codes
- `evidencebus-types` — packet, bundle, and validation report types
- `evidencebus-core` — canonicalization, validation, digesting, summary rules
- `evidencebus-fs` — packet loading, bundle writing, strict filesystem checks
- `evidencebus-export` — Markdown and SARIF rendering
- `evidencebus-fixtures` — reusable sample packets for tests
- `evidencebus-cli` — composition root and operator-facing commands

## Flow

1. Producer writes a packet JSON file plus attachments.
2. evidencebus validates the packet.
3. evidencebus bundles one or more packets into a deterministic directory layout.
4. Downstream tools read the bundle manifest and packet files.
5. Packet-local artifacts live beneath each packet directory.
6. Exports derive from the canonical packet or bundle, never the other way around.

## Core design rules

- keep bundle layout deterministic
- use relative paths and digests
- preserve native payloads through typed attachments
- keep exports explicitly lossy where formats cannot express the full model

## Bundle shape

```text
evidence-bundle/
  bundle.eb.json
  packets/
    <packet-id>/
      packet.eb.json
      artifacts/
```
