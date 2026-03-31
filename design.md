# evidencebus design

## Boundary

evidencebus moves and normalizes evidence. `cockpitctl` decides what that
evidence means for merge.

## Core model

The packet model is **envelope + common projections + typed attachments**.

- Envelope: identity, producer, subject, summary, provenance
- Projections: assertions, findings, metrics, relations, attachments
- Typed attachments: native JSON payloads, HTML reports, logs, text, binaries

This keeps a shared contract without flattening richer tools into mush.

## Bundle representation

v0.1 uses a directory bundle rather than an opaque blob:

```text
evidence-bundle/
  bundle.eb.json
  packets/
    <packet-id>/
      packet.eb.json
      artifacts/
```

Directory-first makes the product easy to inspect, diff, validate, and zip
later if transport packaging is needed.

## Validation modes

- `schema_only` — structure only
- `strict` — structure + file existence + digest checks

## Architecture

The workspace is intentionally lean:

- `evidencebus-codes`
- `evidencebus-types`
- `evidencebus-core`
- `evidencebus-fs`
- `evidencebus-export`
- `evidencebus-fixtures`
- `evidencebus-cli`

There is no `app` crate yet because the seam has not earned it.
