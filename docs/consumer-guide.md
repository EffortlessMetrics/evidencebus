# Consumer guide

evidencebus is meant to reduce consumer complexity.

## Preferred ingest path

1. Read `bundle.eb.json`
2. Load packet files listed in the manifest
3. Use common projections where possible
4. Read typed attachments only when deeper tool-native behavior is needed

## What belongs in consumers

- merge policy
- required vs optional checks
- operator decision views
- review workflows

## What does not belong in evidencebus

- merge blocking semantics
- approval routing
- deployment logic

`cockpitctl` is the natural downstream consumer for merge-time interpretation.
