# Testing strategy

evidencebus should be proof-heavy in the semantic center.

## Core

- scenario tests for validation and conflict rules
- property tests for ordering and digest stability
- mutation tests for semantic branches

## Filesystem

- tempdir-based bundle round trips
- strict validation of referenced artifacts
- unsafe path rejection

## Exports

- snapshot or golden tests for Markdown and SARIF
- explicit lossy-export expectations

## CLI

- help surface checks
- smoke tests around validate, bundle, inspect, and emit
