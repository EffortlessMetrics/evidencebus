# AGENTS.md

## Repo law

evidencebus is neutral evidence transport and validation. Do not add merge
policy, required/optional gate semantics, or review workflow logic here.

## Preferred change shape

- keep types deterministic
- keep filesystem behavior explicit
- keep exports obviously lossy
- keep the canonical bundle truth in JSON + attached artifacts

## Fast commands

```bash
cargo test --workspace --all-targets
cargo run -p evidencebus-cli -- --help
```

## When a change is not done

A change is not done when it updates producer-facing or consumer-facing schema
surfaces without corresponding updates to:

- `schemas/*.json`
- docs
- fixtures
- golden outputs where applicable
