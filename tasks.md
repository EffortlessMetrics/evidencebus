# evidencebus implementation tasks

## M0 — boundary and docs

- write mission, non-goals, and ADRs
- freeze packet and bundle terminology
- freeze status and severity enums

## M1 — workspace scaffold

- create workspace crates
- add command surface and CI
- check in schemas

## M2 — types and core semantics

- implement packet and bundle value objects
- implement validation rules
- implement canonical ordering and digests
- implement summary rollups

## M3 — filesystem bundling

- load packet files
- validate strict attachment references
- copy artifacts into canonical bundle layout
- write deterministic manifest

## M4 — CLI and exports

- validate
- bundle
- inspect
- emit markdown
- emit sarif
- print schema files

## M5 — fixtures and pilot integrations

- perfgate-style packet
- faultline-style packet
- consumer path for cockpitctl

## M6 — hardening

- snapshot outputs
- property checks
- mutation sweeps
- producer and consumer guides
