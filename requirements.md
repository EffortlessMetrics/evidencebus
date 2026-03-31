# evidencebus requirements

## Product goal

Turn repo-op outputs into a stable evidence contract so that producers do not
invent ad hoc JSON forever and consumers do not accumulate bespoke parsers.

## Functional requirements

1. Define a stable packet envelope for a single tool invocation.
2. Define a deterministic bundle format for collections of packets and artifacts.
3. Preserve producer-native payloads through typed attachments.
4. Validate packets and bundles in schema-only and strict modes.
5. Support portable attachment references with digests and sizes.
6. Provide a small common projection layer: assertions, findings, metrics,
   relations, attachments.
7. Export packet or bundle content to canonical JSON, Markdown, and a clean
   SARIF subset.
8. Remain neutral about policy. evidencebus may summarize evidence but shall
   never decide merge readiness.

## Non-functional requirements

- Local-first, no network requirement in v0.1
- Deterministic bundle output
- Cross-platform safe path handling
- Stable CLI exit codes
- Schema-version discipline
- Snapshot, property, and mutation-friendly core logic

## Non-goals

evidencebus is not:

- a merge cockpit
- a policy engine
- a GitHub bot
- a dashboard platform
- a CI runner
- a remote artifact store
