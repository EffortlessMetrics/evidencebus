# Coverage

Codecov coverage is Rust execution-surface evidence.

## What it answers

> Did tests execute this Rust surface?

## What it does not answer

- whether packet validation is correct,
- whether bundle construction is correct,
- whether schema compatibility is proven,
- whether canonicalization and digest behavior are stable,
- whether filesystem safety checks are complete,
- whether Markdown or SARIF exports are correct,
- whether BDD coverage is adequate,
- whether release readiness is proven.

Those are separate proof lanes.

## When it runs

The Coverage workflow runs on:
- push to `main`,
- `workflow_dispatch`,
- PRs labeled `coverage`, `full-ci`, or `ci:full`.

## Durable receipts

Codecov comments are disabled. Artifacts:
- `coverage.json` — JSON report
- `coverage.txt` — Text summary
- `lcov.info` — LCOV format
- GitHub Actions coverage artifact (14-day retention)
- [Codecov dashboard](https://codecov.io/gh/EffortlessMetrics/evidencebus)
