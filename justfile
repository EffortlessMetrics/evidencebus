set shell := ["bash", "-eu", "-o", "pipefail", "-c"]

default:
    @just --list

fmt:
    cargo fmt --all

fmt-check:
    cargo fmt --all --check

clippy:
    cargo clippy --workspace --all-targets -- -D warnings

test:
    cargo test --workspace --all-targets

ci-fast: fmt-check clippy test

ci-full: ci-fast docs-check

smoke:
    cargo test -p evidencebus-fs fs_bundle_round_trip -- --nocapture

golden:
    cargo test -p evidencebus-export markdown_contains_packet_titles -- --nocapture

mutants:
    cargo mutants -r evidencebus-core -r evidencebus-fs

docs-check:
    test -f schemas/packet.schema.json
    test -f schemas/bundle.schema.json
