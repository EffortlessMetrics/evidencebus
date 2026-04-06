# Testing strategy

evidencebus uses Behavior-Driven Development (BDD) to ensure proof-heavy testing in the semantic center.

## BDD Approach

Behavior-Driven Development focuses on testing observable behaviors rather than implementation details. Tests are written using a descriptive Given-When-Then structure that serves as living documentation of expected behavior.

### Test Structure

Each BDD test follows this pattern:

```rust
#[test]
fn bdd_given_<context>_when_<action>_then_<expected_outcome>() {
    // Given - Set up the test context
    let input = create_test_data();

    // When - Perform the action being tested
    let result = perform_action(&input);

    // Then - Verify the expected outcome
    assert!(result.is_ok());
}
```

### Benefits of BDD

- **Living Documentation**: Tests serve as executable documentation of expected behavior
- **Business Alignment**: Tests are written in business language, not implementation details
- **Easier Maintenance**: Clear test structure makes tests easier to understand and modify
- **Better Coverage**: Scenario-based tests ensure important behaviors are covered
- **Regression Prevention**: Clear test scenarios make it obvious when behavior changes

## Core

### evidencebus-digest

- scenario tests for digest computation and verification
- property tests for digest stability across multiple invocations
- mutation tests for digest format validation

**Key Behaviors**:
- Given valid data, when computing SHA-256 digest, then returns 64-character hex string
- Given data, when computing digest multiple times, then returns identical results
- Given data and matching digest, when verifying, then succeeds
- Given data and mismatched digest, when verifying, then fails with specific error

### evidencebus-canonicalization

- scenario tests for JSON key sorting
- property tests for nested JSON canonicalization
- mutation tests for array order preservation

**Key Behaviors**:
- Given JSON with unsorted keys, when canonicalizing, then keys are sorted alphabetically
- Given nested JSON, when canonicalizing, then all levels are sorted
- Given JSON with arrays, when canonicalizing, then arrays maintain order
- Given packets in random order, when canonicalizing bundle order, then sorted by packet_id

### evidencebus-validation

- scenario tests for validation and conflict rules
- property tests for validation error specificity
- mutation tests for edge cases (path traversal, invalid digests, etc.)

**Packet Validation Behaviors**:
- Given valid packet, when validating, then succeeds
- Given packet with missing required field, when validating, then returns specific error
- Given packet with path traversal, when validating, then returns path traversal error
- Given packet with unsafe path, when validating, then returns unsafe path error
- Given packet with invalid digest format, when validating, then returns reference invalid error

**Bundle Validation Behaviors**:
- Given valid bundle, when validating in schema-only mode, then succeeds without checking files
- Given valid bundle, when validating in strict mode, then checks all digests
- Given bundle with duplicate packet IDs, when validating, then returns conflict error
- Given bundle with missing artifact, when validating, then returns missing artifact error
- Given bundle with digest mismatch, when validating, then returns digest mismatch error

### evidencebus-path

- scenario tests for path validation and sanitization
- property tests for cross-platform path handling
- mutation tests for path traversal detection

**Key Behaviors**:
- Given safe relative path, when validating, then succeeds
- Given absolute path, when validating, then returns absolute path error
- Given path with "..", when validating, then returns path traversal error
- Given path with backslash, when sanitizing, then replaces with underscore
- Given path with spaces, when sanitizing, then replaces with underscore
- Given path with null byte, when sanitizing, then returns invalid component error

### evidencebus-core

- scenario tests for deduplication and conflict rules
- property tests for ordering and manifest stability
- mutation tests for semantic branches

**Deduplication Behaviors**:
- Given packets with duplicate IDs and content, when deduplicating, then removes duplicates
- Given packets with duplicate IDs but different content, when deduplicating, then returns conflict error
- Given unique packets, when deduplicating, then preserves all packets

**Conflict Detection Behaviors**:
- Given packets with same ID and different content, when detecting conflicts, then returns conflict
- Given packets with same ID and same content, when detecting conflicts, then returns no conflicts
- Given unique packet IDs, when detecting conflicts, then returns no conflicts

**Bundle Manifest Building Behaviors**:
- Given packets and artifacts, when building manifest, then includes all entries
- Given packets, when building manifest, then entries are sorted by packet_id
- Given artifacts, when building manifest, then entries are sorted by packet_id then path

**Bundle Summary Building Behaviors**:
- Given packets with various statuses, when building summary, then counts correctly
- Given packets with findings, when building summary, then severity counts are correct
- Given packets with artifacts, when building summary, then total artifacts is correct

## Filesystem

### evidencebus-fs

- tempdir-based bundle round trips
- strict validation of referenced artifacts
- unsafe path rejection

**Packet I/O Behaviors**:
- Given packet, when writing to file, then file contains valid JSON
- Given valid packet file, when reading, then returns packet
- Given packet, when writing then reading, then data is preserved

**Bundle Building Behaviors**:
- Given packet files, when building bundle, then creates correct directory structure
- Given packet files with attachments, when building bundle, then copies artifacts
- Given packet files, when building bundle, then writes manifest

**Bundle Loading Behaviors**:
- Given valid bundle directory, when loading, then returns loaded bundle
- Given bundle with manifest, when loading, then reads all packets

**Validation Behaviors**:
- Given valid packet file, when validating in schema-only mode, then succeeds
- Given valid packet file with attachments, when validating in strict mode, then verifies digests
- Given packet file with missing attachment, when validating in strict mode, then returns error

## Exports

### evidencebus-export-markdown

- snapshot or golden tests for Markdown output
- explicit lossy-export expectations

**Key Behaviors**:
- Given packet with pass status, when exporting to Markdown, then includes pass emoji
- Given packet with findings, when exporting to Markdown, then includes findings section
- Given packet with metrics, when exporting to Markdown, then includes metrics with units
- Given bundle with multiple packets, when exporting to Markdown, then includes inventory
- Given packet with attachments, when exporting to Markdown, then includes attachments with digests

### evidencebus-export-sarif

- snapshot or golden tests for SARIF output
- explicit lossy-export expectations

**Key Behaviors**:
- Given packet with findings, when exporting to SARIF, then includes results
- Given packet with findings with locations, when exporting to SARIF, then includes physical locations
- Given packet with metrics, when exporting to SARIF, then marks as lossy export
- Given packet with attachments, when exporting to SARIF, then omits non-location attachments
- Given multiple packets, when exporting to SARIF, then includes multiple runs

## CLI

### evidencebus-cli

- help surface checks
- smoke tests around validate, bundle, inspect, and emit

**Validate Command Behaviors**:
- Given valid packet file, when running validate, then exits with success code
- Given invalid packet file, when running validate, then exits with validation failed code
- Given packet file, when running validate with schema-only, then skips file checks

**Bundle Command Behaviors**:
- Given packet files, when running bundle, then creates bundle directory
- Given packet files, when running bundle, then writes manifest
- Given packet files, when running bundle with output, then creates at specified path

**Inspect Command Behaviors**:
- Given packet file, when running inspect, then displays packet information
- Given bundle directory, when running inspect, then displays bundle summary

**Emit Command Behaviors**:
- Given packet file, when running emit with markdown, then outputs Markdown
- Given packet file, when running emit with sarif, then outputs SARIF JSON

## Test Organization

Tests are organized by crate with BDD-style tests in dedicated test files:

```
crates/
  evidencebus-digest/
    tests/
      bdd_tests.rs
  evidencebus-canonicalization/
    tests/
      bdd_tests.rs
  evidencebus-validation/
    tests/
      bundle_validation.rs
      packet_validation.rs
  evidencebus-path/
    tests/
      edge_cases_bdd.rs
      path_sanitization_bdd.rs
      path_traversal_bdd.rs
      path_validation_bdd.rs
      relative_path_validation_bdd.rs
  evidencebus-core/
    tests/
      bdd_tests.rs
  evidencebus-fs/
    tests/
      bdd_tests.rs
  evidencebus-export/
    tests/
      bdd_tests.rs
  evidencebus-export-markdown/
    tests/
      bdd_tests.rs
  evidencebus-export-sarif/
    tests/
      bdd_tests.rs
  evidencebus-cli/
    tests/
      bdd_tests.rs
      cli_tests.rs
```

## Golden Testing

For export formats, use golden testing with snapshot files:

```rust
#[test]
fn bdd_given_packet_when_exporting_markdown_then_matches_golden() {
    let packet = create_test_packet();
    let markdown = export_packet_markdown(&packet, &Default::default()).unwrap();
    insta::assert_snapshot!(markdown);
}
```

Golden files are stored in `fixtures/golden/markdown/` and `fixtures/golden/sarif/`.

## Running Tests

```bash
# Run all tests
cargo test --workspace --all-targets

# Run tests for a specific crate
cargo test -p evidencebus-digest

# Run BDD tests only
cargo test --workspace bdd

# Run tests with output
cargo test --workspace -- --nocapture
```

## Writing New BDD Tests

When adding new functionality, follow these guidelines:

1. **Identify the behavior**: What should happen given specific inputs?
2. **Write the test first**: Use the Given-When-Then structure
3. **Make it descriptive**: Use clear, business-language test names
4. **Test edge cases**: Include invalid inputs and boundary conditions
5. **Use fixtures**: Leverage `evidencebus-fixtures` for test data

Example:

```rust
#[test]
fn bdd_given_packet_with_path_traversal_when_validating_then_returns_error() {
    // Given
    let mut packet = create_valid_packet();
    packet.native_payloads.push("../etc/passwd".to_string());

    // When
    let result = validate_packet(&packet);

    // Then
    assert!(matches!(result, Err(ValidationError::PathTraversal(_))));
}
```
