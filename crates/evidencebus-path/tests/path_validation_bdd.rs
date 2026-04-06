//! BDD-style tests for path validation functionality.
//!
//! These tests follow the Given-When-Then structure to clearly express
//! the expected behavior of path validation functions.

use evidencebus_path::validate_path;
use std::path::Path;

/// BDD test: Validating safe paths should succeed
#[test]
fn bdd_validate_safe_paths() {
    // GIVEN: A safe relative path without traversal or special characters
    let safe_path = Path::new("safe/relative/path");

    // WHEN: The path is validated
    let result = validate_path(safe_path);

    // THEN: The validation should succeed
    assert!(result.is_ok(), "Safe path should validate successfully");
}

/// BDD test: Validating single-component paths should succeed
#[test]
fn bdd_validate_single_component_paths() {
    // GIVEN: A single-component path
    let single_path = Path::new("packet");

    // WHEN: The path is validated
    let result = validate_path(single_path);

    // THEN: The validation should succeed
    assert!(
        result.is_ok(),
        "Single-component path should validate successfully"
    );
}

/// BDD test: Validating paths with current directory references should succeed
#[test]
fn bdd_validate_paths_with_current_directory() {
    // GIVEN: A path with current directory references
    let path_with_dot = Path::new("./relative/path");

    // WHEN: The path is validated
    let result = validate_path(path_with_dot);

    // THEN: The validation should succeed
    assert!(result.is_ok(), "Path with ./ should validate successfully");
}

/// BDD test: Validating paths with multiple current directory references should succeed
#[test]
fn bdd_validate_paths_with_multiple_current_directory() {
    // GIVEN: A path with multiple current directory references
    let path_with_dots = Path::new("./a/./b/./c");

    // WHEN: The path is validated
    let result = validate_path(path_with_dots);

    // THEN: The validation should succeed
    assert!(
        result.is_ok(),
        "Path with multiple ./ should validate successfully"
    );
}

/// BDD test: Validating paths with safe characters should succeed
#[test]
fn bdd_validate_paths_with_safe_characters() {
    // GIVEN: Paths with various safe characters
    let test_cases = vec![
        Path::new("packet-123"),
        Path::new("packet_456"),
        Path::new("packet.789"),
        Path::new("a/b-c_d.e"),
        Path::new("packet-with-dashes"),
        Path::new("packet_with_underscores"),
        Path::new("packet.with.dots"),
    ];

    // WHEN: Each path is validated
    for path in test_cases {
        let result = validate_path(path);

        // THEN: All validations should succeed
        assert!(
            result.is_ok(),
            "Path with safe characters '{}' should validate successfully",
            path.display()
        );
    }
}

/// BDD test: Validating empty paths should succeed
#[test]
fn bdd_validate_empty_path() {
    // GIVEN: An empty path
    let empty_path = Path::new("");

    // WHEN: The path is validated
    let result = validate_path(empty_path);

    // THEN: The validation should succeed
    assert!(result.is_ok(), "Empty path should validate successfully");
}

/// BDD test: Validating paths with only current directory should succeed
#[test]
fn bdd_validate_only_current_directory() {
    // GIVEN: A path containing only "."
    let dot_path = Path::new(".");

    // WHEN: The path is validated
    let result = validate_path(dot_path);

    // THEN: The validation should succeed
    assert!(
        result.is_ok(),
        "Path with only '.' should validate successfully"
    );
}

/// BDD test: Validating deeply nested safe paths should succeed
#[test]
fn bdd_validate_deeply_nested_safe_paths() {
    // GIVEN: A deeply nested safe path
    let deep_path = Path::new("a/b/c/d/e/f/g/h/i/j");

    // WHEN: The path is validated
    let result = validate_path(deep_path);

    // THEN: The validation should succeed
    assert!(
        result.is_ok(),
        "Deeply nested safe path should validate successfully"
    );
}
