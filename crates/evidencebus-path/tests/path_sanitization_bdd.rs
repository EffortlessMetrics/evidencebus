#![allow(clippy::unwrap_used, clippy::expect_used)]
//! BDD-style tests for path sanitization functionality.
//!
//! These tests follow the Given-When-Then structure to clearly express
//! the expected behavior of path sanitization functions.

use evidencebus_path::{sanitize_path, sanitize_path_component, PathError};
use std::path::Path;

/// BDD test: Sanitizing path components with safe characters should preserve them
#[test]
fn bdd_sanitize_safe_characters() {
    // GIVEN: Path components with safe characters
    let test_cases = vec![
        ("test-packet", "test-packet"),
        ("test.packet", "test.packet"),
        ("test_packet", "test_packet"),
        ("packet-123", "packet-123"),
        ("packet_456", "packet_456"),
        ("packet.789", "packet.789"),
        ("a-b_c.d", "a-b_c.d"),
    ];

    // WHEN: Each component is sanitized
    for (input, expected) in test_cases {
        let result = sanitize_path_component(input);

        // THEN: The sanitized component should match the expected value
        assert!(
            result.is_ok(),
            "Safe component '{}' should sanitize successfully",
            input
        );
        assert_eq!(
            result.unwrap(),
            expected,
            "Component '{}' should sanitize to '{}'",
            input,
            expected
        );
    }
}

/// BDD test: Sanitizing path components with spaces should replace with underscores
#[test]
fn bdd_sanitize_spaces_to_underscores() {
    // GIVEN: Path components with spaces
    let test_cases = vec![
        ("test packet", "test_packet"),
        ("test  packet", "test__packet"),
        (" test packet ", "_test_packet_"),
        ("a b c", "a_b_c"),
    ];

    // WHEN: Each component is sanitized
    for (input, expected) in test_cases {
        let result = sanitize_path_component(input);

        // THEN: Spaces should be replaced with underscores
        assert!(
            result.is_ok(),
            "Component with spaces should sanitize successfully"
        );
        assert_eq!(
            result.unwrap(),
            expected,
            "Component '{}' should sanitize to '{}'",
            input,
            expected
        );
    }
}

/// BDD test: Sanitizing path components with special characters should replace with underscores
#[test]
fn bdd_sanitize_special_characters_to_underscores() {
    // GIVEN: Path components with special characters
    let test_cases = vec![
        ("test@packet", "test_packet"),
        ("test#packet", "test_packet"),
        ("test$packet", "test_packet"),
        ("test%packet", "test_packet"),
        ("test&packet", "test_packet"),
        ("test*packet", "test_packet"),
        ("test+packet", "test_packet"),
        ("test=packet", "test_packet"),
        ("test?packet", "test_packet"),
        ("test!packet", "test_packet"),
        ("test^packet", "test_packet"),
        ("test~packet", "test_packet"),
        ("test`packet", "test_packet"),
        ("test|packet", "test_packet"),
        ("test\\packet", "test_packet"),
        ("test<packet", "test_packet"),
        ("test>packet", "test_packet"),
        ("test[packet", "test_packet"),
        ("test]packet", "test_packet"),
        ("test{packet", "test_packet"),
        ("test}packet", "test_packet"),
        ("test(packet", "test_packet"),
        ("test)packet", "test_packet"),
        ("test,packet", "test_packet"),
        ("test;packet", "test_packet"),
        ("test:packet", "test_packet"),
        ("test'packet", "test_packet"),
        ("test\"packet", "test_packet"),
    ];

    // WHEN: Each component is sanitized
    for (input, expected) in test_cases {
        let result = sanitize_path_component(input);

        // THEN: Special characters should be replaced with underscores
        assert!(
            result.is_ok(),
            "Component with special characters should sanitize successfully"
        );
        assert_eq!(
            result.unwrap(),
            expected,
            "Component '{}' should sanitize to '{}'",
            input,
            expected
        );
    }
}

/// BDD test: Sanitizing path components with parent traversal should fail
#[test]
fn bdd_sanitize_parent_traversal_fails() {
    // GIVEN: Path components with parent traversal
    let test_cases = vec!["..", "test..", "..test", "test..test"];

    // WHEN: Each component is sanitized
    for input in test_cases {
        let result = sanitize_path_component(input);

        // THEN: The sanitization should fail with PathTraversal error
        assert!(
            matches!(result, Err(PathError::PathTraversal(_))),
            "Component '{}' with parent traversal should be rejected",
            input
        );
    }
}

/// BDD test: Sanitizing path components with null bytes should fail
#[test]
fn bdd_sanitize_null_bytes_fails() {
    // GIVEN: Path components with null bytes
    let test_cases = vec!["test\0packet", "\0test", "test\0", "\0"];

    // WHEN: Each component is sanitized
    for input in test_cases {
        let result = sanitize_path_component(input);

        // THEN: The sanitization should fail with InvalidPathComponent error
        assert!(
            matches!(result, Err(PathError::InvalidPathComponent(_))),
            "Component '{}' with null byte should be rejected",
            input
        );
    }
}

/// BDD test: Sanitizing path components with only unsafe chars produces all-underscore results
#[test]
fn bdd_sanitize_all_unsafe_chars_produces_underscores() {
    // GIVEN: Path components with only unsafe characters
    let test_cases = vec![
        ("!!!", "___"),
        ("@@@", "___"),
        ("###", "___"),
        ("$$$", "___"),
        ("   ", "___"),
        ("!!!@@@###", "_________"),
    ];

    // WHEN: Each component is sanitized
    for (input, expected) in test_cases {
        let result = sanitize_path_component(input);

        // THEN: Each unsafe character should be replaced with underscore
        assert!(
            result.is_ok(),
            "Component '{}' should sanitize successfully (unsafe chars become underscores)",
            input
        );
        assert_eq!(
            result.expect("already checked is_ok"),
            expected,
            "Component '{}' should sanitize to '{}'",
            input,
            expected
        );
    }
}

/// BDD test: Sanitizing an empty path component should fail
#[test]
fn bdd_sanitize_empty_component_fails() {
    // GIVEN: An empty path component
    let input = "";

    // WHEN: The component is sanitized
    let result = sanitize_path_component(input);

    // THEN: The sanitization should fail with InvalidPathComponent error
    assert!(
        matches!(result, Err(PathError::InvalidPathComponent(_))),
        "Empty component should be rejected as InvalidPathComponent"
    );
}

/// BDD test: Sanitizing full paths should sanitize each component
#[test]
fn bdd_sanitize_full_paths() {
    // GIVEN: Paths with components needing sanitization
    let test_cases = vec![
        (Path::new("safe/path"), Path::new("safe/path")),
        (
            Path::new("unsafe@path/with spaces"),
            Path::new("unsafe_path/with_spaces"),
        ),
        (Path::new("a@b/c@d/e@f"), Path::new("a_b/c_d/e_f")),
        (Path::new("a b/c d/e f"), Path::new("a_b/c_d/e_f")),
    ];

    // WHEN: Each path is sanitized
    for (input, expected) in test_cases {
        let result = sanitize_path(input);

        // THEN: The sanitized path should match the expected value
        assert!(
            result.is_ok(),
            "Path '{}' should sanitize successfully",
            input.display()
        );
        assert_eq!(
            result.unwrap(),
            expected,
            "Path '{}' should sanitize to '{}'",
            input.display(),
            expected.display()
        );
    }
}

/// BDD test: Sanitizing full paths with current directory should skip it
#[test]
fn bdd_sanitize_full_paths_with_current_directory() {
    // GIVEN: Paths with current directory references
    let test_cases = vec![
        (Path::new("./a"), Path::new("a")),
        (Path::new("a/./b"), Path::new("a/b")),
        (Path::new("./a/./b"), Path::new("a/b")),
    ];

    // WHEN: Each path is sanitized
    for (input, expected) in test_cases {
        let result = sanitize_path(input);

        // THEN: Current directory references should be skipped
        assert!(result.is_ok(), "Path with ./ should sanitize successfully");
        assert_eq!(
            result.unwrap(),
            expected,
            "Path '{}' should sanitize to '{}'",
            input.display(),
            expected.display()
        );
    }
}

/// BDD test: Sanitizing full paths with traversal should fail
#[test]
fn bdd_sanitize_full_paths_with_traversal_fails() {
    // GIVEN: Paths with traversal
    let test_cases = vec![
        Path::new("a/../b"),
        Path::new("../a"),
        Path::new("a/../../b"),
        Path::new(".."),
    ];

    // WHEN: Each path is sanitized
    for path in test_cases {
        let result = sanitize_path(path);

        // THEN: The sanitization should fail with PathTraversal error
        assert!(
            matches!(result, Err(PathError::PathTraversal(_))),
            "Path '{}' with traversal should be rejected",
            path.display()
        );
    }
}

/// BDD test: Sanitizing empty path should return empty
#[test]
fn bdd_sanitize_empty_path() {
    // GIVEN: An empty path
    let empty_path = Path::new("");

    // WHEN: The path is sanitized
    let result = sanitize_path(empty_path);

    // THEN: The sanitized path should be empty
    assert!(result.is_ok(), "Empty path should sanitize successfully");
    assert_eq!(
        result.unwrap(),
        Path::new(""),
        "Empty path should remain empty"
    );
}

/// BDD test: Sanitizing single-component paths should work
#[test]
fn bdd_sanitize_single_component_paths() {
    // GIVEN: Single-component paths
    let test_cases = vec![
        (Path::new("test-packet"), Path::new("test-packet")),
        (Path::new("test packet"), Path::new("test_packet")),
        (Path::new("test@packet"), Path::new("test_packet")),
    ];

    // WHEN: Each path is sanitized
    for (input, expected) in test_cases {
        let result = sanitize_path(input);

        // THEN: The sanitized path should match the expected value
        assert!(
            result.is_ok(),
            "Single-component path should sanitize successfully"
        );
        assert_eq!(
            result.unwrap(),
            expected,
            "Path '{}' should sanitize to '{}'",
            input.display(),
            expected.display()
        );
    }
}

/// BDD test: Sanitizing alphanumeric characters should preserve them
#[test]
fn bdd_sanitize_alphanumeric_characters() {
    // GIVEN: Path components with alphanumeric characters
    let test_cases = vec![
        ("abc123", "abc123"),
        ("ABC123", "ABC123"),
        ("aBc123XyZ", "aBc123XyZ"),
        ("123abc", "123abc"),
        ("a1b2c3", "a1b2c3"),
    ];

    // WHEN: Each component is sanitized
    for (input, expected) in test_cases {
        let result = sanitize_path_component(input);

        // THEN: Alphanumeric characters should be preserved
        assert!(
            result.is_ok(),
            "Alphanumeric component should sanitize successfully"
        );
        assert_eq!(
            result.unwrap(),
            expected,
            "Component '{}' should sanitize to '{}'",
            input,
            expected
        );
    }
}

/// BDD test: Sanitizing mixed safe and unsafe characters should work correctly
#[test]
fn bdd_sanitize_mixed_characters() {
    // GIVEN: Path components with mixed safe and unsafe characters
    let test_cases = vec![
        ("test-123@packet", "test-123_packet"),
        ("a_b.c#d", "a_b.c_d"),
        ("packet-1_2.3@4", "packet-1_2.3_4"),
    ];

    // WHEN: Each component is sanitized
    for (input, expected) in test_cases {
        let result = sanitize_path_component(input);

        // THEN: Safe characters should be preserved, unsafe replaced
        assert!(
            result.is_ok(),
            "Mixed component should sanitize successfully"
        );
        assert_eq!(
            result.unwrap(),
            expected,
            "Component '{}' should sanitize to '{}'",
            input,
            expected
        );
    }
}

/// BDD test: Sanitizing Unicode characters should replace with underscores
#[test]
fn bdd_sanitize_unicode_characters() {
    // GIVEN: Path components with Unicode characters
    let test_cases = vec![
        ("testé", "test_"),
        ("test日本語", "test___"),
        ("test🎉", "test_"),
        ("αβγ", "___"),
    ];

    // WHEN: Each component is sanitized
    for (input, expected) in test_cases {
        let result = sanitize_path_component(input);

        // THEN: Unicode characters should be replaced with underscores
        assert!(
            result.is_ok(),
            "Unicode component should sanitize successfully"
        );
        assert_eq!(
            result.unwrap(),
            expected,
            "Component '{}' should sanitize to '{}'",
            input,
            expected
        );
    }
}

/// BDD test: Sanitizing components with only dashes, underscores, or dots should preserve them
#[test]
fn bdd_sanitize_only_special_safe_characters() {
    // GIVEN: Path components with only safe special characters
    let test_cases = vec![
        ("---", "---"),
        ("___", "___"),
        ("-_.", "-_."),
        ("._-", "._-"),
    ];

    // WHEN: Each component is sanitized
    for (input, expected) in test_cases {
        let result = sanitize_path_component(input);

        // THEN: Safe special characters should be preserved
        assert!(
            result.is_ok(),
            "Component with only safe special characters should sanitize successfully"
        );
        assert_eq!(
            result.unwrap(),
            expected,
            "Component '{}' should sanitize to '{}'",
            input,
            expected
        );
    }
}
