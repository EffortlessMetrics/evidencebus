#![allow(clippy::unwrap_used)]
//! BDD-style tests for relative path validation functionality.
//!
//! These tests follow the Given-When-Then structure to clearly express
//! the expected behavior of relative path validation functions.

use evidencebus_path::{is_absolute_path, normalize_relative_path, PathError};
use std::path::Path;

/// BDD test: Normalizing simple relative paths should preserve structure
#[test]
fn bdd_normalize_simple_relative_paths() {
    // GIVEN: A simple relative path
    let simple_path = Path::new("a/b/c");

    // WHEN: The path is normalized
    let result = normalize_relative_path(simple_path);

    // THEN: The normalized path should match the original
    assert!(
        result.is_ok(),
        "Simple relative path should normalize successfully"
    );
    assert_eq!(
        result.unwrap(),
        Path::new("a/b/c"),
        "Simple relative path should be preserved"
    );
}

/// BDD test: Normalizing paths with current directory references should remove them
#[test]
fn bdd_normalize_paths_with_current_directory() {
    // GIVEN: Paths with current directory references
    let test_cases = vec![
        (Path::new("./a"), Path::new("a")),
        (Path::new("a/./b"), Path::new("a/b")),
        (Path::new("./a/./b/./c"), Path::new("a/b/c")),
        (Path::new("a/././b"), Path::new("a/b")),
    ];

    // WHEN: Each path is normalized
    for (input, expected) in test_cases {
        let result = normalize_relative_path(input);

        // THEN: The normalized path should have current directory references removed
        assert!(result.is_ok(), "Path with ./ should normalize successfully");
        assert_eq!(
            result.unwrap(),
            expected,
            "Path '{}' should normalize to '{}'",
            input.display(),
            expected.display()
        );
    }
}

/// BDD test: Normalizing paths with empty components should remove them
#[test]
fn bdd_normalize_paths_with_empty_components() {
    // GIVEN: Paths with empty components
    // Note: On Windows, leading "//" is parsed as a UNC path prefix (absolute),
    // so we only include paths that are relative on all platforms.
    let test_cases = vec![
        (Path::new("a//b"), Path::new("a/b")),
        (Path::new("a///b"), Path::new("a/b")),
    ];

    // WHEN: Each path is normalized
    for (input, expected) in test_cases {
        let result = normalize_relative_path(input);

        // THEN: The normalized path should have empty components removed
        assert!(
            result.is_ok(),
            "Path with empty components should normalize successfully"
        );
        assert_eq!(
            result.unwrap(),
            expected,
            "Path '{}' should normalize to '{}'",
            input.display(),
            expected.display()
        );
    }
}

/// BDD test: Normalizing paths with mixed current directory and empty components
#[test]
fn bdd_normalize_paths_with_mixed_components() {
    // GIVEN: Paths with mixed current directory and empty components
    let test_cases = vec![
        (Path::new("./a//./b"), Path::new("a/b")),
        (Path::new("a/./b//./c"), Path::new("a/b/c")),
    ];

    // WHEN: Each path is normalized
    for (input, expected) in test_cases {
        let result = normalize_relative_path(input);

        // THEN: The normalized path should have both removed
        assert!(
            result.is_ok(),
            "Path with mixed components should normalize successfully"
        );
        assert_eq!(
            result.unwrap(),
            expected,
            "Path '{}' should normalize to '{}'",
            input.display(),
            expected.display()
        );
    }
}

/// BDD test: Normalizing single-component paths should preserve them
#[test]
fn bdd_normalize_single_component_paths() {
    // GIVEN: Single-component paths
    let test_cases = vec![Path::new("single"), Path::new("a"), Path::new("test")];

    // WHEN: Each path is normalized
    for path in test_cases {
        let result = normalize_relative_path(path);

        // THEN: The normalized path should match the original
        assert!(
            result.is_ok(),
            "Single-component path should normalize successfully"
        );
        assert_eq!(
            result.unwrap(),
            path,
            "Single-component path '{}' should be preserved",
            path.display()
        );
    }
}

/// BDD test: Normalizing empty path should return empty
#[test]
fn bdd_normalize_empty_path() {
    // GIVEN: An empty path
    let empty_path = Path::new("");

    // WHEN: The path is normalized
    let result = normalize_relative_path(empty_path);

    // THEN: The normalized path should be empty
    assert!(result.is_ok(), "Empty path should normalize successfully");
    assert_eq!(
        result.unwrap(),
        Path::new(""),
        "Empty path should remain empty"
    );
}

/// BDD test: Normalizing only current directory should return empty
#[test]
fn bdd_normalize_only_current_directory() {
    // GIVEN: A path containing only "."
    let dot_path = Path::new(".");

    // WHEN: The path is normalized
    let result = normalize_relative_path(dot_path);

    // THEN: The normalized path should be empty
    assert!(
        result.is_ok(),
        "Path with only '.' should normalize successfully"
    );
    assert_eq!(
        result.unwrap(),
        Path::new(""),
        "Path with only '.' should normalize to empty"
    );
}

/// BDD test: Normalizing absolute paths should fail
#[test]
fn bdd_normalize_absolute_paths_fails() {
    // GIVEN: Various absolute paths (platform-specific)
    // On Windows, paths like "/absolute/path" are NOT absolute (no drive letter),
    // so we only test platform-appropriate absolute paths.
    #[cfg(unix)]
    let test_cases = vec![Path::new("/absolute/path"), Path::new("/")];
    #[cfg(windows)]
    let test_cases = vec![
        Path::new(r"C:\windows\path"),
        Path::new(r"C:/absolute/path"),
    ];

    // WHEN: Each path is normalized
    for path in test_cases {
        let result = normalize_relative_path(path);

        // THEN: The normalization should fail with AbsolutePath error
        assert!(
            matches!(result, Err(PathError::AbsolutePath(_))),
            "Absolute path '{}' should be rejected",
            path.display()
        );
    }
}

/// BDD test: Normalizing paths with traversal should fail
#[test]
fn bdd_normalize_paths_with_traversal_fails() {
    // GIVEN: Paths with traversal
    let test_cases = vec![
        Path::new("safe/../unsafe"),
        Path::new("../safe"),
        Path::new("a/../../b"),
        Path::new(".."),
    ];

    // WHEN: Each path is normalized
    for path in test_cases {
        let result = normalize_relative_path(path);

        // THEN: The normalization should fail with PathTraversal error
        assert!(
            matches!(result, Err(PathError::PathTraversal(_))),
            "Path with traversal '{}' should be rejected",
            path.display()
        );
    }
}

/// BDD test: Detecting absolute paths should work correctly
#[test]
fn bdd_detect_absolute_paths() {
    // GIVEN: Various absolute paths (platform-specific)
    // On Windows, "/absolute/path" is NOT absolute (no drive letter).
    #[cfg(unix)]
    let absolute_paths = vec![Path::new("/absolute/path"), Path::new("/")];
    #[cfg(windows)]
    let absolute_paths = vec![Path::new(r"C:\windows\path"), Path::new(r"\\network\share")];

    // WHEN: Each path is checked for being absolute
    for path in absolute_paths {
        let is_absolute = is_absolute_path(path);

        // THEN: All should be detected as absolute
        assert!(
            is_absolute,
            "Path '{}' should be detected as absolute",
            path.display()
        );
    }
}

/// BDD test: Detecting relative paths should work correctly
#[test]
fn bdd_detect_relative_paths() {
    // GIVEN: Various relative paths
    let relative_paths = vec![
        Path::new("relative/path"),
        Path::new("./relative"),
        Path::new("single"),
        Path::new("."),
        Path::new("../relative"), // Even with traversal, it's still relative
    ];

    // WHEN: Each path is checked for being absolute
    for path in relative_paths {
        let is_absolute = is_absolute_path(path);

        // THEN: None should be detected as absolute
        assert!(
            !is_absolute,
            "Path '{}' should not be detected as absolute",
            path.display()
        );
    }
}

/// BDD test: Normalizing deeply nested paths should preserve structure
#[test]
fn bdd_normalize_deeply_nested_paths() {
    // GIVEN: A deeply nested path
    let deep_path = Path::new("a/b/c/d/e/f/g/h/i/j");

    // WHEN: The path is normalized
    let result = normalize_relative_path(deep_path);

    // THEN: The normalized path should match the original
    assert!(
        result.is_ok(),
        "Deeply nested path should normalize successfully"
    );
    assert_eq!(
        result.unwrap(),
        deep_path,
        "Deeply nested path should be preserved"
    );
}

/// BDD test: Normalizing paths with safe characters should preserve them
#[test]
fn bdd_normalize_paths_with_safe_characters() {
    // GIVEN: Paths with various safe characters
    let test_cases = vec![
        (Path::new("packet-123"), Path::new("packet-123")),
        (Path::new("packet_456"), Path::new("packet_456")),
        (Path::new("packet.789"), Path::new("packet.789")),
        (Path::new("a/b-c_d.e"), Path::new("a/b-c_d.e")),
    ];

    // WHEN: Each path is normalized
    for (input, expected) in test_cases {
        let result = normalize_relative_path(input);

        // THEN: The normalized path should preserve safe characters
        assert!(
            result.is_ok(),
            "Path with safe characters should normalize successfully"
        );
        assert_eq!(
            result.unwrap(),
            expected,
            "Path '{}' should normalize to '{}'",
            input.display(),
            expected.display()
        );
    }
}
