#![allow(clippy::unwrap_used, clippy::expect_used)]
//! BDD-style tests for edge cases and cross-platform path handling.
//!
//! These tests follow the Given-When-Then structure to clearly express
//! the expected behavior of path functions in various edge cases.

use evidencebus_path::{
    normalize_relative_path, sanitize_path_component, to_forward_slash, validate_path, PathError,
};
use std::path::Path;

/// BDD test: Converting Unix-style paths to forward slashes should preserve them
#[test]
fn bdd_to_forward_slash_unix_paths() {
    // GIVEN: Unix-style paths
    let test_cases = vec![
        (Path::new("a/b/c"), "a/b/c"),
        (Path::new("single"), "single"),
        (Path::new("a/b"), "a/b"),
    ];

    // WHEN: Each path is converted to forward slashes
    for (path, expected) in test_cases {
        let result = to_forward_slash(path);

        // THEN: The result should match the expected forward slash representation
        assert_eq!(
            result,
            expected,
            "Path '{}' should convert to '{}'",
            path.display(),
            expected
        );
    }
}

/// BDD test: Converting Windows-style paths to forward slashes should normalize them
#[test]
#[cfg(windows)]
fn bdd_to_forward_slash_windows_paths() {
    // GIVEN: Windows-style paths
    let test_cases = vec![
        (Path::new(r"a\b\c"), "a/b/c"),
        (Path::new(r"a\b"), "a/b"),
        (Path::new(r"single"), "single"),
    ];

    // WHEN: Each path is converted to forward slashes
    for (path, expected) in test_cases {
        let result = to_forward_slash(path);

        // THEN: The result should use forward slashes
        assert_eq!(
            result,
            expected,
            "Windows path '{}' should convert to '{}'",
            path.display(),
            expected
        );
    }
}

/// BDD test: Converting mixed separator paths to forward slashes should normalize them
#[test]
#[cfg(windows)]
fn bdd_to_forward_slash_mixed_separators() {
    // GIVEN: Paths with mixed separators
    let test_cases = vec![
        (Path::new(r"a/b\c"), "a/b/c"),
        (Path::new(r"a\b/c"), "a/b/c"),
        (Path::new(r"a/b\c/d"), "a/b/c/d"),
    ];

    // WHEN: Each path is converted to forward slashes
    for (path, expected) in test_cases {
        let result = to_forward_slash(path);

        // THEN: The result should use only forward slashes
        assert_eq!(
            result,
            expected,
            "Mixed separator path '{}' should convert to '{}'",
            path.display(),
            expected
        );
    }
}

/// BDD test: Validating Windows drive letters should reject them as absolute
#[test]
#[cfg(windows)]
fn bdd_validate_windows_drive_letters() {
    // GIVEN: Paths with Windows drive letters
    let test_cases = vec![
        Path::new(r"C:\path"),
        Path::new(r"D:\path"),
        Path::new(r"C:/path"),
        Path::new(r"D:/path"),
    ];

    // WHEN: Each path is validated
    for path in test_cases {
        let result = validate_path(path);

        // THEN: The validation should fail with AbsolutePath error
        assert!(
            matches!(result, Err(PathError::AbsolutePath(_))),
            "Windows drive path '{}' should be rejected as absolute",
            path.display()
        );
    }
}

/// BDD test: Validating UNC paths should reject them as absolute
#[test]
#[cfg(windows)]
fn bdd_validate_unc_paths() {
    // GIVEN: UNC paths (network paths)
    let test_cases = vec![
        Path::new(r"\\server\share"),
        Path::new(r"\\server\share\path"),
    ];

    // WHEN: Each path is validated
    for path in test_cases {
        let result = validate_path(path);

        // THEN: The validation should fail with AbsolutePath error
        assert!(
            matches!(result, Err(PathError::AbsolutePath(_))),
            "UNC path '{}' should be rejected as absolute",
            path.display()
        );
    }
}

/// BDD test: Validating root paths should reject them as absolute
#[test]
fn bdd_validate_root_paths() {
    // GIVEN: Root paths
    let test_cases = vec![
        #[cfg(unix)]
        Path::new("/"),
        #[cfg(windows)]
        Path::new(r"C:\"),
    ];

    // WHEN: Each path is validated
    for path in test_cases {
        let result = validate_path(path);

        // THEN: The validation should fail with AbsolutePath error
        assert!(
            matches!(result, Err(PathError::AbsolutePath(_))),
            "Root path '{}' should be rejected as absolute",
            path.display()
        );
    }
}

/// BDD test: Normalizing paths with trailing slashes should work correctly
#[test]
fn bdd_normalize_paths_with_trailing_slashes() {
    // GIVEN: Paths with trailing slashes
    let test_cases = vec![
        (Path::new("a/b/"), Path::new("a/b")),
        (Path::new("a/b//"), Path::new("a/b")),
        (Path::new("a///"), Path::new("a")),
    ];

    // WHEN: Each path is normalized
    for (input, expected) in test_cases {
        let result = normalize_relative_path(input);

        // THEN: Trailing slashes should be removed
        assert!(
            result.is_ok(),
            "Path with trailing slash should normalize successfully"
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

/// BDD test: Normalizing paths with leading slashes should reject as absolute
#[test]
fn bdd_normalize_paths_with_leading_slashes() {
    // GIVEN: Paths with leading slashes
    let test_cases = vec![
        #[cfg(unix)]
        Path::new("/a/b"),
        #[cfg(unix)]
        Path::new("//a/b"),
        #[cfg(windows)]
        Path::new(r"C:\a\b"),
    ];

    // WHEN: Each path is normalized
    for path in test_cases {
        let result = normalize_relative_path(path);

        // THEN: The normalization should fail with AbsolutePath error
        assert!(
            matches!(result, Err(PathError::AbsolutePath(_))),
            "Path with leading slash '{}' should be rejected as absolute",
            path.display()
        );
    }
}

/// BDD test: Sanitizing components with consecutive dots should be rejected as traversal
#[test]
fn bdd_sanitize_only_dots() {
    // GIVEN: Path components with multiple consecutive dots (contain "..")
    let test_cases = vec!["...", "...."];

    // WHEN: Each component is sanitized
    for input in test_cases {
        let result = sanitize_path_component(input);

        // THEN: Components containing ".." should be rejected as traversal
        assert!(
            matches!(result, Err(PathError::PathTraversal(_))),
            "Component '{}' containing '..' should be rejected as traversal",
            input
        );
    }
}

/// BDD test: Sanitizing single dot component should preserve it
#[test]
fn bdd_sanitize_single_dot() {
    // GIVEN: A single dot component
    let single_dot = ".";

    // WHEN: The component is sanitized
    let result = sanitize_path_component(single_dot);

    // THEN: The single dot should be preserved
    assert!(
        result.is_ok(),
        "Single dot component should sanitize successfully"
    );
    assert_eq!(
        result.unwrap(),
        ".",
        "Single dot component should be preserved"
    );
}

/// BDD test: Sanitizing components with mixed dots and other safe characters
#[test]
fn bdd_sanitize_mixed_dots() {
    // GIVEN: Path components with dots — those containing ".." are rejected as traversal
    let ok_cases = vec![(".test.", ".test."), ("test.test", "test.test")];
    let traversal_cases = vec!["test..test", "...test", "test..."];

    // WHEN: Each ok-component is sanitized
    for (input, expected) in ok_cases {
        let result = sanitize_path_component(input);

        // THEN: Single dots should be preserved
        assert!(
            result.is_ok(),
            "Component '{}' should sanitize successfully",
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

    // WHEN: Each traversal-component is sanitized
    for input in traversal_cases {
        let result = sanitize_path_component(input);

        // THEN: Components containing ".." should be rejected as traversal
        assert!(
            matches!(result, Err(PathError::PathTraversal(_))),
            "Component '{}' containing '..' should be rejected as traversal",
            input
        );
    }
}

/// BDD test: Validating paths with very long names should work correctly
#[test]
fn bdd_validate_very_long_path_names() {
    // GIVEN: A path with a very long component name
    let long_name = "a".repeat(255);
    let long_path = Path::new(&long_name);

    // WHEN: The path is validated
    let result = validate_path(long_path);

    // THEN: The validation should succeed
    assert!(
        result.is_ok(),
        "Path with very long component name should validate successfully"
    );
}

/// BDD test: Sanitizing components with very long names should work correctly
#[test]
fn bdd_sanitize_very_long_component_names() {
    // GIVEN: A component with a very long name
    let long_name = "a".repeat(255);

    // WHEN: The component is sanitized
    let result = sanitize_path_component(&long_name);

    // THEN: The sanitization should succeed
    assert!(
        result.is_ok(),
        "Component with very long name should sanitize successfully"
    );
    assert_eq!(
        result.unwrap(),
        long_name,
        "Long component should be preserved"
    );
}

/// BDD test: Validating paths with multiple consecutive dots should work correctly
#[test]
fn bdd_validate_multiple_consecutive_dots() {
    // GIVEN: Paths with multiple consecutive dots
    let test_cases = vec![
        Path::new(".../test"),
        Path::new("test/..."),
        Path::new("a/.../b"),
    ];

    // WHEN: Each path is validated
    for path in test_cases {
        let result = validate_path(path);

        // THEN: The validation should succeed (multiple dots are safe)
        assert!(
            result.is_ok(),
            "Path with multiple consecutive dots '{}' should validate successfully",
            path.display()
        );
    }
}

/// BDD test: Validating paths with mixed case should work correctly
#[test]
fn bdd_validate_mixed_case_paths() {
    // GIVEN: Paths with mixed case
    let test_cases = vec![
        Path::new("Mixed/Case/Path"),
        Path::new("UPPERCASE"),
        Path::new("lowercase"),
        Path::new("CamelCase/Path"),
    ];

    // WHEN: Each path is validated
    for path in test_cases {
        let result = validate_path(path);

        // THEN: The validation should succeed
        assert!(
            result.is_ok(),
            "Path with mixed case '{}' should validate successfully",
            path.display()
        );
    }
}

/// BDD test: Sanitizing components with mixed case should preserve case
#[test]
fn bdd_sanitize_mixed_case_components() {
    // GIVEN: Components with mixed case
    let test_cases = vec![
        ("MixedCase", "MixedCase"),
        ("UPPERCASE", "UPPERCASE"),
        ("lowercase", "lowercase"),
        ("CamelCase", "CamelCase"),
    ];

    // WHEN: Each component is sanitized
    for (input, expected) in test_cases {
        let result = sanitize_path_component(input);

        // THEN: Case should be preserved
        assert!(
            result.is_ok(),
            "Component with mixed case should sanitize successfully"
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

/// BDD test: Validating paths with numeric components should work correctly
#[test]
fn bdd_validate_numeric_components() {
    // GIVEN: Paths with numeric components
    let test_cases = vec![
        Path::new("123/456"),
        Path::new("0"),
        Path::new("1.2.3"),
        Path::new("packet-123"),
    ];

    // WHEN: Each path is validated
    for path in test_cases {
        let result = validate_path(path);

        // THEN: The validation should succeed
        assert!(
            result.is_ok(),
            "Path with numeric components '{}' should validate successfully",
            path.display()
        );
    }
}

/// BDD test: Normalizing paths with only current directory should return empty
#[test]
fn bdd_normalize_only_current_directory_variants() {
    // GIVEN: Paths with only current directory references
    let test_cases = vec![Path::new("."), Path::new("./."), Path::new("././.")];

    // WHEN: Each path is normalized
    for path in test_cases {
        let result = normalize_relative_path(path);

        // THEN: The normalized path should be empty
        assert!(
            result.is_ok(),
            "Path with only ./ should normalize successfully"
        );
        assert_eq!(
            result.unwrap(),
            Path::new(""),
            "Path '{}' should normalize to empty",
            path.display()
        );
    }
}

/// BDD test: Validating paths with Unicode characters should work correctly
#[test]
fn bdd_validate_unicode_paths() {
    // GIVEN: Paths with Unicode characters
    let test_cases = vec![
        Path::new("test/日本語"),
        Path::new("test/émojis🎉"),
        Path::new("αβγ/δεζ"),
    ];

    // WHEN: Each path is validated
    for path in test_cases {
        let result = validate_path(path);

        // THEN: The validation should succeed
        assert!(
            result.is_ok(),
            "Path with Unicode characters '{}' should validate successfully",
            path.display()
        );
    }
}

/// BDD test: Converting empty path to forward slashes should return empty string
#[test]
fn bdd_to_forward_slash_empty_path() {
    // GIVEN: An empty path
    let empty_path = Path::new("");

    // WHEN: The path is converted to forward slashes
    let result = to_forward_slash(empty_path);

    // THEN: The result should be an empty string
    assert_eq!(result, "", "Empty path should convert to empty string");
}

/// BDD test: Converting single component path to forward slashes should return component
#[test]
fn bdd_to_forward_slash_single_component() {
    // GIVEN: A single component path
    let single_path = Path::new("single");

    // WHEN: The path is converted to forward slashes
    let result = to_forward_slash(single_path);

    // THEN: The result should be the component name
    assert_eq!(
        result, "single",
        "Single component path should convert to component name"
    );
}

/// BDD test: Validating paths with backslashes on Unix should treat them as literal characters
#[test]
#[cfg(not(windows))]
fn bdd_validate_backslashes_on_unix() {
    // GIVEN: Paths with backslashes on Unix (treated as literal characters)
    let test_cases = vec![Path::new(r"a\b\c"), Path::new(r"test\file")];

    // WHEN: Each path is validated
    for path in test_cases {
        let result = validate_path(path);

        // THEN: The validation should succeed (backslash is a valid character on Unix)
        assert!(
            result.is_ok(),
            "Path with backslash on Unix '{}' should validate successfully",
            path.display()
        );
    }
}
