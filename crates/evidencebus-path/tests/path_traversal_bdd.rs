//! BDD-style tests for path traversal detection functionality.
//!
//! These tests follow the Given-When-Then structure to clearly express
//! the expected behavior of path traversal detection functions.

use evidencebus_path::{contains_traversal, validate_path, PathError};
use std::path::Path;

/// BDD test: Detecting parent directory traversal at the start
#[test]
fn bdd_detect_parent_traversal_at_start() {
    // GIVEN: A path starting with parent directory reference
    let traversal_path = Path::new("../safe/path");

    // WHEN: The path is validated
    let result = validate_path(traversal_path);

    // THEN: The validation should fail with PathTraversal error
    assert!(
        matches!(result, Err(PathError::PathTraversal(_))),
        "Path starting with ../ should be rejected as traversal"
    );
}

/// BDD test: Detecting parent directory traversal in the middle
#[test]
fn bdd_detect_parent_traversal_in_middle() {
    // GIVEN: A path with parent directory reference in the middle
    let traversal_path = Path::new("safe/../unsafe");

    // WHEN: The path is validated
    let result = validate_path(traversal_path);

    // THEN: The validation should fail with PathTraversal error
    assert!(
        matches!(result, Err(PathError::PathTraversal(_))),
        "Path with ../ in the middle should be rejected as traversal"
    );
}

/// BDD test: Detecting parent directory traversal at the end
#[test]
fn bdd_detect_parent_traversal_at_end() {
    // GIVEN: A path ending with parent directory reference
    let traversal_path = Path::new("safe/path/..");

    // WHEN: The path is validated
    let result = validate_path(traversal_path);

    // THEN: The validation should fail with PathTraversal error
    assert!(
        matches!(result, Err(PathError::PathTraversal(_))),
        "Path ending with .. should be rejected as traversal"
    );
}

/// BDD test: Detecting multiple parent directory traversals
#[test]
fn bdd_detect_multiple_parent_traversals() {
    // GIVEN: A path with multiple parent directory references
    let traversal_path = Path::new("a/../../b");

    // WHEN: The path is validated
    let result = validate_path(traversal_path);

    // THEN: The validation should fail with PathTraversal error
    assert!(
        matches!(result, Err(PathError::PathTraversal(_))),
        "Path with multiple ../ should be rejected as traversal"
    );
}

/// BDD test: Detecting consecutive parent directory traversals
#[test]
fn bdd_detect_consecutive_parent_traversals() {
    // GIVEN: A path with consecutive parent directory references
    let traversal_path = Path::new("safe/../../../unsafe");

    // WHEN: The path is validated
    let result = validate_path(traversal_path);

    // THEN: The validation should fail with PathTraversal error
    assert!(
        matches!(result, Err(PathError::PathTraversal(_))),
        "Path with consecutive ../ should be rejected as traversal"
    );
}

/// BDD test: Detecting parent directory traversal in deeply nested paths
#[test]
fn bdd_detect_parent_traversal_in_deeply_nested() {
    // GIVEN: A deeply nested path with parent directory reference
    let traversal_path = Path::new("a/b/c/d/e/../f");

    // WHEN: The path is validated
    let result = validate_path(traversal_path);

    // THEN: The validation should fail with PathTraversal error
    assert!(
        matches!(result, Err(PathError::PathTraversal(_))),
        "Deeply nested path with ../ should be rejected as traversal"
    );
}

/// BDD test: Detecting only parent directory traversal
#[test]
fn bdd_detect_only_parent_traversal() {
    // GIVEN: A path containing only parent directory reference
    let traversal_path = Path::new("..");

    // WHEN: The path is validated
    let result = validate_path(traversal_path);

    // THEN: The validation should fail with PathTraversal error
    assert!(
        matches!(result, Err(PathError::PathTraversal(_))),
        "Path with only .. should be rejected as traversal"
    );
}

/// BDD test: Using contains_traversal function with traversal paths
#[test]
fn bdd_contains_traversal_function_with_traversal() {
    // GIVEN: Various paths with traversal
    let test_cases = vec![
        Path::new("../safe"),
        Path::new("safe/../unsafe"),
        Path::new("a/../../b"),
        Path::new(".."),
        Path::new("a/b/../c/../d"),
    ];

    // WHEN: Each path is checked for traversal
    for path in test_cases {
        let has_traversal = contains_traversal(path);

        // THEN: All should be detected as containing traversal
        assert!(
            has_traversal,
            "Path '{}' should be detected as containing traversal",
            path.display()
        );
    }
}

/// BDD test: Using contains_traversal function with safe paths
#[test]
fn bdd_contains_traversal_function_with_safe_paths() {
    // GIVEN: Various safe paths without traversal
    let test_cases = vec![
        Path::new("safe/relative/path"),
        Path::new("single"),
        Path::new("./relative"),
        Path::new("a/b/c"),
        Path::new("."),
    ];

    // WHEN: Each path is checked for traversal
    for path in test_cases {
        let has_traversal = contains_traversal(path);

        // THEN: None should be detected as containing traversal
        assert!(
            !has_traversal,
            "Path '{}' should not be detected as containing traversal",
            path.display()
        );
    }
}

/// BDD test: Error message should include the problematic path
#[test]
fn bdd_traversal_error_includes_path() {
    // GIVEN: A path with traversal
    let traversal_path = Path::new("safe/../unsafe");

    // WHEN: The path is validated
    let result = validate_path(traversal_path);

    // THEN: The error message should include the path
    if let Err(PathError::PathTraversal(path_str)) = result {
        assert!(
            path_str.contains("safe/../unsafe") || path_str.contains("safe"),
            "Error message should include the problematic path"
        );
    } else {
        panic!("Expected PathError::PathTraversal");
    }
}

/// BDD test: Windows-style backslash traversal should be detected
#[test]
#[cfg(windows)]
fn bdd_detect_windows_style_traversal() {
    // GIVEN: A Windows-style path with parent directory reference
    let traversal_path = Path::new(r"safe\..\unsafe");

    // WHEN: The path is validated
    let result = validate_path(traversal_path);

    // THEN: The validation should fail with PathTraversal error
    assert!(
        matches!(result, Err(PathError::PathTraversal(_))),
        "Windows-style path with .. should be rejected as traversal"
    );
}

/// BDD test: Mixed separator traversal should be detected on Windows
///
/// On Unix, backslash is a valid filename character, not a path separator,
/// so `Path::new("safe/..\\unsafe")` treats `..\\unsafe` as a single component
/// and does not detect `..` as traversal. On Windows, backslash is a separator,
/// so `..` is correctly recognized as a parent-directory component.
#[test]
#[cfg(windows)]
fn bdd_detect_mixed_separator_traversal() {
    // GIVEN: A path with mixed separators and traversal
    let traversal_path = Path::new("safe/..\\unsafe");

    // WHEN: The path is validated
    let result = validate_path(traversal_path);

    // THEN: The validation should fail with PathTraversal error
    assert!(
        matches!(result, Err(PathError::PathTraversal(_))),
        "Path with mixed separators and .. should be rejected as traversal"
    );
}
