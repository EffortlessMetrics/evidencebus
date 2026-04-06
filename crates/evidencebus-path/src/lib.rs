//! Path validation and sanitization for evidencebus.
//!
//! This crate provides functions for validating and sanitizing paths
//! to prevent path traversal attacks and ensure safe path handling.
//! It focuses purely on path operations without any I/O.

use std::path::{Path, PathBuf};
use thiserror::Error;

/// Error type for path validation.
#[derive(Debug, Error, PartialEq, Clone)]
pub enum PathError {
    #[error("path traversal detected: {0}")]
    PathTraversal(String),
    #[error("absolute path not allowed: {0}")]
    AbsolutePath(String),
    #[error("invalid path component: {0}")]
    InvalidPathComponent(String),
    #[error("path would escape bundle directory: {0}")]
    OutsideBundle(String),
}

/// Checks if a path contains traversal components (..).
///
/// # Examples
///
/// ```
/// use evidencebus_path::contains_traversal;
///
/// assert!(contains_traversal("../safe"));
/// assert!(contains_traversal("safe/../unsafe"));
/// assert!(!contains_traversal("safe/relative/path"));
/// ```
pub fn contains_traversal(path: &Path) -> bool {
    for component in path.components() {
        let comp = component.as_os_str().to_string_lossy();
        if comp == ".." {
            return true;
        }
    }
    false
}

/// Checks if a path contains null bytes.
///
/// # Examples
///
/// ```
/// use evidencebus_path::contains_null_byte;
///
/// assert!(contains_null_byte("safe\0path"));
/// assert!(!contains_null_byte("safe/path"));
/// ```
pub fn contains_null_byte(path: &str) -> bool {
    path.contains('\0')
}

/// Checks if a path is absolute.
///
/// # Examples
///
/// ```
/// use evidencebus_path::is_absolute_path;
/// use std::path::Path;
///
/// assert!(is_absolute_path(Path::new("/absolute/path")));
/// assert!(!is_absolute_path(Path::new("relative/path")));
/// ```
pub fn is_absolute_path(path: &Path) -> bool {
    path.is_absolute()
}

/// Validates that a path is safe (no traversal, no absolute paths, no null bytes).
///
/// # Errors
///
/// Returns `PathError` if the path is unsafe.
///
/// # Examples
///
/// ```
/// use evidencebus_path::validate_path;
/// use std::path::Path;
///
/// assert!(validate_path(Path::new("safe/relative/path")).is_ok());
/// assert!(validate_path(Path::new("/absolute/path")).is_err());
/// assert!(validate_path(Path::new("safe/../unsafe")).is_err());
/// ```
pub fn validate_path(path: &Path) -> Result<(), PathError> {
    // Reject absolute paths
    if is_absolute_path(path) {
        return Err(PathError::AbsolutePath(path.display().to_string()));
    }

    // Check for path traversal components
    if contains_traversal(path) {
        return Err(PathError::PathTraversal(path.display().to_string()));
    }

    // Check for null bytes
    let path_str = path.to_string_lossy();
    if contains_null_byte(&path_str) {
        return Err(PathError::InvalidPathComponent(
            "null byte detected".to_string(),
        ));
    }

    Ok(())
}

/// Normalizes a relative path by removing '.' components and empty components.
/// Does not resolve '..' - use `validate_path` first to ensure safety.
///
/// # Errors
///
/// Returns `PathError` if the path is absolute or contains traversal.
///
/// # Examples
///
/// ```
/// use evidencebus_path::normalize_relative_path;
/// use std::path::Path;
///
/// assert_eq!(
///     normalize_relative_path(Path::new("a/b/c")).unwrap(),
///     PathBuf::from("a/b/c")
/// );
/// assert_eq!(
///     normalize_relative_path(Path::new("a/./b")).unwrap(),
///     PathBuf::from("a/b")
/// );
/// assert_eq!(
///     normalize_relative_path(Path::new("./a")).unwrap(),
///     PathBuf::from("a")
/// );
/// ```
pub fn normalize_relative_path(path: &Path) -> Result<PathBuf, PathError> {
    // Reject absolute paths
    if is_absolute_path(path) {
        return Err(PathError::AbsolutePath(path.display().to_string()));
    }

    // Check for path traversal
    if contains_traversal(path) {
        return Err(PathError::PathTraversal(path.display().to_string()));
    }

    // Normalize the path
    let mut result = PathBuf::new();
    for component in path.components() {
        let comp = component.as_os_str().to_string_lossy();
        if comp != "." && !comp.is_empty() {
            result.push(&*comp);
        }
    }

    Ok(result)
}

/// Sanitizes a path component by removing dangerous characters and replacing them with underscores.
///
/// # Errors
///
/// Returns `PathError` if the component contains '..' or null bytes, or if the result is empty.
///
/// # Examples
///
/// ```
/// use evidencebus_path::sanitize_path_component;
///
/// assert_eq!(sanitize_path_component("test-packet").unwrap(), "test-packet");
/// assert_eq!(sanitize_path_component("test.packet").unwrap(), "test.packet");
/// assert_eq!(sanitize_path_component("test packet").unwrap(), "test_packet");
/// assert_eq!(sanitize_path_component("test@packet").unwrap(), "test_packet");
/// assert!(sanitize_path_component("..").is_err());
/// assert!(sanitize_path_component("test\0packet").is_err());
/// ```
pub fn sanitize_path_component(component: &str) -> Result<String, PathError> {
    // Check for traversal
    if component.contains("..") {
        return Err(PathError::PathTraversal(component.to_string()));
    }

    // Check for null bytes
    if contains_null_byte(component) {
        return Err(PathError::InvalidPathComponent(
            "null byte detected".to_string(),
        ));
    }

    // Sanitize the component by replacing unsafe characters
    let mut output = String::with_capacity(component.len());
    for ch in component.chars() {
        if ch.is_ascii_alphanumeric() || matches!(ch, '-' | '_' | '.') {
            output.push(ch);
        } else {
            output.push('_');
        }
    }

    if output.is_empty() {
        return Err(PathError::InvalidPathComponent(
            "component is empty after sanitization".to_string(),
        ));
    }

    Ok(output)
}

/// Sanitizes a full path by sanitizing each component individually.
///
/// # Errors
///
/// Returns `PathError` if any component contains '..' or null bytes, or if the result is empty.
///
/// # Examples
///
/// ```
/// use evidencebus_path::sanitize_path;
/// use std::path::Path;
///
/// assert_eq!(
///     sanitize_path(Path::new("safe/path")).unwrap(),
///     PathBuf::from("safe/path")
/// );
/// assert_eq!(
///     sanitize_path(Path::new("unsafe@path/with spaces")).unwrap(),
///     PathBuf::from("unsafe_path/with_spaces")
/// );
/// ```
pub fn sanitize_path(path: &Path) -> Result<PathBuf, PathError> {
    let mut result = PathBuf::new();

    for component in path.components() {
        let comp = component.as_os_str().to_string_lossy();
        if comp == ".." {
            return Err(PathError::PathTraversal(path.display().to_string()));
        }

        // Skip '.' and empty components
        if comp == "." || comp.is_empty() {
            continue;
        }

        let sanitized = sanitize_path_component(&comp)?;
        result.push(&sanitized);
    }

    Ok(result)
}

/// Converts a path to use forward slashes (canonical representation).
///
/// # Examples
///
/// ```
/// use evidencebus_path::to_forward_slash;
/// use std::path::PathBuf;
///
/// let path = PathBuf::from("a/b/c");
/// assert_eq!(to_forward_slash(&path), "a/b/c");
///
/// #[cfg(windows)]
/// {
///     let windows_path = PathBuf::from(r"a\b\c");
///     assert_eq!(to_forward_slash(&windows_path), "a/b/c");
/// }
/// ```
pub fn to_forward_slash(path: &Path) -> String {
    path.iter()
        .map(|component| component.to_string_lossy().to_string())
        .collect::<Vec<_>>()
        .join("/")
}

/// Joins two paths safely, ensuring the result is relative and doesn't escape.
///
/// # Errors
///
/// Returns `PathError` if the result would contain traversal or be absolute.
///
/// # Examples
///
/// ```
/// use evidencebus_path::join_paths;
/// use std::path::Path;
///
/// assert_eq!(
///     join_paths(Path::new("base"), Path::new("sub")).unwrap(),
///     PathBuf::from("base/sub")
/// );
/// assert!(join_paths(Path::new("base"), Path::new("..")).is_err());
/// ```
pub fn join_paths(base: &Path, relative: &Path) -> Result<PathBuf, PathError> {
    let result = base.join(relative);
    validate_path(&result)?;
    normalize_relative_path(&result)
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn test_contains_traversal() {
        assert!(contains_traversal(Path::new("../safe")));
        assert!(contains_traversal(Path::new("safe/../unsafe")));
        assert!(contains_traversal(Path::new("a/../../b")));
        assert!(!contains_traversal(Path::new("safe/relative/path")));
        assert!(!contains_traversal(Path::new("single")));
    }

    #[test]
    fn test_contains_null_byte() {
        assert!(contains_null_byte("safe\0path"));
        assert!(contains_null_byte("\0"));
        assert!(!contains_null_byte("safe/path"));
        assert!(!contains_null_byte(""));
    }

    #[test]
    fn test_is_absolute_path() {
        #[cfg(unix)]
        {
            assert!(is_absolute_path(Path::new("/absolute/path")));
        }
        #[cfg(windows)]
        {
            assert!(is_absolute_path(Path::new("C:\\windows\\path")));
            assert!(is_absolute_path(Path::new(r"C:/windows/path")));
        }
        assert!(!is_absolute_path(Path::new("relative/path")));
        assert!(!is_absolute_path(Path::new("./relative")));
    }

    #[test]
    fn test_validate_path() {
        // Valid paths
        assert!(validate_path(Path::new("safe/relative/path")).is_ok());
        assert!(validate_path(Path::new("single")).is_ok());
        assert!(validate_path(Path::new("./relative")).is_ok());

        // Invalid paths - traversal
        assert!(matches!(
            validate_path(Path::new("safe/../unsafe")),
            Err(PathError::PathTraversal(_))
        ));
        assert!(matches!(
            validate_path(Path::new("safe\0path")),
            Err(PathError::InvalidPathComponent(_))
        ));

        // Invalid paths - absolute (platform-specific)
        #[cfg(unix)]
        {
            assert!(matches!(
                validate_path(Path::new("/absolute/path")),
                Err(PathError::AbsolutePath(_))
            ));
        }
        #[cfg(windows)]
        {
            assert!(matches!(
                validate_path(Path::new("C:\\windows\\path")),
                Err(PathError::AbsolutePath(_))
            ));
        }
    }

    #[test]
    fn test_normalize_relative_path() {
        assert_eq!(
            normalize_relative_path(Path::new("a/b/c")).unwrap(),
            PathBuf::from("a/b/c")
        );
        assert_eq!(
            normalize_relative_path(Path::new("a/./b")).unwrap(),
            PathBuf::from("a/b")
        );
        assert_eq!(
            normalize_relative_path(Path::new("./a")).unwrap(),
            PathBuf::from("a")
        );
        assert_eq!(
            normalize_relative_path(Path::new("a//b")).unwrap(),
            PathBuf::from("a/b")
        );

        // Invalid paths - traversal
        assert!(matches!(
            normalize_relative_path(Path::new("safe/../unsafe")),
            Err(PathError::PathTraversal(_))
        ));

        // Invalid paths - absolute (platform-specific)
        #[cfg(unix)]
        {
            assert!(matches!(
                normalize_relative_path(Path::new("/absolute")),
                Err(PathError::AbsolutePath(_))
            ));
        }
        #[cfg(windows)]
        {
            assert!(matches!(
                normalize_relative_path(Path::new("C:\\absolute")),
                Err(PathError::AbsolutePath(_))
            ));
        }
    }

    #[test]
    fn test_sanitize_path_component() {
        assert_eq!(
            sanitize_path_component("test-packet").unwrap(),
            "test-packet"
        );
        assert_eq!(
            sanitize_path_component("test.packet").unwrap(),
            "test.packet"
        );
        assert_eq!(
            sanitize_path_component("test packet").unwrap(),
            "test_packet"
        );
        assert_eq!(
            sanitize_path_component("test@packet").unwrap(),
            "test_packet"
        );
        assert_eq!(
            sanitize_path_component("test#packet").unwrap(),
            "test_packet"
        );
        assert_eq!(
            sanitize_path_component("test_packet").unwrap(),
            "test_packet"
        );
        assert_eq!(sanitize_path_component("!!!").unwrap(), "___");

        // Invalid components
        assert!(matches!(
            sanitize_path_component(".."),
            Err(PathError::PathTraversal(_))
        ));
        assert!(matches!(
            sanitize_path_component("test\0packet"),
            Err(PathError::InvalidPathComponent(_))
        ));
    }

    #[test]
    fn test_sanitize_path() {
        assert_eq!(
            sanitize_path(Path::new("safe/path")).unwrap(),
            PathBuf::from("safe/path")
        );
        assert_eq!(
            sanitize_path(Path::new("unsafe@path/with spaces")).unwrap(),
            PathBuf::from("unsafe_path/with_spaces")
        );
        assert_eq!(
            sanitize_path(Path::new("./a/b")).unwrap(),
            PathBuf::from("a/b")
        );

        // Invalid paths
        assert!(matches!(
            sanitize_path(Path::new("a/../b")),
            Err(PathError::PathTraversal(_))
        ));
    }

    #[test]
    fn test_to_forward_slash() {
        let path = PathBuf::from("a/b/c");
        assert_eq!(to_forward_slash(&path), "a/b/c");

        #[cfg(windows)]
        {
            let windows_path = PathBuf::from(r"a\b\c");
            assert_eq!(to_forward_slash(&windows_path), "a/b/c");
        }
    }

    #[test]
    fn test_join_paths() {
        assert_eq!(
            join_paths(Path::new("base"), Path::new("sub")).unwrap(),
            PathBuf::from("base/sub")
        );
        assert_eq!(
            join_paths(Path::new("base/"), Path::new("sub")).unwrap(),
            PathBuf::from("base/sub")
        );

        // Invalid joins
        assert!(matches!(
            join_paths(Path::new("base"), Path::new("..")),
            Err(PathError::PathTraversal(_))
        ));
    }
}
