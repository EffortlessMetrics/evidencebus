#![allow(clippy::unwrap_used)]
//! Tests for the public helper functions `validate_artifact_path`,
//! `validate_artifact_digest`, and `validate_attachment`. Focuses on the
//! `match` arms over `PathError`/`DigestError` so every branch in the
//! mapping from the underlying error to `ValidationError` is exercised.

use evidencebus_types::{Attachment, AttachmentRole, Digest};
use evidencebus_validation::{
    validate_artifact_digest, validate_artifact_path, validate_attachment, ValidationError,
};
use std::path::Path;

// ---------------------------------------------------------------------------
// validate_artifact_path
// ---------------------------------------------------------------------------

#[test]
fn given_valid_relative_path_when_validate_artifact_path_then_succeeds() {
    // Given
    let path = Path::new("packets/packet-1/artifacts/report.html");

    // When
    let result = validate_artifact_path(path);

    // Then
    assert!(result.is_ok());
}

#[test]
fn given_path_with_traversal_when_validate_artifact_path_then_returns_path_traversal() {
    // Given
    let path = Path::new("packets/../etc/passwd");

    // When
    let result = validate_artifact_path(path);

    // Then
    assert!(matches!(result, Err(ValidationError::PathTraversal(_))));
}

#[test]
fn given_absolute_path_when_validate_artifact_path_then_returns_unsafe_path() {
    // Given
    let path = if cfg!(windows) {
        Path::new("C:\\Windows\\System32\\config")
    } else {
        Path::new("/etc/passwd")
    };

    // When
    let result = validate_artifact_path(path);

    // Then - the AbsolutePath arm maps to UnsafePath.
    assert!(matches!(result, Err(ValidationError::UnsafePath(_))));
}

#[test]
fn given_path_with_invalid_component_when_validate_artifact_path_then_returns_unsafe_path() {
    // Given - a NUL byte forces evidencebus-path's InvalidPathComponent arm,
    // which our mapping turns into UnsafePath.
    let path_str = "packets/\0nul/artifact.txt";
    let path = Path::new(path_str);

    // When
    let result = validate_artifact_path(path);

    // Then
    assert!(matches!(result, Err(ValidationError::UnsafePath(_))));
}

// ---------------------------------------------------------------------------
// validate_artifact_digest
// ---------------------------------------------------------------------------

#[test]
fn given_valid_digest_when_validate_artifact_digest_then_succeeds() {
    // Given
    let digest = Digest::new("a".repeat(64)).unwrap();

    // When
    let result = validate_artifact_digest(&digest);

    // Then
    assert!(result.is_ok());
}

#[test]
fn given_short_digest_via_serde_when_validate_artifact_digest_then_returns_reference_invalid() {
    // Given - bypass `Digest::new`'s length check via serde_json so we can
    // construct an invalid digest and force `validate_artifact_digest` to take
    // the length-check branch.
    let digest: Digest = serde_json::from_str("\"abc\"").unwrap();

    // When
    let result = validate_artifact_digest(&digest);

    // Then
    match result {
        Err(ValidationError::ReferenceInvalid(msg)) => {
            assert!(
                msg.contains("invalid length"),
                "expected length-related message, got `{}`",
                msg
            );
        }
        other => panic!("expected ReferenceInvalid (length), got {:?}", other),
    }
}

#[test]
fn given_non_hex_digest_via_serde_when_validate_artifact_digest_then_returns_reference_invalid() {
    // Given - 64 chars but non-hex.
    let raw = format!("\"{}\"", "z".repeat(64));
    let digest: Digest = serde_json::from_str(&raw).unwrap();

    // When
    let result = validate_artifact_digest(&digest);

    // Then
    match result {
        Err(ValidationError::ReferenceInvalid(msg)) => {
            assert!(
                msg.contains("non-hex"),
                "expected non-hex message, got `{}`",
                msg
            );
        }
        other => panic!("expected ReferenceInvalid (hex), got {:?}", other),
    }
}

// ---------------------------------------------------------------------------
// validate_attachment (public helper)
// ---------------------------------------------------------------------------

fn make_attachment(media_type: &str, relative_path: &str, sha256_str: &str) -> Attachment {
    // Build a JSON form so we can inject an arbitrary `sha256` string without
    // going through `Digest::new`'s validation.
    let json = serde_json::json!({
        "role": "report_html",
        "media_type": media_type,
        "relative_path": relative_path,
        "sha256": sha256_str,
    });
    serde_json::from_value(json).unwrap()
}

#[test]
fn given_valid_attachment_when_validate_attachment_then_succeeds() {
    // Given
    let attachment = Attachment::new(
        AttachmentRole::ReportHtml,
        "text/html".to_string(),
        "report.html".to_string(),
        Digest::new("a".repeat(64)).unwrap(),
    );

    // When
    let result = validate_attachment(&attachment);

    // Then
    assert!(result.is_ok());
}

#[test]
fn given_attachment_with_short_digest_when_validate_attachment_then_returns_reference_invalid() {
    // Given
    let attachment = make_attachment("text/plain", "test.txt", "abc");

    // When
    let result = validate_attachment(&attachment);

    // Then
    match result {
        Err(ValidationError::ReferenceInvalid(msg)) => {
            assert!(
                msg.contains("invalid length"),
                "expected length-related message, got `{}`",
                msg
            );
        }
        other => panic!("expected ReferenceInvalid (length), got {:?}", other),
    }
}

#[test]
fn given_attachment_with_non_hex_digest_when_validate_attachment_then_returns_reference_invalid() {
    // Given
    let attachment = make_attachment("text/plain", "test.txt", &"z".repeat(64));

    // When
    let result = validate_attachment(&attachment);

    // Then
    match result {
        Err(ValidationError::ReferenceInvalid(msg)) => {
            assert!(
                msg.contains("invalid hex"),
                "expected hex-related message, got `{}`",
                msg
            );
        }
        other => panic!("expected ReferenceInvalid (hex), got {:?}", other),
    }
}

#[test]
fn given_attachment_with_empty_media_type_when_validate_attachment_then_returns_missing_field() {
    // Given
    let attachment = Attachment::new(
        AttachmentRole::ReportHtml,
        String::new(),
        "test.txt".to_string(),
        Digest::new("a".repeat(64)).unwrap(),
    );

    // When
    let result = validate_attachment(&attachment);

    // Then
    assert!(matches!(
        result,
        Err(ValidationError::MissingRequiredField(_))
    ));
}

#[test]
fn given_attachment_with_traversal_path_when_validate_attachment_then_returns_path_traversal() {
    // Given
    let attachment = Attachment::new(
        AttachmentRole::ReportHtml,
        "text/plain".to_string(),
        "packets/../etc/passwd".to_string(),
        Digest::new("a".repeat(64)).unwrap(),
    );

    // When
    let result = validate_attachment(&attachment);

    // Then
    assert!(matches!(result, Err(ValidationError::PathTraversal(_))));
}

#[test]
fn given_attachment_with_absolute_path_when_validate_attachment_then_returns_unsafe_path() {
    // Given
    let abs_path = if cfg!(windows) {
        "C:\\Windows\\notepad.exe".to_string()
    } else {
        "/etc/passwd".to_string()
    };
    let attachment = Attachment::new(
        AttachmentRole::ReportHtml,
        "text/plain".to_string(),
        abs_path,
        Digest::new("a".repeat(64)).unwrap(),
    );

    // When
    let result = validate_attachment(&attachment);

    // Then - the AbsolutePath arm maps to UnsafePath.
    assert!(matches!(result, Err(ValidationError::UnsafePath(_))));
}

#[test]
fn given_attachment_with_invalid_component_when_validate_attachment_then_returns_unsafe_path() {
    // Given - a NUL byte forces the InvalidPathComponent arm.
    let attachment = Attachment::new(
        AttachmentRole::ReportHtml,
        "text/plain".to_string(),
        "packets/\0nul/file.txt".to_string(),
        Digest::new("a".repeat(64)).unwrap(),
    );

    // When
    let result = validate_attachment(&attachment);

    // Then
    assert!(matches!(result, Err(ValidationError::UnsafePath(_))));
}

#[test]
fn given_attachment_with_backslash_when_validate_attachment_then_returns_unsafe_path() {
    // Given
    let attachment = Attachment::new(
        AttachmentRole::ReportHtml,
        "text/plain".to_string(),
        "packets\\packet-1\\report.html".to_string(),
        Digest::new("a".repeat(64)).unwrap(),
    );

    // When
    let result = validate_attachment(&attachment);

    // Then
    assert!(matches!(result, Err(ValidationError::UnsafePath(_))));
}
