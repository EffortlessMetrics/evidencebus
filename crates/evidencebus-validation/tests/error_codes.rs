#![allow(clippy::unwrap_used)]
//! Tests covering the `code()` accessor of every `ValidationError` and
//! `BundleValidationError` variant.

use evidencebus_codes::{BundleErrorCode, ValidationErrorCode};
use evidencebus_types::{Digest, DigestError};
use evidencebus_validation::{BundleValidationError, ValidationError};

#[test]
fn validation_error_code_schema_invalid_returns_schema_invalid() {
    // Given
    let err = ValidationError::SchemaInvalid("bad".to_string());

    // When / Then
    assert_eq!(err.code(), ValidationErrorCode::SchemaInvalid);
}

#[test]
fn validation_error_code_missing_required_field_returns_missing_required_field() {
    // Given
    let err = ValidationError::MissingRequiredField("packet_id".to_string());

    // When / Then
    assert_eq!(err.code(), ValidationErrorCode::MissingRequiredField);
}

#[test]
fn validation_error_code_invalid_enum_returns_invalid_enum() {
    // Given
    let err = ValidationError::InvalidEnum("bogus".to_string());

    // When / Then
    assert_eq!(err.code(), ValidationErrorCode::InvalidEnum);
}

#[test]
fn validation_error_code_reference_invalid_returns_reference_invalid() {
    // Given
    let err = ValidationError::ReferenceInvalid("attachment".to_string());

    // When / Then
    assert_eq!(err.code(), ValidationErrorCode::ReferenceInvalid);
}

#[test]
fn validation_error_code_digest_mismatch_returns_digest_mismatch() {
    // Given
    let err = ValidationError::DigestMismatch {
        expected: "a".repeat(64),
        actual: "b".repeat(64),
    };

    // When / Then
    assert_eq!(err.code(), ValidationErrorCode::DigestMismatch);
}

#[test]
fn validation_error_code_duplicate_packet_id_returns_duplicate_packet_id() {
    // Given
    let err = ValidationError::DuplicatePacketId("pkt".to_string());

    // When / Then
    assert_eq!(err.code(), ValidationErrorCode::DuplicatePacketId);
}

#[test]
fn validation_error_code_path_traversal_returns_path_traversal() {
    // Given
    let err = ValidationError::PathTraversal("..".to_string());

    // When / Then
    assert_eq!(err.code(), ValidationErrorCode::PathTraversal);
}

#[test]
fn validation_error_code_unsafe_path_returns_unsafe_path() {
    // Given
    let err = ValidationError::UnsafePath("/etc/passwd".to_string());

    // When / Then
    assert_eq!(err.code(), ValidationErrorCode::UnsafePath);
}

#[test]
fn bundle_validation_error_code_manifest_invalid_returns_manifest_invalid() {
    // Given
    let err = BundleValidationError::ManifestInvalid("oops".to_string());

    // When / Then
    assert_eq!(err.code(), BundleErrorCode::ManifestInvalid);
}

#[test]
fn bundle_validation_error_code_missing_artifact_returns_missing_artifact() {
    // Given
    let err = BundleValidationError::MissingArtifact("artifact".to_string());

    // When / Then
    assert_eq!(err.code(), BundleErrorCode::MissingArtifact);
}

#[test]
fn bundle_validation_error_code_conflicting_packet_returns_conflicting_packet() {
    // Given
    let err = BundleValidationError::ConflictingPacket("dup".to_string());

    // When / Then
    assert_eq!(err.code(), BundleErrorCode::ConflictingPacket);
}

#[test]
fn bundle_validation_error_code_inventory_mismatch_returns_inventory_mismatch() {
    // Given
    let err = BundleValidationError::InventoryMismatch("not-in-manifest".to_string());

    // When / Then
    assert_eq!(err.code(), BundleErrorCode::InventoryMismatch);
}

#[test]
fn bundle_validation_error_code_digest_mismatch_returns_manifest_invalid() {
    // Given
    let err = BundleValidationError::DigestMismatch("packet x".to_string());

    // When / Then - DigestMismatch maps to ManifestInvalid per the impl.
    assert_eq!(err.code(), BundleErrorCode::ManifestInvalid);
}

#[test]
fn bundle_validation_error_code_invalid_digest_returns_manifest_invalid() {
    // Given - construct an InvalidDigest via the `From<DigestError>` conversion.
    let digest_err: DigestError = Digest::new("not-64-chars").unwrap_err();
    let err: BundleValidationError = digest_err.into();

    // When / Then - InvalidDigest maps to ManifestInvalid per the impl.
    assert_eq!(err.code(), BundleErrorCode::ManifestInvalid);
}
