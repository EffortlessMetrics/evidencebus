#![allow(clippy::unwrap_used)]
//! BDD-style tests for packet validation.

use evidencebus_codes::{FindingSeverity, PacketStatus};
use evidencebus_fixtures::PacketBuilder;
use evidencebus_types::{Attachment, AttachmentRole, Digest, Finding, VcsKind};
use evidencebus_validation::{validate_attachment, validate_packet, ValidationError};

fn create_valid_packet() -> evidencebus_types::Packet {
    PacketBuilder::new()
        .with_id("test-packet")
        .with_producer("test-tool", "1.0.0")
        .with_subject(VcsKind::Git, "owner/repo", "abc123")
        .with_status(PacketStatus::Pass)
        .with_title("Test")
        .with_summary("Test summary")
        .build()
        .unwrap()
}

#[test]
fn bdd_given_valid_packet_when_validating_then_succeeds() {
    // Given
    let packet = create_valid_packet();

    // When
    let result = validate_packet(&packet);

    // Then
    assert!(result.is_ok(), "Valid packet should pass validation");
}

#[test]
fn bdd_given_packet_with_empty_title_when_validating_then_returns_error() {
    // Given
    let mut packet = create_valid_packet();
    packet.summary.title = String::new();

    // When
    let result = validate_packet(&packet);

    // Then
    assert!(matches!(
        result,
        Err(ValidationError::MissingRequiredField(_))
    ));
}

#[test]
fn bdd_given_packet_with_empty_short_summary_when_validating_then_returns_error() {
    // Given
    let mut packet = create_valid_packet();
    packet.summary.short_summary = String::new();

    // When
    let result = validate_packet(&packet);

    // Then
    assert!(matches!(
        result,
        Err(ValidationError::MissingRequiredField(_))
    ));
}

#[test]
fn bdd_given_packet_with_invalid_created_at_format_when_validating_then_returns_error() {
    // Given
    let mut packet = create_valid_packet();
    packet.created_at = "invalid-format".to_string();

    // When
    let result = validate_packet(&packet);

    // Then
    assert!(matches!(result, Err(ValidationError::InvalidEnum(_))));
}

#[test]
fn bdd_given_packet_with_path_traversal_in_native_payload_when_validating_then_returns_error() {
    // Given
    let mut packet = create_valid_packet();
    packet.native_payloads.push("../etc/passwd".to_string());

    // When
    let result = validate_packet(&packet);

    // Then
    assert!(matches!(result, Err(ValidationError::PathTraversal(_))));
}

#[test]
fn bdd_given_packet_with_path_traversal_in_artifact_when_validating_then_returns_error() {
    // Given
    let mut packet = create_valid_packet();
    packet.artifacts.push("safe/../unsafe".to_string());

    // When
    let result = validate_packet(&packet);

    // Then
    assert!(matches!(result, Err(ValidationError::PathTraversal(_))));
}

#[test]
fn bdd_given_packet_with_backslash_in_native_payload_when_validating_then_returns_error() {
    // Given
    let mut packet = create_valid_packet();
    packet.native_payloads.push("path\\to\\file".to_string());

    // When
    let result = validate_packet(&packet);

    // Then
    assert!(matches!(result, Err(ValidationError::UnsafePath(_))));
}

#[test]
fn bdd_given_packet_with_backslash_in_artifact_when_validating_then_returns_error() {
    // Given
    let mut packet = create_valid_packet();
    packet.artifacts.push("path\\to\\file".to_string());

    // When
    let result = validate_packet(&packet);

    // Then
    assert!(matches!(result, Err(ValidationError::UnsafePath(_))));
}

#[test]
fn bdd_given_packet_with_attachment_with_invalid_digest_length_when_validating_then_returns_error()
{
    // Given - Digest::new() already validates, so we test that it rejects invalid input
    let result = Digest::new("abc123".to_string());

    // Then
    assert!(result.is_err(), "Digest::new should reject invalid length");
}

#[test]
fn bdd_given_packet_with_attachment_with_invalid_hex_digest_when_validating_then_returns_error() {
    // Given - Digest::new() already validates, so we test that it rejects invalid input
    let invalid_digest = "g".repeat(64);
    let result = Digest::new(invalid_digest);

    // Then
    assert!(
        result.is_err(),
        "Digest::new should reject non-hex characters"
    );
}

#[test]
fn bdd_given_packet_with_attachment_with_empty_media_type_when_validating_then_returns_error() {
    // Given
    let mut packet = create_valid_packet();
    let valid_digest = "a".repeat(64);
    packet.projections.attachments.push(Attachment::new(
        AttachmentRole::ReportHtml,
        String::new(),
        "test.txt".to_string(),
        Digest::new(valid_digest).unwrap(),
    ));

    // When
    let result = validate_packet(&packet);

    // Then
    assert!(matches!(
        result,
        Err(ValidationError::MissingRequiredField(_))
    ));
}

#[test]
fn bdd_given_packet_with_attachment_with_path_traversal_when_validating_then_returns_error() {
    // Given
    let mut packet = create_valid_packet();
    let valid_digest = "a".repeat(64);
    packet.projections.attachments.push(Attachment::new(
        AttachmentRole::ReportHtml,
        "text/plain".to_string(),
        "../safe/test.txt".to_string(),
        Digest::new(valid_digest).unwrap(),
    ));

    // When
    let result = validate_packet(&packet);

    // Then
    assert!(matches!(result, Err(ValidationError::PathTraversal(_))));
}

#[test]
fn bdd_given_packet_with_attachment_with_backslash_when_validating_then_returns_error() {
    // Given
    let mut packet = create_valid_packet();
    let valid_digest = "a".repeat(64);
    packet.projections.attachments.push(Attachment::new(
        AttachmentRole::ReportHtml,
        "text/plain".to_string(),
        "path\\to\\test.txt".to_string(),
        Digest::new(valid_digest).unwrap(),
    ));

    // When
    let result = validate_packet(&packet);

    // Then
    assert!(matches!(result, Err(ValidationError::UnsafePath(_))));
}

#[test]
fn bdd_given_packet_with_valid_attachments_when_validating_then_succeeds() {
    // Given
    let mut packet = create_valid_packet();
    let valid_digest = "a".repeat(64);
    packet.projections.attachments.push(Attachment::new(
        AttachmentRole::ReportHtml,
        "text/plain".to_string(),
        "test.txt".to_string(),
        Digest::new(valid_digest).unwrap(),
    ));

    // When
    let result = validate_packet(&packet);

    // Then
    assert!(result.is_ok());
}

#[test]
fn bdd_given_packet_with_valid_native_payloads_when_validating_then_succeeds() {
    // Given
    let mut packet = create_valid_packet();
    packet.native_payloads.push("report.json".to_string());
    packet.native_payloads.push("logs/output.log".to_string());

    // When
    let result = validate_packet(&packet);

    // Then
    assert!(result.is_ok());
}

#[test]
fn bdd_given_packet_with_valid_artifacts_when_validating_then_succeeds() {
    // Given
    let mut packet = create_valid_packet();
    packet.artifacts.push("report.html".to_string());
    packet
        .artifacts
        .push("screenshots/screenshot.png".to_string());

    // When
    let result = validate_packet(&packet);

    // Then
    assert!(result.is_ok());
}

#[test]
fn bdd_given_packet_with_findings_when_validating_then_succeeds() {
    // Given
    let mut packet = create_valid_packet();
    packet.projections.findings.push(Finding::new(
        "f1",
        FindingSeverity::Error,
        "Error",
        "Error message",
    ));
    packet.projections.findings.push(Finding::new(
        "f2",
        FindingSeverity::Warning,
        "Warning",
        "Warning message",
    ));

    // When
    let result = validate_packet(&packet);

    // Then
    assert!(result.is_ok());
}

#[test]
fn bdd_given_packet_with_metrics_when_validating_then_succeeds() {
    // Given
    let mut packet = create_valid_packet();
    packet
        .projections
        .metrics
        .push(evidencebus_types::Metric::new("metric1".to_string(), 42.0));

    // When
    let result = validate_packet(&packet);

    // Then
    assert!(result.is_ok());
}

#[test]
fn bdd_given_packet_with_valid_iso8601_timestamp_when_validating_then_succeeds() {
    // Given
    let mut packet = create_valid_packet();
    packet.created_at = "2024-01-01T00:00:00Z".to_string();

    // When
    let result = validate_packet(&packet);

    // Then
    assert!(result.is_ok());
}

#[test]
fn bdd_given_packet_with_valid_schema_version_when_validating_then_succeeds() {
    // Given
    let mut packet = create_valid_packet();
    packet.eb_version = evidencebus_types::SchemaVersion::new("1.2.3");

    // When
    let result = validate_packet(&packet);

    // Then
    assert!(result.is_ok());
}

#[test]
fn bdd_given_packet_with_invalid_schema_version_when_validating_then_returns_error() {
    // Given
    let mut packet = create_valid_packet();
    packet.eb_version = evidencebus_types::SchemaVersion::new("invalid@version");

    // When
    let result = validate_packet(&packet);

    // Then
    assert!(matches!(result, Err(ValidationError::SchemaInvalid(_))));
}

#[test]
fn bdd_given_valid_attachment_when_validating_then_succeeds() {
    // Given
    let valid_digest = "a".repeat(64);
    let attachment = Attachment::new(
        AttachmentRole::ReportHtml,
        "text/plain".to_string(),
        "test.txt".to_string(),
        Digest::new(valid_digest).unwrap(),
    );

    // When
    let result = validate_attachment(&attachment);

    // Then
    assert!(result.is_ok());
}

#[test]
fn bdd_given_attachment_with_invalid_digest_length_when_validating_then_returns_error() {
    // Given - Digest::new() already validates, so we test that it rejects invalid input
    let result = Digest::new("abc123".to_string());

    // Then
    assert!(result.is_err(), "Digest::new should reject invalid length");
}

#[test]
fn bdd_given_attachment_with_invalid_hex_digest_when_validating_then_returns_error() {
    // Given - Digest::new() already validates, so we test that it rejects invalid input
    let invalid_digest = "g".repeat(64);
    let result = Digest::new(invalid_digest);

    // Then
    assert!(
        result.is_err(),
        "Digest::new should reject non-hex characters"
    );
}

#[test]
fn bdd_given_attachment_with_empty_media_type_when_validating_then_returns_error() {
    // Given
    let valid_digest = "a".repeat(64);
    let attachment = Attachment::new(
        AttachmentRole::ReportHtml,
        String::new(),
        "test.txt".to_string(),
        Digest::new(valid_digest).unwrap(),
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
fn bdd_given_attachment_with_path_traversal_when_validating_then_returns_error() {
    // Given
    let valid_digest = "a".repeat(64);
    let attachment = Attachment::new(
        AttachmentRole::ReportHtml,
        "text/plain".to_string(),
        "../safe/test.txt".to_string(),
        Digest::new(valid_digest).unwrap(),
    );

    // When
    let result = validate_attachment(&attachment);

    // Then
    assert!(matches!(result, Err(ValidationError::PathTraversal(_))));
}

#[test]
fn bdd_given_attachment_with_backslash_when_validating_then_returns_error() {
    // Given
    let valid_digest = "a".repeat(64);
    let attachment = Attachment::new(
        AttachmentRole::ReportHtml,
        "text/plain".to_string(),
        "path\\to\\test.txt".to_string(),
        Digest::new(valid_digest).unwrap(),
    );

    // When
    let result = validate_attachment(&attachment);

    // Then
    assert!(matches!(result, Err(ValidationError::UnsafePath(_))));
}
