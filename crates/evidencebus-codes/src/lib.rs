//! Shared enums and status codes for evidencebus.
//!
//! This crate provides the foundational types used across the evidencebus ecosystem,
//! including status codes, severity levels, and error codes.

use serde::{Deserialize, Serialize};

/// Exit codes for the CLI.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExitCode {
    /// Success.
    Success = 0,
    /// Validation failed.
    ValidationFailed = 1,
    /// IO error.
    Io = 2,
    /// Invalid input.
    InvalidInput = 3,
    /// Internal error.
    Internal = 4,
    /// Export failed.
    ExportFailed = 5,
}

impl ExitCode {
    /// Returns the integer exit code.
    pub fn code(&self) -> i32 {
        *self as i32
    }
}

/// Validation mode for packet and bundle validation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ValidationMode {
    /// Validate schema only, skip file existence checks.
    SchemaOnly,
    /// Strict validation including file existence and digest verification.
    Strict,
}

/// The status of a packet or assertion.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum PacketStatus {
    /// The packet or assertion passed successfully.
    Pass,
    /// The packet or assertion failed.
    Fail,
    /// The packet or assertion produced a warning.
    Warn,
    /// The packet or assertion status cannot be determined.
    Indeterminate,
    /// An error occurred while processing the packet or assertion.
    Error,
}

impl PacketStatus {
    /// Returns true if the status represents a successful outcome.
    pub fn is_success(&self) -> bool {
        matches!(self, Self::Pass)
    }

    /// Returns true if the status represents a failure or error.
    pub fn is_failure(&self) -> bool {
        matches!(self, Self::Fail | Self::Error)
    }

    /// Returns true if the status represents a warning or indeterminate state.
    pub fn is_warning(&self) -> bool {
        matches!(self, Self::Warn | Self::Indeterminate)
    }
}

/// The severity level of a finding.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum FindingSeverity {
    /// An informational note.
    Note,
    /// A warning finding.
    Warning,
    /// An error finding.
    Error,
}

impl FindingSeverity {
    /// Returns the numeric severity level (higher = more severe).
    pub fn level(&self) -> u8 {
        match self {
            Self::Note => 1,
            Self::Warning => 2,
            Self::Error => 3,
        }
    }
}

/// Validation error codes for packet validation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ValidationErrorCode {
    /// The packet schema is invalid.
    SchemaInvalid,
    /// A required field is missing from the packet.
    MissingRequiredField,
    /// An invalid enum value was provided.
    InvalidEnum,
    /// A reference (e.g., attachment) is invalid.
    ReferenceInvalid,
    /// The digest does not match the computed value.
    DigestMismatch,
    /// Duplicate packet ID detected.
    DuplicatePacketId,
    /// Path traversal attempt detected.
    PathTraversal,
    /// Unsafe path detected.
    UnsafePath,
}

/// Bundle error codes for bundle validation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BundleErrorCode {
    /// The bundle manifest is invalid.
    ManifestInvalid,
    /// An artifact referenced in the manifest is missing.
    MissingArtifact,
    /// Conflicting packets detected (same ID, different content).
    ConflictingPacket,
    /// The inventory does not match the actual files.
    InventoryMismatch,
}

/// Export error codes for export operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExportErrorCode {
    /// The requested export format is not supported.
    UnsupportedFormat,
    /// The export operation results in lossy conversion.
    LossyExport,
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn test_packet_status_is_success() {
        assert!(PacketStatus::Pass.is_success());
        assert!(!PacketStatus::Fail.is_success());
        assert!(!PacketStatus::Warn.is_success());
        assert!(!PacketStatus::Indeterminate.is_success());
        assert!(!PacketStatus::Error.is_success());
    }

    #[test]
    fn test_packet_status_is_failure() {
        assert!(!PacketStatus::Pass.is_failure());
        assert!(PacketStatus::Fail.is_failure());
        assert!(!PacketStatus::Warn.is_failure());
        assert!(!PacketStatus::Indeterminate.is_failure());
        assert!(PacketStatus::Error.is_failure());
    }

    #[test]
    fn test_packet_status_is_warning() {
        assert!(!PacketStatus::Pass.is_warning());
        assert!(!PacketStatus::Fail.is_warning());
        assert!(PacketStatus::Warn.is_warning());
        assert!(PacketStatus::Indeterminate.is_warning());
        assert!(!PacketStatus::Error.is_warning());
    }

    #[test]
    fn test_finding_severity_level() {
        assert_eq!(FindingSeverity::Note.level(), 1);
        assert_eq!(FindingSeverity::Warning.level(), 2);
        assert_eq!(FindingSeverity::Error.level(), 3);
    }

    #[test]
    fn test_packet_status_serialization() {
        let status = PacketStatus::Pass;
        let json = serde_json::to_string(&status).unwrap();
        assert_eq!(json, "\"pass\"");

        let deserialized: PacketStatus = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized, status);
    }

    #[test]
    fn test_finding_severity_serialization() {
        let severity = FindingSeverity::Warning;
        let json = serde_json::to_string(&severity).unwrap();
        assert_eq!(json, "\"warning\"");

        let deserialized: FindingSeverity = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized, severity);
    }

    #[test]
    fn test_validation_error_code_serialization() {
        let code = ValidationErrorCode::DigestMismatch;
        let json = serde_json::to_string(&code).unwrap();
        assert_eq!(json, "\"digest_mismatch\"");

        let deserialized: ValidationErrorCode = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized, code);
    }
}
