//! Packet and bundle validation for evidencebus.
//!
//! This crate provides validation functions for packets, bundles, and artifacts,
//! with comprehensive error reporting for validation failures.

use evidencebus_codes::{BundleErrorCode, ValidationErrorCode};
use evidencebus_digest::compute_sha256;
use evidencebus_path::{validate_path, PathError};
use evidencebus_types::{Attachment, Bundle, Digest, DigestError, Packet, PacketId, Projections};
use std::collections::HashMap;
use std::path::Path;
use thiserror::Error;

/// Error type for packet validation.
#[derive(Debug, Error)]
pub enum ValidationError {
    #[error("schema version is invalid: {0}")]
    SchemaInvalid(String),
    #[error("missing required field: {0}")]
    MissingRequiredField(String),
    #[error("invalid enum value: {0}")]
    InvalidEnum(String),
    #[error("reference invalid: {0}")]
    ReferenceInvalid(String),
    #[error("digest mismatch: expected {expected}, got {actual}")]
    DigestMismatch { expected: String, actual: String },
    #[error("duplicate packet ID: {0}")]
    DuplicatePacketId(String),
    #[error("path traversal detected: {0}")]
    PathTraversal(String),
    #[error("unsafe path detected: {0}")]
    UnsafePath(String),
}

impl ValidationError {
    /// Returns the error code for this validation error.
    pub fn code(&self) -> ValidationErrorCode {
        match self {
            Self::SchemaInvalid(_) => ValidationErrorCode::SchemaInvalid,
            Self::MissingRequiredField(_) => ValidationErrorCode::MissingRequiredField,
            Self::InvalidEnum(_) => ValidationErrorCode::InvalidEnum,
            Self::ReferenceInvalid(_) => ValidationErrorCode::ReferenceInvalid,
            Self::DigestMismatch { .. } => ValidationErrorCode::DigestMismatch,
            Self::DuplicatePacketId(_) => ValidationErrorCode::DuplicatePacketId,
            Self::PathTraversal(_) => ValidationErrorCode::PathTraversal,
            Self::UnsafePath(_) => ValidationErrorCode::UnsafePath,
        }
    }
}

/// Error type for bundle validation.
#[derive(Debug, Error)]
pub enum BundleValidationError {
    #[error("manifest is invalid: {0}")]
    ManifestInvalid(String),
    #[error("missing artifact: {0}")]
    MissingArtifact(String),
    #[error("conflicting packet: {0}")]
    ConflictingPacket(String),
    #[error("inventory mismatch: {0}")]
    InventoryMismatch(String),
    #[error("digest mismatch: {0}")]
    DigestMismatch(String),
    #[error("invalid digest: {0}")]
    InvalidDigest(#[from] DigestError),
}

impl BundleValidationError {
    /// Returns the error code for this bundle validation error.
    pub fn code(&self) -> BundleErrorCode {
        match self {
            Self::ManifestInvalid(_) => BundleErrorCode::ManifestInvalid,
            Self::MissingArtifact(_) => BundleErrorCode::MissingArtifact,
            Self::ConflictingPacket(_) => BundleErrorCode::ConflictingPacket,
            Self::InventoryMismatch(_) => BundleErrorCode::InventoryMismatch,
            Self::DigestMismatch(_) => BundleErrorCode::ManifestInvalid,
            Self::InvalidDigest(_) => BundleErrorCode::ManifestInvalid,
        }
    }
}

/// Validates a packet.
///
/// # Errors
/// Returns a `ValidationError` if the packet is invalid.
pub fn validate_packet(packet: &Packet) -> Result<(), ValidationError> {
    // Validate schema version format
    let version = packet.eb_version.as_str();
    if !version.chars().all(|c| c.is_ascii_digit() || c == '.') {
        return Err(ValidationError::SchemaInvalid(format!(
            "invalid version format: {}",
            version
        )));
    }

    // Validate packet ID
    if packet.packet_id.as_str().is_empty() {
        return Err(ValidationError::MissingRequiredField(
            "packet_id".to_string(),
        ));
    }

    // Validate producer fields
    if packet.producer.tool_name.is_empty() {
        return Err(ValidationError::MissingRequiredField(
            "producer.tool_name".to_string(),
        ));
    }
    if packet.producer.tool_version.is_empty() {
        return Err(ValidationError::MissingRequiredField(
            "producer.tool_version".to_string(),
        ));
    }

    // Validate subject fields
    if packet.subject.repo_identifier.is_empty() {
        return Err(ValidationError::MissingRequiredField(
            "subject.repo_identifier".to_string(),
        ));
    }
    if packet.subject.commit.is_empty() {
        return Err(ValidationError::MissingRequiredField(
            "subject.commit".to_string(),
        ));
    }
    if packet.subject.head.is_empty() {
        return Err(ValidationError::MissingRequiredField(
            "subject.head".to_string(),
        ));
    }

    // Validate summary fields
    if packet.summary.title.is_empty() {
        return Err(ValidationError::MissingRequiredField(
            "summary.title".to_string(),
        ));
    }
    if packet.summary.short_summary.is_empty() {
        return Err(ValidationError::MissingRequiredField(
            "summary.short_summary".to_string(),
        ));
    }

    // Validate created_at format (basic ISO 8601 check)
    if !packet.created_at.contains('T') {
        return Err(ValidationError::InvalidEnum(format!(
            "invalid created_at format: {}",
            packet.created_at
        )));
    }

    // Validate attachment references
    validate_attachments(&packet.projections)?;

    // Validate paths for path traversal
    validate_paths(packet)?;

    Ok(())
}

/// Validates attachment references in the projections.
fn validate_attachments(projections: &Projections) -> Result<(), ValidationError> {
    for attachment in &projections.attachments {
        // Validate digest format
        if attachment.sha256.as_str().len() != 64 {
            return Err(ValidationError::ReferenceInvalid(format!(
                "attachment digest has invalid length: {}",
                attachment.relative_path
            )));
        }
        if !attachment
            .sha256
            .as_str()
            .chars()
            .all(|c| c.is_ascii_hexdigit())
        {
            return Err(ValidationError::ReferenceInvalid(format!(
                "attachment digest has invalid hex: {}",
                attachment.relative_path
            )));
        }

        // Validate media type
        if attachment.media_type.is_empty() {
            return Err(ValidationError::MissingRequiredField(format!(
                "attachment media_type for {}",
                attachment.relative_path
            )));
        }
    }

    Ok(())
}

/// Validates paths for path traversal and unsafe characters.
fn validate_paths(packet: &Packet) -> Result<(), ValidationError> {
    let check_path = |path: &str, context: &str| -> Result<(), ValidationError> {
        // Use evidencebus_path for traversal, absolute path, and null byte checks
        validate_path(Path::new(path)).map_err(|e| match e {
            PathError::PathTraversal(_) => {
                ValidationError::PathTraversal(format!("{}: {}", context, path))
            }
            PathError::AbsolutePath(_) => {
                ValidationError::UnsafePath(format!("{}: {}", context, path))
            }
            PathError::InvalidPathComponent(_) | PathError::OutsideBundle(_) => {
                ValidationError::UnsafePath(format!("{}: {}", context, path))
            }
        })?;

        // Reject backslashes for cross-platform safety (evidence paths must use forward slashes)
        if path.contains('\\') {
            return Err(ValidationError::UnsafePath(format!(
                "{}: {}",
                context, path
            )));
        }

        Ok(())
    };

    for path in &packet.native_payloads {
        check_path(path, "native_payload")?;
    }

    for path in &packet.artifacts {
        check_path(path, "artifact")?;
    }

    for attachment in &packet.projections.attachments {
        check_path(&attachment.relative_path, "attachment")?;
    }

    Ok(())
}

/// Validates a bundle.
///
/// # Errors
/// Returns a `BundleValidationError` if the bundle is invalid.
pub fn validate_bundle(
    bundle: &Bundle,
    packet_data: &[(&PacketId, &[u8])],
    artifact_data: &[(&Path, &[u8])],
) -> Result<(), BundleValidationError> {
    // Validate manifest
    validate_manifest(bundle)?;

    // Validate packet inventory
    validate_packet_inventory(bundle, packet_data)?;

    // Validate artifact inventory
    validate_artifact_inventory(bundle, artifact_data)?;

    // Validate digest consistency
    validate_digest_consistency(bundle, packet_data, artifact_data)?;

    Ok(())
}

/// Validates the bundle manifest.
fn validate_manifest(bundle: &Bundle) -> Result<(), BundleValidationError> {
    // Check for duplicate packet IDs in manifest
    let mut seen_ids = HashMap::new();
    for entry in &bundle.manifest.packets {
        if let Some(existing) = seen_ids.get(&entry.packet_id) {
            return Err(BundleValidationError::ConflictingPacket(format!(
                "duplicate packet ID in manifest: {} (paths: {} and {})",
                entry.packet_id, existing, entry.relative_path
            )));
        }
        seen_ids.insert(entry.packet_id.clone(), entry.relative_path.clone());
    }

    // Check for duplicate artifact paths
    let mut seen_artifacts = HashMap::new();
    for entry in &bundle.manifest.artifacts {
        if let Some(existing) = seen_artifacts.get(&entry.relative_path) {
            return Err(BundleValidationError::ConflictingPacket(format!(
                "duplicate artifact path in manifest: {} (packets: {} and {})",
                entry.relative_path, existing, entry.packet_id
            )));
        }
        seen_artifacts.insert(entry.relative_path.clone(), entry.packet_id.clone());
    }

    // Validate integrity metadata
    let manifest = &bundle.manifest;
    if manifest.packets.len() != manifest.integrity.packet_digests.len() {
        return Err(BundleValidationError::ManifestInvalid(format!(
            "packet count mismatch: {} packets, {} digests",
            manifest.packets.len(),
            manifest.integrity.packet_digests.len()
        )));
    }

    Ok(())
}

/// Validates the packet inventory against actual packet data.
fn validate_packet_inventory(
    bundle: &Bundle,
    packet_data: &[(&PacketId, &[u8])],
) -> Result<(), BundleValidationError> {
    let packet_map: HashMap<_, _> = packet_data.iter().cloned().collect();

    // Check all manifest entries have corresponding data
    for entry in &bundle.manifest.packets {
        if let Some(data) = packet_map.get(&entry.packet_id) {
            // Verify digest
            let computed = Digest::new(compute_sha256(data))?;
            if computed != entry.sha256 {
                return Err(BundleValidationError::DigestMismatch(format!(
                    "packet {} digest mismatch: expected {}, computed {}",
                    entry.packet_id, entry.sha256, computed
                )));
            }
        } else {
            return Err(BundleValidationError::MissingArtifact(format!(
                "packet data missing for ID: {}",
                entry.packet_id
            )));
        }
    }

    // Check all provided data is in manifest
    for (packet_id, _) in packet_data {
        if !bundle
            .manifest
            .integrity
            .packet_digests
            .contains_key(*packet_id)
        {
            return Err(BundleValidationError::InventoryMismatch(format!(
                "packet {} not in manifest",
                packet_id
            )));
        }
    }

    Ok(())
}

/// Validates the artifact inventory against actual artifact data.
fn validate_artifact_inventory(
    bundle: &Bundle,
    artifact_data: &[(&Path, &[u8])],
) -> Result<(), BundleValidationError> {
    let artifact_map: HashMap<_, _> = artifact_data
        .iter()
        .map(|(path, data)| (path.to_string_lossy().to_string(), *data))
        .collect();

    // Check all manifest entries have corresponding data
    for entry in &bundle.manifest.artifacts {
        if let Some(data) = artifact_map.get(&entry.relative_path) {
            // Verify digest
            let computed = Digest::new(compute_sha256(data))?;
            if computed != entry.sha256 {
                return Err(BundleValidationError::DigestMismatch(format!(
                    "artifact {} digest mismatch: expected {}, computed {}",
                    entry.relative_path, entry.sha256, computed
                )));
            }
        } else {
            return Err(BundleValidationError::MissingArtifact(format!(
                "artifact data missing for path: {}",
                entry.relative_path
            )));
        }
    }

    // Check all provided data is in manifest
    for (path, _) in artifact_data {
        let path_str = path.to_string_lossy();
        if !bundle
            .manifest
            .integrity
            .artifact_digests
            .contains_key(path_str.as_ref())
        {
            return Err(BundleValidationError::InventoryMismatch(format!(
                "artifact {} not in manifest",
                path_str
            )));
        }
    }

    Ok(())
}

/// Validates digest consistency across the bundle.
fn validate_digest_consistency(
    bundle: &Bundle,
    packet_data: &[(&PacketId, &[u8])],
    artifact_data: &[(&Path, &[u8])],
) -> Result<(), BundleValidationError> {
    // Verify packet digests match
    for (packet_id, data) in packet_data {
        let expected = bundle
            .manifest
            .integrity
            .packet_digests
            .get(*packet_id)
            .ok_or_else(|| {
                BundleValidationError::ManifestInvalid(format!(
                    "packet {} not in integrity metadata",
                    packet_id
                ))
            })?;
        let computed = Digest::new(compute_sha256(data))?;
        if computed != *expected {
            return Err(BundleValidationError::DigestMismatch(format!(
                "packet {} digest mismatch in integrity metadata",
                packet_id
            )));
        }
    }

    // Verify artifact digests match
    for (path, data) in artifact_data {
        let path_str = path.to_string_lossy();
        let expected = bundle
            .manifest
            .integrity
            .artifact_digests
            .get(path_str.as_ref())
            .ok_or_else(|| {
                BundleValidationError::ManifestInvalid(format!(
                    "artifact {} not in integrity metadata",
                    path_str
                ))
            })?;
        let computed = Digest::new(compute_sha256(data))?;
        if computed != *expected {
            return Err(BundleValidationError::DigestMismatch(format!(
                "artifact {} digest mismatch in integrity metadata",
                path_str
            )));
        }
    }

    Ok(())
}

/// Validates an artifact path.
///
/// # Errors
/// Returns a `ValidationError` if the path is invalid.
pub fn validate_artifact_path(path: &Path) -> Result<(), ValidationError> {
    validate_path(path).map_err(|e| match e {
        PathError::AbsolutePath(msg) => ValidationError::UnsafePath(msg),
        PathError::PathTraversal(msg) => ValidationError::PathTraversal(msg),
        PathError::InvalidPathComponent(msg) => ValidationError::UnsafePath(msg),
        PathError::OutsideBundle(msg) => ValidationError::UnsafePath(msg),
    })
}

/// Validates an artifact digest.
///
/// # Errors
/// Returns a `ValidationError` if the digest is invalid.
pub fn validate_artifact_digest(digest: &Digest) -> Result<(), ValidationError> {
    let digest_str = digest.as_str();
    if digest_str.len() != 64 {
        return Err(ValidationError::ReferenceInvalid(format!(
            "digest has invalid length: {}",
            digest_str.len()
        )));
    }
    if !digest_str.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(ValidationError::ReferenceInvalid(
            "digest contains non-hex characters".to_string(),
        ));
    }
    Ok(())
}

/// Validates an attachment.
///
/// # Errors
/// Returns a `ValidationError` if the attachment is invalid.
pub fn validate_attachment(attachment: &Attachment) -> Result<(), ValidationError> {
    // Validate digest format
    if attachment.sha256.as_str().len() != 64 {
        return Err(ValidationError::ReferenceInvalid(format!(
            "attachment digest has invalid length: {}",
            attachment.relative_path
        )));
    }
    if !attachment
        .sha256
        .as_str()
        .chars()
        .all(|c| c.is_ascii_hexdigit())
    {
        return Err(ValidationError::ReferenceInvalid(format!(
            "attachment digest has invalid hex: {}",
            attachment.relative_path
        )));
    }

    // Validate media type
    if attachment.media_type.is_empty() {
        return Err(ValidationError::MissingRequiredField(format!(
            "attachment media_type for {}",
            attachment.relative_path
        )));
    }

    // Validate path using evidencebus_path (catches traversal, absolute paths, null bytes)
    validate_path(Path::new(&attachment.relative_path)).map_err(|e| match e {
        PathError::PathTraversal(_) => {
            ValidationError::PathTraversal(format!("attachment: {}", attachment.relative_path))
        }
        PathError::AbsolutePath(_) => {
            ValidationError::UnsafePath(format!("attachment: {}", attachment.relative_path))
        }
        PathError::InvalidPathComponent(_) | PathError::OutsideBundle(_) => {
            ValidationError::UnsafePath(format!("attachment: {}", attachment.relative_path))
        }
    })?;

    // Reject backslashes for cross-platform safety (evidence paths must use forward slashes)
    if attachment.relative_path.contains('\\') {
        return Err(ValidationError::UnsafePath(format!(
            "attachment: {}",
            attachment.relative_path
        )));
    }

    Ok(())
}
