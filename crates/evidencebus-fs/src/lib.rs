//! Filesystem I/O for evidencebus packets and bundles.
//!
//! This crate provides functions for reading and writing packets and bundles
//! with safe path handling to prevent path traversal attacks.

use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};

use evidencebus_canonicalization::canonicalize_json;
use evidencebus_canonicalization::CanonicalizationError;
use evidencebus_codes::ValidationMode;
use evidencebus_core::{build_bundle_manifest, CoreError};
use evidencebus_digest::{compute_sha256, verify_digest, DigestError};
use evidencebus_path::{
    normalize_relative_path, sanitize_path_component, to_forward_slash, validate_path, PathError,
};
use evidencebus_types::{Artifact, AttachmentRole, BundleManifest, Packet, PacketId};
use evidencebus_validation::{
    validate_bundle, validate_packet, BundleValidationError, ValidationError,
};
use thiserror::Error;

/// A loaded bundle with manifest and packets.
#[derive(Debug)]
pub struct LoadedBundle {
    pub manifest: BundleManifest,
    pub packets: Vec<Packet>,
}

/// A loaded target (either a packet or a bundle).
#[derive(Debug)]
#[allow(clippy::large_enum_variant)]
pub enum LoadedTarget {
    Packet(Packet),
    Bundle(LoadedBundle),
}

/// Error type for filesystem operations.
#[derive(Debug, Error)]
pub enum FsError {
    #[error("IO error at {path}: {source}")]
    IoError {
        path: String,
        #[source]
        source: std::io::Error,
    },
    #[error("invalid JSON at {path}: {source}")]
    InvalidJson {
        path: String,
        #[source]
        source: serde_json::Error,
    },
    #[error(transparent)]
    PathError(#[from] PathError),
    #[error("bundle creation failed: {0}")]
    BundleCreationFailed(String),
    #[error("artifact copy failed: {0}")]
    ArtifactCopyFailed(String),
    #[error(transparent)]
    ValidationError(#[from] ValidationError),
    #[error(transparent)]
    BundleValidationError(#[from] BundleValidationError),
    #[error(transparent)]
    CanonicalizationError(#[from] CanonicalizationError),
    #[error(transparent)]
    DigestError(#[from] DigestError),
    #[error(transparent)]
    CoreError(#[from] CoreError),
    #[error("invalid input: {0}")]
    InvalidInput(String),
}

/// Reads and deserializes a packet JSON file.
pub fn read_packet(path: &Path) -> Result<Packet, FsError> {
    let contents = read_to_string(path)?;
    serde_json::from_str(&contents).map_err(|source| FsError::InvalidJson {
        path: path.display().to_string(),
        source,
    })
}

/// Writes packet to JSON with canonical formatting.
pub fn write_packet(path: &Path, packet: &Packet) -> Result<(), FsError> {
    if let Some(parent) = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
    {
        fs::create_dir_all(parent).map_err(|source| FsError::IoError {
            path: parent.display().to_string(),
            source,
        })?;
    }
    let bytes = canonicalize_json(packet)?;
    fs::write(path, bytes).map_err(|source| FsError::IoError {
        path: path.display().to_string(),
        source,
    })
}

/// Creates bundle directory structure.
pub fn create_bundle_dir(bundle_path: &Path) -> Result<(), FsError> {
    fs::create_dir_all(bundle_path).map_err(|source| FsError::IoError {
        path: bundle_path.display().to_string(),
        source,
    })?;
    fs::create_dir_all(bundle_path.join("packets")).map_err(|source| FsError::IoError {
        path: bundle_path.join("packets").display().to_string(),
        source,
    })?;
    Ok(())
}

/// Writes bundle.eb.json to bundle directory.
pub fn write_bundle_manifest(bundle_path: &Path, bundle: &BundleManifest) -> Result<(), FsError> {
    let manifest_path = bundle_path.join("bundle.eb.json");
    let manifest_bytes =
        serde_json::to_vec_pretty(bundle).map_err(|source| FsError::InvalidJson {
            path: manifest_path.display().to_string(),
            source,
        })?;
    fs::write(&manifest_path, manifest_bytes).map_err(|source| FsError::IoError {
        path: manifest_path.display().to_string(),
        source,
    })
}

/// Reads bundle.eb.json from bundle directory.
pub fn read_bundle_manifest(bundle_path: &Path) -> Result<BundleManifest, FsError> {
    let manifest_path = bundle_path.join("bundle.eb.json");
    let manifest_contents = read_to_string(&manifest_path)?;
    serde_json::from_str(&manifest_contents).map_err(|source| FsError::InvalidJson {
        path: manifest_path.display().to_string(),
        source,
    })
}

/// Copies artifact into bundle with safe path handling.
pub fn copy_artifact_to_bundle(
    source: &Path,
    bundle_path: &Path,
    packet_id: &PacketId,
    relative_dest: &Path,
) -> Result<(), FsError> {
    let sanitized_id = sanitize_path_component(packet_id.as_str())?;
    let normalized_dest = normalize_relative_path(relative_dest)?;

    // Ensure destination is within bundle directory
    let dest_path = bundle_path
        .join("packets")
        .join(&sanitized_id)
        .join("artifacts")
        .join(&normalized_dest);

    // Create parent directories
    if let Some(parent) = dest_path.parent() {
        fs::create_dir_all(parent).map_err(|source| FsError::IoError {
            path: parent.display().to_string(),
            source,
        })?;
    }

    // Copy the file
    fs::copy(source, &dest_path).map_err(|err| {
        FsError::ArtifactCopyFailed(format!(
            "failed to copy {} to {}: {}",
            source.display(),
            dest_path.display(),
            err
        ))
    })?;

    Ok(())
}

/// Ensures path is safe (no traversal, no absolute paths).
pub fn validate_bundle_path(path: &Path) -> Result<(), PathError> {
    validate_path(path)
}

/// Reads packets, copies artifacts, builds bundle manifest.
pub fn build_bundle_from_packets(
    packet_paths: &[PathBuf],
    artifact_map: HashMap<PacketId, Vec<(PathBuf, PathBuf)>>,
    bundle_path: &Path,
) -> Result<BundleManifest, FsError> {
    if packet_paths.is_empty() {
        return Err(FsError::InvalidInput(
            "bundle requires at least one packet path".to_string(),
        ));
    }

    // Create bundle directory structure
    create_bundle_dir(bundle_path)?;

    let mut packets: Vec<Packet> = Vec::new();
    let mut artifacts: Vec<Artifact> = Vec::new();
    let mut seen_ids: HashMap<String, Packet> = HashMap::new();

    // Load and validate packets
    for path in packet_paths {
        let packet = read_packet(path)?;
        validate_packet(&packet)?;

        // Check for duplicate packet IDs
        if let Some(existing) = seen_ids.get(packet.packet_id.as_str()) {
            let existing_json = canonicalize_json(existing)?;
            let new_json = canonicalize_json(&packet)?;
            let existing_digest = compute_sha256(existing_json.as_bytes());
            let new_digest = compute_sha256(new_json.as_bytes());
            if existing_digest != new_digest {
                return Err(FsError::BundleCreationFailed(format!(
                    "conflicting packet content for id {}",
                    packet.packet_id
                )));
            }
        } else {
            seen_ids.insert(packet.packet_id.as_str().to_string(), packet.clone());
        }

        let packet_root = path
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
            .map(Path::to_path_buf)
            .unwrap_or_else(|| PathBuf::from("."));
        let sanitized_id = sanitize_path_component(packet.packet_id.as_str())?;

        // Copy attachments as artifacts
        for attachment in &packet.projections.attachments {
            let original_path = packet_root.join(&attachment.relative_path);
            let bundle_artifact_path = PathBuf::from("packets")
                .join(&sanitized_id)
                .join("artifacts")
                .join(Path::new(&attachment.relative_path));
            let dest_path = bundle_path.join(&bundle_artifact_path);

            if let Some(parent) = dest_path.parent() {
                fs::create_dir_all(parent).map_err(|source| FsError::IoError {
                    path: parent.display().to_string(),
                    source,
                })?;
            }

            // Read artifact data
            let data = read_bytes(&original_path)?;

            // Verify digest if present
            verify_digest(&data, attachment.sha256.as_str())?;

            fs::write(&dest_path, &data).map_err(|source| FsError::IoError {
                path: dest_path.display().to_string(),
                source,
            })?;

            artifacts.push(Artifact {
                packet_id: packet.packet_id.clone(),
                relative_path: attachment.relative_path.clone(),
                role: attachment.role,
                data,
            });
        }

        // Copy additional artifacts from artifact_map
        if let Some(additional_artifacts) = artifact_map.get(&packet.packet_id) {
            for (source_path, relative_dest) in additional_artifacts {
                copy_artifact_to_bundle(
                    source_path,
                    bundle_path,
                    &packet.packet_id,
                    relative_dest,
                )?;
                let data = read_bytes(source_path)?;
                artifacts.push(Artifact {
                    packet_id: packet.packet_id.clone(),
                    relative_path: to_forward_slash(relative_dest),
                    role: AttachmentRole::PlainText,
                    data,
                });
            }
        }

        // Write packet file
        let packet_path = PathBuf::from("packets")
            .join(&sanitized_id)
            .join("packet.eb.json");
        let packet_abs = bundle_path.join(&packet_path);
        write_packet(&packet_abs, &packet)?;

        packets.push(packet);
    }

    // Build manifest
    let manifest = build_bundle_manifest(&packets, &artifacts)?;

    // Write manifest
    write_bundle_manifest(bundle_path, &manifest)?;

    Ok(manifest)
}

/// Builder for incremental bundle construction.
pub struct BundleBuilder {
    bundle_path: PathBuf,
    packets: Vec<Packet>,
    artifacts: Vec<Artifact>,
}

impl BundleBuilder {
    /// Creates a new BundleBuilder.
    pub fn new(bundle_path: &Path) -> Result<Self, FsError> {
        create_bundle_dir(bundle_path)?;

        Ok(Self {
            bundle_path: bundle_path.to_path_buf(),
            packets: Vec::new(),
            artifacts: Vec::new(),
        })
    }

    /// Adds a packet with its artifacts to the bundle.
    pub fn add_packet(
        &mut self,
        packet: Packet,
        artifacts: Vec<(PathBuf, PathBuf)>,
    ) -> Result<(), FsError> {
        validate_packet(&packet)?;
        let sanitized_id = sanitize_path_component(packet.packet_id.as_str())?;

        // Copy attachments as artifacts
        for attachment in &packet.projections.attachments {
            let bundle_artifact_path = PathBuf::from("packets")
                .join(&sanitized_id)
                .join(Path::new(&attachment.relative_path));
            let dest_path = self.bundle_path.join(&bundle_artifact_path);

            if let Some(parent) = dest_path.parent() {
                fs::create_dir_all(parent).map_err(|source| FsError::IoError {
                    path: parent.display().to_string(),
                    source,
                })?;
            }

            let data = read_bytes(Path::new(&attachment.relative_path))?;

            // Verify digest if present
            verify_digest(&data, attachment.sha256.as_str())?;

            fs::write(&dest_path, &data).map_err(|source| FsError::IoError {
                path: dest_path.display().to_string(),
                source,
            })?;

            self.artifacts.push(Artifact {
                packet_id: packet.packet_id.clone(),
                relative_path: to_forward_slash(&bundle_artifact_path),
                role: attachment.role,
                data,
            });
        }

        // Copy additional artifacts
        for (source_path, relative_dest) in artifacts {
            copy_artifact_to_bundle(
                &source_path,
                &self.bundle_path,
                &packet.packet_id,
                &relative_dest,
            )?;
            let data = read_bytes(&source_path)?;
            let bundle_artifact_path = PathBuf::from("packets")
                .join(&sanitized_id)
                .join("artifacts")
                .join(&relative_dest);
            self.artifacts.push(Artifact {
                packet_id: packet.packet_id.clone(),
                relative_path: to_forward_slash(&bundle_artifact_path),
                role: AttachmentRole::PlainText,
                data,
            });
        }

        // Write packet file
        let packet_path = PathBuf::from("packets")
            .join(&sanitized_id)
            .join("packet.eb.json");
        let packet_abs = self.bundle_path.join(&packet_path);
        write_packet(&packet_abs, &packet)?;

        self.packets.push(packet);

        Ok(())
    }

    /// Finalizes the bundle and writes the manifest.
    pub fn finalize(&mut self) -> Result<BundleManifest, FsError> {
        // Build manifest
        let manifest = build_bundle_manifest(&self.packets, &self.artifacts)?;

        // Write manifest
        write_bundle_manifest(&self.bundle_path, &manifest)?;

        Ok(manifest)
    }
}

/// Loads a bundle from a directory.
pub fn load_bundle(dir: &Path) -> Result<LoadedBundle, FsError> {
    let manifest_path = dir.join("bundle.eb.json");
    let manifest_contents = read_to_string(&manifest_path)?;
    let manifest: BundleManifest =
        serde_json::from_str(&manifest_contents).map_err(|source| FsError::InvalidJson {
            path: manifest_path.display().to_string(),
            source,
        })?;

    let mut packets = Vec::new();
    for entry in &manifest.packets {
        let packet_path = dir.join(&entry.relative_path);
        packets.push(read_packet(&packet_path)?);
    }

    Ok(LoadedBundle { manifest, packets })
}

/// Loads a target (packet or bundle).
pub fn load_target(path: &Path) -> Result<LoadedTarget, FsError> {
    if path.is_dir() {
        Ok(LoadedTarget::Bundle(load_bundle(path)?))
    } else {
        Ok(LoadedTarget::Packet(read_packet(path)?))
    }
}

/// Validates a target (packet or bundle).
pub fn validate_target(path: &Path, mode: ValidationMode) -> Result<(), FsError> {
    if path.is_dir() {
        validate_bundle_dir(path, mode)
    } else {
        validate_packet_file(path, mode)
    }
}

/// Validates a packet file.
pub fn validate_packet_file(path: &Path, mode: ValidationMode) -> Result<(), FsError> {
    let packet = read_packet(path)?;
    validate_packet(&packet)?;

    // In schema-only mode, skip file existence checks
    if matches!(mode, ValidationMode::SchemaOnly) {
        return Ok(());
    }

    // Validate attachments exist and have correct digests
    let base_dir = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .map(Path::to_path_buf)
        .unwrap_or_else(|| PathBuf::from("."));

    for attachment in &packet.projections.attachments {
        let artifact_path = base_dir.join(&attachment.relative_path);
        if !artifact_path.is_file() {
            return Err(FsError::InvalidInput(format!(
                "missing artifact {}",
                artifact_path.display()
            )));
        }

        let bytes = read_bytes(&artifact_path)?;
        verify_digest(&bytes, attachment.sha256.as_str())?;
    }

    Ok(())
}

/// Validates a bundle directory.
pub fn validate_bundle_dir(dir: &Path, mode: ValidationMode) -> Result<(), FsError> {
    let LoadedBundle { manifest, packets } = load_bundle(dir)?;

    // Collect packet data for validation
    let mut packet_data_vec: Vec<(PacketId, Vec<u8>)> = Vec::new();
    for packet in &packets {
        let json = canonicalize_json(packet)?;
        packet_data_vec.push((packet.packet_id.clone(), json.into_bytes()));
    }

    // In schema-only mode, skip artifact validation
    if matches!(mode, ValidationMode::SchemaOnly) {
        // Validate packets only
        for packet in &packets {
            validate_packet(packet)?;
        }
        return Ok(());
    }

    // Collect artifact data for validation
    // Use the manifest-relative path as the key (not the full path) so it matches
    // what validate_artifact_inventory looks up via entry.relative_path.
    let mut artifact_data_vec: Vec<(PathBuf, Vec<u8>)> = Vec::new();
    for entry in &manifest.artifacts {
        let artifact_path = dir.join(&entry.relative_path);
        let data = read_bytes(&artifact_path)?;
        artifact_data_vec.push((PathBuf::from(&entry.relative_path), data));
    }

    // Create a temporary bundle for validation
    let bundle = evidencebus_types::Bundle::with_current_timestamp(
        evidencebus_types::SchemaVersion::new("0.1.0"),
        PacketId::new("validation-bundle")
            .map_err(|e| FsError::BundleCreationFailed(format!("invalid bundle id: {e}")))?,
        manifest,
        evidencebus_types::BundleSummary::new(
            packets.len() as u32,
            artifact_data_vec.len() as u32,
            Default::default(),
            Default::default(),
        ),
    );

    // Convert to slices of references for validation
    let packet_data: Vec<(&PacketId, &[u8])> = packet_data_vec
        .iter()
        .map(|(id, data)| (id, data.as_slice()))
        .collect();
    let artifact_data: Vec<(&Path, &[u8])> = artifact_data_vec
        .iter()
        .map(|(path, data)| (path.as_path(), data.as_slice()))
        .collect();

    // Use the validation crate to validate the bundle
    validate_bundle(&bundle, &packet_data, &artifact_data)?;

    Ok(())
}

/// Builds a bundle from packet paths.
pub fn build_bundle(
    packet_paths: &[PathBuf],
    output_dir: &Path,
) -> Result<BundleManifest, FsError> {
    build_bundle_from_packets(packet_paths, HashMap::new(), output_dir)
}

/// Reads a file to string.
fn read_to_string(path: &Path) -> Result<String, FsError> {
    fs::read_to_string(path).map_err(|source| FsError::IoError {
        path: path.display().to_string(),
        source,
    })
}

/// Reads a file to bytes.
fn read_bytes(path: &Path) -> Result<Vec<u8>, FsError> {
    fs::read(path).map_err(|source| FsError::IoError {
        path: path.display().to_string(),
        source,
    })
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use evidencebus_codes::PacketStatus;
    use evidencebus_types::{SchemaVersion, Subject, Summary, VcsKind};
    use tempfile::tempdir;

    use super::*;

    #[test]
    fn test_read_write_packet() -> Result<(), Box<dyn std::error::Error>> {
        let dir = tempdir()?;
        let packet_path = dir.path().join("pkt-test.eb.json");

        // Create a simple test packet
        let packet = Packet::new(
            SchemaVersion::new("0.1.0"),
            PacketId::new("pkt-test")?,
            evidencebus_types::Producer::new("test-tool", "1.0.0"),
            Subject::new(VcsKind::Git, "owner/repo", "abc123", "def456"),
            Summary::new(PacketStatus::Pass, "Test packet", "Test summary"),
        );

        write_packet(&packet_path, &packet)?;
        let loaded = read_packet(&packet_path)?;

        assert_eq!(loaded.packet_id.as_str(), "pkt-test");
        Ok(())
    }

    #[test]
    fn test_path_validation_rejects_absolute() {
        let path = if cfg!(windows) {
            PathBuf::from("C:\\absolute\\path")
        } else {
            PathBuf::from("/absolute/path")
        };
        assert!(validate_bundle_path(&path).is_err());
    }

    #[test]
    fn test_path_validation_rejects_traversal() {
        let path = PathBuf::from("safe/../unsafe");
        assert!(validate_bundle_path(&path).is_err());
    }

    #[test]
    fn test_path_validation_accepts_safe() {
        let path = PathBuf::from("safe/relative/path");
        assert!(validate_bundle_path(&path).is_ok());
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
        assert!(sanitize_path_component("..").is_err());
        assert!(sanitize_path_component("test\0packet").is_err());
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
        let absolute_path = if cfg!(windows) {
            Path::new("C:\\absolute")
        } else {
            Path::new("/absolute")
        };
        assert!(normalize_relative_path(absolute_path).is_err());
        assert!(normalize_relative_path(Path::new("safe/../unsafe")).is_err());
    }

    #[test]
    fn test_create_bundle_dir() -> Result<(), Box<dyn std::error::Error>> {
        let dir = tempdir()?;
        let bundle_path = dir.path().join("test-bundle");

        create_bundle_dir(&bundle_path)?;

        assert!(bundle_path.exists());
        assert!(bundle_path.join("packets").exists());
        Ok(())
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
}
