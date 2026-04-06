#![allow(clippy::unwrap_used)]
//! BDD-style tests for evidencebus-fs filesystem operations.
//!
//! These tests follow the Given-When-Then pattern to ensure comprehensive
//! coverage of filesystem operations for packets, bundles, and artifacts.

use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};

use evidencebus_codes::{FindingSeverity, PacketStatus, ValidationMode};
use evidencebus_digest::compute_sha256;
use evidencebus_fixtures::PacketBuilder;
use evidencebus_fs::{
    build_bundle, build_bundle_from_packets, copy_artifact_to_bundle, create_bundle_dir,
    load_bundle, load_target, read_bundle_manifest, read_packet, validate_bundle_dir,
    validate_bundle_path, validate_packet_file, validate_target, write_bundle_manifest,
    write_packet, BundleBuilder, FsError, LoadedTarget,
};
use evidencebus_types::{AttachmentRole, Digest, PacketId, VcsKind};
use tempfile::tempdir;

fn fixture_path(path: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join("fixtures")
        .join(path)
}

// ============================================================================
// Packet Reading Tests
// ============================================================================

mod packet_reading {
    use super::*;

    #[test]
    fn given_valid_packet_file_when_read_then_returns_packet() {
        // Given: A valid packet file exists on the filesystem
        let dir = tempdir().unwrap();
        let packet_path = dir.path().join("pkt-test.eb.json");

        let packet = PacketBuilder::new()
            .with_id("pkt-test")
            .with_producer("test-tool", "1.0.0")
            .with_subject(VcsKind::Git, "owner/repo", "abc123")
            .with_status(PacketStatus::Pass)
            .with_title("Test Packet")
            .with_summary("Test summary")
            .build()
            .unwrap();

        fs::write(&packet_path, serde_json::to_string_pretty(&packet).unwrap()).unwrap();

        // When: The packet file is read
        let result = read_packet(&packet_path);

        // Then: The packet is successfully loaded with correct data
        assert!(result.is_ok());
        let loaded = result.unwrap();
        assert_eq!(loaded.packet_id.as_str(), "pkt-test");
        assert_eq!(loaded.producer.tool_name, "test-tool");
        assert_eq!(loaded.producer.tool_version, "1.0.0");
    }

    #[test]
    fn given_nonexistent_packet_file_when_read_then_returns_io_error() {
        // Given: A path to a non-existent packet file
        let dir = tempdir().unwrap();
        let packet_path = dir.path().join("nonexistent-packet.json");

        // When: The packet file is read
        let result = read_packet(&packet_path);

        // Then: An IO error is returned
        assert!(result.is_err());
        match result.unwrap_err() {
            FsError::IoError { path, .. } => {
                assert!(path.contains("nonexistent-packet.json"));
            }
            _ => panic!("Expected IoError"),
        }
    }

    #[test]
    fn given_invalid_json_packet_file_when_read_then_returns_invalid_json_error() {
        // Given: A file containing invalid JSON
        let dir = tempdir().unwrap();
        let packet_path = dir.path().join("invalid.json");
        fs::write(&packet_path, "{ invalid json }").unwrap();

        // When: The packet file is read
        let result = read_packet(&packet_path);

        // Then: An InvalidJson error is returned
        assert!(result.is_err());
        match result.unwrap_err() {
            FsError::InvalidJson { path, .. } => {
                assert!(path.contains("invalid.json"));
            }
            _ => panic!("Expected InvalidJson error"),
        }
    }

    #[test]
    fn given_malformed_packet_json_when_read_then_returns_invalid_json_error() {
        // Given: A file containing JSON that doesn't match the packet schema
        let dir = tempdir().unwrap();
        let packet_path = dir.path().join("malformed.json");
        fs::write(&packet_path, r#"{"not": "a packet"}"#).unwrap();

        // When: The packet file is read
        let result = read_packet(&packet_path);

        // Then: An InvalidJson error is returned
        assert!(result.is_err());
        match result.unwrap_err() {
            FsError::InvalidJson { .. } => {}
            _ => panic!("Expected InvalidJson error"),
        }
    }
}

// ============================================================================
// Packet Writing Tests
// ============================================================================

mod packet_writing {
    use super::*;

    #[test]
    fn given_valid_packet_when_written_to_nonexistent_dir_then_creates_dir_and_writes_file() {
        // Given: A valid packet and a path to a non-existent directory
        let dir = tempdir().unwrap();
        let packet_path = dir.path().join("subdir/pkt-test.eb.json");

        let packet = PacketBuilder::new()
            .with_id("pkt-test")
            .with_producer("test-tool", "1.0.0")
            .with_subject(VcsKind::Git, "owner/repo", "abc123")
            .with_status(PacketStatus::Pass)
            .with_title("Test Packet")
            .with_summary("Test summary")
            .build()
            .unwrap();

        // When: The packet is written
        let result = write_packet(&packet_path, &packet);

        // Then: The directory is created and the file is written
        assert!(result.is_ok());
        assert!(packet_path.exists());
        assert!(packet_path.parent().unwrap().exists());
    }

    #[test]
    fn given_valid_packet_when_written_then_creates_canonical_json() {
        // Given: A valid packet and a path
        let dir = tempdir().unwrap();
        let packet_path = dir.path().join("pkt-test.eb.json");

        let packet = PacketBuilder::new()
            .with_id("pkt-test")
            .with_producer("test-tool", "1.0.0")
            .with_subject(VcsKind::Git, "owner/repo", "abc123")
            .with_status(PacketStatus::Pass)
            .with_title("Test Packet")
            .with_summary("Test summary")
            .build()
            .unwrap();

        // When: The packet is written
        write_packet(&packet_path, &packet).unwrap();

        // Then: The file contains valid canonical JSON
        let contents = fs::read_to_string(&packet_path).unwrap();
        let loaded: serde_json::Value = serde_json::from_str(&contents).unwrap();
        assert_eq!(loaded["packet_id"], "pkt-test");
    }

    #[test]
    fn given_packet_with_attachments_when_written_then_file_is_created() {
        // Given: A packet with attachments
        let dir = tempdir().unwrap();
        let packet_path = dir.path().join("pkt-test.eb.json");

        let packet = PacketBuilder::new()
            .with_id("pkt-test")
            .with_producer("test-tool", "1.0.0")
            .with_subject(VcsKind::Git, "owner/repo", "abc123")
            .with_status(PacketStatus::Pass)
            .with_title("Test Packet")
            .with_summary("Test summary")
            .add_attachment(AttachmentRole::PlainText, "report.txt", "text/plain")
            .build()
            .unwrap();

        // When: The packet is written
        let result = write_packet(&packet_path, &packet);

        // Then: The packet file is created successfully
        assert!(result.is_ok());
        assert!(packet_path.exists());
    }

    #[test]
    fn given_packet_when_written_and_read_then_data_is_preserved() {
        // Given: A valid packet
        let dir = tempdir().unwrap();
        let packet_path = dir.path().join("pkt-test.eb.json");

        let original_packet = PacketBuilder::new()
            .with_id("pkt-test")
            .with_producer("test-tool", "1.0.0")
            .with_subject(VcsKind::Git, "owner/repo", "abc123")
            .with_status(PacketStatus::Pass)
            .with_title("Test Packet")
            .with_summary("Test summary")
            .add_assertion("assert-1", PacketStatus::Pass, "Assertion passed")
            .add_finding("find-1", FindingSeverity::Warning, "Warning message")
            .add_metric("coverage", 85.5, Some("%"))
            .build()
            .unwrap();

        // When: The packet is written and then read back
        write_packet(&packet_path, &original_packet).unwrap();
        let loaded_packet = read_packet(&packet_path).unwrap();

        // Then: All data is preserved
        assert_eq!(
            original_packet.packet_id.as_str(),
            loaded_packet.packet_id.as_str()
        );
        assert_eq!(original_packet.summary.status, loaded_packet.summary.status);
        assert_eq!(
            original_packet.projections.assertions.len(),
            loaded_packet.projections.assertions.len()
        );
        assert_eq!(
            original_packet.projections.findings.len(),
            loaded_packet.projections.findings.len()
        );
        assert_eq!(
            original_packet.projections.metrics.len(),
            loaded_packet.projections.metrics.len()
        );
        assert_eq!(
            original_packet.producer.tool_name,
            loaded_packet.producer.tool_name
        );
        assert_eq!(
            original_packet.producer.tool_version,
            loaded_packet.producer.tool_version
        );
    }
}

// ============================================================================
// Bundle Manifest Reading Tests
// ============================================================================

mod bundle_manifest_reading {
    use super::*;

    #[test]
    fn given_valid_bundle_manifest_when_read_then_returns_manifest() {
        // Given: A valid bundle manifest file exists
        let dir = tempdir().unwrap();
        let bundle_path = dir.path().join("test-bundle");
        fs::create_dir_all(&bundle_path).unwrap();

        let manifest_path = bundle_path.join("bundle.eb.json");
        let manifest_json = r#"{
            "packets": [],
            "artifacts": [],
            "integrity": {
                "manifest_digest": "0000000000000000000000000000000000000000000000000000000000000000",
                "packet_digests": {},
                "artifact_digests": {}
            }
        }"#;
        fs::write(&manifest_path, manifest_json).unwrap();

        // When: The bundle manifest is read
        let result = read_bundle_manifest(&bundle_path);

        // Then: The manifest is successfully loaded
        assert!(result.is_ok());
        let manifest = result.unwrap();
        assert_eq!(manifest.packets.len(), 0);
        assert_eq!(manifest.artifacts.len(), 0);
    }

    #[test]
    fn given_nonexistent_bundle_manifest_when_read_then_returns_io_error() {
        // Given: A path to a non-existent bundle directory
        let dir = tempdir().unwrap();
        let bundle_path = dir.path().join("nonexistent-bundle");

        // When: The bundle manifest is read
        let result = read_bundle_manifest(&bundle_path);

        // Then: An IO error is returned
        assert!(result.is_err());
        match result.unwrap_err() {
            FsError::IoError { .. } => {}
            _ => panic!("Expected IoError"),
        }
    }

    #[test]
    fn given_invalid_json_manifest_when_read_then_returns_invalid_json_error() {
        // Given: A bundle directory with invalid JSON manifest
        let dir = tempdir().unwrap();
        let bundle_path = dir.path().join("test-bundle");
        fs::create_dir_all(&bundle_path).unwrap();

        let manifest_path = bundle_path.join("bundle.eb.json");
        fs::write(&manifest_path, "{ invalid json }").unwrap();

        // When: The bundle manifest is read
        let result = read_bundle_manifest(&bundle_path);

        // Then: An InvalidJson error is returned
        assert!(result.is_err());
        match result.unwrap_err() {
            FsError::InvalidJson { .. } => {}
            _ => panic!("Expected InvalidJson error"),
        }
    }
}

// ============================================================================
// Bundle Manifest Writing Tests
// ============================================================================

mod bundle_manifest_writing {
    use super::*;

    #[test]
    fn given_valid_manifest_when_written_then_creates_file() {
        // Given: A valid bundle manifest and bundle path
        let dir = tempdir().unwrap();
        let bundle_path = dir.path().join("test-bundle");
        fs::create_dir_all(&bundle_path).unwrap();

        let manifest = evidencebus_types::BundleManifest::new(
            vec![],
            vec![],
            evidencebus_types::IntegrityMetadata::new(
                Digest::new("0000000000000000000000000000000000000000000000000000000000000000")
                    .unwrap(),
                HashMap::new(),
                HashMap::new(),
            ),
        );

        // When: The manifest is written
        let result = write_bundle_manifest(&bundle_path, &manifest);

        // Then: The manifest file is created
        assert!(result.is_ok());
        let manifest_path = bundle_path.join("bundle.eb.json");
        assert!(manifest_path.exists());
    }

    #[test]
    fn given_manifest_when_written_and_read_then_data_is_preserved() {
        // Given: A valid bundle manifest
        let dir = tempdir().unwrap();
        let bundle_path = dir.path().join("test-bundle");
        fs::create_dir_all(&bundle_path).unwrap();

        let original_manifest = evidencebus_types::BundleManifest::new(
            vec![],
            vec![],
            evidencebus_types::IntegrityMetadata::new(
                Digest::new("0000000000000000000000000000000000000000000000000000000000000000")
                    .unwrap(),
                HashMap::new(),
                HashMap::new(),
            ),
        );

        // When: The manifest is written and then read back
        write_bundle_manifest(&bundle_path, &original_manifest).unwrap();
        let loaded_manifest = read_bundle_manifest(&bundle_path).unwrap();

        // Then: All data is preserved
        assert_eq!(
            original_manifest.packets.len(),
            loaded_manifest.packets.len()
        );
        assert_eq!(
            original_manifest.artifacts.len(),
            loaded_manifest.artifacts.len()
        );
    }
}

// ============================================================================
// Bundle Directory Creation Tests
// ============================================================================

mod bundle_directory_creation {
    use super::*;

    #[test]
    fn given_nonexistent_path_when_creating_bundle_dir_then_creates_structure() {
        // Given: A path to a non-existent bundle directory
        let dir = tempdir().unwrap();
        let bundle_path = dir.path().join("test-bundle");

        // When: The bundle directory structure is created
        let result = create_bundle_dir(&bundle_path);

        // Then: The bundle directory and packets subdirectory are created
        assert!(result.is_ok());
        assert!(bundle_path.exists());
        assert!(bundle_path.is_dir());
        assert!(bundle_path.join("packets").exists());
        assert!(bundle_path.join("packets").is_dir());
    }

    #[test]
    fn given_nested_path_when_creating_bundle_dir_then_creates_all_parents() {
        // Given: A nested path for the bundle directory
        let dir = tempdir().unwrap();
        let bundle_path = dir.path().join("level1/level2/test-bundle");

        // When: The bundle directory structure is created
        let result = create_bundle_dir(&bundle_path);

        // Then: All parent directories are created
        assert!(result.is_ok());
        assert!(bundle_path.exists());
        assert!(bundle_path.join("packets").exists());
    }

    #[test]
    fn given_existing_bundle_dir_when_creating_then_succeeds() {
        // Given: An existing bundle directory structure
        let dir = tempdir().unwrap();
        let bundle_path = dir.path().join("test-bundle");
        create_bundle_dir(&bundle_path).unwrap();

        // When: The bundle directory structure is created again
        let result = create_bundle_dir(&bundle_path);

        // Then: The operation succeeds
        assert!(result.is_ok());
    }
}

// ============================================================================
// Artifact Copying Tests
// ============================================================================

mod artifact_copying {
    use super::*;

    #[test]
    fn given_valid_artifact_when_copied_to_bundle_then_succeeds() {
        // Given: A valid artifact file and bundle directory
        let dir = tempdir().unwrap();
        let bundle_path = dir.path().join("test-bundle");
        create_bundle_dir(&bundle_path).unwrap();

        let artifact_dir = dir.path().join("artifacts");
        fs::create_dir_all(&artifact_dir).unwrap();
        let source_path = artifact_dir.join("test-artifact.txt");
        fs::write(&source_path, "test artifact content").unwrap();

        let packet_id = PacketId::new("pkt-test").unwrap();
        let relative_dest = Path::new("test-artifact.txt");

        // When: The artifact is copied to the bundle
        let result = copy_artifact_to_bundle(&source_path, &bundle_path, &packet_id, relative_dest);

        // Then: The artifact is copied to the correct location
        assert!(result.is_ok());
        let dest_path = bundle_path
            .join("packets")
            .join("pkt-test")
            .join("artifacts")
            .join("test-artifact.txt");
        assert!(dest_path.exists());
        assert_eq!(
            fs::read_to_string(&dest_path).unwrap(),
            "test artifact content"
        );
    }

    #[test]
    fn given_artifact_with_nested_path_when_copied_then_creates_subdirs() {
        // Given: An artifact with a nested destination path
        let dir = tempdir().unwrap();
        let bundle_path = dir.path().join("test-bundle");
        create_bundle_dir(&bundle_path).unwrap();

        let artifact_dir = dir.path().join("artifacts");
        fs::create_dir_all(&artifact_dir).unwrap();
        let source_path = artifact_dir.join("test-artifact.txt");
        fs::write(&source_path, "test artifact content").unwrap();

        let packet_id = PacketId::new("pkt-test").unwrap();
        let relative_dest = Path::new("nested/path/artifact.txt");

        // When: The artifact is copied to the bundle
        let result = copy_artifact_to_bundle(&source_path, &bundle_path, &packet_id, relative_dest);

        // Then: The artifact is copied and subdirectories are created
        assert!(result.is_ok());
        let dest_path = bundle_path
            .join("packets")
            .join("pkt-test")
            .join("artifacts")
            .join("nested/path/artifact.txt");
        assert!(dest_path.exists());
        assert_eq!(
            fs::read_to_string(&dest_path).unwrap(),
            "test artifact content"
        );
    }

    #[test]
    fn given_nonexistent_source_artifact_when_copied_then_returns_error() {
        // Given: A path to a non-existent artifact file
        let dir = tempdir().unwrap();
        let bundle_path = dir.path().join("test-bundle");
        create_bundle_dir(&bundle_path).unwrap();

        let source_path = dir.path().join("nonexistent-artifact.txt");
        let packet_id = PacketId::new("pkt-test").unwrap();
        let relative_dest = Path::new("artifacts/test-artifact.txt");

        // When: The artifact is copied to the bundle
        let result = copy_artifact_to_bundle(&source_path, &bundle_path, &packet_id, relative_dest);

        // Then: An error is returned
        assert!(result.is_err());
        match result.unwrap_err() {
            FsError::ArtifactCopyFailed(_) => {}
            _ => panic!("Expected ArtifactCopyFailed error"),
        }
    }

    #[test]
    fn given_packet_id_with_special_chars_when_copied_then_sanitizes_id() {
        // Given: A packet ID with special characters
        let dir = tempdir().unwrap();
        let bundle_path = dir.path().join("test-bundle");
        create_bundle_dir(&bundle_path).unwrap();

        let artifact_dir = dir.path().join("artifacts");
        fs::create_dir_all(&artifact_dir).unwrap();
        let source_path = artifact_dir.join("test-artifact.txt");
        fs::write(&source_path, "test artifact content").unwrap();

        // Packet ID with spaces and special characters
        let packet_id = PacketId::new("pkt-test-with-spaces").unwrap();
        let relative_dest = Path::new("test-artifact.txt");

        // When: The artifact is copied to the bundle
        let result = copy_artifact_to_bundle(&source_path, &bundle_path, &packet_id, relative_dest);

        // Then: The packet ID is sanitized in the destination path
        assert!(result.is_ok());
        let dest_path = bundle_path
            .join("packets")
            .join("pkt-test-with-spaces") // Hyphens are allowed in PacketId
            .join("artifacts")
            .join("test-artifact.txt");
        assert!(dest_path.exists());
        assert_eq!(
            fs::read_to_string(&dest_path).unwrap(),
            "test artifact content"
        );
    }
}

// ============================================================================
// Bundle Building Tests
// ============================================================================

mod bundle_building {
    use super::*;

    #[test]
    fn given_single_packet_when_building_bundle_then_creates_complete_bundle() {
        // Given: A single packet file
        let dir = tempdir().unwrap();
        let packet_dir = dir.path().join("packets");
        fs::create_dir_all(&packet_dir).unwrap();

        let packet = PacketBuilder::new()
            .with_id("pkt-test")
            .with_producer("test-tool", "1.0.0")
            .with_subject(VcsKind::Git, "owner/repo", "abc123")
            .with_status(PacketStatus::Pass)
            .with_title("Test Packet")
            .with_summary("Test summary")
            .build()
            .unwrap();

        let packet_path = packet_dir.join("pkt-test.eb.json");
        write_packet(&packet_path, &packet).unwrap();

        let bundle_path = dir.path().join("test-bundle");

        // When: A bundle is built from the packet
        let result = build_bundle(&[packet_path], &bundle_path);

        // Then: A complete bundle is created
        assert!(result.is_ok());
        assert!(bundle_path.exists());
        assert!(bundle_path.join("bundle.eb.json").exists());
        assert!(bundle_path.join("packets/pkt-test/packet.eb.json").exists());
    }

    #[test]
    fn given_multiple_packets_when_building_bundle_then_includes_all_packets() {
        // Given: Multiple packet files
        let dir = tempdir().unwrap();
        let packet_dir = dir.path().join("packets");
        fs::create_dir_all(&packet_dir).unwrap();

        let packet1 = PacketBuilder::new()
            .with_id("pkt-test1")
            .with_producer("test-tool", "1.0.0")
            .with_subject(VcsKind::Git, "owner/repo", "abc123")
            .with_status(PacketStatus::Pass)
            .with_title("Test Packet 1")
            .with_summary("Test summary 1")
            .build()
            .unwrap();

        let packet2 = PacketBuilder::new()
            .with_id("pkt-test2")
            .with_producer("test-tool", "1.0.0")
            .with_subject(VcsKind::Git, "owner/repo", "abc123")
            .with_status(PacketStatus::Pass)
            .with_title("Test Packet 2")
            .with_summary("Test summary 2")
            .build()
            .unwrap();

        let packet1_path = packet_dir.join("pkt-test1.eb.json");
        let packet2_path = packet_dir.join("pkt-test2.eb.json");
        write_packet(&packet1_path, &packet1).unwrap();
        write_packet(&packet2_path, &packet2).unwrap();

        let bundle_path = dir.path().join("test-bundle");

        // When: A bundle is built from the packets
        let result = build_bundle(&[packet1_path, packet2_path], &bundle_path);

        // Then: All packets are included in the bundle
        assert!(result.is_ok());
        let manifest = result.unwrap();
        assert_eq!(manifest.packets.len(), 2);
        assert!(bundle_path
            .join("packets/pkt-test1/packet.eb.json")
            .exists());
        assert!(bundle_path
            .join("packets/pkt-test2/packet.eb.json")
            .exists());
    }

    #[test]
    fn given_empty_packet_list_when_building_bundle_then_returns_error() {
        // Given: An empty list of packet paths
        let dir = tempdir().unwrap();
        let bundle_path = dir.path().join("test-bundle");
        let packet_paths: Vec<PathBuf> = vec![];

        // When: A bundle is built with no packets
        let result = build_bundle(&packet_paths, &bundle_path);

        // Then: An InvalidInput error is returned
        assert!(result.is_err());
        match result.unwrap_err() {
            FsError::InvalidInput(msg) => {
                assert!(msg.contains("at least one packet"));
            }
            _ => panic!("Expected InvalidInput error"),
        }
    }

    #[test]
    fn given_duplicate_packet_ids_with_same_content_when_building_bundle_then_succeeds() {
        // Given: Two packets with the same ID and identical content
        let dir = tempdir().unwrap();
        let packet_dir = dir.path().join("packets");
        fs::create_dir_all(&packet_dir).unwrap();

        let packet = PacketBuilder::new()
            .with_id("pkt-test")
            .with_producer("test-tool", "1.0.0")
            .with_subject(VcsKind::Git, "owner/repo", "abc123")
            .with_status(PacketStatus::Pass)
            .with_title("Test Packet")
            .with_summary("Test summary")
            .build()
            .unwrap();

        let packet1_path = packet_dir.join("pkt-test1.eb.json");
        let packet2_path = packet_dir.join("pkt-test2.eb.json");
        write_packet(&packet1_path, &packet).unwrap();
        write_packet(&packet2_path, &packet).unwrap();

        let bundle_path = dir.path().join("test-bundle");

        // When: A bundle is built from the duplicate packets
        let result = build_bundle(&[packet1_path, packet2_path], &bundle_path);

        // Then: The bundle is created successfully (duplicates are ignored)
        assert!(result.is_ok());
    }

    #[test]
    fn given_duplicate_packet_ids_with_different_content_when_building_bundle_then_returns_error() {
        // Given: Two packets with the same ID but different content
        let dir = tempdir().unwrap();
        let packet_dir = dir.path().join("packets");
        fs::create_dir_all(&packet_dir).unwrap();

        let packet1 = PacketBuilder::new()
            .with_id("pkt-test")
            .with_producer("test-tool", "1.0.0")
            .with_subject(VcsKind::Git, "owner/repo", "abc123")
            .with_status(PacketStatus::Pass)
            .with_title("Test Packet 1")
            .with_summary("Test summary 1")
            .build()
            .unwrap();

        let packet2 = PacketBuilder::new()
            .with_id("pkt-test")
            .with_producer("test-tool", "1.0.0")
            .with_subject(VcsKind::Git, "owner/repo", "abc123")
            .with_status(PacketStatus::Pass)
            .with_title("Test Packet 2")
            .with_summary("Test summary 2")
            .build()
            .unwrap();

        let packet1_path = packet_dir.join("pkt-test1.eb.json");
        let packet2_path = packet_dir.join("pkt-test2.eb.json");
        write_packet(&packet1_path, &packet1).unwrap();
        write_packet(&packet2_path, &packet2).unwrap();

        let bundle_path = dir.path().join("test-bundle");

        // When: A bundle is built from the conflicting packets
        let result = build_bundle(&[packet1_path, packet2_path], &bundle_path);

        // Then: A BundleCreationFailed error is returned
        assert!(result.is_err());
        match result.unwrap_err() {
            FsError::BundleCreationFailed(msg) => {
                assert!(msg.contains("conflicting packet content"));
            }
            _ => panic!("Expected BundleCreationFailed error"),
        }
    }

    #[test]
    fn given_packet_with_artifacts_when_building_bundle_then_copies_artifacts() {
        // Given: A packet with attachment artifacts
        let dir = tempdir().unwrap();
        let packet_dir = dir.path().join("packets");
        fs::create_dir_all(&packet_dir).unwrap();

        // Create an artifact file
        let artifact_content = "test artifact content";
        let artifact_path = packet_dir.join("artifact.txt");
        fs::write(&artifact_path, artifact_content).unwrap();

        // Create packet with attachment
        let packet = PacketBuilder::new()
            .with_id("pkt-test")
            .with_producer("test-tool", "1.0.0")
            .with_subject(VcsKind::Git, "owner/repo", "abc123")
            .with_status(PacketStatus::Pass)
            .with_title("Test Packet")
            .with_summary("Test summary")
            .add_attachment(AttachmentRole::PlainText, "artifact.txt", "text/plain")
            .build()
            .unwrap();

        // Update attachment digest
        let digest = compute_sha256(artifact_content.as_bytes());
        let packet = evidencebus_types::Packet {
            projections: evidencebus_types::Projections {
                attachments: vec![evidencebus_types::Attachment {
                    role: AttachmentRole::PlainText,
                    relative_path: "artifact.txt".to_string(),
                    media_type: "text/plain".to_string(),
                    sha256: Digest::new(digest).unwrap(),
                    size: Some(artifact_content.len() as u64),
                    schema_id: None,
                }],
                ..packet.projections
            },
            ..packet
        };

        let packet_path = packet_dir.join("pkt-test.eb.json");
        write_packet(&packet_path, &packet).unwrap();

        let bundle_path = dir.path().join("test-bundle");

        // When: A bundle is built from the packet
        let result = build_bundle(&[packet_path], &bundle_path);

        // Then: The artifact is copied to the bundle
        assert!(result.is_ok());
        let bundle_artifact_path = bundle_path.join("packets/pkt-test/artifacts/artifact.txt");
        assert!(bundle_artifact_path.exists());
        assert_eq!(
            fs::read_to_string(&bundle_artifact_path).unwrap(),
            artifact_content
        );
    }

    #[test]
    fn given_additional_artifact_map_when_building_bundle_then_copies_additional_artifacts() {
        // Given: A packet and additional artifacts in an artifact map
        let dir = tempdir().unwrap();
        let packet_dir = dir.path().join("packets");
        fs::create_dir_all(&packet_dir).unwrap();

        let packet = PacketBuilder::new()
            .with_id("pkt-test")
            .with_producer("test-tool", "1.0.0")
            .with_subject(VcsKind::Git, "owner/repo", "abc123")
            .with_status(PacketStatus::Pass)
            .with_title("Test Packet")
            .with_summary("Test summary")
            .build()
            .unwrap();

        let packet_path = packet_dir.join("pkt-test.eb.json");
        write_packet(&packet_path, &packet).unwrap();

        // Create additional artifact
        let additional_artifact_dir = dir.path().join("additional");
        fs::create_dir_all(&additional_artifact_dir).unwrap();
        let additional_artifact_path = additional_artifact_dir.join("extra.txt");
        fs::write(&additional_artifact_path, "extra content").unwrap();

        let mut artifact_map = HashMap::new();
        artifact_map.insert(
            packet.packet_id.clone(),
            vec![(additional_artifact_path, PathBuf::from("extra.txt"))],
        );

        let bundle_path = dir.path().join("test-bundle");

        // When: A bundle is built with additional artifacts
        let result = build_bundle_from_packets(&[packet_path], artifact_map, &bundle_path);

        // Then: The additional artifacts are copied
        assert!(result.is_ok());
        let bundle_artifact_path = bundle_path.join("packets/pkt-test/artifacts/extra.txt");
        assert!(bundle_artifact_path.exists());
    }
}

// ============================================================================
// Bundle Builder Tests
// ============================================================================

mod bundle_builder_api {
    use super::*;

    #[test]
    fn given_new_bundle_builder_when_initialized_then_creates_bundle_structure() {
        // Given: A path for a new bundle
        let dir = tempdir().unwrap();
        let bundle_path = dir.path().join("test-bundle");

        // When: A new BundleBuilder is created
        let result = BundleBuilder::new(&bundle_path);

        // Then: The bundle directory structure is created
        assert!(result.is_ok());
        assert!(bundle_path.exists());
        assert!(bundle_path.join("packets").exists());
    }

    #[test]
    fn given_bundle_builder_when_adding_packet_then_packet_is_added() {
        // Given: A BundleBuilder and a packet
        let dir = tempdir().unwrap();
        let bundle_path = dir.path().join("test-bundle");
        let mut builder = BundleBuilder::new(&bundle_path).unwrap();

        let packet = PacketBuilder::new()
            .with_id("pkt-test")
            .with_producer("test-tool", "1.0.0")
            .with_subject(VcsKind::Git, "owner/repo", "abc123")
            .with_status(PacketStatus::Pass)
            .with_title("Test Packet")
            .with_summary("Test summary")
            .build()
            .unwrap();

        // When: The packet is added to the bundle
        let result = builder.add_packet(packet, vec![]);

        // Then: The packet is added successfully
        assert!(result.is_ok());
        assert!(bundle_path.join("packets/pkt-test/packet.eb.json").exists());
    }

    #[test]
    fn given_bundle_builder_when_finalizing_then_manifest_is_written() {
        // Given: A BundleBuilder with a packet
        let dir = tempdir().unwrap();
        let bundle_path = dir.path().join("test-bundle");
        let mut builder = BundleBuilder::new(&bundle_path).unwrap();

        let packet = PacketBuilder::new()
            .with_id("pkt-test")
            .with_producer("test-tool", "1.0.0")
            .with_subject(VcsKind::Git, "owner/repo", "abc123")
            .with_status(PacketStatus::Pass)
            .with_title("Test Packet")
            .with_summary("Test summary")
            .build()
            .unwrap();

        builder.add_packet(packet, vec![]).unwrap();

        // When: The bundle is finalized
        let result = builder.finalize();

        // Then: The manifest is written
        assert!(result.is_ok());
        assert!(bundle_path.join("bundle.eb.json").exists());
    }

    #[test]
    fn given_bundle_builder_when_adding_multiple_packets_then_all_are_included() {
        // Given: A BundleBuilder and multiple packets
        let dir = tempdir().unwrap();
        let bundle_path = dir.path().join("test-bundle");
        let mut builder = BundleBuilder::new(&bundle_path).unwrap();

        let packet1 = PacketBuilder::new()
            .with_id("pkt-test1")
            .with_producer("test-tool", "1.0.0")
            .with_subject(VcsKind::Git, "owner/repo", "abc123")
            .with_status(PacketStatus::Pass)
            .with_title("Test Packet 1")
            .with_summary("Test summary 1")
            .build()
            .unwrap();

        let packet2 = PacketBuilder::new()
            .with_id("pkt-test2")
            .with_producer("test-tool", "1.0.0")
            .with_subject(VcsKind::Git, "owner/repo", "abc123")
            .with_status(PacketStatus::Pass)
            .with_title("Test Packet 2")
            .with_summary("Test summary 2")
            .build()
            .unwrap();

        // When: Multiple packets are added
        builder.add_packet(packet1, vec![]).unwrap();
        builder.add_packet(packet2, vec![]).unwrap();
        let manifest = builder.finalize().unwrap();

        // Then: All packets are included in the manifest
        assert_eq!(manifest.packets.len(), 2);
    }
}

// ============================================================================
// Bundle Loading Tests
// ============================================================================

mod bundle_loading {
    use super::*;

    #[test]
    fn given_valid_bundle_directory_when_loading_then_returns_loaded_bundle() {
        // Given: A valid bundle directory
        let dir = tempdir().unwrap();
        let bundle_path = dir.path().join("test-bundle");

        let packet = PacketBuilder::new()
            .with_id("pkt-test")
            .with_producer("test-tool", "1.0.0")
            .with_subject(VcsKind::Git, "owner/repo", "abc123")
            .with_status(PacketStatus::Pass)
            .with_title("Test Packet")
            .with_summary("Test summary")
            .build()
            .unwrap();

        build_bundle(&[], &bundle_path).unwrap_err(); // Create directory structure
        create_bundle_dir(&bundle_path).unwrap();

        let packet_path = dir.path().join("pkt-test.eb.json");
        write_packet(&packet_path, &packet).unwrap();
        build_bundle(&[packet_path], &bundle_path).unwrap();

        // When: The bundle is loaded
        let result = load_bundle(&bundle_path);

        // Then: The bundle is loaded with manifest and packets
        assert!(result.is_ok());
        let loaded = result.unwrap();
        assert!(!loaded.packets.is_empty());
    }

    #[test]
    fn given_nonexistent_bundle_directory_when_loading_then_returns_io_error() {
        // Given: A path to a non-existent bundle directory
        let dir = tempdir().unwrap();
        let bundle_path = dir.path().join("nonexistent-bundle");

        // When: The bundle is loaded
        let result = load_bundle(&bundle_path);

        // Then: An IO error is returned
        assert!(result.is_err());
        match result.unwrap_err() {
            FsError::IoError { .. } => {}
            _ => panic!("Expected IoError"),
        }
    }
}

// ============================================================================
// Target Loading Tests
// ============================================================================

mod target_loading {
    use super::*;

    #[test]
    fn given_packet_file_when_loading_target_then_returns_packet() {
        // Given: A valid packet file
        let dir = tempdir().unwrap();
        let packet_path = dir.path().join("pkt-test.eb.json");

        let packet = PacketBuilder::new()
            .with_id("pkt-test")
            .with_producer("test-tool", "1.0.0")
            .with_subject(VcsKind::Git, "owner/repo", "abc123")
            .with_status(PacketStatus::Pass)
            .with_title("Test Packet")
            .with_summary("Test summary")
            .build()
            .unwrap();

        write_packet(&packet_path, &packet).unwrap();

        // When: The target is loaded
        let result = load_target(&packet_path);

        // Then: A Packet variant is returned
        assert!(result.is_ok());
        match result.unwrap() {
            LoadedTarget::Packet(loaded) => {
                assert_eq!(loaded.packet_id.as_str(), "pkt-test");
            }
            _ => panic!("Expected LoadedTarget::Packet"),
        }
    }

    #[test]
    fn given_bundle_directory_when_loading_target_then_returns_bundle() {
        // Given: A valid bundle directory
        let dir = tempdir().unwrap();
        let bundle_path = dir.path().join("test-bundle");

        let packet = PacketBuilder::new()
            .with_id("pkt-test")
            .with_producer("test-tool", "1.0.0")
            .with_subject(VcsKind::Git, "owner/repo", "abc123")
            .with_status(PacketStatus::Pass)
            .with_title("Test Packet")
            .with_summary("Test summary")
            .build()
            .unwrap();

        let packet_path = dir.path().join("pkt-test.eb.json");
        write_packet(&packet_path, &packet).unwrap();
        build_bundle(&[packet_path], &bundle_path).unwrap();

        // When: The target is loaded
        let result = load_target(&bundle_path);

        // Then: A Bundle variant is returned
        assert!(result.is_ok());
        match result.unwrap() {
            LoadedTarget::Bundle(loaded) => {
                assert!(!loaded.packets.is_empty());
            }
            _ => panic!("Expected LoadedTarget::Bundle"),
        }
    }
}

// ============================================================================
// Path Validation Tests
// ============================================================================

mod path_validation {
    use super::*;

    #[test]
    fn given_safe_relative_path_when_validating_then_succeeds() {
        // Given: A safe relative path
        let safe_path = PathBuf::from("safe/relative/path");

        // When: The path is validated
        let result = validate_bundle_path(&safe_path);

        // Then: Validation succeeds
        assert!(result.is_ok());
    }

    #[test]
    fn given_absolute_path_when_validating_then_returns_error() {
        // Given: An absolute path
        let absolute_path = if cfg!(windows) {
            PathBuf::from("C:\\absolute\\path")
        } else {
            PathBuf::from("/absolute/path")
        };

        // When: The path is validated
        let result = validate_bundle_path(&absolute_path);

        // Then: Validation fails
        assert!(result.is_err());
    }

    #[test]
    fn given_path_with_traversal_when_validating_then_returns_error() {
        // Given: A path with directory traversal
        let traversal_path = PathBuf::from("safe/../unsafe");

        // When: The path is validated
        let result = validate_bundle_path(&traversal_path);

        // Then: Validation fails
        assert!(result.is_err());
    }

    #[test]
    fn given_path_with_current_dir_when_validating_then_succeeds() {
        // Given: A path with current directory reference
        let path = PathBuf::from("./safe/path");

        // When: The path is validated
        let result = validate_bundle_path(&path);

        // Then: Validation succeeds (normalized)
        assert!(result.is_ok());
    }
}

// ============================================================================
// Packet Validation Tests
// ============================================================================

mod packet_validation {
    use super::*;

    #[test]
    fn given_valid_packet_file_when_validating_in_schema_mode_then_succeeds() {
        // Given: A valid packet file
        let dir = tempdir().unwrap();
        let packet_path = dir.path().join("pkt-test.eb.json");

        let packet = PacketBuilder::new()
            .with_id("pkt-test")
            .with_producer("test-tool", "1.0.0")
            .with_subject(VcsKind::Git, "owner/repo", "abc123")
            .with_status(PacketStatus::Pass)
            .with_title("Test Packet")
            .with_summary("Test summary")
            .build()
            .unwrap();

        write_packet(&packet_path, &packet).unwrap();

        // When: The packet is validated in schema-only mode
        let result = validate_packet_file(&packet_path, ValidationMode::SchemaOnly);

        // Then: Validation succeeds
        assert!(result.is_ok());
    }

    #[test]
    fn given_packet_with_missing_attachment_when_validating_in_full_mode_then_returns_error() {
        // Given: A packet with an attachment that doesn't exist
        let dir = tempdir().unwrap();
        let packet_path = dir.path().join("pkt-test.eb.json");

        let packet = PacketBuilder::new()
            .with_id("pkt-test")
            .with_producer("test-tool", "1.0.0")
            .with_subject(VcsKind::Git, "owner/repo", "abc123")
            .with_status(PacketStatus::Pass)
            .with_title("Test Packet")
            .with_summary("Test summary")
            .add_attachment(AttachmentRole::PlainText, "nonexistent.txt", "text/plain")
            .build()
            .unwrap();

        write_packet(&packet_path, &packet).unwrap();

        // When: The packet is validated in strict mode
        let result = validate_packet_file(&packet_path, ValidationMode::Strict);

        // Then: Validation fails with missing artifact error
        assert!(result.is_err());
        match result.unwrap_err() {
            FsError::InvalidInput(msg) => {
                assert!(msg.contains("missing artifact"));
            }
            _ => panic!("Expected InvalidInput error"),
        }
    }

    #[test]
    fn given_packet_with_invalid_digest_when_validating_in_strict_mode_then_returns_error() {
        // Given: A packet with an attachment that has an incorrect digest
        let dir = tempdir().unwrap();
        let packet_path = dir.path().join("pkt-test.eb.json");

        // Create artifact file
        let artifact_path = dir.path().join("artifact.txt");
        fs::write(&artifact_path, "actual content").unwrap();

        let packet = PacketBuilder::new()
            .with_id("pkt-test")
            .with_producer("test-tool", "1.0.0")
            .with_subject(VcsKind::Git, "owner/repo", "abc123")
            .with_status(PacketStatus::Pass)
            .with_title("Test Packet")
            .with_summary("Test summary")
            .add_attachment(AttachmentRole::PlainText, "artifact.txt", "text/plain")
            .build()
            .unwrap();

        // Manually set an incorrect digest (64 hex chars, but wrong value)
        let packet = evidencebus_types::Packet {
            projections: evidencebus_types::Projections {
                attachments: vec![evidencebus_types::Attachment {
                    role: AttachmentRole::PlainText,
                    relative_path: "artifact.txt".to_string(),
                    media_type: "text/plain".to_string(),
                    sha256: Digest::new(
                        "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
                    )
                    .unwrap(),
                    size: None,
                    schema_id: None,
                }],
                ..packet.projections
            },
            ..packet
        };

        write_packet(&packet_path, &packet).unwrap();

        // When: The packet is validated in strict mode
        let result = validate_packet_file(&packet_path, ValidationMode::Strict);

        // Then: Validation fails with digest error
        assert!(result.is_err());
        match result.unwrap_err() {
            FsError::DigestError(_) => {}
            _ => panic!("Expected DigestError"),
        }
    }
}

// ============================================================================
// Bundle Validation Tests
// ============================================================================

mod bundle_validation {
    use super::*;

    #[test]
    fn given_valid_bundle_when_validating_in_schema_mode_then_succeeds() {
        // Given: A valid bundle
        let dir = tempdir().unwrap();
        let bundle_path = dir.path().join("test-bundle");

        let packet = PacketBuilder::new()
            .with_id("pkt-test")
            .with_producer("test-tool", "1.0.0")
            .with_subject(VcsKind::Git, "owner/repo", "abc123")
            .with_status(PacketStatus::Pass)
            .with_title("Test Packet")
            .with_summary("Test summary")
            .build()
            .unwrap();

        let packet_path = dir.path().join("pkt-test.eb.json");
        write_packet(&packet_path, &packet).unwrap();
        build_bundle(&[packet_path], &bundle_path).unwrap();

        // When: The bundle is validated in schema-only mode
        let result = validate_bundle_dir(&bundle_path, ValidationMode::SchemaOnly);

        // Then: Validation succeeds
        assert!(result.is_ok());
    }

    #[test]
    fn given_fixture_packets_when_building_bundle_then_artifacts_and_digests_roundtrip() {
        // Given: Real fixture packets that carry attachment artifacts
        let dir = tempdir().unwrap();
        let bundle_path = dir.path().join("fixture-bundle");

        let packet_paths = vec![
            fixture_path("packets/perfgate/pkt-perfgate.eb.json"),
            fixture_path("packets/faultline/pkt-faultline.eb.json"),
        ];

        // When: A fixture bundle is built
        build_bundle(&packet_paths, &bundle_path).unwrap();

        // Then: Bundle manifest matches expected packet files
        let manifest = read_bundle_manifest(&bundle_path).unwrap();
        assert_eq!(manifest.packets.len(), 2);
        for packet_entry in &manifest.packets {
            let expected_path = format!("packets/{}/packet.eb.json", packet_entry.packet_id);
            assert_eq!(packet_entry.relative_path, expected_path);
            assert!(bundle_path.join(&packet_entry.relative_path).is_file());
        }

        // And: Manifest artifact list matches fixture attachment layout
        let mut expected_artifact_paths = Vec::new();
        for packet_path in &packet_paths {
            let packet = read_packet(packet_path).unwrap();
            let packet_prefix = format!("packets/{}/artifacts/", packet.packet_id);
            for attachment in &packet.projections.attachments {
                expected_artifact_paths.push(format!(
                    "{}{}",
                    packet_prefix, attachment.relative_path
                ));
            }
        }
        assert_eq!(manifest.artifacts.len(), expected_artifact_paths.len());
        for expected_path in &expected_artifact_paths {
            assert!(
                manifest
                    .artifacts
                    .iter()
                    .any(|artifact| &artifact.relative_path == expected_path),
                "missing manifest artifact: {expected_path}"
            );
        }

        // And: Each artifact path is correctly rooted and has the expected digest
        for artifact in &manifest.artifacts {
            let expected_prefix = format!("packets/{}/artifacts/", artifact.packet_id);
            assert!(artifact.relative_path.starts_with(&expected_prefix));
            let packet_id = artifact.packet_id.as_str();
            assert!(!artifact.relative_path.starts_with(&format!(
                "packets/{}/artifacts/packets/{}/",
                packet_id, packet_id
            )));

            let artifact_path = bundle_path.join(&artifact.relative_path);
            let bytes = fs::read(&artifact_path).unwrap();
            assert_eq!(
                artifact.sha256.as_str(),
                compute_sha256(&bytes),
                "digest mismatch: {}",
                artifact.relative_path
            );
            assert!(artifact_path.is_file());
        }

        // And: Full bundle validation succeeds
        assert!(validate_bundle_dir(&bundle_path, ValidationMode::Strict).is_ok());
    }
}

// ============================================================================
// Target Validation Tests
// ============================================================================

mod target_validation {
    use super::*;

    #[test]
    fn given_packet_file_when_validating_target_then_validates_packet() {
        // Given: A valid packet file
        let dir = tempdir().unwrap();
        let packet_path = dir.path().join("pkt-test.eb.json");

        let packet = PacketBuilder::new()
            .with_id("pkt-test")
            .with_producer("test-tool", "1.0.0")
            .with_subject(VcsKind::Git, "owner/repo", "abc123")
            .with_status(PacketStatus::Pass)
            .with_title("Test Packet")
            .with_summary("Test summary")
            .build()
            .unwrap();

        write_packet(&packet_path, &packet).unwrap();

        // When: The target is validated
        let result = validate_target(&packet_path, ValidationMode::SchemaOnly);

        // Then: Validation succeeds
        assert!(result.is_ok());
    }

    #[test]
    fn given_bundle_directory_when_validating_target_then_validates_bundle() {
        // Given: A valid bundle directory
        let dir = tempdir().unwrap();
        let bundle_path = dir.path().join("test-bundle");

        let packet = PacketBuilder::new()
            .with_id("pkt-test")
            .with_producer("test-tool", "1.0.0")
            .with_subject(VcsKind::Git, "owner/repo", "abc123")
            .with_status(PacketStatus::Pass)
            .with_title("Test Packet")
            .with_summary("Test summary")
            .build()
            .unwrap();

        let packet_path = dir.path().join("pkt-test.eb.json");
        write_packet(&packet_path, &packet).unwrap();
        build_bundle(&[packet_path], &bundle_path).unwrap();

        // When: The target is validated
        let result = validate_target(&bundle_path, ValidationMode::SchemaOnly);

        // Then: Validation succeeds
        assert!(result.is_ok());
    }
}

// ============================================================================
// Edge Cases and Boundary Conditions
// ============================================================================

mod edge_cases {
    use super::*;

    #[test]
    fn given_empty_packet_id_when_sanitizing_then_returns_error() {
        // Given: An empty packet ID string
        let empty_id = "";

        // When: Attempting to create a PacketId with empty string
        let result = PacketId::new(empty_id);

        // Then: An error is returned
        assert!(result.is_err());
    }

    #[test]
    fn given_packet_id_with_path_traversal_when_sanitizing_then_returns_error() {
        // Given: A packet ID with path traversal characters
        let id_with_traversal = "../test-packet";

        // When: Attempting to create a PacketId with path traversal
        let result = PacketId::new(id_with_traversal);

        // Then: An error is returned
        assert!(result.is_err());
    }

    #[test]
    fn given_very_long_packet_id_when_using_then_succeeds() {
        // Given: A very long packet ID
        let long_id = "pkt-".repeat(100);

        // When: Creating a packet with the long ID
        let result = PacketId::new(&long_id);

        // Then: The ID is created successfully
        assert!(result.is_ok());
    }

    #[test]
    fn given_deeply_nested_path_when_creating_bundle_then_succeeds() {
        // Given: A deeply nested path
        let dir = tempdir().unwrap();
        let bundle_path = dir.path().join("a/b/c/d/e/f/g/h/bundle");

        // When: Creating the bundle directory
        let result = create_bundle_dir(&bundle_path);

        // Then: All directories are created
        assert!(result.is_ok());
        assert!(bundle_path.exists());
        assert!(bundle_path.join("packets").exists());
    }

    #[test]
    fn given_packet_with_many_attachments_when_writing_then_succeeds() {
        // Given: A packet with many attachments
        let dir = tempdir().unwrap();
        let packet_path = dir.path().join("pkt-test.eb.json");

        let mut builder = PacketBuilder::new()
            .with_id("pkt-test")
            .with_producer("test-tool", "1.0.0")
            .with_subject(VcsKind::Git, "owner/repo", "abc123")
            .with_status(PacketStatus::Pass)
            .with_title("Test Packet")
            .with_summary("Test summary");

        // Add many attachments
        for i in 0..20 {
            builder = builder.add_attachment(
                AttachmentRole::PlainText,
                &format!("artifact{}.txt", i),
                "text/plain",
            );
        }

        let packet = builder.build().unwrap();

        // When: The packet is written
        let result = write_packet(&packet_path, &packet);

        // Then: The packet is written successfully
        assert!(result.is_ok());
        assert!(packet_path.exists());
    }

    #[test]
    fn given_packet_with_unicode_in_id_when_using_then_succeeds() {
        // Given: A packet ID with Unicode characters
        let unicode_id = "pkt-测试-🎉";

        // When: Creating a packet with Unicode ID
        let result = PacketId::new(unicode_id);

        // Then: The ID is created successfully
        assert!(result.is_ok());
    }

    #[test]
    fn given_empty_artifact_content_when_copying_then_succeeds() {
        // Given: An artifact with empty content
        let dir = tempdir().unwrap();
        let bundle_path = dir.path().join("test-bundle");
        create_bundle_dir(&bundle_path).unwrap();

        let artifact_dir = dir.path().join("artifacts");
        fs::create_dir_all(&artifact_dir).unwrap();
        let source_path = artifact_dir.join("empty.txt");
        fs::write(&source_path, "").unwrap();

        let packet_id = PacketId::new("pkt-test").unwrap();
        let relative_dest = Path::new("empty.txt");

        // When: The empty artifact is copied
        let result = copy_artifact_to_bundle(&source_path, &bundle_path, &packet_id, relative_dest);

        // Then: The artifact is copied successfully
        assert!(result.is_ok());
        let dest_path = bundle_path
            .join("packets")
            .join("pkt-test")
            .join("artifacts")
            .join("empty.txt");
        assert!(dest_path.exists());
        assert_eq!(fs::read_to_string(&dest_path).unwrap(), "");
    }
}
