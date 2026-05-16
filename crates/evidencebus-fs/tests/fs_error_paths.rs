#![allow(clippy::unwrap_used)]
//! BDD-style tests for error branches in evidencebus-fs.
//!
//! These tests cover IO error paths, JSON parsing errors, missing artifacts,
//! and conflicting packet detection that are otherwise uncovered.

use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;

use evidencebus_codes::{PacketStatus, ValidationMode};
use evidencebus_fixtures::PacketBuilder;
use evidencebus_fs::{
    build_bundle, build_bundle_from_packets, create_bundle_dir, load_bundle, validate_packet_file,
    write_bundle_manifest, write_packet, FsError,
};
use evidencebus_types::{AttachmentRole, Digest, VcsKind};
use tempfile::tempdir;

// ============================================================================
// write_packet IO error branches
// ============================================================================

#[test]
fn bdd_given_parent_path_occupied_by_file_when_write_packet_then_returns_io_error() {
    // Given: A file exists at what would otherwise be the parent directory
    let dir = tempdir().unwrap();
    let blocking_file = dir.path().join("not_a_dir");
    fs::write(&blocking_file, "blocking").unwrap();

    let packet_path = blocking_file.join("nested").join("pkt.eb.json");

    let packet = PacketBuilder::new()
        .with_id("pkt-test")
        .with_producer("test-tool", "1.0.0")
        .with_subject(VcsKind::Git, "owner/repo", "abc123")
        .with_status(PacketStatus::Pass)
        .with_title("Test Packet")
        .with_summary("Test summary")
        .build()
        .unwrap();

    // When: write_packet is asked to create a directory that collides with the file
    let result = write_packet(&packet_path, &packet);

    // Then: An IoError is returned referencing the failing parent path
    assert!(result.is_err());
    match result.unwrap_err() {
        FsError::IoError { path, .. } => {
            assert!(path.contains("not_a_dir"));
        }
        other => panic!("Expected IoError, got {other:?}"),
    }
}

// ============================================================================
// create_bundle_dir IO error branches
// ============================================================================

#[test]
fn bdd_given_path_is_file_when_create_bundle_dir_then_returns_io_error() {
    // Given: A regular file exists at the bundle path
    let dir = tempdir().unwrap();
    let bundle_path = dir.path().join("bundle_collision");
    fs::write(&bundle_path, "i am a file").unwrap();

    // When: create_bundle_dir is called on the existing file path
    let result = create_bundle_dir(&bundle_path);

    // Then: An IoError is returned for the bundle path
    assert!(result.is_err());
    match result.unwrap_err() {
        FsError::IoError { path, .. } => {
            assert!(path.contains("bundle_collision"));
        }
        other => panic!("Expected IoError, got {other:?}"),
    }
}

#[test]
fn bdd_given_packets_subpath_blocked_by_file_when_create_bundle_dir_then_returns_io_error() {
    // Given: The bundle directory exists but a file blocks the `packets` subdir
    let dir = tempdir().unwrap();
    let bundle_path = dir.path().join("bundle_packets_blocked");
    fs::create_dir_all(&bundle_path).unwrap();
    let packets_path = bundle_path.join("packets");
    fs::write(&packets_path, "blocking file").unwrap();

    // When: create_bundle_dir tries to create the packets subdirectory
    let result = create_bundle_dir(&bundle_path);

    // Then: An IoError is returned for the packets subpath
    assert!(result.is_err());
    match result.unwrap_err() {
        FsError::IoError { path, .. } => {
            assert!(path.contains("packets"));
        }
        other => panic!("Expected IoError, got {other:?}"),
    }
}

// ============================================================================
// write_bundle_manifest IO error branch
// ============================================================================

#[test]
fn bdd_given_missing_bundle_dir_when_write_bundle_manifest_then_returns_io_error() {
    // Given: A bundle path that does not exist on disk
    let dir = tempdir().unwrap();
    let bundle_path = dir.path().join("does_not_exist");

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

    // When: write_bundle_manifest is invoked against the missing directory
    let result = write_bundle_manifest(&bundle_path, &manifest);

    // Then: An IoError is returned for the manifest path
    assert!(result.is_err());
    match result.unwrap_err() {
        FsError::IoError { path, .. } => {
            assert!(path.contains("bundle.eb.json"));
        }
        other => panic!("Expected IoError, got {other:?}"),
    }
}

// ============================================================================
// build_bundle_from_packets error branches
// ============================================================================

#[test]
fn bdd_given_conflicting_packets_when_build_bundle_then_returns_bundle_creation_failed() {
    // Given: Two packet files share the same id but carry different summaries
    let dir = tempdir().unwrap();
    let packet_dir = dir.path().join("packets");
    fs::create_dir_all(&packet_dir).unwrap();

    let packet1 = PacketBuilder::new()
        .with_id("pkt-conflict")
        .with_producer("test-tool", "1.0.0")
        .with_subject(VcsKind::Git, "owner/repo", "abc123")
        .with_status(PacketStatus::Pass)
        .with_title("First Title")
        .with_summary("First summary")
        .build()
        .unwrap();

    let packet2 = PacketBuilder::new()
        .with_id("pkt-conflict")
        .with_producer("test-tool", "1.0.0")
        .with_subject(VcsKind::Git, "owner/repo", "abc123")
        .with_status(PacketStatus::Pass)
        .with_title("Second Title")
        .with_summary("Second summary which is different")
        .build()
        .unwrap();

    let p1 = packet_dir.join("pkt-conflict-1.eb.json");
    let p2 = packet_dir.join("pkt-conflict-2.eb.json");
    write_packet(&p1, &packet1).unwrap();
    write_packet(&p2, &packet2).unwrap();

    let bundle_path = dir.path().join("conflict-bundle");

    // When: A bundle is built from both conflicting packets
    let result = build_bundle(&[p1, p2], &bundle_path);

    // Then: BundleCreationFailed is returned mentioning the conflicting id
    match result {
        Err(FsError::BundleCreationFailed(msg)) => {
            assert!(msg.contains("conflicting packet content"));
            assert!(msg.contains("pkt-conflict"));
        }
        other => panic!("Expected BundleCreationFailed, got {other:?}"),
    }
}

#[test]
fn bdd_given_packet_with_missing_attachment_when_build_bundle_then_returns_io_error() {
    // Given: A packet that references an attachment that is not on disk
    let dir = tempdir().unwrap();
    let packet_dir = dir.path().join("packets");
    fs::create_dir_all(&packet_dir).unwrap();

    let packet = PacketBuilder::new()
        .with_id("pkt-missing-attachment")
        .with_producer("test-tool", "1.0.0")
        .with_subject(VcsKind::Git, "owner/repo", "abc123")
        .with_status(PacketStatus::Pass)
        .with_title("Missing Attachment")
        .with_summary("Has a missing attachment")
        .add_attachment(AttachmentRole::PlainText, "missing.txt", "text/plain")
        .build()
        .unwrap();

    let packet_path = packet_dir.join("pkt-missing-attachment.eb.json");
    write_packet(&packet_path, &packet).unwrap();

    let bundle_path = dir.path().join("missing-attachment-bundle");

    // When: A bundle is built from the packet
    let result = build_bundle(&[packet_path], &bundle_path);

    // Then: An IoError is returned for the missing attachment source path
    assert!(result.is_err());
    match result.unwrap_err() {
        FsError::IoError { path, .. } => {
            assert!(path.contains("missing.txt"));
        }
        other => panic!("Expected IoError for missing attachment, got {other:?}"),
    }
}

// ============================================================================
// load_bundle invalid JSON branch
// ============================================================================

#[test]
fn bdd_given_garbage_manifest_when_load_bundle_then_returns_invalid_json_error() {
    // Given: A bundle directory containing a non-JSON bundle.eb.json file
    let dir = tempdir().unwrap();
    let bundle_path = dir.path().join("garbage-bundle");
    fs::create_dir_all(&bundle_path).unwrap();
    fs::write(bundle_path.join("bundle.eb.json"), "{ this is not json }").unwrap();

    // When: load_bundle attempts to parse the manifest
    let result = load_bundle(&bundle_path);

    // Then: An InvalidJson error is returned for the manifest path
    assert!(result.is_err());
    match result.unwrap_err() {
        FsError::InvalidJson { path, .. } => {
            assert!(path.contains("bundle.eb.json"));
        }
        other => panic!("Expected InvalidJson, got {other:?}"),
    }
}

// ============================================================================
// read_bytes error branch via validate_packet_file
// ============================================================================

#[test]
fn bdd_given_attachment_path_is_directory_when_validate_packet_file_then_returns_invalid_input() {
    // Given: A packet whose attachment path resolves to a directory on disk
    let dir = tempdir().unwrap();
    let packet_path = dir.path().join("pkt-attachment-dir.eb.json");
    fs::create_dir_all(dir.path().join("artifact.txt")).unwrap();

    let packet = PacketBuilder::new()
        .with_id("pkt-attachment-dir")
        .with_producer("test-tool", "1.0.0")
        .with_subject(VcsKind::Git, "owner/repo", "abc123")
        .with_status(PacketStatus::Pass)
        .with_title("Attachment is dir")
        .with_summary("Attachment path resolves to a directory")
        .add_attachment(AttachmentRole::PlainText, "artifact.txt", "text/plain")
        .build()
        .unwrap();

    write_packet(&packet_path, &packet).unwrap();

    // When: The packet is validated in strict mode
    let result = validate_packet_file(&packet_path, ValidationMode::Strict);

    // Then: InvalidInput is returned because the attachment is not a regular file
    assert!(result.is_err());
    match result.unwrap_err() {
        FsError::InvalidInput(msg) => {
            assert!(msg.contains("missing artifact"));
        }
        other => panic!("Expected InvalidInput, got {other:?}"),
    }
}

#[test]
fn bdd_given_extra_artifact_missing_when_build_bundle_from_packets_then_returns_artifact_copy_failed(
) {
    // Given: A valid packet but an additional artifact path that does not exist
    let dir = tempdir().unwrap();
    let packet_dir = dir.path().join("packets");
    fs::create_dir_all(&packet_dir).unwrap();

    let packet = PacketBuilder::new()
        .with_id("pkt-extra-missing")
        .with_producer("test-tool", "1.0.0")
        .with_subject(VcsKind::Git, "owner/repo", "abc123")
        .with_status(PacketStatus::Pass)
        .with_title("Test Packet")
        .with_summary("Test summary")
        .build()
        .unwrap();

    let packet_path = packet_dir.join("pkt-extra-missing.eb.json");
    write_packet(&packet_path, &packet).unwrap();

    let bundle_path = dir.path().join("extra-missing-bundle");

    let mut artifact_map = HashMap::new();
    artifact_map.insert(
        packet.packet_id.clone(),
        vec![(
            dir.path().join("nope-does-not-exist.txt"),
            PathBuf::from("dest.txt"),
        )],
    );

    // When: build_bundle_from_packets is invoked with the missing extra artifact
    let result = build_bundle_from_packets(&[packet_path], artifact_map, &bundle_path);

    // Then: ArtifactCopyFailed is returned (propagated from copy_artifact_to_bundle)
    match result {
        Err(FsError::ArtifactCopyFailed(msg)) => {
            assert!(msg.contains("nope-does-not-exist.txt"));
        }
        other => panic!("Expected ArtifactCopyFailed, got {other:?}"),
    }
}

#[test]
fn bdd_given_empty_packet_paths_when_build_bundle_from_packets_then_returns_invalid_input() {
    // Given: An empty packet list and an arbitrary artifact map
    let dir = tempdir().unwrap();
    let bundle_path = dir.path().join("empty-bundle");
    let empty: Vec<PathBuf> = Vec::new();

    // When: build_bundle_from_packets is called
    let result = build_bundle_from_packets(&empty, HashMap::new(), &bundle_path);

    // Then: InvalidInput is returned
    match result {
        Err(FsError::InvalidInput(msg)) => assert!(msg.contains("at least one packet")),
        other => panic!("Expected InvalidInput, got {other:?}"),
    }
}
