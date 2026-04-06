#![allow(clippy::unwrap_used)]
//! BDD-style tests for bundle validation.

use evidencebus_canonicalization::canonicalize_json;
use evidencebus_codes::PacketStatus;
use evidencebus_fixtures::PacketBuilder;
use evidencebus_types::{
    AttachmentRole, Bundle, BundleManifest, BundleSummary, Digest, IntegrityMetadata, PacketId,
    PacketInventoryEntry, SchemaVersion, VcsKind,
};
use evidencebus_validation::{
    validate_artifact_digest, validate_artifact_path, validate_bundle, BundleValidationError,
};

fn create_valid_packet(id: &str) -> evidencebus_types::Packet {
    PacketBuilder::new()
        .with_id(id)
        .with_producer("test-tool", "1.0.0")
        .with_subject(VcsKind::Git, "owner/repo", "abc123")
        .with_status(PacketStatus::Pass)
        .with_title("Test")
        .with_summary("Test summary")
        .build()
        .unwrap()
}

#[test]
fn bdd_given_valid_bundle_when_validating_then_succeeds() {
    // Given
    let packet1 = create_valid_packet("packet-1");
    let packet2 = create_valid_packet("packet-2");

    let json1 = canonicalize_json(&packet1).unwrap();
    let json2 = canonicalize_json(&packet2).unwrap();
    let data1 = json1.as_bytes().to_vec();
    let data2 = json2.as_bytes().to_vec();

    let packet_id1 = PacketId::new("packet-1").unwrap();
    let packet_id2 = PacketId::new("packet-2").unwrap();

    let digest1 = Digest::new(evidencebus_digest::compute_sha256(&data1)).unwrap();
    let digest2 = Digest::new(evidencebus_digest::compute_sha256(&data2)).unwrap();

    let packet_entries = vec![
        PacketInventoryEntry::new(
            packet_id1.clone(),
            "packets/packet-1/packet.eb.json".to_string(),
            digest1.clone(),
        ),
        PacketInventoryEntry::new(
            packet_id2.clone(),
            "packets/packet-2/packet.eb.json".to_string(),
            digest2.clone(),
        ),
    ];

    let artifact1_data = b"artifact data".to_vec();
    let artifact1_digest =
        Digest::new(evidencebus_digest::compute_sha256(&artifact1_data)).unwrap();
    let artifact1_path = "packets/packet-1/artifacts/report.html".to_string();

    let artifact_entries = vec![evidencebus_types::ArtifactInventoryEntry::new(
        packet_id1.clone(),
        artifact1_path.clone(),
        AttachmentRole::ReportHtml,
        artifact1_digest.clone(),
    )];

    let mut packet_digests = std::collections::HashMap::new();
    packet_digests.insert(packet_id1.clone(), digest1);
    packet_digests.insert(packet_id2.clone(), digest2);

    let mut artifact_digests = std::collections::HashMap::new();
    artifact_digests.insert(artifact1_path.clone(), artifact1_digest);

    let manifest_data =
        serde_json::to_vec(&(packet_entries.clone(), artifact_entries.clone())).unwrap();
    let manifest_digest = Digest::new(evidencebus_digest::compute_sha256(&manifest_data)).unwrap();

    let integrity = IntegrityMetadata::new(manifest_digest, packet_digests, artifact_digests);
    let manifest = BundleManifest::new(packet_entries, artifact_entries, integrity);

    let summary = BundleSummary::new(2, 1, Default::default(), Default::default());

    let bundle = Bundle::with_current_timestamp(
        SchemaVersion::new("0.1.0"),
        PacketId::new("test-bundle").unwrap(),
        manifest,
        summary,
    );

    let packet_data: Vec<(&PacketId, &[u8])> = vec![
        (&packet_id1, data1.as_slice()),
        (&packet_id2, data2.as_slice()),
    ];
    let artifact1_path_std = std::path::Path::new(&artifact1_path);
    let artifact_data: Vec<(&std::path::Path, &[u8])> =
        vec![(artifact1_path_std, artifact1_data.as_slice())];

    // When
    let result = validate_bundle(&bundle, &packet_data, &artifact_data);

    // Then
    assert!(result.is_ok(), "Valid bundle should pass validation");
}

#[test]
fn bdd_given_bundle_with_duplicate_packet_ids_when_validating_then_returns_error() {
    // Given
    let packet1 = create_valid_packet("packet-1");
    let packet2 = create_valid_packet("packet-2");

    let json1 = canonicalize_json(&packet1).unwrap();
    let json2 = canonicalize_json(&packet2).unwrap();
    let data1 = json1.as_bytes().to_vec();
    let data2 = json2.as_bytes().to_vec();

    let packet_id1 = PacketId::new("packet-1").unwrap();
    let packet_id2 = PacketId::new("packet-2").unwrap();

    let digest1 = Digest::new(evidencebus_digest::compute_sha256(&data1)).unwrap();
    let digest2 = Digest::new(evidencebus_digest::compute_sha256(&data2)).unwrap();

    let packet_entries = vec![
        PacketInventoryEntry::new(
            packet_id1.clone(),
            "packets/packet-1/packet.eb.json".to_string(),
            digest1.clone(),
        ),
        PacketInventoryEntry::new(
            packet_id2.clone(),
            "packets/packet-2/packet.eb.json".to_string(),
            digest2.clone(),
        ),
    ];

    let artifact1_data = b"artifact data".to_vec();
    let artifact1_digest =
        Digest::new(evidencebus_digest::compute_sha256(&artifact1_data)).unwrap();
    let artifact1_path = "packets/packet-1/artifacts/report.html".to_string();

    let artifact_entries = vec![evidencebus_types::ArtifactInventoryEntry::new(
        packet_id1.clone(),
        artifact1_path.clone(),
        AttachmentRole::ReportHtml,
        artifact1_digest.clone(),
    )];

    let mut packet_digests = std::collections::HashMap::new();
    packet_digests.insert(packet_id1.clone(), digest1);
    packet_digests.insert(packet_id2.clone(), digest2);

    let mut artifact_digests = std::collections::HashMap::new();
    artifact_digests.insert(artifact1_path.clone(), artifact1_digest);

    let manifest_data =
        serde_json::to_vec(&(packet_entries.clone(), artifact_entries.clone())).unwrap();
    let manifest_digest = Digest::new(evidencebus_digest::compute_sha256(&manifest_data)).unwrap();

    let integrity = IntegrityMetadata::new(manifest_digest, packet_digests, artifact_digests);
    let mut manifest = BundleManifest::new(packet_entries, artifact_entries, integrity);

    // Add a duplicate packet entry
    let duplicate_entry = manifest.packets[0].clone();
    manifest.packets.push(duplicate_entry);

    let summary = BundleSummary::new(2, 1, Default::default(), Default::default());

    let bundle = Bundle::with_current_timestamp(
        SchemaVersion::new("0.1.0"),
        PacketId::new("test-bundle").unwrap(),
        manifest,
        summary,
    );

    let packet_data: Vec<(&PacketId, &[u8])> = vec![
        (&packet_id1, data1.as_slice()),
        (&packet_id2, data2.as_slice()),
    ];
    let artifact_data: Vec<(&std::path::Path, &[u8])> = vec![(
        std::path::Path::new(&artifact1_path),
        artifact1_data.as_slice(),
    )];

    // When
    let result = validate_bundle(&bundle, &packet_data, &artifact_data);

    // Then
    assert!(matches!(
        result,
        Err(BundleValidationError::ConflictingPacket(_))
    ));
}

#[test]
fn bdd_given_bundle_with_missing_packet_data_when_validating_then_returns_error() {
    // Given
    let packet1 = create_valid_packet("packet-1");
    let packet2 = create_valid_packet("packet-2");

    let json1 = canonicalize_json(&packet1).unwrap();
    let json2 = canonicalize_json(&packet2).unwrap();
    let data1 = json1.as_bytes().to_vec();
    let data2 = json2.as_bytes().to_vec();

    let packet_id1 = PacketId::new("packet-1").unwrap();
    let packet_id2 = PacketId::new("packet-2").unwrap();

    let digest1 = Digest::new(evidencebus_digest::compute_sha256(&data1)).unwrap();
    let digest2 = Digest::new(evidencebus_digest::compute_sha256(&data2)).unwrap();

    let packet_entries = vec![
        PacketInventoryEntry::new(
            packet_id1.clone(),
            "packets/packet-1/packet.eb.json".to_string(),
            digest1.clone(),
        ),
        PacketInventoryEntry::new(
            packet_id2.clone(),
            "packets/packet-2/packet.eb.json".to_string(),
            digest2.clone(),
        ),
    ];

    let artifact1_data = b"artifact data".to_vec();
    let artifact1_digest =
        Digest::new(evidencebus_digest::compute_sha256(&artifact1_data)).unwrap();
    let artifact1_path = "packets/packet-1/artifacts/report.html".to_string();

    let artifact_entries = vec![evidencebus_types::ArtifactInventoryEntry::new(
        packet_id1.clone(),
        artifact1_path.clone(),
        AttachmentRole::ReportHtml,
        artifact1_digest.clone(),
    )];

    let mut packet_digests = std::collections::HashMap::new();
    packet_digests.insert(packet_id1.clone(), digest1);
    packet_digests.insert(packet_id2.clone(), digest2);

    let mut artifact_digests = std::collections::HashMap::new();
    artifact_digests.insert(artifact1_path.clone(), artifact1_digest);

    let manifest_data =
        serde_json::to_vec(&(packet_entries.clone(), artifact_entries.clone())).unwrap();
    let manifest_digest = Digest::new(evidencebus_digest::compute_sha256(&manifest_data)).unwrap();

    let integrity = IntegrityMetadata::new(manifest_digest, packet_digests, artifact_digests);
    let manifest = BundleManifest::new(packet_entries, artifact_entries, integrity);

    let summary = BundleSummary::new(2, 1, Default::default(), Default::default());

    let bundle = Bundle::with_current_timestamp(
        SchemaVersion::new("0.1.0"),
        PacketId::new("test-bundle").unwrap(),
        manifest,
        summary,
    );

    let packet_data: Vec<(&PacketId, &[u8])> = vec![];
    let artifact_data: Vec<(&std::path::Path, &[u8])> = vec![(
        std::path::Path::new(&artifact1_path),
        artifact1_data.as_slice(),
    )];

    // When
    let result = validate_bundle(&bundle, &packet_data, &artifact_data);

    // Then
    assert!(matches!(
        result,
        Err(BundleValidationError::MissingArtifact(_))
    ));
}

#[test]
fn bdd_given_bundle_with_packet_digest_mismatch_when_validating_then_returns_error() {
    // Given
    let packet1 = create_valid_packet("packet-1");
    let packet2 = create_valid_packet("packet-2");

    let json1 = canonicalize_json(&packet1).unwrap();
    let json2 = canonicalize_json(&packet2).unwrap();
    let mut data1 = json1.as_bytes().to_vec();
    let data2 = json2.as_bytes().to_vec();

    let packet_id1 = PacketId::new("packet-1").unwrap();
    let packet_id2 = PacketId::new("packet-2").unwrap();

    let digest1 = Digest::new(evidencebus_digest::compute_sha256(&data1)).unwrap();
    let digest2 = Digest::new(evidencebus_digest::compute_sha256(&data2)).unwrap();

    let packet_entries = vec![
        PacketInventoryEntry::new(
            packet_id1.clone(),
            "packets/packet-1/packet.eb.json".to_string(),
            digest1.clone(),
        ),
        PacketInventoryEntry::new(
            packet_id2.clone(),
            "packets/packet-2/packet.eb.json".to_string(),
            digest2.clone(),
        ),
    ];

    let artifact1_data = b"artifact data".to_vec();
    let artifact1_digest =
        Digest::new(evidencebus_digest::compute_sha256(&artifact1_data)).unwrap();
    let artifact1_path = "packets/packet-1/artifacts/report.html".to_string();

    let artifact_entries = vec![evidencebus_types::ArtifactInventoryEntry::new(
        packet_id1.clone(),
        artifact1_path.clone(),
        AttachmentRole::ReportHtml,
        artifact1_digest.clone(),
    )];

    let mut packet_digests = std::collections::HashMap::new();
    packet_digests.insert(packet_id1.clone(), digest1);
    packet_digests.insert(packet_id2.clone(), digest2);

    let mut artifact_digests = std::collections::HashMap::new();
    artifact_digests.insert(artifact1_path.clone(), artifact1_digest);

    let manifest_data =
        serde_json::to_vec(&(packet_entries.clone(), artifact_entries.clone())).unwrap();
    let manifest_digest = Digest::new(evidencebus_digest::compute_sha256(&manifest_data)).unwrap();

    let integrity = IntegrityMetadata::new(manifest_digest, packet_digests, artifact_digests);
    let manifest = BundleManifest::new(packet_entries, artifact_entries, integrity);

    let summary = BundleSummary::new(2, 1, Default::default(), Default::default());

    let bundle = Bundle::with_current_timestamp(
        SchemaVersion::new("0.1.0"),
        PacketId::new("test-bundle").unwrap(),
        manifest,
        summary,
    );

    // Modify packet data to cause digest mismatch
    data1 = b"wrong data".to_vec();

    let packet_data: Vec<(&PacketId, &[u8])> = vec![
        (&packet_id1, data1.as_slice()),
        (&packet_id2, data2.as_slice()),
    ];
    let artifact_data: Vec<(&std::path::Path, &[u8])> = vec![(
        std::path::Path::new(&artifact1_path),
        artifact1_data.as_slice(),
    )];

    // When
    let result = validate_bundle(&bundle, &packet_data, &artifact_data);

    // Then
    assert!(matches!(
        result,
        Err(BundleValidationError::DigestMismatch(_))
    ));
}

#[test]
fn bdd_given_bundle_with_missing_artifact_data_when_validating_then_returns_error() {
    // Given
    let packet1 = create_valid_packet("packet-1");
    let packet2 = create_valid_packet("packet-2");

    let json1 = canonicalize_json(&packet1).unwrap();
    let json2 = canonicalize_json(&packet2).unwrap();
    let data1 = json1.as_bytes().to_vec();
    let data2 = json2.as_bytes().to_vec();

    let packet_id1 = PacketId::new("packet-1").unwrap();
    let packet_id2 = PacketId::new("packet-2").unwrap();

    let digest1 = Digest::new(evidencebus_digest::compute_sha256(&data1)).unwrap();
    let digest2 = Digest::new(evidencebus_digest::compute_sha256(&data2)).unwrap();

    let packet_entries = vec![
        PacketInventoryEntry::new(
            packet_id1.clone(),
            "packets/packet-1/packet.eb.json".to_string(),
            digest1.clone(),
        ),
        PacketInventoryEntry::new(
            packet_id2.clone(),
            "packets/packet-2/packet.eb.json".to_string(),
            digest2.clone(),
        ),
    ];

    let artifact1_data = b"artifact data".to_vec();
    let artifact1_digest =
        Digest::new(evidencebus_digest::compute_sha256(&artifact1_data)).unwrap();
    let artifact1_path = "packets/packet-1/artifacts/report.html".to_string();

    let artifact_entries = vec![evidencebus_types::ArtifactInventoryEntry::new(
        packet_id1.clone(),
        artifact1_path.clone(),
        AttachmentRole::ReportHtml,
        artifact1_digest.clone(),
    )];

    let mut packet_digests = std::collections::HashMap::new();
    packet_digests.insert(packet_id1.clone(), digest1);
    packet_digests.insert(packet_id2.clone(), digest2);

    let mut artifact_digests = std::collections::HashMap::new();
    artifact_digests.insert(artifact1_path.clone(), artifact1_digest);

    let manifest_data =
        serde_json::to_vec(&(packet_entries.clone(), artifact_entries.clone())).unwrap();
    let manifest_digest = Digest::new(evidencebus_digest::compute_sha256(&manifest_data)).unwrap();

    let integrity = IntegrityMetadata::new(manifest_digest, packet_digests, artifact_digests);
    let manifest = BundleManifest::new(packet_entries, artifact_entries, integrity);

    let summary = BundleSummary::new(2, 1, Default::default(), Default::default());

    let bundle = Bundle::with_current_timestamp(
        SchemaVersion::new("0.1.0"),
        PacketId::new("test-bundle").unwrap(),
        manifest,
        summary,
    );

    let packet_data: Vec<(&PacketId, &[u8])> = vec![
        (&packet_id1, data1.as_slice()),
        (&packet_id2, data2.as_slice()),
    ];
    let artifact_data: Vec<(&std::path::Path, &[u8])> = vec![];

    // When
    let result = validate_bundle(&bundle, &packet_data, &artifact_data);

    // Then
    assert!(matches!(
        result,
        Err(BundleValidationError::MissingArtifact(_))
    ));
}

#[test]
fn bdd_given_bundle_with_artifact_digest_mismatch_when_validating_then_returns_error() {
    // Given
    let packet1 = create_valid_packet("packet-1");
    let packet2 = create_valid_packet("packet-2");

    let json1 = canonicalize_json(&packet1).unwrap();
    let json2 = canonicalize_json(&packet2).unwrap();
    let data1 = json1.as_bytes().to_vec();
    let data2 = json2.as_bytes().to_vec();

    let packet_id1 = PacketId::new("packet-1").unwrap();
    let packet_id2 = PacketId::new("packet-2").unwrap();

    let digest1 = Digest::new(evidencebus_digest::compute_sha256(&data1)).unwrap();
    let digest2 = Digest::new(evidencebus_digest::compute_sha256(&data2)).unwrap();

    let packet_entries = vec![
        PacketInventoryEntry::new(
            packet_id1.clone(),
            "packets/packet-1/packet.eb.json".to_string(),
            digest1.clone(),
        ),
        PacketInventoryEntry::new(
            packet_id2.clone(),
            "packets/packet-2/packet.eb.json".to_string(),
            digest2.clone(),
        ),
    ];

    let mut artifact1_data = b"artifact data".to_vec();
    let artifact1_digest =
        Digest::new(evidencebus_digest::compute_sha256(&artifact1_data)).unwrap();
    let artifact1_path = "packets/packet-1/artifacts/report.html".to_string();

    let artifact_entries = vec![evidencebus_types::ArtifactInventoryEntry::new(
        packet_id1.clone(),
        artifact1_path.clone(),
        AttachmentRole::ReportHtml,
        artifact1_digest.clone(),
    )];

    let mut packet_digests = std::collections::HashMap::new();
    packet_digests.insert(packet_id1.clone(), digest1);
    packet_digests.insert(packet_id2.clone(), digest2);

    let mut artifact_digests = std::collections::HashMap::new();
    artifact_digests.insert(artifact1_path.clone(), artifact1_digest);

    let manifest_data =
        serde_json::to_vec(&(packet_entries.clone(), artifact_entries.clone())).unwrap();
    let manifest_digest = Digest::new(evidencebus_digest::compute_sha256(&manifest_data)).unwrap();

    let integrity = IntegrityMetadata::new(manifest_digest, packet_digests, artifact_digests);
    let manifest = BundleManifest::new(packet_entries, artifact_entries, integrity);

    let summary = BundleSummary::new(2, 1, Default::default(), Default::default());

    let bundle = Bundle::with_current_timestamp(
        SchemaVersion::new("0.1.0"),
        PacketId::new("test-bundle").unwrap(),
        manifest,
        summary,
    );

    // Modify artifact data to cause digest mismatch
    artifact1_data = b"wrong data".to_vec();

    let packet_data: Vec<(&PacketId, &[u8])> = vec![
        (&packet_id1, data1.as_slice()),
        (&packet_id2, data2.as_slice()),
    ];
    let artifact_data: Vec<(&std::path::Path, &[u8])> = vec![(
        std::path::Path::new(&artifact1_path),
        artifact1_data.as_slice(),
    )];

    // When
    let result = validate_bundle(&bundle, &packet_data, &artifact_data);

    // Then
    assert!(matches!(
        result,
        Err(BundleValidationError::DigestMismatch(_))
    ));
}

#[test]
fn bdd_given_bundle_with_packet_not_in_manifest_when_validating_then_returns_error() {
    // Given
    let packet1 = create_valid_packet("packet-1");
    let packet2 = create_valid_packet("packet-2");

    let json1 = canonicalize_json(&packet1).unwrap();
    let json2 = canonicalize_json(&packet2).unwrap();
    let data1 = json1.as_bytes().to_vec();
    let data2 = json2.as_bytes().to_vec();

    let packet_id1 = PacketId::new("packet-1").unwrap();
    let packet_id2 = PacketId::new("packet-2").unwrap();

    let digest1 = Digest::new(evidencebus_digest::compute_sha256(&data1)).unwrap();
    let digest2 = Digest::new(evidencebus_digest::compute_sha256(&data2)).unwrap();

    let packet_entries = vec![
        PacketInventoryEntry::new(
            packet_id1.clone(),
            "packets/packet-1/packet.eb.json".to_string(),
            digest1.clone(),
        ),
        PacketInventoryEntry::new(
            packet_id2.clone(),
            "packets/packet-2/packet.eb.json".to_string(),
            digest2.clone(),
        ),
    ];

    let artifact1_data = b"artifact data".to_vec();
    let artifact1_digest =
        Digest::new(evidencebus_digest::compute_sha256(&artifact1_data)).unwrap();
    let artifact1_path = "packets/packet-1/artifacts/report.html".to_string();

    let artifact_entries = vec![evidencebus_types::ArtifactInventoryEntry::new(
        packet_id1.clone(),
        artifact1_path.clone(),
        AttachmentRole::ReportHtml,
        artifact1_digest.clone(),
    )];

    let mut packet_digests = std::collections::HashMap::new();
    packet_digests.insert(packet_id1.clone(), digest1);
    packet_digests.insert(packet_id2.clone(), digest2);

    let mut artifact_digests = std::collections::HashMap::new();
    artifact_digests.insert(artifact1_path.clone(), artifact1_digest);

    let manifest_data =
        serde_json::to_vec(&(packet_entries.clone(), artifact_entries.clone())).unwrap();
    let manifest_digest = Digest::new(evidencebus_digest::compute_sha256(&manifest_data)).unwrap();

    let integrity = IntegrityMetadata::new(manifest_digest, packet_digests, artifact_digests);
    let manifest = BundleManifest::new(packet_entries, artifact_entries, integrity);

    let summary = BundleSummary::new(2, 1, Default::default(), Default::default());

    let bundle = Bundle::with_current_timestamp(
        SchemaVersion::new("0.1.0"),
        PacketId::new("test-bundle").unwrap(),
        manifest,
        summary,
    );

    // Add extra packet data not in manifest
    let extra_packet = create_valid_packet("extra-packet");
    let extra_json = canonicalize_json(&extra_packet).unwrap();
    let extra_id = PacketId::new("extra-packet").unwrap();
    let extra_data = extra_json.as_bytes().to_vec();

    let packet_data: Vec<(&PacketId, &[u8])> = vec![
        (&packet_id1, data1.as_slice()),
        (&packet_id2, data2.as_slice()),
        (&extra_id, extra_data.as_slice()),
    ];
    let artifact_data: Vec<(&std::path::Path, &[u8])> = vec![(
        std::path::Path::new(&artifact1_path),
        artifact1_data.as_slice(),
    )];

    // When
    let result = validate_bundle(&bundle, &packet_data, &artifact_data);

    // Then
    assert!(matches!(
        result,
        Err(BundleValidationError::InventoryMismatch(_))
    ));
}

#[test]
fn bdd_given_bundle_with_artifact_not_in_manifest_when_validating_then_returns_error() {
    // Given
    let packet1 = create_valid_packet("packet-1");
    let packet2 = create_valid_packet("packet-2");

    let json1 = canonicalize_json(&packet1).unwrap();
    let json2 = canonicalize_json(&packet2).unwrap();
    let data1 = json1.as_bytes().to_vec();
    let data2 = json2.as_bytes().to_vec();

    let packet_id1 = PacketId::new("packet-1").unwrap();
    let packet_id2 = PacketId::new("packet-2").unwrap();

    let digest1 = Digest::new(evidencebus_digest::compute_sha256(&data1)).unwrap();
    let digest2 = Digest::new(evidencebus_digest::compute_sha256(&data2)).unwrap();

    let packet_entries = vec![
        PacketInventoryEntry::new(
            packet_id1.clone(),
            "packets/packet-1/packet.eb.json".to_string(),
            digest1.clone(),
        ),
        PacketInventoryEntry::new(
            packet_id2.clone(),
            "packets/packet-2/packet.eb.json".to_string(),
            digest2.clone(),
        ),
    ];

    let artifact1_data = b"artifact data".to_vec();
    let artifact1_digest =
        Digest::new(evidencebus_digest::compute_sha256(&artifact1_data)).unwrap();
    let artifact1_path = "packets/packet-1/artifacts/report.html".to_string();

    let artifact_entries = vec![evidencebus_types::ArtifactInventoryEntry::new(
        packet_id1.clone(),
        artifact1_path.clone(),
        AttachmentRole::ReportHtml,
        artifact1_digest.clone(),
    )];

    let mut packet_digests = std::collections::HashMap::new();
    packet_digests.insert(packet_id1.clone(), digest1);
    packet_digests.insert(packet_id2.clone(), digest2);

    let mut artifact_digests = std::collections::HashMap::new();
    artifact_digests.insert(artifact1_path.clone(), artifact1_digest);

    let manifest_data =
        serde_json::to_vec(&(packet_entries.clone(), artifact_entries.clone())).unwrap();
    let manifest_digest = Digest::new(evidencebus_digest::compute_sha256(&manifest_data)).unwrap();

    let integrity = IntegrityMetadata::new(manifest_digest, packet_digests, artifact_digests);
    let manifest = BundleManifest::new(packet_entries, artifact_entries, integrity);

    let summary = BundleSummary::new(2, 1, Default::default(), Default::default());

    let bundle = Bundle::with_current_timestamp(
        SchemaVersion::new("0.1.0"),
        PacketId::new("test-bundle").unwrap(),
        manifest,
        summary,
    );

    let packet_data: Vec<(&PacketId, &[u8])> = vec![
        (&packet_id1, data1.as_slice()),
        (&packet_id2, data2.as_slice()),
    ];
    // Add extra artifact data not in manifest
    let extra_path = std::path::Path::new("packets/extra/artifact.txt");
    let extra_data = b"extra data".to_vec();
    let artifact_data: Vec<(&std::path::Path, &[u8])> = vec![
        (
            std::path::Path::new(&artifact1_path),
            artifact1_data.as_slice(),
        ),
        (extra_path, extra_data.as_slice()),
    ];

    // When
    let result = validate_bundle(&bundle, &packet_data, &artifact_data);

    // Then
    assert!(matches!(
        result,
        Err(BundleValidationError::InventoryMismatch(_))
    ));
}

#[test]
fn bdd_given_bundle_with_packet_digest_mismatch_in_integrity_when_validating_then_returns_error() {
    // Given
    let packet1 = create_valid_packet("packet-1");
    let packet2 = create_valid_packet("packet-2");

    let json1 = canonicalize_json(&packet1).unwrap();
    let json2 = canonicalize_json(&packet2).unwrap();
    let data1 = json1.as_bytes().to_vec();
    let data2 = json2.as_bytes().to_vec();

    let packet_id1 = PacketId::new("packet-1").unwrap();
    let packet_id2 = PacketId::new("packet-2").unwrap();

    let digest1 = Digest::new(evidencebus_digest::compute_sha256(&data1)).unwrap();
    let digest2 = Digest::new(evidencebus_digest::compute_sha256(&data2)).unwrap();

    let packet_entries = vec![
        PacketInventoryEntry::new(
            packet_id1.clone(),
            "packets/packet-1/packet.eb.json".to_string(),
            digest1.clone(),
        ),
        PacketInventoryEntry::new(
            packet_id2.clone(),
            "packets/packet-2/packet.eb.json".to_string(),
            digest2.clone(),
        ),
    ];

    let artifact1_data = b"artifact data".to_vec();
    let artifact1_digest =
        Digest::new(evidencebus_digest::compute_sha256(&artifact1_data)).unwrap();
    let artifact1_path = "packets/packet-1/artifacts/report.html".to_string();

    let artifact_entries = vec![evidencebus_types::ArtifactInventoryEntry::new(
        packet_id1.clone(),
        artifact1_path.clone(),
        AttachmentRole::ReportHtml,
        artifact1_digest.clone(),
    )];

    let mut packet_digests = std::collections::HashMap::new();
    packet_digests.insert(packet_id1.clone(), digest1);
    packet_digests.insert(packet_id2.clone(), digest2);

    let mut artifact_digests = std::collections::HashMap::new();
    artifact_digests.insert(artifact1_path.clone(), artifact1_digest);

    let manifest_data =
        serde_json::to_vec(&(packet_entries.clone(), artifact_entries.clone())).unwrap();
    let manifest_digest = Digest::new(evidencebus_digest::compute_sha256(&manifest_data)).unwrap();

    let mut integrity = IntegrityMetadata::new(manifest_digest, packet_digests, artifact_digests);

    // Modify integrity metadata to cause digest mismatch
    let packet_id = &packet_entries[0].packet_id;
    if let Some(digest) = integrity.packet_digests.get_mut(packet_id) {
        *digest = Digest::new("b".repeat(64)).unwrap();
    }

    let manifest = BundleManifest::new(packet_entries, artifact_entries, integrity);

    let summary = BundleSummary::new(2, 1, Default::default(), Default::default());

    let bundle = Bundle::with_current_timestamp(
        SchemaVersion::new("0.1.0"),
        PacketId::new("test-bundle").unwrap(),
        manifest,
        summary,
    );

    let packet_data: Vec<(&PacketId, &[u8])> = vec![
        (&packet_id1, data1.as_slice()),
        (&packet_id2, data2.as_slice()),
    ];
    let artifact_data: Vec<(&std::path::Path, &[u8])> = vec![(
        std::path::Path::new(&artifact1_path),
        artifact1_data.as_slice(),
    )];

    // When
    let result = validate_bundle(&bundle, &packet_data, &artifact_data);

    // Then
    assert!(matches!(
        result,
        Err(BundleValidationError::DigestMismatch(_))
    ));
}

#[test]
fn bdd_given_bundle_with_packet_not_in_integrity_metadata_when_validating_then_returns_error() {
    // Given
    let packet1 = create_valid_packet("packet-1");
    let packet2 = create_valid_packet("packet-2");

    let json1 = canonicalize_json(&packet1).unwrap();
    let json2 = canonicalize_json(&packet2).unwrap();
    let data1 = json1.as_bytes().to_vec();
    let data2 = json2.as_bytes().to_vec();

    let packet_id1 = PacketId::new("packet-1").unwrap();
    let packet_id2 = PacketId::new("packet-2").unwrap();

    let digest1 = Digest::new(evidencebus_digest::compute_sha256(&data1)).unwrap();
    let digest2 = Digest::new(evidencebus_digest::compute_sha256(&data2)).unwrap();

    let packet_entries = vec![
        PacketInventoryEntry::new(
            packet_id1.clone(),
            "packets/packet-1/packet.eb.json".to_string(),
            digest1.clone(),
        ),
        PacketInventoryEntry::new(
            packet_id2.clone(),
            "packets/packet-2/packet.eb.json".to_string(),
            digest2.clone(),
        ),
    ];

    let artifact1_data = b"artifact data".to_vec();
    let artifact1_digest =
        Digest::new(evidencebus_digest::compute_sha256(&artifact1_data)).unwrap();
    let artifact1_path = "packets/packet-1/artifacts/report.html".to_string();

    let artifact_entries = vec![evidencebus_types::ArtifactInventoryEntry::new(
        packet_id1.clone(),
        artifact1_path.clone(),
        AttachmentRole::ReportHtml,
        artifact1_digest.clone(),
    )];

    let mut packet_digests = std::collections::HashMap::new();
    packet_digests.insert(packet_id1.clone(), digest1);
    packet_digests.insert(packet_id2.clone(), digest2);

    let mut artifact_digests = std::collections::HashMap::new();
    artifact_digests.insert(artifact1_path.clone(), artifact1_digest);

    let manifest_data =
        serde_json::to_vec(&(packet_entries.clone(), artifact_entries.clone())).unwrap();
    let manifest_digest = Digest::new(evidencebus_digest::compute_sha256(&manifest_data)).unwrap();

    let mut integrity = IntegrityMetadata::new(manifest_digest, packet_digests, artifact_digests);

    // Remove packet from integrity metadata
    let packet_id = packet_entries[0].packet_id.clone();
    integrity.packet_digests.remove(&packet_id);

    let manifest = BundleManifest::new(packet_entries, artifact_entries, integrity);

    let summary = BundleSummary::new(2, 1, Default::default(), Default::default());

    let bundle = Bundle::with_current_timestamp(
        SchemaVersion::new("0.1.0"),
        PacketId::new("test-bundle").unwrap(),
        manifest,
        summary,
    );

    let packet_data: Vec<(&PacketId, &[u8])> = vec![
        (&packet_id1, data1.as_slice()),
        (&packet_id2, data2.as_slice()),
    ];
    let artifact_data: Vec<(&std::path::Path, &[u8])> = vec![(
        std::path::Path::new(&artifact1_path),
        artifact1_data.as_slice(),
    )];

    // When
    let result = validate_bundle(&bundle, &packet_data, &artifact_data);

    // Then
    assert!(matches!(
        result,
        Err(BundleValidationError::ManifestInvalid(_))
    ));
}

#[test]
fn bdd_given_bundle_with_artifact_not_in_integrity_metadata_when_validating_then_returns_error() {
    // Given
    let packet1 = create_valid_packet("packet-1");
    let packet2 = create_valid_packet("packet-2");

    let json1 = canonicalize_json(&packet1).unwrap();
    let json2 = canonicalize_json(&packet2).unwrap();
    let data1 = json1.as_bytes().to_vec();
    let data2 = json2.as_bytes().to_vec();

    let packet_id1 = PacketId::new("packet-1").unwrap();
    let packet_id2 = PacketId::new("packet-2").unwrap();

    let digest1 = Digest::new(evidencebus_digest::compute_sha256(&data1)).unwrap();
    let digest2 = Digest::new(evidencebus_digest::compute_sha256(&data2)).unwrap();

    let packet_entries = vec![
        PacketInventoryEntry::new(
            packet_id1.clone(),
            "packets/packet-1/packet.eb.json".to_string(),
            digest1.clone(),
        ),
        PacketInventoryEntry::new(
            packet_id2.clone(),
            "packets/packet-2/packet.eb.json".to_string(),
            digest2.clone(),
        ),
    ];

    let artifact1_data = b"artifact data".to_vec();
    let artifact1_digest =
        Digest::new(evidencebus_digest::compute_sha256(&artifact1_data)).unwrap();
    let artifact1_path = "packets/packet-1/artifacts/report.html".to_string();

    let artifact_entries = vec![evidencebus_types::ArtifactInventoryEntry::new(
        packet_id1.clone(),
        artifact1_path.clone(),
        AttachmentRole::ReportHtml,
        artifact1_digest.clone(),
    )];

    let mut packet_digests = std::collections::HashMap::new();
    packet_digests.insert(packet_id1.clone(), digest1);
    packet_digests.insert(packet_id2.clone(), digest2);

    let mut artifact_digests = std::collections::HashMap::new();
    artifact_digests.insert(artifact1_path.clone(), artifact1_digest);

    let manifest_data =
        serde_json::to_vec(&(packet_entries.clone(), artifact_entries.clone())).unwrap();
    let manifest_digest = Digest::new(evidencebus_digest::compute_sha256(&manifest_data)).unwrap();

    let mut integrity = IntegrityMetadata::new(manifest_digest, packet_digests, artifact_digests);

    // Remove artifact from integrity metadata
    let artifact_path = artifact_entries[0].relative_path.clone();
    integrity.artifact_digests.remove(&artifact_path);

    let manifest = BundleManifest::new(packet_entries, artifact_entries, integrity);

    let summary = BundleSummary::new(2, 1, Default::default(), Default::default());

    let bundle = Bundle::with_current_timestamp(
        SchemaVersion::new("0.1.0"),
        PacketId::new("test-bundle").unwrap(),
        manifest,
        summary,
    );

    let packet_data: Vec<(&PacketId, &[u8])> = vec![
        (&packet_id1, data1.as_slice()),
        (&packet_id2, data2.as_slice()),
    ];
    let artifact_data: Vec<(&std::path::Path, &[u8])> = vec![(
        std::path::Path::new(&artifact1_path),
        artifact1_data.as_slice(),
    )];

    // When
    let result = validate_bundle(&bundle, &packet_data, &artifact_data);

    // Then
    assert!(matches!(
        result,
        Err(BundleValidationError::InventoryMismatch(_))
    ));
}

#[test]
fn bdd_given_valid_artifact_digest_when_validating_then_succeeds() {
    // Given
    let valid_digest = Digest::new("a".repeat(64)).unwrap();

    // When
    let result = validate_artifact_digest(&valid_digest);

    // Then
    assert!(result.is_ok());
}

#[test]
fn bdd_given_artifact_digest_with_invalid_length_when_validating_then_returns_error() {
    // Given - Digest::new() already validates, so we test that it rejects invalid input
    let result = Digest::new("abc123".to_string());

    // Then
    assert!(result.is_err(), "Digest::new should reject invalid length");
}

#[test]
fn bdd_given_artifact_digest_with_invalid_hex_when_validating_then_returns_error() {
    // Given - Digest::new() already validates, so we test that it rejects invalid input
    let result = Digest::new("g".repeat(64));

    // Then
    assert!(
        result.is_err(),
        "Digest::new should reject non-hex characters"
    );
}

#[test]
fn bdd_given_valid_artifact_path_when_validating_then_succeeds() {
    // Given
    let path = std::path::Path::new("packets/packet-1/artifacts/report.html");

    // When
    let result = validate_artifact_path(path);

    // Then
    assert!(result.is_ok());
}

#[test]
fn bdd_given_artifact_path_with_traversal_when_validating_then_returns_error() {
    // Given
    let path = std::path::Path::new("packets/../unsafe/artifact.txt");

    // When
    let result = validate_artifact_path(path);

    // Then
    assert!(result.is_err());
}

#[test]
fn bdd_given_artifact_path_absolute_when_validating_then_returns_error() {
    // Given - use platform-appropriate absolute path
    let path = if cfg!(windows) {
        std::path::Path::new("C:\\absolute\\path\\artifact.txt")
    } else {
        std::path::Path::new("/absolute/path/artifact.txt")
    };

    // When
    let result = validate_artifact_path(path);

    // Then
    assert!(result.is_err());
}
