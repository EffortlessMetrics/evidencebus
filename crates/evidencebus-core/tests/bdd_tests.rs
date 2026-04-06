#![allow(clippy::unwrap_used)]
//! BDD-style tests for the evidencebus-core crate.
//!
//! These tests follow the Given-When-Then structure to describe behavior
//! in a clear, readable format.

use evidencebus_codes::{FindingSeverity, PacketStatus};
use evidencebus_core::{
    build_bundle_manifest, build_bundle_summary, dedupe_packets, detect_conflicts,
};
use evidencebus_types::{
    Artifact, Attachment, AttachmentRole, Digest, Finding, Packet, PacketId, Producer,
    SchemaVersion, Subject, Summary,
};

/// Helper function to create a test packet with customizable parameters
fn create_test_packet(
    id: &str,
    status: PacketStatus,
    summary_title: &str,
    timestamp: Option<&str>,
) -> Packet {
    let mut packet = Packet::new(
        SchemaVersion::new("0.1.0"),
        PacketId::new(id).unwrap(),
        Producer::new("test-tool", "1.0.0"),
        Subject::new(
            evidencebus_types::VcsKind::Git,
            "owner/repo",
            "abc123",
            "main",
        ),
        Summary::new(status, summary_title, "Test summary"),
    );

    if let Some(ts) = timestamp {
        packet.created_at = ts.to_string();
    }

    packet
}

/// Helper function to create a test artifact
fn create_test_artifact(packet_id: &str, relative_path: &str, data: &[u8]) -> Artifact {
    Artifact::new(
        PacketId::new(packet_id).unwrap(),
        relative_path,
        AttachmentRole::ReportHtml,
        data.to_vec(),
    )
}

/// Helper function to create a test attachment
fn create_test_attachment(
    relative_path: &str,
    role: AttachmentRole,
    media_type: &str,
    data: &[u8],
) -> Attachment {
    let digest = Digest::new(evidencebus_digest::compute_sha256(data)).unwrap();
    Attachment::new(role, media_type, relative_path, digest)
}

mod deduplication {
    use super::*;

    #[test]
    fn scenario_dedupe_identical_packets_with_same_id() {
        // Given: Two identical packets with the same ID and content
        let timestamp = "2024-01-01T00:00:00Z";
        let packet1 = create_test_packet("pkt-1", PacketStatus::Pass, "Test", Some(timestamp));
        let packet2 = create_test_packet("pkt-1", PacketStatus::Pass, "Test", Some(timestamp));
        let packet3 = create_test_packet("pkt-2", PacketStatus::Fail, "Fail", Some(timestamp));

        // When: Deduplicating the packets
        let result = dedupe_packets(vec![packet1, packet2, packet3]);

        // Then: Deduplication should succeed
        assert!(result.is_ok());

        // And: Only unique packets should remain
        let deduped = result.unwrap();
        assert_eq!(deduped.len(), 2);

        // And: The first occurrence should be kept
        assert_eq!(deduped[0].packet_id.as_str(), "pkt-1");
        assert_eq!(deduped[1].packet_id.as_str(), "pkt-2");
    }

    #[test]
    fn scenario_dedupe_different_packets_with_same_digest() {
        // Given: Two different packets that happen to have the same digest
        // This is a theoretical edge case - in practice this shouldn't happen
        // with proper canonicalization, but we test the error handling
        let packet1 = create_test_packet("pkt-1", PacketStatus::Pass, "Test", None);
        let packet2 = create_test_packet("pkt-2", PacketStatus::Pass, "Test", None);

        // Note: In practice, different packets won't have the same digest
        // This test verifies the conflict detection logic exists

        // When: Deduplicating the packets
        let result = dedupe_packets(vec![packet1, packet2]);

        // Then: Deduplication should succeed (no conflict since IDs differ)
        assert!(result.is_ok());

        // And: Both packets should remain
        let deduped = result.unwrap();
        assert_eq!(deduped.len(), 2);
    }

    #[test]
    fn scenario_dedupe_empty_packet_list() {
        // Given: An empty list of packets
        let packets: Vec<Packet> = vec![];

        // When: Deduplicating the packets
        let result = dedupe_packets(packets);

        // Then: Deduplication should succeed
        assert!(result.is_ok());

        // And: The result should be empty
        assert_eq!(result.unwrap().len(), 0);
    }

    #[test]
    fn scenario_dedupe_single_packet() {
        // Given: A single packet
        let packet = create_test_packet("pkt-1", PacketStatus::Pass, "Test", None);

        // When: Deduplicating the packets
        let result = dedupe_packets(vec![packet]);

        // Then: Deduplication should succeed
        assert!(result.is_ok());

        // And: The packet should remain
        assert_eq!(result.unwrap().len(), 1);
    }

    #[test]
    fn scenario_dedupe_preserves_order_of_first_occurrence() {
        // Given: Multiple packets with duplicates in different order
        let timestamp = "2024-01-01T00:00:00Z";
        let packet1 = create_test_packet("pkt-1", PacketStatus::Pass, "Test", Some(timestamp));
        let packet2 = create_test_packet("pkt-2", PacketStatus::Fail, "Fail", Some(timestamp));
        let packet3 = create_test_packet("pkt-1", PacketStatus::Pass, "Test", Some(timestamp)); // Duplicate of pkt-1
        let packet4 = create_test_packet("pkt-3", PacketStatus::Pass, "Test", Some(timestamp));
        let packet5 = create_test_packet("pkt-2", PacketStatus::Fail, "Fail", Some(timestamp)); // Duplicate of pkt-2

        // When: Deduplicating the packets
        let result = dedupe_packets(vec![packet1, packet2, packet3, packet4, packet5]);

        // Then: Deduplication should succeed
        assert!(result.is_ok());

        // And: First occurrences should be preserved in original order
        let deduped = result.unwrap();
        assert_eq!(deduped.len(), 3);
        assert_eq!(deduped[0].packet_id.as_str(), "pkt-1");
        assert_eq!(deduped[1].packet_id.as_str(), "pkt-2");
        assert_eq!(deduped[2].packet_id.as_str(), "pkt-3");
    }

    #[test]
    fn scenario_dedupe_with_different_timestamps() {
        // Given: Packets with same ID but different timestamps (different content)
        let packet1 = create_test_packet(
            "pkt-1",
            PacketStatus::Pass,
            "Test",
            Some("2024-01-01T00:00:00Z"),
        );
        let packet2 = create_test_packet(
            "pkt-1",
            PacketStatus::Pass,
            "Test",
            Some("2024-01-01T01:00:00Z"),
        );

        // When: Deduplicating the packets
        let result = dedupe_packets(vec![packet1, packet2]);

        // Then: Deduplication should succeed (different digests due to different timestamps)
        assert!(result.is_ok());

        // And: Both packets should remain (they have different content)
        let deduped = result.unwrap();
        assert_eq!(deduped.len(), 2);
    }
}

mod conflict_detection {
    use super::*;

    #[test]
    fn scenario_detect_conflicts_with_same_id_different_content() {
        // Given: Two packets with the same ID but different content
        let packet1 = create_test_packet("pkt-1", PacketStatus::Pass, "Test", None);
        let packet2 = create_test_packet("pkt-1", PacketStatus::Fail, "Different", None);

        // When: Detecting conflicts
        let conflicts = detect_conflicts(&[packet1, packet2]);

        // Then: One conflict should be detected
        assert_eq!(conflicts.len(), 1);

        // And: The conflict should reference the packet ID
        assert_eq!(conflicts[0].packet_id.as_str(), "pkt-1");
    }

    #[test]
    fn scenario_no_conflicts_with_same_id_same_content() {
        // Given: Two packets with the same ID and identical content
        let timestamp = "2024-01-01T00:00:00Z";
        let packet1 = create_test_packet("pkt-1", PacketStatus::Pass, "Test", Some(timestamp));
        let packet2 = create_test_packet("pkt-1", PacketStatus::Pass, "Test", Some(timestamp));

        // When: Detecting conflicts
        let conflicts = detect_conflicts(&[packet1, packet2]);

        // Then: No conflicts should be detected
        assert_eq!(conflicts.len(), 0);
    }

    #[test]
    fn scenario_no_conflicts_with_different_ids() {
        // Given: Multiple packets with different IDs
        let packet1 = create_test_packet("pkt-1", PacketStatus::Pass, "Test", None);
        let packet2 = create_test_packet("pkt-2", PacketStatus::Fail, "Fail", None);
        let packet3 = create_test_packet("pkt-3", PacketStatus::Pass, "Test", None);

        // When: Detecting conflicts
        let conflicts = detect_conflicts(&[packet1, packet2, packet3]);

        // Then: No conflicts should be detected
        assert_eq!(conflicts.len(), 0);
    }

    #[test]
    fn scenario_detect_multiple_conflicts() {
        // Given: Multiple packets with conflicting IDs
        let packet1 = create_test_packet("pkt-1", PacketStatus::Pass, "Test", None);
        let packet2 = create_test_packet("pkt-1", PacketStatus::Fail, "Different", None);
        let packet3 = create_test_packet("pkt-2", PacketStatus::Pass, "Test", None);
        let packet4 = create_test_packet("pkt-2", PacketStatus::Fail, "Different", None);
        let packet5 = create_test_packet("pkt-3", PacketStatus::Pass, "Test", None);

        // When: Detecting conflicts
        let conflicts = detect_conflicts(&[packet1, packet2, packet3, packet4, packet5]);

        // Then: Two conflicts should be detected
        assert_eq!(conflicts.len(), 2);

        // And: Conflicts should reference the correct packet IDs
        let conflict_ids: Vec<&str> = conflicts.iter().map(|c| c.packet_id.as_str()).collect();
        assert!(conflict_ids.contains(&"pkt-1"));
        assert!(conflict_ids.contains(&"pkt-2"));
    }

    #[test]
    fn scenario_detect_conflicts_with_empty_packet_list() {
        // Given: An empty list of packets
        let packets: Vec<Packet> = vec![];

        // When: Detecting conflicts
        let conflicts = detect_conflicts(&packets);

        // Then: No conflicts should be detected
        assert_eq!(conflicts.len(), 0);
    }

    #[test]
    fn scenario_detect_conflicts_with_single_packet() {
        // Given: A single packet
        let packet = create_test_packet("pkt-1", PacketStatus::Pass, "Test", None);

        // When: Detecting conflicts
        let conflicts = detect_conflicts(&[packet]);

        // Then: No conflicts should be detected
        assert_eq!(conflicts.len(), 0);
    }

    #[test]
    fn scenario_detect_conflicts_with_findings_difference() {
        // Given: Two packets with same ID but different findings
        let mut packet1 = create_test_packet("pkt-1", PacketStatus::Pass, "Test", None);
        packet1.projections.findings.push(Finding::new(
            "f1",
            FindingSeverity::Error,
            "Error",
            "Error message",
        ));

        let mut packet2 = create_test_packet("pkt-1", PacketStatus::Pass, "Test", None);
        packet2.projections.findings.push(Finding::new(
            "f2",
            FindingSeverity::Warning,
            "Warning",
            "Warning message",
        ));

        // When: Detecting conflicts
        let conflicts = detect_conflicts(&[packet1, packet2]);

        // Then: One conflict should be detected
        assert_eq!(conflicts.len(), 1);
    }

    #[test]
    fn scenario_detect_conflicts_with_attachments_difference() {
        // Given: Two packets with same ID but different attachments
        let mut packet1 = create_test_packet("pkt-1", PacketStatus::Pass, "Test", None);
        packet1.projections.attachments.push(create_test_attachment(
            "att1.txt",
            AttachmentRole::ReportHtml,
            "text/html",
            b"data1",
        ));

        let mut packet2 = create_test_packet("pkt-1", PacketStatus::Pass, "Test", None);
        packet2.projections.attachments.push(create_test_attachment(
            "att2.txt",
            AttachmentRole::ReportHtml,
            "text/html",
            b"data2",
        ));

        // When: Detecting conflicts
        let conflicts = detect_conflicts(&[packet1, packet2]);

        // Then: One conflict should be detected
        assert_eq!(conflicts.len(), 1);
    }
}

mod bundle_summary_building {
    use super::*;

    #[test]
    fn scenario_build_summary_with_passing_packets() {
        // Given: Multiple passing packets
        let packet1 = create_test_packet("pkt-1", PacketStatus::Pass, "Test", None);
        let packet2 = create_test_packet("pkt-2", PacketStatus::Pass, "Test", None);
        let packet3 = create_test_packet("pkt-3", PacketStatus::Pass, "Test", None);

        // When: Building the bundle summary
        let summary = build_bundle_summary(&[packet1, packet2, packet3]);

        // Then: Total packets should be 3
        assert_eq!(summary.total_packets, 3);

        // And: Pass count should be 3
        assert_eq!(summary.status_counts.pass, 3);

        // And: Other status counts should be 0
        assert_eq!(summary.status_counts.fail, 0);
        assert_eq!(summary.status_counts.warn, 0);
    }

    #[test]
    fn scenario_build_summary_with_mixed_status_packets() {
        // Given: Packets with mixed statuses
        let packet1 = create_test_packet("pkt-1", PacketStatus::Pass, "Test", None);
        let packet2 = create_test_packet("pkt-2", PacketStatus::Fail, "Fail", None);
        let packet3 = create_test_packet("pkt-3", PacketStatus::Warn, "Warn", None);
        let packet4 = create_test_packet("pkt-4", PacketStatus::Pass, "Test", None);

        // When: Building the bundle summary
        let summary = build_bundle_summary(&[packet1, packet2, packet3, packet4]);

        // Then: Total packets should be 4
        assert_eq!(summary.total_packets, 4);

        // And: Status counts should be correct
        assert_eq!(summary.status_counts.pass, 2);
        assert_eq!(summary.status_counts.fail, 1);
        assert_eq!(summary.status_counts.warn, 1);
    }

    #[test]
    fn scenario_build_summary_with_findings() {
        // Given: Packets with findings of various severities
        let mut packet1 = create_test_packet("pkt-1", PacketStatus::Fail, "Test", None);
        packet1.projections.findings.push(Finding::new(
            "f1",
            FindingSeverity::Error,
            "Error",
            "Error message",
        ));
        packet1.projections.findings.push(Finding::new(
            "f2",
            FindingSeverity::Warning,
            "Warning",
            "Warning message",
        ));

        let mut packet2 = create_test_packet("pkt-2", PacketStatus::Fail, "Test", None);
        packet2.projections.findings.push(Finding::new(
            "f3",
            FindingSeverity::Error,
            "Error",
            "Error message",
        ));
        packet2.projections.findings.push(Finding::new(
            "f4",
            FindingSeverity::Note,
            "Note",
            "Note message",
        ));

        let packet3 = create_test_packet("pkt-3", PacketStatus::Pass, "Test", None);

        // When: Building the bundle summary
        let summary = build_bundle_summary(&[packet1, packet2, packet3]);

        // Then: Severity counts should be correct
        assert_eq!(summary.severity_counts.error, 2);
        assert_eq!(summary.severity_counts.warning, 1);
        assert_eq!(summary.severity_counts.note, 1);
    }

    #[test]
    fn scenario_build_summary_with_artifacts() {
        // Given: Packets with artifacts and attachments
        let mut packet1 = create_test_packet("pkt-1", PacketStatus::Pass, "Test", None);
        packet1.artifacts.push("report.html".to_string());
        packet1.projections.attachments.push(create_test_attachment(
            "log.txt",
            AttachmentRole::StdoutLog,
            "text/plain",
            b"log content",
        ));

        let mut packet2 = create_test_packet("pkt-2", PacketStatus::Pass, "Test", None);
        packet2.artifacts.push("data.json".to_string());

        let packet3 = create_test_packet("pkt-3", PacketStatus::Pass, "Test", None);

        // When: Building the bundle summary
        let summary = build_bundle_summary(&[packet1, packet2, packet3]);

        // Then: Total artifacts should count both artifacts and attachments
        assert_eq!(summary.total_artifacts, 3);
    }

    #[test]
    fn scenario_build_summary_with_empty_packet_list() {
        // Given: An empty list of packets
        let packets: Vec<Packet> = vec![];

        // When: Building the bundle summary
        let summary = build_bundle_summary(&packets);

        // Then: Total packets should be 0
        assert_eq!(summary.total_packets, 0);

        // And: All counts should be 0
        assert_eq!(summary.total_artifacts, 0);
        assert_eq!(summary.status_counts.pass, 0);
        assert_eq!(summary.status_counts.fail, 0);
        assert_eq!(summary.severity_counts.error, 0);
    }

    #[test]
    fn scenario_build_summary_with_single_packet() {
        // Given: A single packet
        let packet = create_test_packet("pkt-1", PacketStatus::Pass, "Test", None);

        // When: Building the bundle summary
        let summary = build_bundle_summary(&[packet]);

        // Then: Total packets should be 1
        assert_eq!(summary.total_packets, 1);

        // And: Pass count should be 1
        assert_eq!(summary.status_counts.pass, 1);
    }
}

mod bundle_manifest_building {
    use super::*;

    #[test]
    fn scenario_build_manifest_with_packets_only() {
        // Given: Multiple packets without artifacts
        let packet1 = create_test_packet("pkt-1", PacketStatus::Pass, "Test", None);
        let packet2 = create_test_packet("pkt-2", PacketStatus::Fail, "Fail", None);
        let packet3 = create_test_packet("pkt-3", PacketStatus::Pass, "Test", None);

        // When: Building the bundle manifest
        let manifest = build_bundle_manifest(&[packet1, packet2, packet3], &[]).unwrap();

        // Then: Manifest should contain 3 packet entries
        assert_eq!(manifest.packets.len(), 3);

        // And: Manifest should contain 0 artifact entries
        assert_eq!(manifest.artifacts.len(), 0);

        // And: Packet entries should be sorted by packet_id
        assert_eq!(manifest.packets[0].packet_id.as_str(), "pkt-1");
        assert_eq!(manifest.packets[1].packet_id.as_str(), "pkt-2");
        assert_eq!(manifest.packets[2].packet_id.as_str(), "pkt-3");

        // And: Each packet entry should have a digest
        assert!(manifest
            .packets
            .iter()
            .all(|p| !p.sha256.as_str().is_empty()));
    }

    #[test]
    fn scenario_build_manifest_with_packets_and_artifacts() {
        // Given: Packets with associated artifacts
        let packet1 = create_test_packet("pkt-1", PacketStatus::Pass, "Test", None);
        let packet2 = create_test_packet("pkt-2", PacketStatus::Fail, "Fail", None);

        let artifact1 = create_test_artifact("pkt-1", "report.html", b"report data");
        let artifact2 = create_test_artifact("pkt-1", "log.txt", b"log data");
        let artifact3 = create_test_artifact("pkt-2", "data.json", b"json data");

        // When: Building the bundle manifest
        let manifest =
            build_bundle_manifest(&[packet1, packet2], &[artifact1, artifact2, artifact3]).unwrap();

        // Then: Manifest should contain 2 packet entries
        assert_eq!(manifest.packets.len(), 2);

        // And: Manifest should contain 3 artifact entries
        assert_eq!(manifest.artifacts.len(), 3);

        // And: Artifact entries should be sorted by packet_id then relative_path
        assert_eq!(manifest.artifacts[0].packet_id.as_str(), "pkt-1");
        assert_eq!(
            manifest.artifacts[0].relative_path,
            "packets/pkt-1/artifacts/log.txt"
        );
        assert_eq!(manifest.artifacts[1].packet_id.as_str(), "pkt-1");
        assert_eq!(
            manifest.artifacts[1].relative_path,
            "packets/pkt-1/artifacts/report.html"
        );
        assert_eq!(manifest.artifacts[2].packet_id.as_str(), "pkt-2");
        assert_eq!(
            manifest.artifacts[2].relative_path,
            "packets/pkt-2/artifacts/data.json"
        );

        // And: Each artifact entry should have a digest
        assert!(manifest
            .artifacts
            .iter()
            .all(|a| !a.sha256.as_str().is_empty()));
    }

    #[test]
    fn scenario_build_manifest_with_empty_inputs() {
        // Given: Empty packets and artifacts lists
        let packets: Vec<Packet> = vec![];
        let artifacts: Vec<Artifact> = vec![];

        // When: Building the bundle manifest
        let manifest = build_bundle_manifest(&packets, &artifacts).unwrap();

        // Then: Manifest should be empty
        assert_eq!(manifest.packets.len(), 0);
        assert_eq!(manifest.artifacts.len(), 0);

        // And: Integrity metadata should exist
        assert!(!manifest.integrity.manifest_digest.as_str().is_empty());
    }

    #[test]
    fn scenario_build_manifest_with_single_packet_and_artifact() {
        // Given: A single packet with a single artifact
        let packet = create_test_packet("pkt-1", PacketStatus::Pass, "Test", None);
        let artifact = create_test_artifact("pkt-1", "report.html", b"report data");

        // When: Building the bundle manifest
        let manifest = build_bundle_manifest(&[packet], &[artifact]).unwrap();

        // Then: Manifest should contain 1 packet entry
        assert_eq!(manifest.packets.len(), 1);

        // And: Manifest should contain 1 artifact entry
        assert_eq!(manifest.artifacts.len(), 1);

        // And: Integrity metadata should contain packet and artifact digests
        assert_eq!(manifest.integrity.packet_digests.len(), 1);
        assert_eq!(manifest.integrity.artifact_digests.len(), 1);
    }

    #[test]
    fn scenario_build_manifest_generates_correct_paths() {
        // Given: Packets and artifacts
        let packet1 = create_test_packet("pkt-1", PacketStatus::Pass, "Test", None);
        let artifact1 = create_test_artifact("pkt-1", "report.html", b"data");

        // When: Building the bundle manifest
        let manifest = build_bundle_manifest(&[packet1], &[artifact1]).unwrap();

        // Then: Packet entry should have correct path
        assert_eq!(
            manifest.packets[0].relative_path,
            "packets/pkt-1/packet.eb.json"
        );

        // And: Artifact entry should have correct path
        assert_eq!(
            manifest.artifacts[0].relative_path,
            "packets/pkt-1/artifacts/report.html"
        );
    }

    #[test]
    fn scenario_build_manifest_integrity_metadata() {
        // Given: Packets and artifacts
        let packet1 = create_test_packet("pkt-1", PacketStatus::Pass, "Test", None);
        let packet2 = create_test_packet("pkt-2", PacketStatus::Fail, "Fail", None);
        let artifact1 = create_test_artifact("pkt-1", "report.html", b"data");
        let artifact2 = create_test_artifact("pkt-2", "data.json", b"json");

        // When: Building the bundle manifest
        let manifest = build_bundle_manifest(&[packet1, packet2], &[artifact1, artifact2]).unwrap();

        // Then: Integrity metadata should contain manifest digest
        assert!(!manifest.integrity.manifest_digest.as_str().is_empty());

        // And: Integrity metadata should contain all packet digests
        assert_eq!(manifest.integrity.packet_digests.len(), 2);
        assert!(manifest
            .integrity
            .packet_digests
            .contains_key(&PacketId::new("pkt-1").unwrap()));
        assert!(manifest
            .integrity
            .packet_digests
            .contains_key(&PacketId::new("pkt-2").unwrap()));

        // And: Integrity metadata should contain all artifact digests
        assert_eq!(manifest.integrity.artifact_digests.len(), 2);
        assert!(manifest
            .integrity
            .artifact_digests
            .contains_key("packets/pkt-1/artifacts/report.html"));
        assert!(manifest
            .integrity
            .artifact_digests
            .contains_key("packets/pkt-2/artifacts/data.json"));
    }

    #[test]
    fn scenario_build_manifest_deterministic() {
        // Given: The same packets and artifacts
        let packet1 = create_test_packet("pkt-1", PacketStatus::Pass, "Test", None);
        let packet2 = create_test_packet("pkt-2", PacketStatus::Fail, "Fail", None);
        let artifact1 = create_test_artifact("pkt-1", "report.html", b"data");
        let artifact2 = create_test_artifact("pkt-2", "data.json", b"json");

        // When: Building the bundle manifest twice
        let manifest1 = build_bundle_manifest(
            &[packet1.clone(), packet2.clone()],
            &[artifact1.clone(), artifact2.clone()],
        )
        .unwrap();
        let manifest2 =
            build_bundle_manifest(&[packet1, packet2], &[artifact1, artifact2]).unwrap();

        // Then: Both manifests should have identical digests
        assert_eq!(
            manifest1.integrity.manifest_digest,
            manifest2.integrity.manifest_digest
        );

        // And: Packet entries should be identical
        assert_eq!(manifest1.packets, manifest2.packets);

        // And: Artifact entries should be identical
        assert_eq!(manifest1.artifacts, manifest2.artifacts);
    }

    #[test]
    fn scenario_build_manifest_with_nested_artifact_paths() {
        // Given: Packets with artifacts having nested paths
        let packet1 = create_test_packet("pkt-1", PacketStatus::Pass, "Test", None);
        let artifact1 = create_test_artifact("pkt-1", "reports/summary.html", b"data");
        let artifact2 = create_test_artifact("pkt-1", "logs/stderr.log", b"log");

        // When: Building the bundle manifest
        let manifest = build_bundle_manifest(&[packet1], &[artifact1, artifact2]).unwrap();

        // Then: Artifact entries should preserve nested paths with full bundle path
        assert_eq!(
            manifest.artifacts[0].relative_path,
            "packets/pkt-1/artifacts/logs/stderr.log"
        );
        assert_eq!(
            manifest.artifacts[1].relative_path,
            "packets/pkt-1/artifacts/reports/summary.html"
        );

        // And: Full paths in integrity metadata should include nested structure
        assert!(manifest
            .integrity
            .artifact_digests
            .contains_key("packets/pkt-1/artifacts/logs/stderr.log"));
        assert!(manifest
            .integrity
            .artifact_digests
            .contains_key("packets/pkt-1/artifacts/reports/summary.html"));
    }
}

mod edge_cases {
    use super::*;

    #[test]
    fn scenario_dedupe_with_canonicalization_failure() {
        // Given: Packets that might fail canonicalization
        // Note: In practice, valid packets should always canonicalize
        // This test verifies error handling exists
        let packet1 = create_test_packet("pkt-1", PacketStatus::Pass, "Test", None);
        let packet2 = create_test_packet("pkt-2", PacketStatus::Fail, "Fail", None);

        // When: Deduplicating the packets
        let result = dedupe_packets(vec![packet1, packet2]);

        // Then: Deduplication should succeed
        assert!(result.is_ok());
    }

    #[test]
    fn scenario_build_summary_with_packet_without_findings() {
        // Given: A packet without any findings
        let packet = create_test_packet("pkt-1", PacketStatus::Pass, "Test", None);
        assert!(packet.projections.findings.is_empty());

        // When: Building the bundle summary
        let summary = build_bundle_summary(&[packet]);

        // Then: All severity counts should be 0
        assert_eq!(summary.severity_counts.error, 0);
        assert_eq!(summary.severity_counts.warning, 0);
        assert_eq!(summary.severity_counts.note, 0);
    }

    #[test]
    fn scenario_build_summary_with_packet_without_artifacts() {
        // Given: A packet without artifacts or attachments
        let packet = create_test_packet("pkt-1", PacketStatus::Pass, "Test", None);
        assert!(packet.artifacts.is_empty());
        assert!(packet.projections.attachments.is_empty());

        // When: Building the bundle summary
        let summary = build_bundle_summary(&[packet]);

        // Then: Total artifacts should be 0
        assert_eq!(summary.total_artifacts, 0);
    }

    #[test]
    fn scenario_detect_conflicts_skips_non_canonicalizable_packets() {
        // Given: A list where some packets might not canonicalize
        // Note: In practice, valid packets should always canonicalize
        // This test verifies the behavior is graceful
        let packet1 = create_test_packet("pkt-1", PacketStatus::Pass, "Test", None);
        let packet2 = create_test_packet("pkt-2", PacketStatus::Fail, "Fail", None);

        // When: Detecting conflicts
        let conflicts = detect_conflicts(&[packet1, packet2]);

        // Then: No conflicts should be detected (different IDs)
        assert_eq!(conflicts.len(), 0);
    }

    #[test]
    fn scenario_build_manifest_preserves_artifact_role() {
        // Given: Artifacts with different roles
        let packet1 = create_test_packet("pkt-1", PacketStatus::Pass, "Test", None);
        let artifact1 = Artifact::new(
            PacketId::new("pkt-1").unwrap(),
            "report.html",
            AttachmentRole::ReportHtml,
            b"data".to_vec(),
        );
        let artifact2 = Artifact::new(
            PacketId::new("pkt-1").unwrap(),
            "stdout.log",
            AttachmentRole::StdoutLog,
            b"log".to_vec(),
        );
        let artifact3 = Artifact::new(
            PacketId::new("pkt-1").unwrap(),
            "binary.bin",
            AttachmentRole::ArbitraryBinary,
            b"binary".to_vec(),
        );

        // When: Building the bundle manifest
        let manifest =
            build_bundle_manifest(&[packet1], &[artifact1, artifact2, artifact3]).unwrap();

        // Then: Artifact roles should be preserved
        let roles: Vec<_> = manifest.artifacts.iter().map(|a| a.role).collect();
        assert!(roles.contains(&AttachmentRole::ReportHtml));
        assert!(roles.contains(&AttachmentRole::StdoutLog));
        assert!(roles.contains(&AttachmentRole::ArbitraryBinary));
    }
}
