#![allow(clippy::unwrap_used)]
//! BDD-style tests for Markdown export functionality.
//!
//! These tests follow the Given-When-Then pattern to describe
//! behavior in a clear, readable format.

use evidencebus_codes::{FindingSeverity, PacketStatus};
use evidencebus_export_markdown::{export_bundle, export_packet};
use evidencebus_types::{
    ArtifactInventoryEntry, Attachment, AttachmentRole, Bundle, BundleManifest, BundleSummary,
    Digest, IntegrityMetadata, Location, Metric, Packet, PacketId, PacketInventoryEntry, Producer,
    Projections, SchemaVersion, StatusCounts, Subject, Summary, VcsKind,
};
use std::collections::HashMap;

/// Helper function to create a minimal valid packet.
fn create_minimal_packet(id: &str, status: PacketStatus) -> Packet {
    Packet {
        eb_version: SchemaVersion::new("0.1.0"),
        packet_id: PacketId::new(id).unwrap(),
        producer: Producer::new("test-tool", "1.0.0"),
        subject: Subject::new(VcsKind::Git, "owner/repo", "abc123", "def456"),
        summary: Summary::new(status, "Test Title", "Test summary"),
        projections: Projections::new(),
        native_payloads: vec![],
        artifacts: vec![],
        links: None,
        labels: None,
        created_at: "2024-01-01T12:00:00Z".to_string(),
    }
}

/// Helper function to create a packet with all fields populated.
fn create_full_packet(id: &str, status: PacketStatus) -> Packet {
    Packet {
        eb_version: SchemaVersion::new("0.1.0"),
        packet_id: PacketId::new(id).unwrap(),
        producer: Producer::new("test-tool", "1.0.0"),
        subject: Subject::new(VcsKind::Git, "owner/repo", "abc123", "def456")
            .with_base("base123")
            .with_path_scope("src/"),
        summary: Summary::new(status, "Test Title", "Test summary"),
        projections: Projections::new()
            .add_assertion(
                evidencebus_types::Assertion::new(
                    "assert-1",
                    PacketStatus::Pass,
                    Summary::new(PacketStatus::Pass, "Assert 1", "Passed"),
                )
                .with_details("Additional assertion details"),
            )
            .add_finding(
                evidencebus_types::Finding::new(
                    "finding-1",
                    FindingSeverity::Warning,
                    "Finding 1",
                    "This is a warning",
                )
                .with_location(Location::new("src/main.rs").with_line(42).with_column(10)),
            )
            .add_metric(
                Metric::new("coverage", 85.5)
                    .with_unit("%")
                    .with_baseline(80.0),
            )
            .add_attachment(
                Attachment::new(
                    AttachmentRole::ReportHtml,
                    "text/html",
                    "report.html",
                    Digest::new("0".repeat(64)).unwrap(),
                )
                .with_size(1024)
                .with_schema_id("schema-1"),
            )
            .add_relation(
                evidencebus_types::Relation::new(
                    evidencebus_types::RelationKind::DerivedFrom,
                    PacketId::new("parent-packet").unwrap(),
                )
                .with_details("Derived from parent"),
            ),
        native_payloads: vec!["payload.json".to_string()],
        artifacts: vec!["artifact.txt".to_string()],
        links: Some({
            let mut map = HashMap::new();
            map.insert("CI".to_string(), "https://ci.example.com".to_string());
            map.insert(
                "Dashboard".to_string(),
                "https://dashboard.example.com".to_string(),
            );
            map
        }),
        labels: Some({
            let mut map = HashMap::new();
            map.insert("team".to_string(), "platform".to_string());
            map.insert("environment".to_string(), "production".to_string());
            map
        }),
        created_at: "2024-01-01T12:00:00Z".to_string(),
    }
}

/// Helper function to create a minimal valid bundle.
fn create_minimal_bundle(id: &str) -> Bundle {
    Bundle {
        eb_version: SchemaVersion::new("0.1.0"),
        bundle_id: PacketId::new(id).unwrap(),
        created_at: "2024-01-01T12:00:00Z".to_string(),
        manifest: BundleManifest::new(
            vec![],
            vec![],
            IntegrityMetadata::new(
                Digest::new("0".repeat(64)).unwrap(),
                HashMap::new(),
                HashMap::new(),
            ),
        ),
        summary: BundleSummary::new(
            0,
            0,
            StatusCounts {
                pass: 0,
                fail: 0,
                warn: 0,
                indeterminate: 0,
                error: 0,
            },
            evidencebus_types::SeverityCounts {
                note: 0,
                warning: 0,
                error: 0,
            },
        ),
    }
}

/// Helper function to create a bundle with entries.
fn create_bundle_with_entries(id: &str) -> Bundle {
    Bundle {
        eb_version: SchemaVersion::new("0.1.0"),
        bundle_id: PacketId::new(id).unwrap(),
        created_at: "2024-01-01T12:00:00Z".to_string(),
        manifest: BundleManifest::new(
            vec![
                PacketInventoryEntry {
                    packet_id: PacketId::new("packet-1").unwrap(),
                    relative_path: "packets/packet-1/packet.eb.json".to_string(),
                    sha256: Digest::new("1".repeat(64)).unwrap(),
                },
                PacketInventoryEntry {
                    packet_id: PacketId::new("packet-2").unwrap(),
                    relative_path: "packets/packet-2/packet.eb.json".to_string(),
                    sha256: Digest::new("2".repeat(64)).unwrap(),
                },
            ],
            vec![ArtifactInventoryEntry {
                packet_id: PacketId::new("packet-1").unwrap(),
                relative_path: "packets/packet-1/artifacts/report.html".to_string(),
                role: AttachmentRole::ReportHtml,
                sha256: Digest::new("3".repeat(64)).unwrap(),
            }],
            IntegrityMetadata::new(
                Digest::new("0".repeat(64)).unwrap(),
                {
                    let mut map = HashMap::new();
                    map.insert(
                        PacketId::new("packet-1").unwrap(),
                        Digest::new("1".repeat(64)).unwrap(),
                    );
                    map.insert(
                        PacketId::new("packet-2").unwrap(),
                        Digest::new("2".repeat(64)).unwrap(),
                    );
                    map
                },
                {
                    let mut map = HashMap::new();
                    map.insert(
                        "packet-1/report.html".to_string(),
                        Digest::new("3".repeat(64)).unwrap(),
                    );
                    map
                },
            ),
        ),
        summary: BundleSummary::new(
            2,
            1,
            StatusCounts {
                pass: 1,
                fail: 1,
                warn: 0,
                indeterminate: 0,
                error: 0,
            },
            evidencebus_types::SeverityCounts {
                note: 0,
                warning: 1,
                error: 0,
            },
        ),
    }
}

// ============================================================================
// PACKET EXPORT TESTS
// ============================================================================

mod packet_export {
    use super::*;

    #[test]
    fn given_valid_packet_when_exporting_then_produces_markdown_with_all_sections() {
        // Given: A valid packet with all fields populated
        let packet = create_full_packet("test-packet", PacketStatus::Pass);

        // When: Exporting the packet to Markdown
        let result = export_packet(&packet);

        // Then: The export succeeds
        assert!(result.is_ok());

        // And: The Markdown contains all expected sections
        let markdown = result.unwrap();
        assert!(markdown.contains("# Evidence Packet: test-packet"));
        assert!(markdown.contains("## Producer"));
        assert!(markdown.contains("## Subject"));
        assert!(markdown.contains("## Summary"));
        assert!(markdown.contains("## Assertions"));
        assert!(markdown.contains("## Findings"));
        assert!(markdown.contains("## Metrics"));
        assert!(markdown.contains("## Attachments"));
        assert!(markdown.contains("## Relations"));
        assert!(markdown.contains("## Native Payloads"));
        assert!(markdown.contains("## Artifacts"));
        assert!(markdown.contains("## Links"));
        assert!(markdown.contains("## Labels"));
    }

    #[test]
    fn given_packet_with_pass_status_when_exporting_then_shows_pass_emoji() {
        // Given: A packet with Pass status
        let packet = create_minimal_packet("test-packet", PacketStatus::Pass);

        // When: Exporting the packet to Markdown
        let markdown = export_packet(&packet).unwrap();

        // Then: The Markdown shows the pass emoji
        assert!(markdown.contains("✅"));
        assert!(markdown.contains("**Status:** Pass"));
    }

    #[test]
    fn given_packet_with_fail_status_when_exporting_then_shows_fail_emoji() {
        // Given: A packet with Fail status
        let packet = create_minimal_packet("test-packet", PacketStatus::Fail);

        // When: Exporting the packet to Markdown
        let markdown = export_packet(&packet).unwrap();

        // Then: The Markdown shows the fail emoji
        assert!(markdown.contains("❌"));
        assert!(markdown.contains("**Status:** Fail"));
    }

    #[test]
    fn given_packet_with_warn_status_when_exporting_then_shows_warn_emoji() {
        // Given: A packet with Warn status
        let packet = create_minimal_packet("test-packet", PacketStatus::Warn);

        // When: Exporting the packet to Markdown
        let markdown = export_packet(&packet).unwrap();

        // Then: The Markdown shows the warn emoji
        assert!(markdown.contains("⚠️"));
        assert!(markdown.contains("**Status:** Warn"));
    }

    #[test]
    fn given_packet_with_indeterminate_status_when_exporting_then_shows_indeterminate_emoji() {
        // Given: A packet with Indeterminate status
        let packet = create_minimal_packet("test-packet", PacketStatus::Indeterminate);

        // When: Exporting the packet to Markdown
        let markdown = export_packet(&packet).unwrap();

        // Then: The Markdown shows the indeterminate emoji
        assert!(markdown.contains("❓"));
        assert!(markdown.contains("**Status:** Indeterminate"));
    }

    #[test]
    fn given_packet_with_error_status_when_exporting_then_shows_error_emoji() {
        // Given: A packet with Error status
        let packet = create_minimal_packet("test-packet", PacketStatus::Error);

        // When: Exporting the packet to Markdown
        let markdown = export_packet(&packet).unwrap();

        // Then: The Markdown shows the error emoji
        assert!(markdown.contains("💥"));
        assert!(markdown.contains("**Status:** Error"));
    }

    #[test]
    fn given_packet_with_assertions_when_exporting_then_includes_assertions_section() {
        // Given: A packet with assertions
        let packet = create_full_packet("test-packet", PacketStatus::Pass);

        // When: Exporting the packet to Markdown
        let markdown = export_packet(&packet).unwrap();

        // Then: The Markdown includes the assertions
        assert!(markdown.contains("## Assertions"));
        assert!(markdown.contains("assert-1"));
        assert!(markdown.contains("Assert 1"));
        assert!(markdown.contains("Passed"));
        assert!(markdown.contains("Additional assertion details"));
    }

    #[test]
    fn given_packet_with_findings_when_exporting_then_includes_findings_section() {
        // Given: A packet with findings
        let packet = create_full_packet("test-packet", PacketStatus::Pass);

        // When: Exporting the packet to Markdown
        let markdown = export_packet(&packet).unwrap();

        // Then: The Markdown includes the findings
        assert!(markdown.contains("## Findings"));
        assert!(markdown.contains("finding-1"));
        assert!(markdown.contains("Finding 1"));
        assert!(markdown.contains("This is a warning"));
        assert!(markdown.contains("src/main.rs:42:10"));
    }

    #[test]
    fn given_packet_with_metrics_when_exporting_then_includes_metrics_section() {
        // Given: A packet with metrics
        let packet = create_full_packet("test-packet", PacketStatus::Pass);

        // When: Exporting the packet to Markdown
        let markdown = export_packet(&packet).unwrap();

        // Then: The Markdown includes the metrics
        assert!(markdown.contains("## Metrics"));
        assert!(markdown.contains("coverage"));
        assert!(markdown.contains("85.5"));
        assert!(markdown.contains("%"));
        assert!(markdown.contains("(baseline: 80)"));
    }

    #[test]
    fn given_packet_with_attachments_when_exporting_then_includes_attachments_section() {
        // Given: A packet with attachments
        let packet = create_full_packet("test-packet", PacketStatus::Pass);

        // When: Exporting the packet to Markdown
        let markdown = export_packet(&packet).unwrap();

        // Then: The Markdown includes the attachments
        assert!(markdown.contains("## Attachments"));
        assert!(markdown.contains("ReportHtml"));
        assert!(markdown.contains("report.html"));
        assert!(markdown.contains("text/html"));
        assert!(markdown.contains("SHA-256:"));
        assert!(markdown.contains("Size: 1024 bytes"));
        assert!(markdown.contains("Schema ID: schema-1"));
    }

    #[test]
    fn given_packet_with_relations_when_exporting_then_includes_relations_section() {
        // Given: A packet with relations
        let packet = create_full_packet("test-packet", PacketStatus::Pass);

        // When: Exporting the packet to Markdown
        let markdown = export_packet(&packet).unwrap();

        // Then: The Markdown includes the relations
        assert!(markdown.contains("## Relations"));
        assert!(markdown.contains("DerivedFrom"));
        assert!(markdown.contains("parent-packet"));
        assert!(markdown.contains("Derived from parent"));
    }

    #[test]
    fn given_packet_with_links_when_exporting_then_includes_links_section() {
        // Given: A packet with links
        let packet = create_full_packet("test-packet", PacketStatus::Pass);

        // When: Exporting the packet to Markdown
        let markdown = export_packet(&packet).unwrap();

        // Then: The Markdown includes the links
        assert!(markdown.contains("## Links"));
        assert!(markdown.contains("[CI](https://ci.example.com)"));
        assert!(markdown.contains("[Dashboard](https://dashboard.example.com)"));
    }

    #[test]
    fn given_packet_with_labels_when_exporting_then_includes_labels_section() {
        // Given: A packet with labels
        let packet = create_full_packet("test-packet", PacketStatus::Pass);

        // When: Exporting the packet to Markdown
        let markdown = export_packet(&packet).unwrap();

        // Then: The Markdown includes the labels
        assert!(markdown.contains("## Labels"));
        assert!(markdown.contains("**team**: platform"));
        assert!(markdown.contains("**environment**: production"));
    }

    #[test]
    fn given_packet_with_empty_projections_when_exporting_then_omits_empty_sections() {
        // Given: A packet with no projections
        let packet = create_minimal_packet("test-packet", PacketStatus::Pass);

        // When: Exporting the packet to Markdown
        let markdown = export_packet(&packet).unwrap();

        // Then: The Markdown does not include empty projection sections
        assert!(!markdown.contains("## Assertions"));
        assert!(!markdown.contains("## Findings"));
        assert!(!markdown.contains("## Metrics"));
        assert!(!markdown.contains("## Attachments"));
        assert!(!markdown.contains("## Relations"));
        assert!(!markdown.contains("## Native Payloads"));
        assert!(!markdown.contains("## Artifacts"));
        assert!(!markdown.contains("## Links"));
        assert!(!markdown.contains("## Labels"));
    }

    #[test]
    fn given_packet_with_base_commit_when_exporting_then_includes_base() {
        // Given: A packet with a base commit
        let packet = create_full_packet("test-packet", PacketStatus::Pass);

        // When: Exporting the packet to Markdown
        let markdown = export_packet(&packet).unwrap();

        // Then: The Markdown includes the base commit
        assert!(markdown.contains("**Base:** base123"));
    }

    #[test]
    fn given_packet_with_path_scope_when_exporting_then_includes_path_scope() {
        // Given: A packet with a path scope
        let packet = create_full_packet("test-packet", PacketStatus::Pass);

        // When: Exporting the packet to Markdown
        let markdown = export_packet(&packet).unwrap();

        // Then: The Markdown includes the path scope
        assert!(markdown.contains("**Path Scope:** src/"));
    }

    #[test]
    fn given_packet_with_invocation_id_when_exporting_then_includes_invocation_id() {
        // Given: A packet with an invocation ID
        let mut packet = create_minimal_packet("test-packet", PacketStatus::Pass);
        packet.producer.invocation_id = Some("inv-123".to_string());

        // When: Exporting the packet to Markdown
        let markdown = export_packet(&packet).unwrap();

        // Then: The Markdown includes the invocation ID
        assert!(markdown.contains("**Invocation ID:** inv-123"));
    }

    #[test]
    fn given_packet_when_exporting_then_output_is_deterministic() {
        // Given: The same packet exported twice
        let packet = create_full_packet("test-packet", PacketStatus::Pass);

        // When: Exporting the packet twice
        let markdown1 = export_packet(&packet).unwrap();
        let markdown2 = export_packet(&packet).unwrap();

        // Then: The outputs are identical
        assert_eq!(markdown1, markdown2);
    }
}

// ============================================================================
// BUNDLE EXPORT TESTS
// ============================================================================

mod bundle_export {
    use super::*;

    #[test]
    fn given_valid_bundle_when_exporting_then_produces_markdown_with_all_sections() {
        // Given: A valid bundle with entries
        let bundle = create_bundle_with_entries("test-bundle");

        // When: Exporting the bundle to Markdown
        let result = export_bundle(&bundle);

        // Then: The export succeeds
        assert!(result.is_ok());

        // And: The Markdown contains all expected sections
        let markdown = result.unwrap();
        assert!(markdown.contains("# Evidence Bundle: test-bundle"));
        assert!(markdown.contains("## Summary"));
        assert!(markdown.contains("### Status Counts"));
        assert!(markdown.contains("### Severity Counts"));
        assert!(markdown.contains("## Packet Inventory"));
        assert!(markdown.contains("## Artifact Inventory"));
        assert!(markdown.contains("## Integrity"));
    }

    #[test]
    fn given_bundle_with_status_counts_when_exporting_then_includes_status_counts() {
        // Given: A bundle with status counts
        let bundle = create_bundle_with_entries("test-bundle");

        // When: Exporting the bundle to Markdown
        let markdown = export_bundle(&bundle).unwrap();

        // Then: The Markdown includes all status counts with emojis
        assert!(markdown.contains("✅ Pass"));
        assert!(markdown.contains("Count: 1"));
        assert!(markdown.contains("❌ Fail"));
        assert!(markdown.contains("Count: 1"));
        assert!(markdown.contains("⚠️ Warn"));
        assert!(markdown.contains("Count: 0"));
        assert!(markdown.contains("❓ Indeterminate"));
        assert!(markdown.contains("Count: 0"));
        assert!(markdown.contains("💥 Error"));
        assert!(markdown.contains("Count: 0"));
    }

    #[test]
    fn given_bundle_with_severity_counts_when_exporting_then_includes_severity_counts() {
        // Given: A bundle with severity counts
        let bundle = create_bundle_with_entries("test-bundle");

        // When: Exporting the bundle to Markdown
        let markdown = export_bundle(&bundle).unwrap();

        // Then: The Markdown includes all severity counts with emojis
        assert!(markdown.contains("ℹ️ Note"));
        assert!(markdown.contains("Count: 0"));
        assert!(markdown.contains("⚠️ Warning"));
        assert!(markdown.contains("Count: 1"));
        assert!(markdown.contains("🔴 Error"));
        assert!(markdown.contains("Count: 0"));
    }

    #[test]
    fn given_bundle_with_packet_inventory_when_exporting_then_includes_packet_entries() {
        // Given: A bundle with packet inventory
        let bundle = create_bundle_with_entries("test-bundle");

        // When: Exporting the bundle to Markdown
        let markdown = export_bundle(&bundle).unwrap();

        // Then: The Markdown includes all packet entries
        assert!(markdown.contains("**packet-1**"));
        assert!(markdown.contains("Path: packets/packet-1/packet.eb.json"));
        assert!(markdown.contains("**packet-2**"));
        assert!(markdown.contains("Path: packets/packet-2/packet.eb.json"));
    }

    #[test]
    fn given_bundle_with_artifact_inventory_when_exporting_then_includes_artifact_entries() {
        // Given: A bundle with artifact inventory
        let bundle = create_bundle_with_entries("test-bundle");

        // When: Exporting the bundle to Markdown
        let markdown = export_bundle(&bundle).unwrap();

        // Then: The Markdown includes all artifact entries
        assert!(markdown.contains("**packet-1**"));
        assert!(markdown.contains("Path: packets/packet-1/artifacts/report.html"));
        assert!(markdown.contains("Role: ReportHtml"));
    }

    #[test]
    fn given_bundle_with_integrity_info_when_exporting_then_includes_integrity_section() {
        // Given: A bundle with integrity metadata
        let bundle = create_bundle_with_entries("test-bundle");

        // When: Exporting the bundle to Markdown
        let markdown = export_bundle(&bundle).unwrap();

        // Then: The Markdown includes integrity information
        assert!(markdown.contains("## Integrity"));
        assert!(markdown.contains("**Manifest digest:**"));
        assert!(markdown.contains("**Packet digests:** 2 entries"));
        assert!(markdown.contains("**Artifact digests:** 1 entries"));
    }

    #[test]
    fn given_bundle_with_empty_inventory_when_exporting_then_shows_empty_inventories() {
        // Given: A bundle with empty inventories
        let bundle = create_minimal_bundle("test-bundle");

        // When: Exporting the bundle to Markdown
        let markdown = export_bundle(&bundle).unwrap();

        // Then: The Markdown shows the inventory sections but they're empty
        assert!(markdown.contains("## Packet Inventory"));
        assert!(markdown.contains("## Artifact Inventory"));
        assert!(markdown.contains("**Total packets:** 0"));
        assert!(markdown.contains("**Total artifacts:** 0"));
    }

    #[test]
    fn given_bundle_when_exporting_then_output_is_deterministic() {
        // Given: The same bundle exported twice
        let bundle = create_bundle_with_entries("test-bundle");

        // When: Exporting the bundle twice
        let markdown1 = export_bundle(&bundle).unwrap();
        let markdown2 = export_bundle(&bundle).unwrap();

        // Then: The outputs are identical
        assert_eq!(markdown1, markdown2);
    }

    #[test]
    fn given_bundle_when_exporting_then_includes_version_and_timestamp() {
        // Given: A valid bundle
        let bundle = create_bundle_with_entries("test-bundle");

        // When: Exporting the bundle to Markdown
        let markdown = export_bundle(&bundle).unwrap();

        // Then: The Markdown includes version and timestamp
        assert!(markdown.contains("**Created:** 2024-01-01T12:00:00Z"));
        assert!(markdown.contains("**Version:** 0.1.0"));
    }
}

// ============================================================================
// EDGE CASE TESTS
// ============================================================================

mod edge_cases {
    use super::*;

    #[test]
    fn given_packet_with_finding_without_location_when_exporting_then_includes_finding_without_location(
    ) {
        // Given: A packet with a finding that has no location
        let mut packet = create_minimal_packet("test-packet", PacketStatus::Pass);
        packet.projections = Projections::new().add_finding(evidencebus_types::Finding::new(
            "finding-1",
            FindingSeverity::Warning,
            "Finding 1",
            "This is a warning",
        ));

        // When: Exporting the packet to Markdown
        let markdown = export_packet(&packet).unwrap();

        // Then: The Markdown includes the finding without location
        assert!(markdown.contains("## Findings"));
        assert!(markdown.contains("finding-1"));
        assert!(markdown.contains("This is a warning"));
        assert!(!markdown.contains("Location:"));
    }

    #[test]
    fn given_packet_with_finding_with_line_only_when_exporting_then_includes_line_only() {
        // Given: A packet with a finding that has only a line number
        let mut packet = create_minimal_packet("test-packet", PacketStatus::Pass);
        packet.projections = Projections::new().add_finding(
            evidencebus_types::Finding::new(
                "finding-1",
                FindingSeverity::Warning,
                "Finding 1",
                "This is a warning",
            )
            .with_location(Location::new("src/main.rs").with_line(42)),
        );

        // When: Exporting the packet to Markdown
        let markdown = export_packet(&packet).unwrap();

        // Then: The Markdown includes the finding with line number only
        assert!(markdown.contains("Location: src/main.rs:42"));
        assert!(!markdown.contains(":42:"));
    }

    #[test]
    fn given_packet_with_metric_without_unit_when_exporting_then_includes_metric_without_unit() {
        // Given: A packet with a metric that has no unit
        let mut packet = create_minimal_packet("test-packet", PacketStatus::Pass);
        packet.projections = Projections::new().add_metric(Metric::new("count", 42.0));

        // When: Exporting the packet to Markdown
        let markdown = export_packet(&packet).unwrap();

        // Then: The Markdown includes metric without unit
        assert!(markdown.contains("## Metrics"));
        assert!(markdown.contains("- **count**: 42"));
    }

    #[test]
    fn given_packet_with_metric_without_baseline_when_exporting_then_includes_metric_without_baseline(
    ) {
        // Given: A packet with a metric that has no baseline
        let mut packet = create_minimal_packet("test-packet", PacketStatus::Pass);
        packet.projections =
            Projections::new().add_metric(Metric::new("coverage", 85.5).with_unit("%"));

        // When: Exporting the packet to Markdown
        let markdown = export_packet(&packet).unwrap();

        // Then: The Markdown includes metric without baseline
        assert!(markdown.contains("## Metrics"));
        assert!(markdown.contains("- **coverage**: 85.5 %"));
        assert!(!markdown.contains("baseline:"));
    }

    #[test]
    fn given_packet_with_attachment_without_size_when_exporting_then_includes_attachment_without_size(
    ) {
        // Given: A packet with an attachment that has no size
        let mut packet = create_minimal_packet("test-packet", PacketStatus::Pass);
        packet.projections = Projections::new().add_attachment(Attachment::new(
            AttachmentRole::ReportHtml,
            "text/html",
            "report.html",
            Digest::new("0".repeat(64)).unwrap(),
        ));

        // When: Exporting the packet to Markdown
        let markdown = export_packet(&packet).unwrap();

        // Then: The Markdown includes the attachment without size
        assert!(markdown.contains("## Attachments"));
        assert!(markdown.contains("report.html"));
        assert!(!markdown.contains("Size:"));
    }

    #[test]
    fn given_packet_with_attachment_without_schema_when_exporting_then_includes_attachment_without_schema(
    ) {
        // Given: A packet with an attachment that has no schema ID
        let mut packet = create_minimal_packet("test-packet", PacketStatus::Pass);
        packet.projections = Projections::new().add_attachment(Attachment::new(
            AttachmentRole::ReportHtml,
            "text/html",
            "report.html",
            Digest::new("0".repeat(64)).unwrap(),
        ));

        // When: Exporting the packet to Markdown
        let markdown = export_packet(&packet).unwrap();

        // Then: The Markdown includes the attachment without schema ID
        assert!(markdown.contains("## Attachments"));
        assert!(markdown.contains("report.html"));
        assert!(!markdown.contains("Schema ID:"));
    }

    #[test]
    fn given_packet_with_relation_without_details_when_exporting_then_includes_relation_without_details(
    ) {
        // Given: A packet with a relation that has no details
        let mut packet = create_minimal_packet("test-packet", PacketStatus::Pass);
        packet.projections = Projections::new().add_relation(evidencebus_types::Relation::new(
            evidencebus_types::RelationKind::DerivedFrom,
            PacketId::new("parent-packet").unwrap(),
        ));

        // When: Exporting the packet to Markdown
        let markdown = export_packet(&packet).unwrap();

        // Then: The Markdown includes the relation without details
        assert!(markdown.contains("## Relations"));
        assert!(markdown.contains("DerivedFrom"));
        assert!(markdown.contains("parent-packet"));
        assert!(!markdown.contains("  - "));
    }

    #[test]
    fn given_packet_with_assertion_without_details_when_exporting_then_includes_assertion_without_details(
    ) {
        // Given: A packet with an assertion that has no details
        let mut packet = create_minimal_packet("test-packet", PacketStatus::Pass);
        packet.projections = Projections::new().add_assertion(evidencebus_types::Assertion::new(
            "assert-1",
            PacketStatus::Pass,
            Summary::new(PacketStatus::Pass, "Assert 1", "Passed"),
        ));

        // When: Exporting the packet to Markdown
        let markdown = export_packet(&packet).unwrap();

        // Then: The Markdown includes the assertion without details
        assert!(markdown.contains("## Assertions"));
        assert!(markdown.contains("assert-1"));
        assert!(markdown.contains("Assert 1"));
        assert!(markdown.contains("Passed"));
        assert!(!markdown.contains("Details:"));
    }

    #[test]
    fn given_packet_with_subject_without_base_when_exporting_then_omits_base() {
        // Given: A packet with a subject that has no base commit
        let packet = create_minimal_packet("test-packet", PacketStatus::Pass);

        // When: Exporting the packet to Markdown
        let markdown = export_packet(&packet).unwrap();

        // Then: The Markdown does not include base commit
        assert!(!markdown.contains("**Base:**"));
    }

    #[test]
    fn given_packet_with_subject_without_path_scope_when_exporting_then_omits_path_scope() {
        // Given: A packet with a subject that has no path scope
        let packet = create_minimal_packet("test-packet", PacketStatus::Pass);

        // When: Exporting the packet to Markdown
        let markdown = export_packet(&packet).unwrap();

        // Then: The Markdown does not include path scope
        assert!(!markdown.contains("**Path Scope:**"));
    }

    #[test]
    fn given_packet_with_multiple_findings_when_exporting_then_includes_all_findings() {
        // Given: A packet with multiple findings
        let mut packet = create_minimal_packet("test-packet", PacketStatus::Pass);
        packet.projections = Projections::new()
            .add_finding(evidencebus_types::Finding::new(
                "finding-1",
                FindingSeverity::Warning,
                "Finding 1",
                "This is a warning",
            ))
            .add_finding(evidencebus_types::Finding::new(
                "finding-2",
                FindingSeverity::Error,
                "Finding 2",
                "This is an error",
            ));

        // When: Exporting the packet to Markdown
        let markdown = export_packet(&packet).unwrap();

        // Then: The Markdown includes all findings
        assert!(markdown.contains("finding-1"));
        assert!(markdown.contains("Finding 1"));
        assert!(markdown.contains("finding-2"));
        assert!(markdown.contains("Finding 2"));
    }

    #[test]
    fn given_packet_with_multiple_metrics_when_exporting_then_includes_all_metrics() {
        // Given: A packet with multiple metrics
        let mut packet = create_minimal_packet("test-packet", PacketStatus::Pass);
        packet.projections = Projections::new()
            .add_metric(Metric::new("coverage", 85.5).with_unit("%"))
            .add_metric(Metric::new("duration", 1234.0).with_unit("ms"));

        // When: Exporting the packet to Markdown
        let markdown = export_packet(&packet).unwrap();

        // Then: The Markdown includes all metrics
        assert!(markdown.contains("coverage"));
        assert!(markdown.contains("85.5"));
        assert!(markdown.contains("duration"));
        assert!(markdown.contains("1234"));
    }

    #[test]
    fn given_packet_with_multiple_attachments_when_exporting_then_includes_all_attachments() {
        // Given: A packet with multiple attachments
        let mut packet = create_minimal_packet("test-packet", PacketStatus::Pass);
        packet.projections = Projections::new()
            .add_attachment(Attachment::new(
                AttachmentRole::ReportHtml,
                "text/html",
                "report.html",
                Digest::new("0".repeat(64)).unwrap(),
            ))
            .add_attachment(Attachment::new(
                AttachmentRole::PlainText,
                "text/plain",
                "log.txt",
                Digest::new("1".repeat(64)).unwrap(),
            ));

        // When: Exporting the packet to Markdown
        let markdown = export_packet(&packet).unwrap();

        // Then: The Markdown includes all attachments
        assert!(markdown.contains("report.html"));
        assert!(markdown.contains("log.txt"));
    }

    #[test]
    fn given_packet_with_multiple_assertions_when_exporting_then_includes_all_assertions() {
        // Given: A packet with multiple assertions
        let mut packet = create_minimal_packet("test-packet", PacketStatus::Pass);
        packet.projections = Projections::new()
            .add_assertion(evidencebus_types::Assertion::new(
                "assert-1",
                PacketStatus::Pass,
                Summary::new(PacketStatus::Pass, "Assert 1", "Passed"),
            ))
            .add_assertion(evidencebus_types::Assertion::new(
                "assert-2",
                PacketStatus::Fail,
                Summary::new(PacketStatus::Fail, "Assert 2", "Failed"),
            ));

        // When: Exporting the packet to Markdown
        let markdown = export_packet(&packet).unwrap();

        // Then: The Markdown includes all assertions
        assert!(markdown.contains("assert-1"));
        assert!(markdown.contains("Assert 1"));
        assert!(markdown.contains("assert-2"));
        assert!(markdown.contains("Assert 2"));
    }
}
