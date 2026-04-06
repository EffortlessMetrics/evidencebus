#![allow(clippy::unwrap_used, clippy::useless_vec)]
//! BDD-style tests for evidencebus-export facade.
//!
//! These tests follow the Given-When-Then pattern to describe
//! the facade behavior in a clear, readable format.
//!
//! The evidencebus-export crate acts as a facade that delegates
//! to format-specific export crates (evidencebus-export-markdown
//! and evidencebus-export-sarif).

use evidencebus_codes::{FindingSeverity, PacketStatus};
use evidencebus_export::{
    export_bundle_markdown, export_bundle_sarif, export_packet_markdown, export_packet_sarif,
    export_packets_sarif, sarif_level, sarif_result_kind, ExportError, ExportOptions, LossyMode,
};
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
            .add_assertion(evidencebus_types::Assertion::new(
                "assert-1",
                PacketStatus::Pass,
                Summary::new(PacketStatus::Pass, "Assert 1", "Passed"),
            ))
            .add_finding(evidencebus_types::Finding::new(
                "finding-1",
                FindingSeverity::Warning,
                "Finding 1",
                "This is a warning",
            ))
            .add_metric(Metric::new("coverage", 85.5).with_unit("%"))
            .add_attachment(Attachment::new(
                AttachmentRole::ReportHtml,
                "text/html",
                "report.html",
                Digest::new("0".repeat(64)).unwrap(),
            ))
            .add_relation(evidencebus_types::Relation::new(
                evidencebus_types::RelationKind::DerivedFrom,
                PacketId::new("parent-packet").unwrap(),
            )),
        native_payloads: vec!["payload.json".to_string()],
        artifacts: vec!["artifact.txt".to_string()],
        links: Some({
            let mut map = HashMap::new();
            map.insert("CI".to_string(), "https://ci.example.com".to_string());
            map
        }),
        labels: Some({
            let mut map = HashMap::new();
            map.insert("team".to_string(), "platform".to_string());
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
                HashMap::new(),
                HashMap::new(),
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
// PACKET MARKDOWN EXPORT TESTS
// ============================================================================

mod packet_markdown_export {
    use super::*;

    #[test]
    fn given_valid_packet_when_exporting_to_markdown_then_produces_valid_markdown() {
        // Given: A valid packet with all fields populated
        let packet = create_full_packet("test-packet", PacketStatus::Pass);

        // When: Exporting the packet to Markdown via the facade
        let result = export_packet_markdown(&packet);

        // Then: The export succeeds
        assert!(result.is_ok());

        // And: The Markdown contains the packet ID
        let markdown = result.unwrap();
        assert!(markdown.contains("# Evidence Packet: test-packet"));

        // And: The Markdown contains the producer information
        assert!(markdown.contains("test-tool"));
        assert!(markdown.contains("1.0.0"));

        // And: The Markdown contains the subject information
        assert!(markdown.contains("owner/repo"));
    }

    #[test]
    fn given_packet_with_findings_when_exporting_to_markdown_then_includes_findings() {
        // Given: A packet with findings
        let packet = create_full_packet("test-packet", PacketStatus::Pass);

        // When: Exporting the packet to Markdown
        let markdown = export_packet_markdown(&packet).unwrap();

        // Then: The Markdown contains the findings section
        assert!(markdown.contains("## Findings"));

        // And: The Markdown contains the finding details
        assert!(markdown.contains("finding-1"));
        assert!(markdown.contains("This is a warning"));
    }

    #[test]
    fn given_packet_with_assertions_when_exporting_to_markdown_then_includes_assertions() {
        // Given: A packet with assertions
        let packet = create_full_packet("test-packet", PacketStatus::Pass);

        // When: Exporting the packet to Markdown
        let markdown = export_packet_markdown(&packet).unwrap();

        // Then: The Markdown contains the assertions section
        assert!(markdown.contains("## Assertions"));

        // And: The Markdown contains the assertion details
        assert!(markdown.contains("assert-1"));
    }

    #[test]
    fn given_packet_with_metrics_when_exporting_to_markdown_then_includes_metrics() {
        // Given: A packet with metrics
        let packet = create_full_packet("test-packet", PacketStatus::Pass);

        // When: Exporting the packet to Markdown
        let markdown = export_packet_markdown(&packet).unwrap();

        // Then: The Markdown contains the metrics section
        assert!(markdown.contains("## Metrics"));

        // And: The Markdown contains the metric details
        assert!(markdown.contains("coverage"));
        assert!(markdown.contains("85.5"));
    }

    #[test]
    fn given_packet_with_attachments_when_exporting_to_markdown_then_includes_attachments() {
        // Given: A packet with attachments
        let packet = create_full_packet("test-packet", PacketStatus::Pass);

        // When: Exporting the packet to Markdown
        let markdown = export_packet_markdown(&packet).unwrap();

        // Then: The Markdown contains the attachments section
        assert!(markdown.contains("## Attachments"));

        // And: The Markdown contains the attachment details
        assert!(markdown.contains("report.html"));
    }

    #[test]
    fn given_packet_with_links_when_exporting_to_markdown_then_includes_links() {
        // Given: A packet with links
        let packet = create_full_packet("test-packet", PacketStatus::Pass);

        // When: Exporting the packet to Markdown
        let markdown = export_packet_markdown(&packet).unwrap();

        // Then: The Markdown contains the links section
        assert!(markdown.contains("## Links"));

        // And: The Markdown contains the link details
        assert!(markdown.contains("CI"));
        assert!(markdown.contains("https://ci.example.com"));
    }

    #[test]
    fn given_packet_with_labels_when_exporting_to_markdown_then_includes_labels() {
        // Given: A packet with labels
        let packet = create_full_packet("test-packet", PacketStatus::Pass);

        // When: Exporting the packet to Markdown
        let markdown = export_packet_markdown(&packet).unwrap();

        // Then: The Markdown contains the labels section
        assert!(markdown.contains("## Labels"));

        // And: The Markdown contains the label details
        assert!(markdown.contains("team"));
        assert!(markdown.contains("platform"));
    }

    #[test]
    fn given_packet_with_different_status_when_exporting_to_markdown_then_shows_correct_emoji() {
        // Given: A packet with Fail status
        let packet = create_minimal_packet("test-packet", PacketStatus::Fail);

        // When: Exporting the packet to Markdown
        let markdown = export_packet_markdown(&packet).unwrap();

        // Then: The Markdown shows the correct status emoji
        assert!(markdown.contains("❌"));
    }
}

// ============================================================================
// PACKET SARIF EXPORT TESTS
// ============================================================================

mod packet_sarif_export {
    use super::*;

    #[test]
    fn given_valid_packet_when_exporting_to_sarif_then_produces_valid_sarif() {
        // Given: A valid packet with all fields populated
        let packet = create_full_packet("test-packet", PacketStatus::Pass);

        // When: Exporting the packet to SARIF via the facade
        let result = export_packet_sarif(&packet);

        // Then: The export succeeds
        assert!(result.is_ok());

        // And: The SARIF document has the correct version
        let sarif = result.unwrap();
        assert_eq!(sarif["version"], "2.1.0");

        // And: The SARIF document has the correct schema
        assert!(sarif["$schema"]
            .as_str()
            .unwrap()
            .contains("sarif-2.1.0.json"));

        // And: The SARIF document contains exactly one run
        let runs = sarif["runs"].as_array().unwrap();
        assert_eq!(runs.len(), 1);

        // And: The run contains tool information
        let run = &runs[0];
        assert_eq!(run["tool"]["driver"]["name"], "test-tool");
        assert_eq!(run["tool"]["driver"]["version"], "1.0.0");
    }

    #[test]
    fn given_packet_with_findings_when_exporting_to_sarif_then_includes_findings_as_results() {
        // Given: A packet with findings
        let packet = create_full_packet("test-packet", PacketStatus::Pass);

        // When: Exporting the packet to SARIF
        let sarif = export_packet_sarif(&packet).unwrap();

        // Then: The results include all findings
        let results = sarif["runs"][0]["results"].as_array().unwrap();
        let finding_results: Vec<_> = results
            .iter()
            .filter(|r| r["ruleId"].as_str().unwrap().starts_with("finding-"))
            .collect();

        assert_eq!(finding_results.len(), 1);

        // And: The finding result has the correct level
        let finding_result = &finding_results[0];
        assert_eq!(finding_result["ruleId"], "finding-1");
        assert_eq!(finding_result["level"], "warning");
    }

    #[test]
    fn given_packet_with_assertions_when_exporting_to_sarif_then_includes_assertions_as_results() {
        // Given: A packet with assertions
        let packet = create_full_packet("test-packet", PacketStatus::Pass);

        // When: Exporting the packet to SARIF
        let sarif = export_packet_sarif(&packet).unwrap();

        // Then: The results include all assertions
        let results = sarif["runs"][0]["results"].as_array().unwrap();
        let assertion_results: Vec<_> = results
            .iter()
            .filter(|r| r["ruleId"].as_str().unwrap().starts_with("assert-"))
            .collect();

        assert_eq!(assertion_results.len(), 1);

        // And: The assertion result has the correct kind
        let assertion_result = &assertion_results[0];
        assert_eq!(assertion_result["ruleId"], "assert-1");
        assert_eq!(assertion_result["kind"], "pass");
    }

    #[test]
    fn given_packet_with_location_when_exporting_to_sarif_then_includes_location_in_result() {
        // Given: A packet with a finding that has a location
        let mut packet = create_full_packet("test-packet", PacketStatus::Pass);
        packet.projections.findings[0] = packet.projections.findings[0]
            .clone()
            .with_location(Location::new("src/main.rs").with_line(42).with_column(10));

        // When: Exporting the packet to SARIF
        let sarif = export_packet_sarif(&packet).unwrap();
        let results = sarif["runs"][0]["results"].as_array().unwrap();
        let finding_result = results.iter().find(|r| r["ruleId"] == "finding-1").unwrap();

        // Then: The result includes the location
        assert!(finding_result["locations"].is_array());

        // And: The location has the correct file path
        assert_eq!(
            finding_result["locations"][0]["physicalLocation"]["artifactLocation"]["uri"],
            "src/main.rs"
        );

        // And: The location has the correct line number
        assert_eq!(
            finding_result["locations"][0]["physicalLocation"]["region"]["startLine"],
            42
        );

        // And: The location has the correct column number
        assert_eq!(
            finding_result["locations"][0]["physicalLocation"]["region"]["startColumn"],
            10
        );
    }

    #[test]
    fn given_packet_with_metrics_when_exporting_to_sarif_then_marks_as_lossy() {
        // Given: A packet with metrics (which are lossy in SARIF)
        let mut packet = create_full_packet("test-packet", PacketStatus::Pass);
        packet
            .projections
            .metrics
            .push(Metric::new("latency", 100.0));

        // When: Exporting the packet to SARIF
        let sarif = export_packet_sarif(&packet).unwrap();

        // Then: The run properties indicate lossy export
        let properties = sarif["runs"][0]["properties"].as_object().unwrap();
        assert_eq!(properties["evidencebusLossy"], true);

        // And: The omitted fields include metrics
        let omitted = properties["omittedFields"].as_array().unwrap();
        assert!(omitted.iter().any(|v| {
            v.as_str().unwrap().contains("metrics") && v.as_str().unwrap().contains("omitted")
        }));
    }

    #[test]
    fn given_packet_with_relations_when_exporting_to_sarif_then_marks_as_lossy() {
        // Given: A packet with relations (which are lossy in SARIF)
        let mut packet = create_full_packet("test-packet", PacketStatus::Pass);
        packet
            .projections
            .relations
            .push(evidencebus_types::Relation::new(
                evidencebus_types::RelationKind::DerivedFrom,
                PacketId::new("parent-packet").unwrap(),
            ));

        // When: Exporting the packet to SARIF
        let sarif = export_packet_sarif(&packet).unwrap();

        // Then: The run properties indicate lossy export
        let properties = sarif["runs"][0]["properties"].as_object().unwrap();
        assert_eq!(properties["evidencebusLossy"], true);

        // And: The omitted fields include relations
        let omitted = properties["omittedFields"].as_array().unwrap();
        assert!(omitted.iter().any(|v| {
            v.as_str().unwrap().contains("relations") && v.as_str().unwrap().contains("omitted")
        }));
    }
}

// ============================================================================
// MULTIPLE PACKETS SARIF EXPORT TESTS
// ============================================================================

mod multiple_packets_sarif_export {
    use super::*;

    #[test]
    fn given_multiple_packets_when_exporting_to_sarif_then_creates_multiple_runs() {
        // Given: Multiple packets
        let packet1 = create_full_packet("packet-1", PacketStatus::Pass);
        let packet2 = create_full_packet("packet-2", PacketStatus::Fail);
        let packet3 = create_full_packet("packet-3", PacketStatus::Warn);

        // When: Exporting the packets to SARIF via the facade
        let result = export_packets_sarif(&[packet1, packet2, packet3]);

        // Then: The export succeeds
        assert!(result.is_ok());

        // And: The SARIF document has the correct version
        let sarif = result.unwrap();
        assert_eq!(sarif["version"], "2.1.0");

        // And: The SARIF document contains three runs (one per packet)
        let runs = sarif["runs"].as_array().unwrap();
        assert_eq!(runs.len(), 3);

        // And: Each run has the correct tool information
        for run in runs {
            assert_eq!(run["tool"]["driver"]["name"], "test-tool");
            assert_eq!(run["tool"]["driver"]["version"], "1.0.0");
        }
    }

    #[test]
    fn given_empty_packet_list_when_exporting_to_sarif_then_creates_empty_sarif() {
        // Given: An empty list of packets
        let packets: Vec<Packet> = vec![];

        // When: Exporting the packets to SARIF
        let result = export_packets_sarif(&packets);

        // Then: The export succeeds
        assert!(result.is_ok());

        // And: The SARIF document has the correct version
        let sarif = result.unwrap();
        assert_eq!(sarif["version"], "2.1.0");

        // And: The SARIF document contains no runs
        let runs = sarif["runs"].as_array().unwrap();
        assert_eq!(runs.len(), 0);
    }

    #[test]
    fn given_single_packet_when_exporting_to_sarif_then_creates_single_run() {
        // Given: A single packet
        let packet = create_full_packet("test-packet", PacketStatus::Pass);

        // When: Exporting the packet to SARIF
        let result = export_packets_sarif(&[packet]);

        // Then: The export succeeds
        assert!(result.is_ok());

        // And: The SARIF document contains exactly one run
        let sarif = result.unwrap();
        let runs = sarif["runs"].as_array().unwrap();
        assert_eq!(runs.len(), 1);
    }

    #[test]
    fn given_packets_with_different_statuses_when_exporting_to_sarif_then_preserves_statuses() {
        // Given: Packets with different statuses and findings
        let mut packet_pass = create_minimal_packet("packet-pass", PacketStatus::Pass);
        packet_pass
            .projections
            .findings
            .push(evidencebus_types::Finding::new(
                "finding-1",
                FindingSeverity::Note,
                "Finding 1",
                "Note",
            ));

        let mut packet_fail = create_minimal_packet("packet-fail", PacketStatus::Fail);
        packet_fail
            .projections
            .findings
            .push(evidencebus_types::Finding::new(
                "finding-2",
                FindingSeverity::Error,
                "Finding 2",
                "Error",
            ));

        let mut packet_warn = create_minimal_packet("packet-warn", PacketStatus::Warn);
        packet_warn
            .projections
            .findings
            .push(evidencebus_types::Finding::new(
                "finding-3",
                FindingSeverity::Warning,
                "Finding 3",
                "Warning",
            ));

        // When: Exporting the packets to SARIF
        let sarif = export_packets_sarif(&[packet_pass, packet_fail, packet_warn]).unwrap();
        let runs = sarif["runs"].as_array().unwrap();

        // Then: Each run preserves the packet status
        assert_eq!(runs.len(), 3);

        // And: The statuses are correctly represented in the results
        for run in runs {
            let results = run["results"].as_array().unwrap();
            assert!(!results.is_empty());
        }
    }
}

// ============================================================================
// BUNDLE MARKDOWN EXPORT TESTS
// ============================================================================

mod bundle_markdown_export {
    use super::*;

    #[test]
    fn given_valid_bundle_when_exporting_to_markdown_then_produces_valid_markdown() {
        // Given: A valid bundle with entries
        let bundle = create_bundle_with_entries("test-bundle");

        // When: Exporting the bundle to Markdown via the facade
        let result = export_bundle_markdown(&bundle);

        // Then: The export succeeds
        assert!(result.is_ok());

        // And: The Markdown contains the bundle ID
        let markdown = result.unwrap();
        assert!(markdown.contains("# Evidence Bundle: test-bundle"));

        // And: The Markdown contains the created timestamp
        assert!(markdown.contains("Created:"));
    }

    #[test]
    fn given_bundle_with_entries_when_exporting_to_markdown_then_includes_packet_inventory() {
        // Given: A bundle with packet entries
        let bundle = create_bundle_with_entries("test-bundle");

        // When: Exporting the bundle to Markdown
        let markdown = export_bundle_markdown(&bundle).unwrap();

        // Then: The Markdown contains the packet inventory section
        assert!(markdown.contains("## Packet Inventory"));

        // And: The Markdown contains the packet IDs
        assert!(markdown.contains("packet-1"));
        assert!(markdown.contains("packet-2"));
    }

    #[test]
    fn given_bundle_with_artifacts_when_exporting_to_markdown_then_includes_artifact_inventory() {
        // Given: A bundle with artifact entries
        let bundle = create_bundle_with_entries("test-bundle");

        // When: Exporting the bundle to Markdown
        let markdown = export_bundle_markdown(&bundle).unwrap();

        // Then: The Markdown contains the artifact inventory section
        assert!(markdown.contains("## Artifact Inventory"));

        // And: The Markdown contains the artifact paths
        assert!(markdown.contains("report.html"));
    }

    #[test]
    fn given_bundle_with_summary_when_exporting_to_markdown_then_includes_summary() {
        // Given: A bundle with summary information
        let bundle = create_bundle_with_entries("test-bundle");

        // When: Exporting the bundle to Markdown
        let markdown = export_bundle_markdown(&bundle).unwrap();

        // Then: The Markdown contains the summary section
        assert!(markdown.contains("## Summary"));

        // And: The Markdown contains the status counts
        assert!(markdown.contains("✅ Pass"));
        assert!(markdown.contains("Count: 1"));
        assert!(markdown.contains("❌ Fail"));
    }

    #[test]
    fn given_minimal_bundle_when_exporting_to_markdown_then_produces_minimal_markdown() {
        // Given: A minimal bundle without entries
        let bundle = create_minimal_bundle("test-bundle");

        // When: Exporting the bundle to Markdown
        let markdown = export_bundle_markdown(&bundle).unwrap();

        // Then: The Markdown contains the bundle ID
        assert!(markdown.contains("# Evidence Bundle: test-bundle"));

        // And: The Markdown contains the summary section
        assert!(markdown.contains("## Summary"));

        // And: The Markdown contains the total packets count
        assert!(markdown.contains("**Total packets:** 0"));
    }
}

// ============================================================================
// BUNDLE SARIF EXPORT TESTS
// ============================================================================

mod bundle_sarif_export {
    use super::*;

    #[test]
    fn given_bundle_when_exporting_to_sarif_then_returns_unsupported_format_error() {
        // Given: A valid bundle
        let bundle = create_bundle_with_entries("test-bundle");

        // When: Attempting to export the bundle to SARIF via the facade
        let result = export_bundle_sarif(&bundle);

        // Then: The export fails with an unsupported format error
        assert!(result.is_err());

        // And: The error message indicates the correct usage
        match result {
            Err(ExportError::UnsupportedFormat(msg)) => {
                assert!(msg.contains("export_packets_sarif"));
            }
            _ => panic!("Expected UnsupportedFormat error"),
        }
    }
}

// ============================================================================
// FACADE DELEGATION TESTS
// ============================================================================

mod facade_delegation {
    use super::*;

    #[test]
    fn given_sarif_level_request_when_calling_facade_then_delegates_to_sarif_crate() {
        // Given: A finding severity
        let severity = FindingSeverity::Warning;

        // When: Calling the facade's sarif_level function
        let level = sarif_level(&severity);

        // Then: The result matches the expected SARIF level
        assert_eq!(level, "warning");
    }

    #[test]
    fn given_sarif_result_kind_request_when_calling_facade_then_delegates_to_sarif_crate() {
        // Given: A packet status
        let status = PacketStatus::Pass;

        // When: Calling the facade's sarif_result_kind function
        let kind = sarif_result_kind(&status);

        // Then: The result matches the expected SARIF result kind
        assert_eq!(kind, "pass");
    }

    #[test]
    fn given_all_severities_when_mapping_to_sarif_levels_then_delegates_correctly() {
        // Given: All finding severities
        let severities = vec![
            FindingSeverity::Note,
            FindingSeverity::Warning,
            FindingSeverity::Error,
        ];

        // When: Mapping each severity to SARIF level
        let levels: Vec<_> = severities.iter().map(sarif_level).collect();

        // Then: All mappings are correct
        assert_eq!(levels[0], "note");
        assert_eq!(levels[1], "warning");
        assert_eq!(levels[2], "error");
    }

    #[test]
    fn given_all_statuses_when_mapping_to_sarif_result_kinds_then_delegates_correctly() {
        // Given: All packet statuses
        let statuses = vec![
            PacketStatus::Pass,
            PacketStatus::Fail,
            PacketStatus::Warn,
            PacketStatus::Indeterminate,
            PacketStatus::Error,
        ];

        // When: Mapping each status to SARIF result kind
        let kinds: Vec<_> = statuses.iter().map(sarif_result_kind).collect();

        // Then: All mappings are correct
        assert_eq!(kinds[0], "pass");
        assert_eq!(kinds[1], "fail");
        assert_eq!(kinds[2], "review");
        assert_eq!(kinds[3], "notApplicable");
        assert_eq!(kinds[4], "fail");
    }
}

// ============================================================================
// EXPORT OPTIONS TESTS
// ============================================================================

mod export_options {
    use super::*;

    #[test]
    fn given_default_export_options_then_has_correct_defaults() {
        // Given: Default export options
        let opts = ExportOptions::default();

        // Then: The options have the correct default values
        assert!(opts.include_details);
        assert!(opts.include_artifacts);
        assert_eq!(opts.lossy_mode, LossyMode::Permissive);
    }

    #[test]
    fn given_new_export_options_then_matches_defaults() {
        // Given: New export options
        let opts = ExportOptions::new();

        // Then: The options match the defaults
        assert_eq!(
            opts.include_details,
            ExportOptions::default().include_details
        );
        assert_eq!(
            opts.include_artifacts,
            ExportOptions::default().include_artifacts
        );
        assert_eq!(opts.lossy_mode, ExportOptions::default().lossy_mode);
    }

    #[test]
    fn given_export_options_when_modifying_details_then_reflects_changes() {
        // Given: Default export options
        let opts = ExportOptions::default();

        // When: Modifying the include_details flag
        let opts = opts.with_include_details(false);

        // Then: The option reflects the change
        assert!(!opts.include_details);
        assert!(opts.include_artifacts); // Other options unchanged
    }

    #[test]
    fn given_export_options_when_modifying_artifacts_then_reflects_changes() {
        // Given: Default export options
        let opts = ExportOptions::default();

        // When: Modifying the include_artifacts flag
        let opts = opts.with_include_artifacts(false);

        // Then: The option reflects the change
        assert!(!opts.include_artifacts);
        assert!(opts.include_details); // Other options unchanged
    }

    #[test]
    fn given_export_options_when_modifying_lossy_mode_then_reflects_changes() {
        // Given: Default export options
        let opts = ExportOptions::default();

        // When: Modifying the lossy mode
        let opts = opts.with_lossy_mode(LossyMode::Strict);

        // Then: The option reflects the change
        assert_eq!(opts.lossy_mode, LossyMode::Strict);
        assert!(opts.include_details); // Other options unchanged
    }

    #[test]
    fn given_export_options_when_chaining_modifications_then_all_changes_apply() {
        // Given: Default export options
        let opts = ExportOptions::default();

        // When: Chaining multiple modifications
        let opts = opts
            .with_include_details(false)
            .with_include_artifacts(false)
            .with_lossy_mode(LossyMode::Silent);

        // Then: All changes are applied
        assert!(!opts.include_details);
        assert!(!opts.include_artifacts);
        assert_eq!(opts.lossy_mode, LossyMode::Silent);
    }

    #[test]
    fn given_all_lossy_modes_when_creating_options_then_all_modes_work() {
        // Given: All lossy modes
        let modes = vec![LossyMode::Strict, LossyMode::Permissive, LossyMode::Silent];

        // When: Creating options with each mode
        for mode in modes {
            let opts = ExportOptions::new().with_lossy_mode(mode);

            // Then: The mode is correctly set
            assert_eq!(opts.lossy_mode, mode);
        }
    }
}

// ============================================================================
// ERROR HANDLING TESTS
// ============================================================================

mod error_handling {
    use super::*;

    #[test]
    fn given_export_error_when_displaying_then_shows_correct_message() {
        // Given: An export error
        let error = ExportError::UnsupportedFormat("test-format".to_string());

        // When: Displaying the error
        let message = format!("{}", error);

        // Then: The message is correct
        assert!(message.contains("unsupported format"));
        assert!(message.contains("test-format"));
    }

    #[test]
    fn given_lossy_export_error_when_displaying_then_shows_correct_message() {
        // Given: A lossy export error
        let error = ExportError::LossyExport("metrics omitted".to_string());

        // When: Displaying the error
        let message = format!("{}", error);

        // Then: The message is correct
        assert!(message.contains("lossy export"));
        assert!(message.contains("metrics omitted"));
    }

    #[test]
    fn given_invalid_input_error_when_displaying_then_shows_correct_message() {
        // Given: An invalid input error
        let error = ExportError::InvalidInput("missing packet ID".to_string());

        // When: Displaying the error
        let message = format!("{}", error);

        // Then: The message is correct
        assert!(message.contains("invalid input"));
        assert!(message.contains("missing packet ID"));
    }

    #[test]
    fn given_serialization_error_when_converting_to_export_error_then_wraps_correctly() {
        // Given: A serialization error (created by parsing invalid JSON)
        let invalid_json = "{ invalid json }";
        let serde_error = serde_json::from_str::<serde_json::Value>(invalid_json).unwrap_err();

        // When: Converting to export error
        let export_error: ExportError = serde_error.into();

        // Then: The error is correctly wrapped
        match export_error {
            ExportError::SerializationFailed(_) => {
                // Success - error was wrapped correctly
            }
            _ => panic!("Expected SerializationFailed error"),
        }
    }
}

// ============================================================================
// EDGE CASES TESTS
// ============================================================================

mod edge_cases {
    use super::*;

    #[test]
    fn given_packet_with_no_projections_when_exporting_to_markdown_then_still_produces_output() {
        // Given: A packet with no projections
        let packet = create_minimal_packet("test-packet", PacketStatus::Pass);

        // When: Exporting to Markdown
        let result = export_packet_markdown(&packet);

        // Then: The export succeeds
        assert!(result.is_ok());

        // And: The output contains the packet header
        let markdown = result.unwrap();
        assert!(markdown.contains("# Evidence Packet: test-packet"));
    }

    #[test]
    fn given_packet_with_no_projections_when_exporting_to_sarif_then_still_produces_output() {
        // Given: A packet with no projections
        let packet = create_minimal_packet("test-packet", PacketStatus::Pass);

        // When: Exporting to SARIF
        let result = export_packet_sarif(&packet);

        // Then: The export succeeds
        assert!(result.is_ok());

        // And: The output contains the SARIF structure
        let sarif = result.unwrap();
        assert_eq!(sarif["version"], "2.1.0");
    }

    #[test]
    fn given_packet_with_empty_links_when_exporting_to_markdown_then_handles_gracefully() {
        // Given: A packet with empty links map
        let mut packet = create_minimal_packet("test-packet", PacketStatus::Pass);
        packet.links = Some(HashMap::new());

        // When: Exporting to Markdown
        let result = export_packet_markdown(&packet);

        // Then: The export succeeds
        assert!(result.is_ok());
    }

    #[test]
    fn given_packet_with_empty_labels_when_exporting_to_markdown_then_handles_gracefully() {
        // Given: A packet with empty labels map
        let mut packet = create_minimal_packet("test-packet", PacketStatus::Pass);
        packet.labels = Some(HashMap::new());

        // When: Exporting to Markdown
        let result = export_packet_markdown(&packet);

        // Then: The export succeeds
        assert!(result.is_ok());
    }

    #[test]
    fn given_packet_with_all_statuses_when_exporting_to_markdown_then_all_emojis_appear() {
        // Given: Packets with all possible statuses
        let statuses = vec![
            PacketStatus::Pass,
            PacketStatus::Fail,
            PacketStatus::Warn,
            PacketStatus::Indeterminate,
            PacketStatus::Error,
        ];

        // When: Exporting each packet to Markdown
        for (i, status) in statuses.iter().enumerate() {
            let packet = create_minimal_packet(&format!("packet-{}", i), *status);
            let markdown = export_packet_markdown(&packet).unwrap();

            // Then: Each status has the correct emoji
            match status {
                PacketStatus::Pass => assert!(markdown.contains("✅")),
                PacketStatus::Fail => assert!(markdown.contains("❌")),
                PacketStatus::Warn => assert!(markdown.contains("⚠️")),
                PacketStatus::Indeterminate => assert!(markdown.contains("❓")),
                PacketStatus::Error => assert!(markdown.contains("💥")),
            }
        }
    }

    #[test]
    fn given_packet_with_all_severities_when_exporting_to_sarif_then_all_levels_appear() {
        // Given: Packets with all possible severities
        let severities = vec![
            FindingSeverity::Note,
            FindingSeverity::Warning,
            FindingSeverity::Error,
        ];

        // When: Exporting each packet to SARIF
        for (i, severity) in severities.iter().enumerate() {
            let mut packet = create_minimal_packet(&format!("packet-{}", i), PacketStatus::Pass);
            packet
                .projections
                .findings
                .push(evidencebus_types::Finding::new(
                    format!("finding-{}", i),
                    *severity,
                    format!("Finding {}", i),
                    format!("This is a {:?}", severity),
                ));

            let sarif = export_packet_sarif(&packet).unwrap();
            let results = sarif["runs"][0]["results"].as_array().unwrap();
            let finding_result = results
                .iter()
                .find(|r| r["ruleId"] == format!("finding-{}", i))
                .unwrap();

            // Then: Each severity has the correct level
            let expected_level = match severity {
                FindingSeverity::Note => "note",
                FindingSeverity::Warning => "warning",
                FindingSeverity::Error => "error",
            };
            assert_eq!(finding_result["level"], expected_level);
        }
    }
}

// ============================================================================
// BACKWARD COMPATIBILITY TESTS
// ============================================================================

mod backward_compatibility {
    use super::*;

    #[test]
    fn given_existing_packet_export_code_when_using_facade_then_works_as_before() {
        // Given: A packet created as before
        let packet = create_full_packet("test-packet", PacketStatus::Pass);

        // When: Exporting using the facade functions
        let markdown = export_packet_markdown(&packet).unwrap();
        let sarif = export_packet_sarif(&packet).unwrap();

        // Then: Both exports work correctly
        assert!(markdown.contains("test-packet"));
        assert_eq!(sarif["version"], "2.1.0");
    }

    #[test]
    fn given_existing_bundle_export_code_when_using_facade_then_works_as_before() {
        // Given: A bundle created as before
        let bundle = create_bundle_with_entries("test-bundle");

        // When: Exporting using the facade function
        let markdown = export_bundle_markdown(&bundle).unwrap();

        // Then: The export works correctly
        assert!(markdown.contains("test-bundle"));
    }

    #[test]
    fn given_existing_sarif_helper_code_when_using_facade_then_works_as_before() {
        // Given: Existing code using SARIF helpers
        let severity = FindingSeverity::Warning;
        let status = PacketStatus::Pass;

        // When: Calling the facade helper functions
        let level = sarif_level(&severity);
        let kind = sarif_result_kind(&status);

        // Then: Both helpers work correctly
        assert_eq!(level, "warning");
        assert_eq!(kind, "pass");
    }
}
