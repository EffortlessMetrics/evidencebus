#![allow(clippy::unwrap_used)]
//! BDD-style tests for SARIF export functionality.
//!
//! These tests follow the Given-When-Then pattern to describe
//! behavior in a clear, readable format.

use evidencebus_codes::{FindingSeverity, PacketStatus};
use evidencebus_export_sarif::{export_packet, export_packets, sarif_level, sarif_result_kind};
use evidencebus_types::{
    Attachment, AttachmentRole, Digest, Location, Metric, Packet, PacketId, Producer, Projections,
    SchemaVersion, Subject, Summary, VcsKind,
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
        producer: Producer::new("test-tool", "1.0.0").with_invocation_id("inv-123"),
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
            .add_finding(
                evidencebus_types::Finding::new(
                    "finding-2",
                    FindingSeverity::Error,
                    "Finding 2",
                    "This is an error",
                )
                .with_location(Location::new("src/main.rs").with_line(42).with_column(10)),
            )
            .add_metric(
                Metric::new("coverage", 85.5)
                    .with_unit("%")
                    .with_baseline(80.0),
            )
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

// ============================================================================
// PACKET EXPORT TESTS
// ============================================================================

mod packet_export {
    use super::*;

    #[test]
    fn given_valid_packet_when_exporting_then_produces_valid_sarif() {
        // Given: A valid packet with all fields populated
        let packet = create_full_packet("test-packet", PacketStatus::Pass);

        // When: Exporting the packet to SARIF
        let result = export_packet(&packet);

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
        assert_eq!(
            run["tool"]["driver"]["informationUri"],
            "https://github.com/EffortlessMetrics/evidencebus"
        );
    }

    #[test]
    fn given_packet_with_findings_when_exporting_then_includes_findings_as_results() {
        // Given: A packet with multiple findings
        let packet = create_full_packet("test-packet", PacketStatus::Pass);

        // When: Exporting the packet to SARIF
        let sarif = export_packet(&packet).unwrap();

        // Then: The results include all findings
        let results = sarif["runs"][0]["results"].as_array().unwrap();
        let finding_results: Vec<_> = results
            .iter()
            .filter(|r| r["ruleId"].as_str().unwrap().starts_with("finding-"))
            .collect();

        assert_eq!(finding_results.len(), 2);

        // And: Each finding has the correct level
        let warning_result = finding_results
            .iter()
            .find(|r| r["ruleId"] == "finding-1")
            .unwrap();
        assert_eq!(warning_result["level"], "warning");

        let error_result = finding_results
            .iter()
            .find(|r| r["ruleId"] == "finding-2")
            .unwrap();
        assert_eq!(error_result["level"], "error");

        // And: Each finding has a message
        assert!(warning_result["message"]["text"].is_string());
        assert!(error_result["message"]["text"].is_string());
    }

    #[test]
    fn given_packet_with_assertions_when_exporting_then_includes_assertions_as_results() {
        // Given: A packet with assertions
        let packet = create_full_packet("test-packet", PacketStatus::Pass);

        // When: Exporting the packet to SARIF
        let sarif = export_packet(&packet).unwrap();

        // Then: The results include all assertions
        let results = sarif["runs"][0]["results"].as_array().unwrap();
        let assertion_results: Vec<_> = results
            .iter()
            .filter(|r| r["ruleId"].as_str().unwrap().starts_with("assert-"))
            .collect();

        assert_eq!(assertion_results.len(), 1);

        // And: The assertion has the correct level
        let assertion_result = &assertion_results[0];
        assert_eq!(assertion_result["level"], "note");

        // And: The assertion has the correct kind
        assert_eq!(assertion_result["kind"], "pass");

        // And: The assertion has a message
        assert!(assertion_result["message"]["text"].is_string());
    }

    #[test]
    fn given_packet_with_location_when_exporting_then_includes_location_in_result() {
        // Given: A packet with a finding that has a location
        let packet = create_full_packet("test-packet", PacketStatus::Pass);

        // When: Exporting the packet to SARIF
        let sarif = export_packet(&packet).unwrap();

        // Then: The finding with location includes location information
        let results = sarif["runs"][0]["results"].as_array().unwrap();
        let finding_with_location = results.iter().find(|r| r["ruleId"] == "finding-2").unwrap();

        assert!(finding_with_location["locations"].is_array());

        let location = &finding_with_location["locations"][0];
        assert_eq!(
            location["physicalLocation"]["artifactLocation"]["uri"],
            "src/main.rs"
        );
        assert_eq!(location["physicalLocation"]["region"]["startLine"], 42);
        assert_eq!(location["physicalLocation"]["region"]["startColumn"], 10);
    }

    #[test]
    fn given_packet_with_invocation_id_when_exporting_then_includes_guid() {
        // Given: A packet with an invocation ID
        let packet = create_full_packet("test-packet", PacketStatus::Pass);

        // When: Exporting the packet to SARIF
        let sarif = export_packet(&packet).unwrap();

        // Then: The automation details include the GUID
        let automation_details = &sarif["runs"][0]["automationDetails"];
        assert_eq!(automation_details["id"], "test-packet");
        assert_eq!(automation_details["guid"], "inv-123");
    }

    #[test]
    fn given_packet_with_pass_status_when_exporting_then_sets_correct_result_kind() {
        // Given: A packet with Pass status
        let packet = create_minimal_packet("test-packet", PacketStatus::Pass);

        // When: Exporting the packet to SARIF
        let sarif = export_packet(&packet).unwrap();

        // Then: The result kind is "pass"
        let results = sarif["runs"][0]["results"].as_array().unwrap();
        for result in results {
            assert_eq!(result["kind"], "pass");
        }
    }

    #[test]
    fn given_packet_with_fail_status_when_exporting_then_sets_correct_result_kind() {
        // Given: A packet with Fail status
        let packet = create_minimal_packet("test-packet", PacketStatus::Fail);

        // When: Exporting the packet to SARIF
        let sarif = export_packet(&packet).unwrap();

        // Then: The result kind is "fail"
        let results = sarif["runs"][0]["results"].as_array().unwrap();
        for result in results {
            assert_eq!(result["kind"], "fail");
        }
    }

    #[test]
    fn given_packet_with_warn_status_when_exporting_then_sets_correct_result_kind() {
        // Given: A packet with Warn status
        let packet = create_minimal_packet("test-packet", PacketStatus::Warn);

        // When: Exporting the packet to SARIF
        let sarif = export_packet(&packet).unwrap();

        // Then: The result kind is "review"
        let results = sarif["runs"][0]["results"].as_array().unwrap();
        for result in results {
            assert_eq!(result["kind"], "review");
        }
    }

    #[test]
    fn given_packet_with_indeterminate_status_when_exporting_then_sets_correct_result_kind() {
        // Given: A packet with Indeterminate status
        let packet = create_minimal_packet("test-packet", PacketStatus::Indeterminate);

        // When: Exporting the packet to SARIF
        let sarif = export_packet(&packet).unwrap();

        // Then: The result kind is "notApplicable"
        let results = sarif["runs"][0]["results"].as_array().unwrap();
        for result in results {
            assert_eq!(result["kind"], "notApplicable");
        }
    }

    #[test]
    fn given_packet_with_error_status_when_exporting_then_sets_correct_result_kind() {
        // Given: A packet with Error status
        let packet = create_minimal_packet("test-packet", PacketStatus::Error);

        // When: Exporting the packet to SARIF
        let sarif = export_packet(&packet).unwrap();

        // Then: The result kind is "fail"
        let results = sarif["runs"][0]["results"].as_array().unwrap();
        for result in results {
            assert_eq!(result["kind"], "fail");
        }
    }
}

// ============================================================================
// MULTI-PACKET EXPORT TESTS
// ============================================================================

mod multi_packet_export {
    use super::*;

    #[test]
    fn given_multiple_packets_when_exporting_then_produces_multiple_runs() {
        // Given: Multiple packets
        let packet1 = create_minimal_packet("packet-1", PacketStatus::Pass);
        let packet2 = create_minimal_packet("packet-2", PacketStatus::Fail);
        let packet3 = create_minimal_packet("packet-3", PacketStatus::Warn);

        // When: Exporting the packets to SARIF
        let sarif = export_packets(&[packet1, packet2, packet3]).unwrap();

        // Then: The SARIF document contains one run per packet
        let runs = sarif["runs"].as_array().unwrap();
        assert_eq!(runs.len(), 3);

        // And: Each run has a unique automation ID
        let ids: Vec<_> = runs
            .iter()
            .map(|r| r["automationDetails"]["id"].as_str().unwrap())
            .collect();
        assert!(ids.contains(&"packet-1"));
        assert!(ids.contains(&"packet-2"));
        assert!(ids.contains(&"packet-3"));
    }

    #[test]
    fn given_multiple_packets_when_exporting_then_maintains_order() {
        // Given: Multiple packets in a specific order
        let packet1 = create_minimal_packet("packet-1", PacketStatus::Pass);
        let packet2 = create_minimal_packet("packet-2", PacketStatus::Fail);

        // When: Exporting the packets to SARIF
        let sarif = export_packets(&[packet1, packet2]).unwrap();

        // Then: The runs are in the same order
        let runs = sarif["runs"].as_array().unwrap();
        assert_eq!(runs[0]["automationDetails"]["id"], "packet-1");
        assert_eq!(runs[1]["automationDetails"]["id"], "packet-2");
    }

    #[test]
    fn given_empty_packet_list_when_exporting_then_produces_sarif_with_no_runs() {
        // Given: An empty list of packets
        let packets: Vec<Packet> = vec![];

        // When: Exporting the packets to SARIF
        let sarif = export_packets(&packets).unwrap();

        // Then: The SARIF document has no runs
        let runs = sarif["runs"].as_array().unwrap();
        assert_eq!(runs.len(), 0);

        // And: The SARIF document still has version and schema
        assert_eq!(sarif["version"], "2.1.0");
        assert!(sarif["$schema"]
            .as_str()
            .unwrap()
            .contains("sarif-2.1.0.json"));
    }
}

// ============================================================================
// LOSSY EXPORT TESTS
// ============================================================================

mod lossy_export {
    use super::*;

    #[test]
    fn given_packet_with_metrics_when_exporting_then_tracks_omitted_metrics() {
        // Given: A packet with metrics
        let packet = create_full_packet("test-packet", PacketStatus::Pass);

        // When: Exporting the packet to SARIF
        let sarif = export_packet(&packet).unwrap();

        // Then: The run properties indicate lossy export
        let properties = sarif["runs"][0]["properties"].as_object().unwrap();
        assert_eq!(properties["evidencebusLossy"], true);

        // And: The omitted fields include metrics
        let omitted = properties["omittedFields"].as_array().unwrap();
        let metrics_omitted: Vec<_> = omitted
            .iter()
            .filter(|f| f.as_str().unwrap().contains("metrics omitted"))
            .collect();
        assert!(!metrics_omitted.is_empty());
    }

    #[test]
    fn given_packet_with_relations_when_exporting_then_tracks_omitted_relations() {
        // Given: A packet with relations
        let packet = create_full_packet("test-packet", PacketStatus::Pass);

        // When: Exporting the packet to SARIF
        let sarif = export_packet(&packet).unwrap();

        // Then: The omitted fields include relations
        let properties = sarif["runs"][0]["properties"].as_object().unwrap();
        let omitted = properties["omittedFields"].as_array().unwrap();
        let relations_omitted: Vec<_> = omitted
            .iter()
            .filter(|f| f.as_str().unwrap().contains("relations omitted"))
            .collect();
        assert!(!relations_omitted.is_empty());
    }

    #[test]
    fn given_packet_with_native_payloads_when_exporting_then_tracks_omitted_payloads() {
        // Given: A packet with native payloads
        let packet = create_full_packet("test-packet", PacketStatus::Pass);

        // When: Exporting the packet to SARIF
        let sarif = export_packet(&packet).unwrap();

        // Then: The omitted fields include native payloads
        let properties = sarif["runs"][0]["properties"].as_object().unwrap();
        let omitted = properties["omittedFields"].as_array().unwrap();
        let payloads_omitted: Vec<_> = omitted
            .iter()
            .filter(|f| f.as_str().unwrap().contains("native payloads"))
            .collect();
        assert!(!payloads_omitted.is_empty());
    }

    #[test]
    fn given_packet_with_attachments_without_locations_when_exporting_then_tracks_omitted_attachments(
    ) {
        // Given: A packet with attachments without locations (StdoutLog, StderrLog)
        let mut packet = create_minimal_packet("test-packet", PacketStatus::Pass);
        packet.projections = Projections::new()
            .add_attachment(Attachment::new(
                AttachmentRole::StdoutLog,
                "text/plain",
                "stdout.log",
                Digest::new("0".repeat(64)).unwrap(),
            ))
            .add_attachment(Attachment::new(
                AttachmentRole::StderrLog,
                "text/plain",
                "stderr.log",
                Digest::new("1".repeat(64)).unwrap(),
            ));

        // When: Exporting the packet to SARIF
        let sarif = export_packet(&packet).unwrap();

        // Then: The omitted fields include attachments without locations
        let properties = sarif["runs"][0]["properties"].as_object().unwrap();
        let omitted = properties["omittedFields"].as_array().unwrap();
        let attachments_omitted: Vec<_> = omitted
            .iter()
            .filter(|f| f.as_str().unwrap().contains("attachments omitted"))
            .collect();
        assert!(!attachments_omitted.is_empty());
    }

    #[test]
    fn given_packets_with_lossy_fields_when_exporting_then_includes_global_properties() {
        // Given: Packets with lossy fields
        let packet = create_full_packet("test-packet", PacketStatus::Pass);

        // When: Exporting the packets to SARIF
        let sarif = export_packet(&packet).unwrap();

        // Then: The SARIF document has global properties indicating lossy export
        let properties = sarif["properties"].as_object().unwrap();
        assert_eq!(properties["lossyExport"], true);
        assert!(properties["omittedFields"].is_array());
        assert!(!properties["omittedFields"].as_array().unwrap().is_empty());
    }
}

// ============================================================================
// SARIF MAPPING TESTS
// ============================================================================

mod sarif_mappings {
    use super::*;

    #[test]
    fn given_finding_severity_note_when_mapping_then_returns_note_level() {
        // Given: A finding severity of Note
        let severity = FindingSeverity::Note;

        // When: Mapping to SARIF level
        let level = sarif_level(&severity);

        // Then: The level is "note"
        assert_eq!(level, "note");
    }

    #[test]
    fn given_finding_severity_warning_when_mapping_then_returns_warning_level() {
        // Given: A finding severity of Warning
        let severity = FindingSeverity::Warning;

        // When: Mapping to SARIF level
        let level = sarif_level(&severity);

        // Then: The level is "warning"
        assert_eq!(level, "warning");
    }

    #[test]
    fn given_finding_severity_error_when_mapping_then_returns_error_level() {
        // Given: A finding severity of Error
        let severity = FindingSeverity::Error;

        // When: Mapping to SARIF level
        let level = sarif_level(&severity);

        // Then: The level is "error"
        assert_eq!(level, "error");
    }

    #[test]
    fn given_packet_status_pass_when_mapping_then_returns_pass_kind() {
        // Given: A packet status of Pass
        let status = PacketStatus::Pass;

        // When: Mapping to SARIF result kind
        let kind = sarif_result_kind(&status);

        // Then: The kind is "pass"
        assert_eq!(kind, "pass");
    }

    #[test]
    fn given_packet_status_fail_when_mapping_then_returns_fail_kind() {
        // Given: A packet status of Fail
        let status = PacketStatus::Fail;

        // When: Mapping to SARIF result kind
        let kind = sarif_result_kind(&status);

        // Then: The kind is "fail"
        assert_eq!(kind, "fail");
    }

    #[test]
    fn given_packet_status_warn_when_mapping_then_returns_review_kind() {
        // Given: A packet status of Warn
        let status = PacketStatus::Warn;

        // When: Mapping to SARIF result kind
        let kind = sarif_result_kind(&status);

        // Then: The kind is "review"
        assert_eq!(kind, "review");
    }

    #[test]
    fn given_packet_status_indeterminate_when_mapping_then_returns_not_applicable_kind() {
        // Given: A packet status of Indeterminate
        let status = PacketStatus::Indeterminate;

        // When: Mapping to SARIF result kind
        let kind = sarif_result_kind(&status);

        // Then: The kind is "notApplicable"
        assert_eq!(kind, "notApplicable");
    }

    #[test]
    fn given_packet_status_error_when_mapping_then_returns_fail_kind() {
        // Given: A packet status of Error
        let status = PacketStatus::Error;

        // When: Mapping to SARIF result kind
        let kind = sarif_result_kind(&status);

        // Then: The kind is "fail"
        assert_eq!(kind, "fail");
    }
}

// ============================================================================
// SARIF JSON STRUCTURE VALIDATION TESTS
// ============================================================================

mod sarif_structure_validation {
    use super::*;

    #[test]
    fn given_sarif_output_when_validating_then_has_required_version_field() {
        // Given: A packet exported to SARIF
        let packet = create_minimal_packet("test-packet", PacketStatus::Pass);

        // When: Exporting to SARIF
        let sarif = export_packet(&packet).unwrap();

        // Then: The SARIF document has the version field
        assert!(sarif.get("version").is_some());
        assert_eq!(sarif["version"], "2.1.0");
    }

    #[test]
    fn given_sarif_output_when_validating_then_has_required_schema_field() {
        // Given: A packet exported to SARIF
        let packet = create_minimal_packet("test-packet", PacketStatus::Pass);

        // When: Exporting to SARIF
        let sarif = export_packet(&packet).unwrap();

        // Then: The SARIF document has the schema field
        assert!(sarif.get("$schema").is_some());
        let schema = sarif["$schema"].as_str().unwrap();
        assert!(schema.contains("sarif-2.1.0.json"));
    }

    #[test]
    fn given_sarif_output_when_validating_then_has_required_runs_field() {
        // Given: A packet exported to SARIF
        let packet = create_minimal_packet("test-packet", PacketStatus::Pass);

        // When: Exporting to SARIF
        let sarif = export_packet(&packet).unwrap();

        // Then: The SARIF document has the runs field
        assert!(sarif.get("runs").is_some());
        assert!(sarif["runs"].is_array());
    }

    #[test]
    fn given_sarif_output_when_validating_then_run_has_required_tool_field() {
        // Given: A packet exported to SARIF
        let packet = create_minimal_packet("test-packet", PacketStatus::Pass);

        // When: Exporting to SARIF
        let sarif = export_packet(&packet).unwrap();

        // Then: The run has the tool field
        let run = &sarif["runs"][0];
        assert!(run.get("tool").is_some());
        assert!(run["tool"].is_object());
    }

    #[test]
    fn given_sarif_output_when_validating_then_tool_has_required_driver_field() {
        // Given: A packet exported to SARIF
        let packet = create_minimal_packet("test-packet", PacketStatus::Pass);

        // When: Exporting to SARIF
        let sarif = export_packet(&packet).unwrap();

        // Then: The tool has the driver field
        let tool = &sarif["runs"][0]["tool"];
        assert!(tool.get("driver").is_some());
        assert!(tool["driver"].is_object());
    }

    #[test]
    fn given_sarif_output_when_validating_then_driver_has_required_name_field() {
        // Given: A packet exported to SARIF
        let packet = create_minimal_packet("test-packet", PacketStatus::Pass);

        // When: Exporting to SARIF
        let sarif = export_packet(&packet).unwrap();

        // Then: The driver has the name field
        let driver = &sarif["runs"][0]["tool"]["driver"];
        assert!(driver.get("name").is_some());
        assert!(driver["name"].is_string());
    }

    #[test]
    fn given_sarif_output_when_validating_then_driver_has_required_version_field() {
        // Given: A packet exported to SARIF
        let packet = create_minimal_packet("test-packet", PacketStatus::Pass);

        // When: Exporting to SARIF
        let sarif = export_packet(&packet).unwrap();

        // Then: The driver has the version field
        let driver = &sarif["runs"][0]["tool"]["driver"];
        assert!(driver.get("version").is_some());
        assert!(driver["version"].is_string());
    }

    #[test]
    fn given_sarif_output_when_validating_then_run_has_required_results_field() {
        // Given: A packet exported to SARIF
        let packet = create_minimal_packet("test-packet", PacketStatus::Pass);

        // When: Exporting to SARIF
        let sarif = export_packet(&packet).unwrap();

        // Then: The run has the results field
        let run = &sarif["runs"][0];
        assert!(run.get("results").is_some());
        assert!(run["results"].is_array());
    }

    #[test]
    fn given_sarif_output_when_validating_then_result_has_required_rule_id_field() {
        // Given: A packet with findings exported to SARIF
        let mut packet = create_minimal_packet("test-packet", PacketStatus::Pass);
        packet.projections = Projections::new().add_finding(evidencebus_types::Finding::new(
            "test-rule",
            FindingSeverity::Warning,
            "Test Finding",
            "Test message",
        ));

        // When: Exporting to SARIF
        let sarif = export_packet(&packet).unwrap();

        // Then: The result has the ruleId field
        let result = &sarif["runs"][0]["results"][0];
        assert!(result.get("ruleId").is_some());
        assert!(result["ruleId"].is_string());
    }

    #[test]
    fn given_sarif_output_when_validating_then_result_has_required_level_field() {
        // Given: A packet with findings exported to SARIF
        let mut packet = create_minimal_packet("test-packet", PacketStatus::Pass);
        packet.projections = Projections::new().add_finding(evidencebus_types::Finding::new(
            "test-rule",
            FindingSeverity::Warning,
            "Test Finding",
            "Test message",
        ));

        // When: Exporting to SARIF
        let sarif = export_packet(&packet).unwrap();

        // Then: The result has the level field
        let result = &sarif["runs"][0]["results"][0];
        assert!(result.get("level").is_some());
        assert!(result["level"].is_string());
    }

    #[test]
    fn given_sarif_output_when_validating_then_result_has_required_message_field() {
        // Given: A packet with findings exported to SARIF
        let mut packet = create_minimal_packet("test-packet", PacketStatus::Pass);
        packet.projections = Projections::new().add_finding(evidencebus_types::Finding::new(
            "test-rule",
            FindingSeverity::Warning,
            "Test Finding",
            "Test message",
        ));

        // When: Exporting to SARIF
        let sarif = export_packet(&packet).unwrap();

        // Then: The result has the message field
        let result = &sarif["runs"][0]["results"][0];
        assert!(result.get("message").is_some());
        assert!(result["message"].is_object());
        assert!(result["message"].get("text").is_some());
    }

    #[test]
    fn given_sarif_output_when_validating_then_result_has_required_kind_field() {
        // Given: A packet with findings exported to SARIF
        let mut packet = create_minimal_packet("test-packet", PacketStatus::Pass);
        packet.projections = Projections::new().add_finding(evidencebus_types::Finding::new(
            "test-rule",
            FindingSeverity::Warning,
            "Test Finding",
            "Test message",
        ));

        // When: Exporting to SARIF
        let sarif = export_packet(&packet).unwrap();

        // Then: The result has the kind field
        let result = &sarif["runs"][0]["results"][0];
        assert!(result.get("kind").is_some());
        assert!(result["kind"].is_string());
    }
}

// ============================================================================
// DETERMINISM TESTS
// ============================================================================

mod determinism {
    use super::*;

    #[test]
    fn given_same_packet_when_exporting_twice_then_produces_identical_output() {
        // Given: The same packet
        let packet = create_full_packet("test-packet", PacketStatus::Pass);

        // When: Exporting the packet twice
        let sarif1 = export_packet(&packet).unwrap();
        let sarif2 = export_packet(&packet).unwrap();

        // Then: The outputs are identical
        assert_eq!(
            serde_json::to_string(&sarif1).unwrap(),
            serde_json::to_string(&sarif2).unwrap()
        );
    }

    #[test]
    fn given_same_packets_when_exporting_twice_then_produces_identical_output() {
        // Given: The same list of packets
        let packet1 = create_minimal_packet("packet-1", PacketStatus::Pass);
        let packet2 = create_minimal_packet("packet-2", PacketStatus::Fail);
        let packets = vec![packet1, packet2];

        // When: Exporting the packets twice
        let sarif1 = export_packets(&packets).unwrap();
        let sarif2 = export_packets(&packets).unwrap();

        // Then: The outputs are identical
        assert_eq!(
            serde_json::to_string(&sarif1).unwrap(),
            serde_json::to_string(&sarif2).unwrap()
        );
    }
}

// ============================================================================
// EDGE CASES TESTS
// ============================================================================

mod edge_cases {
    use super::*;

    #[test]
    fn given_packet_with_no_findings_or_assertions_when_exporting_then_produces_empty_results() {
        // Given: A packet with no findings or assertions
        let packet = create_minimal_packet("test-packet", PacketStatus::Pass);

        // When: Exporting the packet to SARIF
        let sarif = export_packet(&packet).unwrap();

        // Then: The results array is empty
        let results = sarif["runs"][0]["results"].as_array().unwrap();
        assert_eq!(results.len(), 0);
    }

    #[test]
    fn given_packet_with_no_invocation_id_when_exporting_then_omits_guid() {
        // Given: A packet without an invocation ID
        let packet = create_minimal_packet("test-packet", PacketStatus::Pass);

        // When: Exporting the packet to SARIF
        let sarif = export_packet(&packet).unwrap();

        // Then: The automation details do not include a GUID
        let automation_details = &sarif["runs"][0]["automationDetails"];
        assert!(automation_details.get("guid").is_none());
    }

    #[test]
    fn given_packet_with_no_lossy_fields_when_exporting_then_still_marks_as_lossy() {
        // Given: A packet with no lossy fields (no metrics, relations, etc.)
        let packet = create_minimal_packet("test-packet", PacketStatus::Pass);

        // When: Exporting the packet to SARIF
        let sarif = export_packet(&packet).unwrap();

        // Then: The run properties still indicate lossy export
        let properties = sarif["runs"][0]["properties"].as_object().unwrap();
        assert_eq!(properties["evidencebusLossy"], true);

        // And: The omitted fields array is empty
        let omitted = properties["omittedFields"].as_array().unwrap();
        assert_eq!(omitted.len(), 0);
    }

    #[test]
    fn given_finding_without_location_when_exporting_then_omits_locations() {
        // Given: A packet with a finding without location
        let mut packet = create_minimal_packet("test-packet", PacketStatus::Pass);
        packet.projections = Projections::new().add_finding(evidencebus_types::Finding::new(
            "test-finding",
            FindingSeverity::Warning,
            "Test Finding",
            "Test message",
        ));

        // When: Exporting the packet to SARIF
        let sarif = export_packet(&packet).unwrap();

        // Then: The result does not include locations
        let result = &sarif["runs"][0]["results"][0];
        assert!(result.get("locations").is_none());
    }

    #[test]
    fn given_finding_with_location_but_no_line_when_exporting_then_includes_uri_only() {
        // Given: A packet with a finding with location but no line number
        let mut packet = create_minimal_packet("test-packet", PacketStatus::Pass);
        packet.projections = Projections::new().add_finding(
            evidencebus_types::Finding::new(
                "test-finding",
                FindingSeverity::Warning,
                "Test Finding",
                "Test message",
            )
            .with_location(Location::new("src/main.rs")),
        );

        // When: Exporting the packet to SARIF
        let sarif = export_packet(&packet).unwrap();

        // Then: The result includes the location with URI but no region
        let result = &sarif["runs"][0]["results"][0];
        assert!(result.get("locations").is_some());
        let location = &result["locations"][0];
        assert_eq!(
            location["physicalLocation"]["artifactLocation"]["uri"],
            "src/main.rs"
        );
        assert!(location["physicalLocation"].get("region").is_none());
    }

    #[test]
    fn given_finding_with_location_with_line_but_no_column_when_exporting_then_includes_line_only()
    {
        // Given: A packet with a finding with location and line but no column
        let mut packet = create_minimal_packet("test-packet", PacketStatus::Pass);
        packet.projections = Projections::new().add_finding(
            evidencebus_types::Finding::new(
                "test-finding",
                FindingSeverity::Warning,
                "Test Finding",
                "Test message",
            )
            .with_location(Location::new("src/main.rs").with_line(42)),
        );

        // When: Exporting the packet to SARIF
        let sarif = export_packet(&packet).unwrap();

        // Then: The result includes the location with line but no column
        let result = &sarif["runs"][0]["results"][0];
        let location = &result["locations"][0];
        assert_eq!(location["physicalLocation"]["region"]["startLine"], 42);
        assert!(location["physicalLocation"]["region"]
            .get("startColumn")
            .is_none());
    }

    #[test]
    fn given_packet_with_only_report_html_attachments_when_exporting_then_includes_all() {
        // Given: A packet with only ReportHtml and PlainText attachments
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

        // When: Exporting the packet to SARIF
        let sarif = export_packet(&packet).unwrap();

        // Then: No attachments are omitted
        let properties = sarif["runs"][0]["properties"].as_object().unwrap();
        let omitted = properties["omittedFields"].as_array().unwrap();
        let attachments_omitted: Vec<_> = omitted
            .iter()
            .filter(|f| f.as_str().unwrap().contains("attachments omitted"))
            .collect();
        assert!(attachments_omitted.is_empty());
    }

    #[test]
    fn given_packet_with_mixed_attachment_types_when_exporting_then_omits_non_location_types() {
        // Given: A packet with mixed attachment types
        let mut packet = create_minimal_packet("test-packet", PacketStatus::Pass);
        packet.projections = Projections::new()
            .add_attachment(Attachment::new(
                AttachmentRole::ReportHtml,
                "text/html",
                "report.html",
                Digest::new("0".repeat(64)).unwrap(),
            ))
            .add_attachment(Attachment::new(
                AttachmentRole::StdoutLog,
                "text/plain",
                "stdout.log",
                Digest::new("1".repeat(64)).unwrap(),
            ))
            .add_attachment(Attachment::new(
                AttachmentRole::StderrLog,
                "text/plain",
                "stderr.log",
                Digest::new("2".repeat(64)).unwrap(),
            ));

        // When: Exporting the packet to SARIF
        let sarif = export_packet(&packet).unwrap();

        // Then: Some attachments are omitted
        let properties = sarif["runs"][0]["properties"].as_object().unwrap();
        let omitted = properties["omittedFields"].as_array().unwrap();
        let attachments_omitted: Vec<_> = omitted
            .iter()
            .filter(|f| f.as_str().unwrap().contains("attachments omitted"))
            .collect();
        assert!(!attachments_omitted.is_empty());
    }
}
