//! SARIF (Static Analysis Results Interchange Format) export for evidencebus.
//!
//! This crate provides functions to convert evidence packets and bundles
//! into SARIF 2.1.0 format for integration with tools like GitHub code scanning.
//!
//! SARIF export is inherently lossy because SARIF is designed for static analysis
//! results, not general evidence. The following fields are omitted:
//! - Metrics (not applicable to SARIF)
//! - Relations (not applicable to SARIF)
//! - Native payloads (referenced but not embedded)
//! - Attachments without locations (no location to report)
//!
//! # Example
//!
//! ```no_run
//! use evidencebus_export_sarif::export_packet;
//! use evidencebus_types::Packet;
//!
//! let packet: Packet = /* ... */;
//! let sarif = export_packet(&packet)?;
//! println!("{}", serde_json::to_string_pretty(&sarif)?);
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```

use evidencebus_codes::{FindingSeverity, PacketStatus};
use evidencebus_types::{AttachmentRole, Packet};
use serde_json::json;
use thiserror::Error;

/// Error types for SARIF export operations.
#[derive(Debug, Error)]
pub enum SarifExportError {
    #[error("serialization failed: {0}")]
    SerializationFailed(#[from] serde_json::Error),
    #[error("invalid input: {0}")]
    InvalidInput(String),
}

/// Maps finding severity to SARIF level.
pub fn sarif_level(severity: &FindingSeverity) -> &'static str {
    match severity {
        FindingSeverity::Note => "note",
        FindingSeverity::Warning => "warning",
        FindingSeverity::Error => "error",
    }
}

/// Maps packet status to SARIF result kind.
pub fn sarif_result_kind(status: &PacketStatus) -> &'static str {
    match status {
        PacketStatus::Pass => "pass",
        PacketStatus::Fail => "fail",
        PacketStatus::Warn => "review",
        PacketStatus::Indeterminate => "notApplicable",
        PacketStatus::Error => "fail",
    }
}

/// Exports a packet to SARIF format.
///
/// This function converts a single evidence packet into a SARIF 2.1.0 document
/// with one run. The packet's findings and assertions are converted to SARIF results.
///
/// # Arguments
///
/// * `packet` - The packet to export
///
/// # Returns
///
/// A JSON value representing the SARIF document
///
/// # Example
///
/// ```
/// use evidencebus_export_sarif::export_packet;
/// use evidencebus_types::{Packet, PacketId, Producer, Subject, Summary, VcsKind, Projections, SchemaVersion};
/// use evidencebus_codes::PacketStatus;
///
/// let packet = Packet {
///     eb_version: SchemaVersion::new("0.1.0"),
///     packet_id: PacketId::new("test-packet").unwrap(),
///     producer: Producer::new("test-tool", "1.0.0"),
///     subject: Subject::new(VcsKind::Git, "owner/repo", "abc123", "def456"),
///     summary: Summary::new(PacketStatus::Pass, "Test Title", "Test summary"),
///     projections: Projections::new(),
///     native_payloads: vec![],
///     artifacts: vec![],
///     links: None,
///     labels: None,
///     created_at: "2024-01-01T12:00:00Z".to_string(),
/// };
///
/// let sarif = export_packet(&packet).unwrap();
/// assert_eq!(sarif["version"], "2.1.0");
/// ```
pub fn export_packet(packet: &Packet) -> Result<serde_json::Value, SarifExportError> {
    export_packets_internal(
        std::slice::from_ref(packet),
        Some(packet.packet_id.as_str()),
    )
}

/// Exports a collection of packets to SARIF format.
///
/// This function converts multiple evidence packets into a SARIF 2.1.0 document
/// with one run per packet. Each packet's findings and assertions are converted
/// to SARIF results.
///
/// # Arguments
///
/// * `packets` - The packets to export
///
/// # Returns
///
/// A JSON value representing the SARIF document
///
/// # Example
///
/// ```
/// use evidencebus_export_sarif::export_packets;
/// use evidencebus_types::{Packet, PacketId, Producer, Subject, Summary, VcsKind, Projections, SchemaVersion};
/// use evidencebus_codes::PacketStatus;
///
/// let packet1 = Packet {
///     eb_version: SchemaVersion::new("0.1.0"),
///     packet_id: PacketId::new("packet-1").unwrap(),
///     producer: Producer::new("test-tool", "1.0.0"),
///     subject: Subject::new(VcsKind::Git, "owner/repo", "abc123", "def456"),
///     summary: Summary::new(PacketStatus::Pass, "Test 1", "Test summary"),
///     projections: Projections::new(),
///     native_payloads: vec![],
///     artifacts: vec![],
///     links: None,
///     labels: None,
///     created_at: "2024-01-01T12:00:00Z".to_string(),
/// };
///
/// let packet2 = Packet {
///     eb_version: SchemaVersion::new("0.1.0"),
///     packet_id: PacketId::new("packet-2").unwrap(),
///     producer: Producer::new("test-tool", "1.0.0"),
///     subject: Subject::new(VcsKind::Git, "owner/repo", "abc123", "def456"),
///     summary: Summary::new(PacketStatus::Fail, "Test 2", "Test summary"),
///     projections: Projections::new(),
///     native_payloads: vec![],
///     artifacts: vec![],
///     links: None,
///     labels: None,
///     created_at: "2024-01-01T12:00:00Z".to_string(),
/// };
///
/// let sarif = export_packets(&[packet1, packet2]).unwrap();
/// assert_eq!(sarif["runs"].as_array().unwrap().len(), 2);
/// ```
pub fn export_packets(packets: &[Packet]) -> Result<serde_json::Value, SarifExportError> {
    export_packets_internal(packets, None)
}

/// Exports a collection of packets to SARIF format with a bundle ID.
///
/// This is an internal function that allows specifying a bundle ID for the export.
/// The bundle ID is included in the SARIF properties for tracking purposes.
fn export_packets_internal(
    packets: &[Packet],
    bundle_id: Option<&str>,
) -> Result<serde_json::Value, SarifExportError> {
    let mut all_lossy_fields = Vec::new();

    let runs: Vec<serde_json::Value> = packets
        .iter()
        .map(|packet| {
            let mut lossy_fields = Vec::new();
            let mut results = Vec::new();

            // Add findings as results
            for finding in &packet.projections.findings {
                // Findings represent detected issues, so kind is always "fail".
                // The level field carries the severity distinction (note/warning/error).
                let mut result = json!({
                    "ruleId": finding.id,
                    "level": sarif_level(&finding.severity),
                    "message": {
                        "text": finding.message,
                    },
                    "kind": "fail",
                });

                // Add location if available
                if let Some(location) = &finding.location {
                    result["locations"] = json!([{
                        "physicalLocation": {
                            "artifactLocation": {
                                "uri": location.path,
                            }
                        }
                    }]);

                    if let Some(line) = location.line {
                        result["locations"][0]["physicalLocation"]["region"] = json!({
                            "startLine": line
                        });

                        if let Some(col) = location.column {
                            result["locations"][0]["physicalLocation"]["region"]["startColumn"] =
                                json!(col);
                        }
                    }
                }

                results.push(result);
            }

            // Add assertions as results
            for assertion in &packet.projections.assertions {
                let level = match assertion.status {
                    PacketStatus::Pass => "note",
                    PacketStatus::Fail => "error",
                    PacketStatus::Warn => "warning",
                    PacketStatus::Indeterminate => "note",
                    PacketStatus::Error => "error",
                };

                results.push(json!({
                    "ruleId": assertion.id,
                    "level": level,
                    "message": {
                        "text": assertion.summary.short_summary,
                    },
                    "kind": sarif_result_kind(&assertion.status),
                }));
            }

            let mut run = json!({
                "tool": {
                    "driver": {
                        "name": packet.producer.tool_name,
                        "version": packet.producer.tool_version,
                        "informationUri": "https://github.com/EffortlessMetrics/evidencebus",
                    }
                },
                "automationDetails": {
                    "id": packet.packet_id.as_str(),
                },
                "results": results,
            });

            // Add invocation ID if available
            if let Some(invocation_id) = &packet.producer.invocation_id {
                run["automationDetails"]["guid"] = json!(invocation_id);
            }

            // Add properties for lossy export tracking
            let mut properties = serde_json::Map::new();
            properties.insert("evidencebusLossy".to_string(), json!(true));

            if let Some(bid) = bundle_id {
                properties.insert("bundleId".to_string(), json!(bid));
            }

            // Track what was omitted
            if !packet.projections.metrics.is_empty() {
                lossy_fields.push(format!(
                    "Packet {}: {} metrics omitted (not applicable to SARIF)",
                    packet.packet_id.as_str(),
                    packet.projections.metrics.len()
                ));
            }

            if !packet.projections.relations.is_empty() {
                lossy_fields.push(format!(
                    "Packet {}: {} relations omitted (not applicable to SARIF)",
                    packet.packet_id.as_str(),
                    packet.projections.relations.len()
                ));
            }

            if !packet.native_payloads.is_empty() {
                lossy_fields.push(format!(
                    "Packet {}: {} native payloads referenced but not embedded",
                    packet.packet_id.as_str(),
                    packet.native_payloads.len()
                ));
            }

            // Attachments without locations are omitted
            let attachments_with_locations: Vec<_> = packet
                .projections
                .attachments
                .iter()
                .filter(|a| {
                    matches!(
                        a.role,
                        AttachmentRole::ReportHtml | AttachmentRole::PlainText
                    )
                })
                .collect();

            if attachments_with_locations.len() < packet.projections.attachments.len() {
                lossy_fields.push(format!(
                    "Packet {}: {} attachments omitted (no location)",
                    packet.packet_id.as_str(),
                    packet.projections.attachments.len() - attachments_with_locations.len()
                ));
            }

            properties.insert("omittedFields".to_string(), json!(&lossy_fields));

            run["properties"] = json!(properties);

            all_lossy_fields.extend(lossy_fields);

            run
        })
        .collect();

    let mut sarif = json!({
        "version": "2.1.0",
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "runs": runs,
    });

    // Add lossy export metadata
    if !all_lossy_fields.is_empty() {
        let mut properties = serde_json::Map::new();
        properties.insert("lossyExport".to_string(), json!(true));
        properties.insert("omittedFields".to_string(), json!(all_lossy_fields));
        sarif["properties"] = json!(properties);
    }

    Ok(sarif)
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use evidencebus_types::{
        Attachment, Digest, Location, Metric, PacketId, Producer, Projections, SchemaVersion,
        Subject, Summary, VcsKind,
    };

    fn create_test_packet(id: &str, status: PacketStatus) -> Packet {
        Packet {
            eb_version: SchemaVersion::new("0.1.0"),
            packet_id: PacketId::new(id).unwrap(),
            producer: Producer::new("test-tool", "1.0.0"),
            subject: Subject::new(VcsKind::Git, "owner/repo", "abc123", "def456"),
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
                )),
            native_payloads: vec!["payload.json".to_string()],
            artifacts: vec!["artifact.txt".to_string()],
            links: None,
            labels: None,
            created_at: "2024-01-01T12:00:00Z".to_string(),
        }
    }

    #[test]
    fn test_export_packet_sarif() {
        let packet = create_test_packet("test-packet", PacketStatus::Pass);
        let sarif = export_packet(&packet).unwrap();

        assert_eq!(sarif["version"], "2.1.0");
        assert!(sarif["$schema"]
            .as_str()
            .unwrap()
            .contains("sarif-2.1.0.json"));
        assert!(sarif["runs"].as_array().unwrap().len() == 1);

        let run = &sarif["runs"][0];
        assert_eq!(run["tool"]["driver"]["name"], "test-tool");
        assert_eq!(run["tool"]["driver"]["version"], "1.0.0");

        let results = run["results"].as_array().unwrap();
        assert!(!results.is_empty());

        // Check finding result
        let finding_result = results.iter().find(|r| r["ruleId"] == "finding-1").unwrap();
        assert_eq!(finding_result["level"], "warning");
        assert_eq!(finding_result["message"]["text"], "This is a warning");
    }

    #[test]
    fn test_export_packet_sarif_with_location() {
        let mut packet = create_test_packet("test-packet", PacketStatus::Pass);
        packet.projections.findings[0] = packet.projections.findings[0]
            .clone()
            .with_location(Location::new("src/main.rs").with_line(42));

        let sarif = export_packet(&packet).unwrap();
        let results = sarif["runs"][0]["results"].as_array().unwrap();
        let finding_result = results.iter().find(|r| r["ruleId"] == "finding-1").unwrap();

        assert!(finding_result["locations"].is_array());
        assert_eq!(
            finding_result["locations"][0]["physicalLocation"]["artifactLocation"]["uri"],
            "src/main.rs"
        );
        assert_eq!(
            finding_result["locations"][0]["physicalLocation"]["region"]["startLine"],
            42
        );
    }

    #[test]
    fn test_export_packets_sarif() {
        let packet1 = create_test_packet("packet-1", PacketStatus::Pass);
        let packet2 = create_test_packet("packet-2", PacketStatus::Fail);

        let sarif = export_packets(&[packet1, packet2]).unwrap();

        assert_eq!(sarif["runs"].as_array().unwrap().len(), 2);
    }

    #[test]
    fn test_sarif_lossy_tracking() {
        let mut packet = create_test_packet("test-packet", PacketStatus::Pass);
        packet
            .projections
            .metrics
            .push(Metric::new("latency", 100.0));
        packet
            .projections
            .relations
            .push(evidencebus_types::Relation::new(
                evidencebus_types::RelationKind::DerivedFrom,
                PacketId::new("parent-packet").unwrap(),
            ));

        let sarif = export_packet(&packet).unwrap();

        // Check that properties include lossy export info
        let properties = sarif["runs"][0]["properties"].as_object().unwrap();
        assert_eq!(properties["evidencebusLossy"], true);

        let omitted = properties["omittedFields"].as_array().unwrap();
        assert!(!omitted.is_empty());
    }

    #[test]
    fn test_sarif_level_mapping() {
        assert_eq!(sarif_level(&FindingSeverity::Note), "note");
        assert_eq!(sarif_level(&FindingSeverity::Warning), "warning");
        assert_eq!(sarif_level(&FindingSeverity::Error), "error");
    }

    #[test]
    fn test_sarif_result_kind_mapping() {
        assert_eq!(sarif_result_kind(&PacketStatus::Pass), "pass");
        assert_eq!(sarif_result_kind(&PacketStatus::Fail), "fail");
        assert_eq!(sarif_result_kind(&PacketStatus::Warn), "review");
        assert_eq!(
            sarif_result_kind(&PacketStatus::Indeterminate),
            "notApplicable"
        );
        assert_eq!(sarif_result_kind(&PacketStatus::Error), "fail");
    }
}
