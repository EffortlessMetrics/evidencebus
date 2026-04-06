//! Evidence export for Markdown and SARIF formats.
//!
//! This crate provides functions to convert evidence packets and bundles
//! into human-readable Markdown summaries and SARIF format for integration
//! with tools like GitHub code scanning.
//!
//! Markdown export functionality is delegated to the `evidencebus-export-markdown` crate.
//! SARIF export functionality is delegated to the `evidencebus-export-sarif` crate.

use evidencebus_codes::{FindingSeverity, PacketStatus};
use evidencebus_export_markdown::{
    export_bundle as export_bundle_markdown_internal,
    export_packet as export_packet_markdown_internal,
};
use evidencebus_export_sarif::{
    export_packet as export_packet_sarif_internal, export_packets as export_packets_sarif_internal,
};
use evidencebus_types::{Bundle, Packet};
use thiserror::Error;

/// Error types for export operations.
#[derive(Debug, Error)]
pub enum ExportError {
    #[error("unsupported format: {0}")]
    UnsupportedFormat(String),
    #[error("lossy export: {0}")]
    LossyExport(String),
    #[error("serialization failed: {0}")]
    SerializationFailed(#[from] serde_json::Error),
    #[error("invalid input: {0}")]
    InvalidInput(String),
}

/// Mode for handling lossy exports.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LossyMode {
    /// Error on lossy export
    Strict,
    /// Warn on lossy export
    Permissive,
    /// Don't report lossiness
    Silent,
}

/// Export options controlling export behavior.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExportOptions {
    /// Include detailed information in exports
    pub include_details: bool,
    /// Include artifacts in exports
    pub include_artifacts: bool,
    /// Mode for handling lossy exports
    pub lossy_mode: LossyMode,
}

impl Default for ExportOptions {
    fn default() -> Self {
        Self {
            include_details: true,
            include_artifacts: true,
            lossy_mode: LossyMode::Permissive,
        }
    }
}

impl ExportOptions {
    /// Creates new export options with default values.
    pub fn new() -> Self {
        Self::default()
    }

    /// Sets whether to include details.
    pub fn with_include_details(mut self, include: bool) -> Self {
        self.include_details = include;
        self
    }

    /// Sets whether to include artifacts.
    pub fn with_include_artifacts(mut self, include: bool) -> Self {
        self.include_artifacts = include;
        self
    }

    /// Sets the lossy mode.
    pub fn with_lossy_mode(mut self, mode: LossyMode) -> Self {
        self.lossy_mode = mode;
        self
    }
}

/// Maps finding severity to SARIF level.
///
/// This function delegates to the `evidencebus-export-sarif` crate.
pub fn sarif_level(severity: &FindingSeverity) -> &'static str {
    evidencebus_export_sarif::sarif_level(severity)
}

/// Maps packet status to SARIF result kind.
///
/// This function delegates to the `evidencebus-export-sarif` crate.
pub fn sarif_result_kind(status: &PacketStatus) -> &'static str {
    evidencebus_export_sarif::sarif_result_kind(status)
}

/// Exports a packet to Markdown format.
///
/// This function delegates to the `evidencebus-export-markdown` crate.
pub fn export_packet_markdown(packet: &Packet) -> Result<String, ExportError> {
    export_packet_markdown_internal(packet).map_err(|e| ExportError::InvalidInput(e.to_string()))
}

/// Exports a bundle to Markdown format.
///
/// This function delegates to the `evidencebus-export-markdown` crate.
pub fn export_bundle_markdown(bundle: &Bundle) -> Result<String, ExportError> {
    export_bundle_markdown_internal(bundle).map_err(|e| ExportError::InvalidInput(e.to_string()))
}

/// Exports a packet to SARIF format.
///
/// This function delegates to the `evidencebus-export-sarif` crate.
pub fn export_packet_sarif(packet: &Packet) -> Result<serde_json::Value, ExportError> {
    export_packet_sarif_internal(packet).map_err(|e| ExportError::InvalidInput(e.to_string()))
}

/// Exports a bundle to SARIF format.
///
/// Note: This function takes a Bundle but we need the actual Packet objects
/// to generate SARIF. Use `export_packets_sarif` instead with loaded packets.
pub fn export_bundle_sarif(_bundle: &Bundle) -> Result<serde_json::Value, ExportError> {
    Err(ExportError::UnsupportedFormat(
        "Bundle SARIF export requires loaded packets. Use export_packets_sarif instead."
            .to_string(),
    ))
}

/// Exports a collection of packets to SARIF format.
///
/// This function delegates to the `evidencebus-export-sarif` crate.
pub fn export_packets_sarif(packets: &[Packet]) -> Result<serde_json::Value, ExportError> {
    export_packets_sarif_internal(packets).map_err(|e| ExportError::InvalidInput(e.to_string()))
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use evidencebus_codes::{FindingSeverity, PacketStatus};
    use evidencebus_types::{
        Attachment, AttachmentRole, Digest, Location, Metric, Packet, PacketId, Producer,
        Projections, SchemaVersion, Subject, Summary, VcsKind,
    };
    use std::collections::HashMap;

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

    #[test]
    fn test_export_packet_sarif() {
        let packet = create_test_packet("test-packet", PacketStatus::Pass);
        let sarif = export_packet_sarif(&packet).unwrap();

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

        let sarif = export_packet_sarif(&packet).unwrap();
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

        let sarif = export_packets_sarif(&[packet1, packet2]).unwrap();

        assert_eq!(sarif["runs"].as_array().unwrap().len(), 2);
    }

    #[test]
    fn test_export_options_default() {
        let opts = ExportOptions::default();
        assert!(opts.include_details);
        assert!(opts.include_artifacts);
        assert_eq!(opts.lossy_mode, LossyMode::Permissive);
    }

    #[test]
    fn test_export_options_builder() {
        let opts = ExportOptions::new()
            .with_include_details(false)
            .with_include_artifacts(false)
            .with_lossy_mode(LossyMode::Strict);

        assert!(!opts.include_details);
        assert!(!opts.include_artifacts);
        assert_eq!(opts.lossy_mode, LossyMode::Strict);
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

        let sarif = export_packet_sarif(&packet).unwrap();

        // Check that properties include lossy export info
        let properties = sarif["runs"][0]["properties"].as_object().unwrap();
        assert_eq!(properties["evidencebusLossy"], true);

        let omitted = properties["omittedFields"].as_array().unwrap();
        assert!(!omitted.is_empty());
    }
}
