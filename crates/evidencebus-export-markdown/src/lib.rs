//! Markdown export for evidencebus packets and bundles.
//!
//! This crate provides functions to convert evidence packets and bundles
//! into human-readable Markdown summaries.

use evidencebus_codes::{FindingSeverity, PacketStatus};
use evidencebus_types::{AttachmentRole, Bundle, Packet};
use thiserror::Error;

/// Error types for Markdown export operations.
#[derive(Debug, Error)]
pub enum MarkdownExportError {
    #[error("invalid input: {0}")]
    InvalidInput(String),
}

/// Formats an ISO 8601 timestamp for human display.
pub fn format_timestamp(timestamp: &str) -> String {
    // Simple formatting - just return the timestamp as-is for now
    // In a full implementation, we might parse and reformat for better readability
    timestamp.to_string()
}

/// Returns an emoji for a packet status.
pub fn status_emoji(status: &PacketStatus) -> &'static str {
    match status {
        PacketStatus::Pass => "✅",
        PacketStatus::Fail => "❌",
        PacketStatus::Warn => "⚠️",
        PacketStatus::Indeterminate => "❓",
        PacketStatus::Error => "💥",
    }
}

/// Returns an emoji for a finding severity.
pub fn severity_emoji(severity: &FindingSeverity) -> &'static str {
    match severity {
        FindingSeverity::Note => "ℹ️",
        FindingSeverity::Warning => "⚠️",
        FindingSeverity::Error => "🔴",
    }
}

/// Returns an emoji for an attachment role.
pub fn attachment_role_emoji(role: &AttachmentRole) -> &'static str {
    match role {
        AttachmentRole::NativePayload => "📦",
        AttachmentRole::ReportHtml => "📊",
        AttachmentRole::StdoutLog => "📝",
        AttachmentRole::StderrLog => "⚠️",
        AttachmentRole::PlainText => "📄",
        AttachmentRole::ArbitraryBinary => "🔧",
    }
}

/// Exports a packet to Markdown format.
///
/// This function converts an evidence packet into a human-readable Markdown
/// document that includes all packet metadata, assertions, findings, metrics,
/// attachments, and other projections.
///
/// # Arguments
///
/// * `packet` - The packet to export
///
/// # Returns
///
/// A Markdown formatted string representing the packet
///
/// # Example
///
/// ```
/// use evidencebus_export_markdown::export_packet;
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
/// let markdown = export_packet(&packet).unwrap();
/// assert!(markdown.contains("# Evidence Packet: test-packet"));
/// ```
pub fn export_packet(packet: &Packet) -> Result<String, MarkdownExportError> {
    let mut output = String::new();

    output.push_str(&format!(
        "# Evidence Packet: {}\n\n",
        packet.packet_id.as_str()
    ));
    output.push_str(&format!(
        "**Created:** {}\n\n",
        format_timestamp(&packet.created_at)
    ));

    output.push_str("## Producer\n\n");
    output.push_str(&format!(
        "- **Tool:** {} {}\n",
        packet.producer.tool_name, packet.producer.tool_version
    ));
    if let Some(invocation_id) = &packet.producer.invocation_id {
        output.push_str(&format!("- **Invocation ID:** {}\n", invocation_id));
    }
    output.push('\n');

    output.push_str("## Subject\n\n");
    output.push_str(&format!("- **VCS:** {:?}\n", packet.subject.vcs_kind));
    output.push_str(&format!(
        "- **Repository:** {}\n",
        packet.subject.repo_identifier
    ));
    output.push_str(&format!("- **Commit:** {}\n", packet.subject.commit));
    output.push_str(&format!("- **Head:** {}\n", packet.subject.head));
    if let Some(base) = &packet.subject.base {
        output.push_str(&format!("- **Base:** {}\n", base));
    }
    if let Some(path_scope) = &packet.subject.path_scope {
        output.push_str(&format!("- **Path Scope:** {}\n", path_scope));
    }
    output.push('\n');

    output.push_str("## Summary\n\n");
    output.push_str(&format!(
        "{} **Status:** {:?}\n",
        status_emoji(&packet.summary.status),
        packet.summary.status
    ));
    output.push_str(&format!("- **Title:** {}\n", packet.summary.title));
    output.push_str(&format!(
        "- **Summary:** {}\n\n",
        packet.summary.short_summary
    ));

    if !packet.projections.assertions.is_empty() {
        output.push_str("## Assertions\n\n");
        for assertion in &packet.projections.assertions {
            output.push_str(&format!(
                "- [{}] **{}**: {}\n",
                status_emoji(&assertion.status),
                assertion.id,
                assertion.summary.title
            ));
            output.push_str(&format!("  - {}\n", assertion.summary.short_summary));
            if let Some(details) = &assertion.details {
                output.push_str(&format!("  - Details: {}\n", details));
            }
            output.push('\n');
        }
    }

    if !packet.projections.findings.is_empty() {
        output.push_str("## Findings\n\n");
        for finding in &packet.projections.findings {
            output.push_str(&format!(
                "- [{}] **{}**: {}\n",
                severity_emoji(&finding.severity),
                finding.id,
                finding.title
            ));
            output.push_str(&format!("  - {}\n", finding.message));
            if let Some(location) = &finding.location {
                output.push_str(&format!("  - Location: {}", location.path));
                if let Some(line) = location.line {
                    output.push_str(&format!(":{}", line));
                    if let Some(col) = location.column {
                        output.push_str(&format!(":{}", col));
                    }
                }
                output.push('\n');
            }
            output.push('\n');
        }
    }

    if !packet.projections.metrics.is_empty() {
        output.push_str("## Metrics\n\n");
        for metric in &packet.projections.metrics {
            output.push_str(&format!(
                "- **{}**: {}{}",
                metric.name,
                metric.value,
                metric
                    .unit
                    .as_ref()
                    .map(|unit| format!(" {}", unit))
                    .unwrap_or_default()
            ));
            if let Some(baseline) = metric.baseline {
                output.push_str(&format!(" (baseline: {})", baseline));
            }
            output.push('\n');
        }
        output.push('\n');
    }

    if !packet.projections.attachments.is_empty() {
        output.push_str("## Attachments\n\n");
        for attachment in &packet.projections.attachments {
            output.push_str(&format!(
                "- [{}] **{:?}**: {}\n",
                attachment_role_emoji(&attachment.role),
                attachment.role,
                attachment.relative_path
            ));
            output.push_str(&format!("  - Media Type: {}\n", attachment.media_type));
            output.push_str(&format!("  - SHA-256: {}\n", attachment.sha256.as_str()));
            if let Some(size) = attachment.size {
                output.push_str(&format!("  - Size: {} bytes\n", size));
            }
            if let Some(schema_id) = &attachment.schema_id {
                output.push_str(&format!("  - Schema ID: {}\n", schema_id));
            }
            output.push('\n');
        }
    }

    if !packet.projections.relations.is_empty() {
        output.push_str("## Relations\n\n");
        for relation in &packet.projections.relations {
            output.push_str(&format!(
                "- **{:?}** → {}\n",
                relation.kind,
                relation.target_packet_id.as_str()
            ));
            if let Some(details) = &relation.details {
                output.push_str(&format!("  - {}\n", details));
            }
            output.push('\n');
        }
    }

    if !packet.native_payloads.is_empty() {
        output.push_str("## Native Payloads\n\n");
        for payload in &packet.native_payloads {
            output.push_str(&format!("- {}\n", payload));
        }
        output.push('\n');
    }

    if !packet.artifacts.is_empty() {
        output.push_str("## Artifacts\n\n");
        for artifact in &packet.artifacts {
            output.push_str(&format!("- {}\n", artifact));
        }
        output.push('\n');
    }

    if let Some(links) = &packet.links {
        if !links.is_empty() {
            output.push_str("## Links\n\n");
            for (name, url) in links {
                output.push_str(&format!("- [{}]({})\n", name, url));
            }
            output.push('\n');
        }
    }

    if let Some(labels) = &packet.labels {
        if !labels.is_empty() {
            output.push_str("## Labels\n\n");
            for (key, value) in labels {
                output.push_str(&format!("- **{}**: {}\n", key, value));
            }
            output.push('\n');
        }
    }

    Ok(output)
}

/// Exports a bundle to Markdown format.
///
/// This function converts an evidence bundle into a human-readable Markdown
/// document that includes bundle metadata, summary statistics, and inventories
/// of packets and artifacts.
///
/// # Arguments
///
/// * `bundle` - The bundle to export
///
/// # Returns
///
/// A Markdown formatted string representing the bundle
///
/// # Example
///
/// ```
/// use evidencebus_export_markdown::export_bundle;
/// use evidencebus_types::{Bundle, BundleManifest, BundleSummary, Digest, IntegrityMetadata, PacketId, SchemaVersion};
/// use std::collections::HashMap;
///
/// let bundle = Bundle {
///     eb_version: SchemaVersion::new("0.1.0"),
///     bundle_id: PacketId::new("test-bundle").unwrap(),
///     created_at: "2024-01-01T12:00:00Z".to_string(),
///     manifest: BundleManifest::new(
///         vec![],
///         vec![],
///         IntegrityMetadata::new(
///             Digest::new("0".repeat(64)).unwrap(),
///             HashMap::new(),
///             HashMap::new(),
///         ),
///     ),
///     summary: BundleSummary::new(
///         2,
///         3,
///         evidencebus_types::StatusCounts {
///             pass: 1,
///             fail: 1,
///             warn: 0,
///             indeterminate: 0,
///             error: 0,
///         },
///         evidencebus_types::SeverityCounts {
///             note: 0,
///             warning: 1,
///             error: 0,
///         },
///     ),
/// };
///
/// let markdown = export_bundle(&bundle).unwrap();
/// assert!(markdown.contains("# Evidence Bundle: test-bundle"));
/// ```
pub fn export_bundle(bundle: &Bundle) -> Result<String, MarkdownExportError> {
    let mut output = String::new();

    output.push_str(&format!(
        "# Evidence Bundle: {}\n\n",
        bundle.bundle_id.as_str()
    ));
    output.push_str(&format!(
        "**Created:** {}\n\n",
        format_timestamp(&bundle.created_at)
    ));
    output.push_str(&format!("**Version:** {}\n\n", bundle.eb_version.as_str()));

    output.push_str("## Summary\n\n");
    output.push_str(&format!(
        "- **Total packets:** {}\n",
        bundle.summary.total_packets
    ));
    output.push_str(&format!(
        "- **Total artifacts:** {}\n",
        bundle.summary.total_artifacts
    ));
    output.push('\n');

    output.push_str("### Status Counts\n\n");
    output.push_str(&format!("- {} Pass\n", status_emoji(&PacketStatus::Pass)));
    output.push_str(&format!(
        "  - Count: {}\n",
        bundle.summary.status_counts.pass
    ));
    output.push_str(&format!("- {} Fail\n", status_emoji(&PacketStatus::Fail)));
    output.push_str(&format!(
        "  - Count: {}\n",
        bundle.summary.status_counts.fail
    ));
    output.push_str(&format!("- {} Warn\n", status_emoji(&PacketStatus::Warn)));
    output.push_str(&format!(
        "  - Count: {}\n",
        bundle.summary.status_counts.warn
    ));
    output.push_str(&format!(
        "- {} Indeterminate\n",
        status_emoji(&PacketStatus::Indeterminate)
    ));
    output.push_str(&format!(
        "  - Count: {}\n",
        bundle.summary.status_counts.indeterminate
    ));
    output.push_str(&format!("- {} Error\n", status_emoji(&PacketStatus::Error)));
    output.push_str(&format!(
        "  - Count: {}\n",
        bundle.summary.status_counts.error
    ));
    output.push('\n');

    output.push_str("### Severity Counts\n\n");
    output.push_str(&format!(
        "- {} Note\n",
        severity_emoji(&FindingSeverity::Note)
    ));
    output.push_str(&format!(
        "  - Count: {}\n",
        bundle.summary.severity_counts.note
    ));
    output.push_str(&format!(
        "- {} Warning\n",
        severity_emoji(&FindingSeverity::Warning)
    ));
    output.push_str(&format!(
        "  - Count: {}\n",
        bundle.summary.severity_counts.warning
    ));
    output.push_str(&format!(
        "- {} Error\n",
        severity_emoji(&FindingSeverity::Error)
    ));
    output.push_str(&format!(
        "  - Count: {}\n",
        bundle.summary.severity_counts.error
    ));
    output.push('\n');

    output.push_str("## Packet Inventory\n\n");
    for entry in &bundle.manifest.packets {
        output.push_str(&format!("- **{}**\n", entry.packet_id.as_str()));
        output.push_str(&format!("  - Path: {}\n", entry.relative_path));
        output.push_str(&format!("  - SHA-256: {}\n\n", entry.sha256.as_str()));
    }

    output.push_str("## Artifact Inventory\n\n");
    for entry in &bundle.manifest.artifacts {
        output.push_str(&format!("- **{}**\n", entry.packet_id.as_str()));
        output.push_str(&format!("  - Path: {}\n", entry.relative_path));
        output.push_str(&format!("  - Role: {:?}\n", entry.role));
        output.push_str(&format!("  - SHA-256: {}\n\n", entry.sha256.as_str()));
    }

    output.push_str("## Integrity\n\n");
    output.push_str(&format!(
        "- **Manifest digest:** {}\n",
        bundle.manifest.integrity.manifest_digest.as_str()
    ));
    output.push_str(&format!(
        "- **Packet digests:** {} entries\n",
        bundle.manifest.integrity.packet_digests.len()
    ));
    output.push_str(&format!(
        "- **Artifact digests:** {} entries\n",
        bundle.manifest.integrity.artifact_digests.len()
    ));

    Ok(output)
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use evidencebus_types::{
        Attachment, Bundle, BundleManifest, BundleSummary, Digest, IntegrityMetadata, Location,
        Metric, Packet, PacketId, Producer, Projections, SchemaVersion, StatusCounts, Subject,
        Summary, VcsKind,
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
    fn test_format_timestamp() {
        let formatted = format_timestamp("2024-01-01T12:00:00Z");
        assert!(formatted.contains("2024"));
        assert!(formatted.contains("12:00:00"));
    }

    #[test]
    fn test_status_emoji() {
        assert_eq!(status_emoji(&PacketStatus::Pass), "✅");
        assert_eq!(status_emoji(&PacketStatus::Fail), "❌");
        assert_eq!(status_emoji(&PacketStatus::Warn), "⚠️");
        assert_eq!(status_emoji(&PacketStatus::Indeterminate), "❓");
        assert_eq!(status_emoji(&PacketStatus::Error), "💥");
    }

    #[test]
    fn test_severity_emoji() {
        assert_eq!(severity_emoji(&FindingSeverity::Note), "ℹ️");
        assert_eq!(severity_emoji(&FindingSeverity::Warning), "⚠️");
        assert_eq!(severity_emoji(&FindingSeverity::Error), "🔴");
    }

    #[test]
    fn test_attachment_role_emoji() {
        assert_eq!(attachment_role_emoji(&AttachmentRole::NativePayload), "📦");
        assert_eq!(attachment_role_emoji(&AttachmentRole::ReportHtml), "📊");
        assert_eq!(attachment_role_emoji(&AttachmentRole::StdoutLog), "📝");
        assert_eq!(attachment_role_emoji(&AttachmentRole::StderrLog), "⚠️");
        assert_eq!(attachment_role_emoji(&AttachmentRole::PlainText), "📄");
        assert_eq!(
            attachment_role_emoji(&AttachmentRole::ArbitraryBinary),
            "🔧"
        );
    }

    #[test]
    fn test_export_packet() {
        let packet = create_test_packet("test-packet", PacketStatus::Pass);
        let markdown = export_packet(&packet).unwrap();

        assert!(markdown.contains("# Evidence Packet: test-packet"));
        assert!(markdown.contains("**Tool:** test-tool 1.0.0"));
        assert!(markdown.contains("**Status:** Pass"));
        assert!(markdown.contains("## Assertions"));
        assert!(markdown.contains("## Findings"));
        assert!(markdown.contains("## Metrics"));
        assert!(markdown.contains("## Attachments"));
        assert!(markdown.contains("coverage"));
        assert!(markdown.contains("85.5"));
    }

    #[test]
    fn test_export_packet_with_location() {
        let mut packet = create_test_packet("test-packet", PacketStatus::Pass);
        packet.projections.findings[0] = packet.projections.findings[0]
            .clone()
            .with_location(Location::new("src/main.rs").with_line(42).with_column(10));

        let markdown = export_packet(&packet).unwrap();
        assert!(markdown.contains("src/main.rs:42:10"));
    }

    #[test]
    fn test_export_packet_empty_projections() {
        let packet = Packet {
            eb_version: SchemaVersion::new("0.1.0"),
            packet_id: PacketId::new("test-packet").unwrap(),
            producer: Producer::new("test-tool", "1.0.0"),
            subject: Subject::new(VcsKind::Git, "owner/repo", "abc123", "def456"),
            summary: Summary::new(PacketStatus::Pass, "Test Title", "Test summary"),
            projections: Projections::new(),
            native_payloads: vec![],
            artifacts: vec![],
            links: None,
            labels: None,
            created_at: "2024-01-01T12:00:00Z".to_string(),
        };

        let markdown = export_packet(&packet).unwrap();
        assert!(markdown.contains("# Evidence Packet: test-packet"));
        assert!(!markdown.contains("## Assertions"));
        assert!(!markdown.contains("## Findings"));
        assert!(!markdown.contains("## Metrics"));
    }

    #[test]
    fn test_export_bundle() {
        let bundle = Bundle {
            eb_version: SchemaVersion::new("0.1.0"),
            bundle_id: PacketId::new("test-bundle").unwrap(),
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
                2,
                3,
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
        };

        let markdown = export_bundle(&bundle).unwrap();

        assert!(markdown.contains("# Evidence Bundle: test-bundle"));
        assert!(markdown.contains("**Total packets:** 2"));
        assert!(markdown.contains("**Total artifacts:** 3"));
        assert!(markdown.contains("✅ Pass"));
        assert!(markdown.contains("❌ Fail"));
        assert!(markdown.contains("Count: 1"));
    }
}
