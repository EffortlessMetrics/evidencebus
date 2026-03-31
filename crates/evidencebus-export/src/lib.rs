use evidencebus_codes::Severity;
use evidencebus_types::{BundleManifest, Packet};
use serde_json::json;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum ExportError {
    #[error("json serialization failed: {0}")]
    Json(#[from] serde_json::Error),
}

pub fn render_markdown_packet(packet: &Packet) -> String {
    let mut output = String::new();
    output.push_str("# Evidence packet\n\n");
    output.push_str(&format!("**Packet ID:** `{}`\n\n", packet.packet_id));
    output.push_str(&format!("**Tool:** `{}` `{}`\n\n", packet.producer.tool, packet.producer.version));
    output.push_str(&format!("**Status:** `{:?}`\n\n", packet.summary.status));
    output.push_str(&format!("## Summary\n\n{}\n\n", packet.summary.summary));

    if !packet.projections.assertions.is_empty() {
        output.push_str("## Assertions\n\n");
        for assertion in &packet.projections.assertions {
            output.push_str(&format!(
                "- `{}` — `{:?}` — {}\n",
                assertion.id, assertion.status, assertion.summary
            ));
        }
        output.push('\n');
    }

    if !packet.projections.findings.is_empty() {
        output.push_str("## Findings\n\n");
        for finding in &packet.projections.findings {
            output.push_str(&format!(
                "- `{}` — `{:?}` — {}\n",
                finding.id, finding.severity, finding.summary
            ));
        }
        output.push('\n');
    }

    if !packet.projections.metrics.is_empty() {
        output.push_str("## Metrics\n\n");
        for metric in &packet.projections.metrics {
            output.push_str(&format!(
                "- `{}` = `{}`{}\n",
                metric.name,
                metric.value,
                metric
                    .unit
                    .as_ref()
                    .map(|unit| format!(" {}", unit))
                    .unwrap_or_default()
            ));
        }
        output.push('\n');
    }

    if !packet.projections.attachments.is_empty() {
        output.push_str("## Attachments\n\n");
        for attachment in &packet.projections.attachments {
            output.push_str(&format!(
                "- `{}` → `{}` ({})\n",
                attachment.role, attachment.relative_path, attachment.media_type
            ));
        }
    }

    output
}

pub fn render_markdown_bundle(manifest: &BundleManifest, packets: &[Packet]) -> String {
    let mut output = String::new();
    output.push_str("# Evidence bundle\n\n");
    output.push_str(&format!("**Bundle ID:** `{}`\n\n", manifest.bundle_id));
    output.push_str(&format!(
        "**Packets:** {}  \n**Pass:** {}  \n**Fail:** {}  \n**Warn:** {}  \n**Indeterminate:** {}  \n**Error:** {}\n\n",
        manifest.summary.packet_count,
        manifest.summary.pass_count,
        manifest.summary.fail_count,
        manifest.summary.warn_count,
        manifest.summary.indeterminate_count,
        manifest.summary.error_count,
    ));
    output.push_str("## Packets\n\n");
    for packet in packets {
        output.push_str(&format!(
            "- `{}` — `{}` — `{:?}` — {}\n",
            packet.packet_id, packet.producer.tool, packet.summary.status, packet.summary.title
        ));
    }

    let finding_count: usize = packets.iter().map(|packet| packet.projections.findings.len()).sum();
    output.push_str(&format!("\n## Findings surfaced\n\n{}\n", finding_count));
    output
}

pub fn render_sarif_packet(packet: &Packet) -> Result<String, ExportError> {
    render_sarif_bundle(&BundleManifest {
        eb_version: "0.1.0".to_string(),
        bundle_id: packet.packet_id.clone(),
        packets: Vec::new(),
        artifacts: Vec::new(),
        summary: Default::default(),
    }, std::slice::from_ref(packet))
}

pub fn render_sarif_bundle(manifest: &BundleManifest, packets: &[Packet]) -> Result<String, ExportError> {
    let runs = packets
        .iter()
        .map(|packet| {
            let results = packet
                .projections
                .findings
                .iter()
                .map(|finding| {
                    let level = match finding.severity {
                        Severity::Note => "note",
                        Severity::Warning => "warning",
                        Severity::Error => "error",
                    };

                    let mut result = json!({
                        "ruleId": finding.id,
                        "level": level,
                        "message": {
                            "text": finding.summary,
                        },
                    });

                    if let Some(location) = &finding.location {
                        result["locations"] = json!([
                            {
                                "physicalLocation": {
                                    "artifactLocation": {
                                        "uri": location,
                                    }
                                }
                            }
                        ]);
                    }

                    result
                })
                .collect::<Vec<_>>();

            json!({
                "tool": {
                    "driver": {
                        "name": packet.producer.tool,
                        "semanticVersion": packet.producer.version,
                        "informationUri": "https://github.com/EffortlessMetrics/evidencebus",
                    }
                },
                "automationDetails": {
                    "id": packet.packet_id,
                },
                "properties": {
                    "evidencebusLossy": true,
                    "bundleId": manifest.bundle_id,
                },
                "results": results,
            })
        })
        .collect::<Vec<_>>();

    serde_json::to_string_pretty(&json!({
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": runs,
    }))
    .map_err(ExportError::from)
}

#[cfg(test)]
mod tests {
    use evidencebus_fixtures::{faultline_packet, perfgate_packet};

    use super::{render_markdown_bundle, render_markdown_packet, render_sarif_bundle};

    #[test]
    fn markdown_contains_packet_titles() {
        let packet = perfgate_packet();
        let markdown = render_markdown_packet(&packet);
        assert!(markdown.contains("Coverage gate passed"));
    }

    #[test]
    fn bundle_markdown_contains_packet_count() {
        let packets = vec![perfgate_packet(), faultline_packet()];
        let manifest = evidencebus_types::BundleManifest {
            eb_version: "0.1.0".to_string(),
            bundle_id: "bundle-1".to_string(),
            packets: Vec::new(),
            artifacts: Vec::new(),
            summary: evidencebus_core::summarize_packets(&packets),
        };

        let markdown = render_markdown_bundle(&manifest, &packets);
        assert!(markdown.contains("Packets"));
    }

    #[test]
    fn sarif_contains_rule_id() -> Result<(), Box<dyn std::error::Error>> {
        let packets = vec![faultline_packet()];
        let manifest = evidencebus_types::BundleManifest {
            eb_version: "0.1.0".to_string(),
            bundle_id: "bundle-1".to_string(),
            packets: Vec::new(),
            artifacts: Vec::new(),
            summary: evidencebus_core::summarize_packets(&packets),
        };

        let sarif = render_sarif_bundle(&manifest, &packets)?;
        assert!(sarif.contains("faultline.suspect_window"));
        Ok(())
    }
}
