use std::collections::BTreeMap;

use evidencebus_codes::{Severity, Status, VcsKind, EVIDENCEBUS_VERSION};
use evidencebus_types::{
    Assertion, AttachmentRef, Finding, Metric, Packet, PacketSummary, PlatformInfo, Producer,
    Projections, Provenance, Subject,
};
use serde_json::json;

pub fn perfgate_packet() -> Packet {
    Packet {
        eb_version: EVIDENCEBUS_VERSION.to_string(),
        packet_id: "pkt-perfgate".to_string(),
        producer: Producer {
            tool: "perfgate".to_string(),
            version: "0.7.0".to_string(),
            invocation_id: Some("run-perfgate-001".to_string()),
        },
        subject: Subject {
            vcs: VcsKind::Git,
            repo: Some("EffortlessMetrics/example".to_string()),
            base: Some("abc123".to_string()),
            head: Some("def456".to_string()),
            paths: vec!["crates/example/src/lib.rs".to_string()],
            workspace_scope: vec!["example".to_string()],
        },
        summary: PacketSummary {
            status: Status::Pass,
            title: "Coverage gate passed".to_string(),
            summary: "Changed modules maintained coverage above the configured floor."
                .to_string(),
        },
        projections: Projections {
            assertions: vec![Assertion {
                id: "perfgate.coverage_floor".to_string(),
                status: Status::Pass,
                title: "Coverage floor".to_string(),
                summary: "Coverage floor met for changed files.".to_string(),
            }],
            findings: Vec::new(),
            metrics: vec![Metric {
                name: "coverage_percent".to_string(),
                value: json!(91.2),
                unit: Some("percent".to_string()),
                baseline: Some(json!(90.0)),
            }],
            relations: Vec::new(),
            attachments: vec![AttachmentRef {
                role: "report_json".to_string(),
                media_type: "application/json".to_string(),
                relative_path: "report.json".to_string(),
                sha256: None,
                size_bytes: None,
                schema_id: None,
            }],
        },
        provenance: Provenance {
            command: Some("perfgate --base abc123 --head def456".to_string()),
            environment_fingerprint: Some("linux-x86_64".to_string()),
            platform: Some(PlatformInfo {
                os: "linux".to_string(),
                arch: "x86_64".to_string(),
                hostname: Some("ci-runner-1".to_string()),
            }),
        },
        labels: BTreeMap::new(),
    }
}

pub fn faultline_packet() -> Packet {
    Packet {
        eb_version: EVIDENCEBUS_VERSION.to_string(),
        packet_id: "pkt-faultline".to_string(),
        producer: Producer {
            tool: "faultline".to_string(),
            version: "0.1.0".to_string(),
            invocation_id: Some("run-faultline-001".to_string()),
        },
        subject: Subject {
            vcs: VcsKind::Git,
            repo: Some("EffortlessMetrics/example".to_string()),
            base: Some("good123".to_string()),
            head: Some("bad456".to_string()),
            paths: vec![
                "crates/parser/src/lib.rs".to_string(),
                "crates/parser/tests/regression.rs".to_string(),
            ],
            workspace_scope: vec!["parser".to_string()],
        },
        summary: PacketSummary {
            status: Status::Indeterminate,
            title: "Suspect window narrowed".to_string(),
            summary: "Skipped midpoint prevented exact first-bad localization."
                .to_string(),
        },
        projections: Projections {
            assertions: vec![Assertion {
                id: "faultline.localization".to_string(),
                status: Status::Indeterminate,
                title: "Localization outcome".to_string(),
                summary: "A suspect window of three commits remains.".to_string(),
            }],
            findings: vec![Finding {
                id: "faultline.suspect_window".to_string(),
                severity: Severity::Warning,
                title: "Suspect window remains".to_string(),
                summary: "Read parser changes and workflow changes first.".to_string(),
                location: Some("crates/parser/src/lib.rs".to_string()),
            }],
            metrics: vec![Metric {
                name: "suspect_window_commits".to_string(),
                value: json!(3),
                unit: Some("count".to_string()),
                baseline: None,
            }],
            relations: Vec::new(),
            attachments: vec![
                AttachmentRef {
                    role: "native_payload".to_string(),
                    media_type: "application/json".to_string(),
                    relative_path: "faultline/analysis.json".to_string(),
                    sha256: None,
                    size_bytes: None,
                    schema_id: Some("faultline.analysis@0.1".to_string()),
                },
                AttachmentRef {
                    role: "report_html".to_string(),
                    media_type: "text/html".to_string(),
                    relative_path: "faultline/index.html".to_string(),
                    sha256: None,
                    size_bytes: None,
                    schema_id: None,
                },
                AttachmentRef {
                    role: "stderr_log".to_string(),
                    media_type: "text/plain".to_string(),
                    relative_path: "logs/stderr.log".to_string(),
                    sha256: None,
                    size_bytes: None,
                    schema_id: None,
                },
            ],
        },
        provenance: Provenance {
            command: Some("faultline --good good123 --bad bad456 --cmd 'cargo test parser_regression'".to_string()),
            environment_fingerprint: Some("linux-x86_64".to_string()),
            platform: Some(PlatformInfo {
                os: "linux".to_string(),
                arch: "x86_64".to_string(),
                hostname: Some("ci-runner-1".to_string()),
            }),
        },
        labels: BTreeMap::new(),
    }
}
