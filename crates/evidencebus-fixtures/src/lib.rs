#![allow(clippy::unwrap_used, clippy::expect_used)]
//! Test fixtures for evidencebus packets and bundles.
//!
//! This crate provides:
//! - Fluent builders for creating test packets and bundles
//! - Fixture loaders for reading test data
//! - Malformed packet generators for testing validation
//! - Golden test helpers for snapshot testing

use evidencebus_codes::{FindingSeverity, PacketStatus};
use evidencebus_types::{
    ArtifactInventoryEntry, Attachment, AttachmentRole, Bundle, BundleManifest, BundleSummary,
    Digest, IntegrityMetadata, Location, Metric, Packet, PacketId, PacketInventoryEntry, Producer,
    Projections, SchemaVersion, SeverityCounts, StatusCounts, Subject, Summary, VcsKind,
};
use serde_json::Value;
use std::collections::HashMap;
use std::path::PathBuf;

// ============================================================================
// Error Types
// ============================================================================

/// Error type for builder operations.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum BuildError {
    #[error("missing required field: {0}")]
    MissingRequiredField(String),
    #[error("invalid value for field '{0}': {1}")]
    InvalidValue(String, String),
    #[error("invalid digest: {0}")]
    InvalidDigest(String),
}

/// Error type for fixture operations.
#[derive(Debug, thiserror::Error)]
pub enum FixtureError {
    #[error("fixture not found: {0}")]
    NotFound(String),
    #[error("failed to load fixture '{0}': {1}")]
    LoadFailed(String, String),
    #[error("failed to write golden '{0}': {1}")]
    WriteFailed(String, String),
    #[error("invalid fixture '{0}': {1}")]
    InvalidFixture(String, String),
}

// ============================================================================
// Packet Builder
// ============================================================================

/// Fluent builder for creating test packets.
#[derive(Debug, Clone, Default)]
pub struct PacketBuilder {
    packet_id: Option<String>,
    producer: Option<(String, String)>,
    subject: Option<(VcsKind, String, String, String)>,
    status: Option<PacketStatus>,
    title: Option<String>,
    summary: Option<String>,
    assertions: Vec<(String, PacketStatus, String)>,
    findings: Vec<(String, FindingSeverity, String)>,
    metrics: Vec<(String, f64, Option<String>)>,
    attachments: Vec<(AttachmentRole, String, String)>,
    native_payloads: Vec<(String, String)>,
}

impl PacketBuilder {
    /// Creates a new PacketBuilder with default values.
    pub fn new() -> Self {
        Self::default()
    }

    /// Sets the packet ID.
    pub fn with_id(mut self, id: &str) -> Self {
        self.packet_id = Some(id.to_string());
        self
    }

    /// Sets the producer metadata.
    pub fn with_producer(mut self, tool: &str, version: &str) -> Self {
        self.producer = Some((tool.to_string(), version.to_string()));
        self
    }

    /// Sets the subject metadata.
    pub fn with_subject(mut self, vcs: VcsKind, repo: &str, commit: &str) -> Self {
        self.subject = Some((
            vcs,
            repo.to_string(),
            commit.to_string(),
            commit.to_string(),
        ));
        self
    }

    /// Sets the packet status.
    pub fn with_status(mut self, status: PacketStatus) -> Self {
        self.status = Some(status);
        self
    }

    /// Sets the packet title.
    pub fn with_title(mut self, title: &str) -> Self {
        self.title = Some(title.to_string());
        self
    }

    /// Sets the packet summary.
    pub fn with_summary(mut self, summary: &str) -> Self {
        self.summary = Some(summary.to_string());
        self
    }

    /// Adds an assertion to the packet.
    pub fn add_assertion(mut self, id: &str, status: PacketStatus, summary: &str) -> Self {
        self.assertions
            .push((id.to_string(), status, summary.to_string()));
        self
    }

    /// Adds a finding to the packet.
    pub fn add_finding(mut self, id: &str, severity: FindingSeverity, message: &str) -> Self {
        self.findings
            .push((id.to_string(), severity, message.to_string()));
        self
    }

    /// Adds a metric to the packet.
    pub fn add_metric(mut self, name: &str, value: f64, unit: Option<&str>) -> Self {
        self.metrics
            .push((name.to_string(), value, unit.map(|u| u.to_string())));
        self
    }

    /// Adds an attachment to the packet.
    pub fn add_attachment(mut self, role: AttachmentRole, path: &str, media_type: &str) -> Self {
        self.attachments
            .push((role, path.to_string(), media_type.to_string()));
        self
    }

    /// Adds a native payload reference to the packet.
    pub fn add_native_payload(mut self, path: &str, schema_id: &str) -> Self {
        self.native_payloads
            .push((path.to_string(), schema_id.to_string()));
        self
    }

    /// Builds the packet, returning an error if required fields are missing.
    pub fn build(self) -> Result<Packet, BuildError> {
        let packet_id = self
            .packet_id
            .ok_or_else(|| BuildError::MissingRequiredField("packet_id".to_string()))?;
        let packet_id = PacketId::new(packet_id)
            .map_err(|e| BuildError::InvalidValue("packet_id".to_string(), e.to_string()))?;

        let (tool, version) = self
            .producer
            .ok_or_else(|| BuildError::MissingRequiredField("producer".to_string()))?;
        let producer = Producer::new(tool, version);

        let (vcs, repo, commit, head) = self
            .subject
            .ok_or_else(|| BuildError::MissingRequiredField("subject".to_string()))?;
        let subject = Subject::new(vcs, repo, commit, head);

        let status = self
            .status
            .ok_or_else(|| BuildError::MissingRequiredField("status".to_string()))?;
        let title = self
            .title
            .ok_or_else(|| BuildError::MissingRequiredField("title".to_string()))?;
        let summary_text = self
            .summary
            .ok_or_else(|| BuildError::MissingRequiredField("summary".to_string()))?;
        let summary = Summary::new(status, title, summary_text);

        let mut projections = Projections::new();

        for (id, status, summary_text) in self.assertions {
            let assertion_summary = Summary::new(status, id.clone(), summary_text);
            projections = projections.add_assertion(evidencebus_types::Assertion::new(
                id,
                status,
                assertion_summary,
            ));
        }

        for (id, severity, message) in self.findings {
            let finding =
                evidencebus_types::Finding::new(id.clone(), severity, id.clone(), message);
            projections = projections.add_finding(finding);
        }

        for (name, value, unit) in self.metrics {
            let mut metric = Metric::new(name, value);
            if let Some(u) = unit {
                metric = metric.with_unit(u);
            }
            projections = projections.add_metric(metric);
        }

        for (role, path, media_type) in self.attachments {
            let digest = Digest::new("0".repeat(64))
                .map_err(|e| BuildError::InvalidDigest(e.to_string()))?;
            let attachment = Attachment::new(role, media_type, path, digest);
            projections = projections.add_attachment(attachment);
        }

        let native_payloads = self
            .native_payloads
            .into_iter()
            .map(|(path, _schema_id)| path)
            .collect();

        Ok(Packet {
            eb_version: SchemaVersion::new("0.1.0"),
            packet_id,
            producer,
            subject,
            summary,
            projections,
            native_payloads,
            artifacts: vec![],
            links: None,
            labels: None,
            created_at: "2024-01-01T12:00:00Z".to_string(),
        })
    }
}

// ============================================================================
// Bundle Builder
// ============================================================================

/// Fluent builder for creating test bundles.
#[derive(Debug, Clone, Default)]
pub struct BundleBuilder {
    bundle_id: Option<String>,
    packets: Vec<Packet>,
    artifacts: Vec<(String, String, AttachmentRole)>,
}

impl BundleBuilder {
    /// Creates a new BundleBuilder with default values.
    pub fn new() -> Self {
        Self::default()
    }

    /// Sets the bundle ID.
    pub fn with_id(mut self, id: &str) -> Self {
        self.bundle_id = Some(id.to_string());
        self
    }

    /// Adds a packet to the bundle.
    pub fn add_packet(mut self, packet: Packet) -> Self {
        self.packets.push(packet);
        self
    }

    /// Adds an artifact reference to the bundle.
    pub fn add_artifact(mut self, packet_id: &str, path: &str, role: AttachmentRole) -> Self {
        self.artifacts
            .push((packet_id.to_string(), path.to_string(), role));
        self
    }

    /// Builds the bundle, returning an error if required fields are missing.
    pub fn build(self) -> Result<Bundle, BuildError> {
        let bundle_id = self
            .bundle_id
            .ok_or_else(|| BuildError::MissingRequiredField("bundle_id".to_string()))?;
        let bundle_id = PacketId::new(bundle_id)
            .map_err(|e| BuildError::InvalidValue("bundle_id".to_string(), e.to_string()))?;

        if self.packets.is_empty() {
            return Err(BuildError::MissingRequiredField(
                "at least one packet".to_string(),
            ));
        }

        let mut packet_digests = HashMap::new();
        let mut packet_entries = Vec::new();
        let mut status_counts = StatusCounts::default();
        let mut severity_counts = SeverityCounts::default();

        for (idx, packet) in self.packets.iter().enumerate() {
            let digest = Digest::new(format!("{:0>64}", idx))
                .map_err(|e| BuildError::InvalidDigest(e.to_string()))?;
            packet_digests.insert(packet.packet_id.clone(), digest.clone());
            status_counts.increment(packet.summary.status);

            for finding in &packet.projections.findings {
                severity_counts.increment(finding.severity);
            }

            packet_entries.push(PacketInventoryEntry::new(
                packet.packet_id.clone(),
                format!("packets/{}/packet.eb.json", packet.packet_id.as_str()),
                digest,
            ));
        }

        let mut artifact_digests = HashMap::new();
        let mut artifact_entries = Vec::new();

        for (idx, (packet_id, path, role)) in self.artifacts.iter().enumerate() {
            let digest = Digest::new(format!("{:0>64}", idx + 100))
                .map_err(|e| BuildError::InvalidDigest(e.to_string()))?;
            artifact_digests.insert(path.clone(), digest.clone());

            let pid = PacketId::new(packet_id.clone())
                .map_err(|e| BuildError::InvalidValue("packet_id".to_string(), e.to_string()))?;
            artifact_entries.push(ArtifactInventoryEntry::new(pid, path, *role, digest));
        }

        let manifest_digest =
            Digest::new("9".repeat(64)).map_err(|e| BuildError::InvalidDigest(e.to_string()))?;

        let integrity = IntegrityMetadata::new(manifest_digest, packet_digests, artifact_digests);

        let manifest = BundleManifest::new(packet_entries, artifact_entries, integrity);

        let summary = BundleSummary::new(
            self.packets.len() as u32,
            self.artifacts.len() as u32,
            status_counts,
            severity_counts,
        );

        Ok(Bundle {
            eb_version: SchemaVersion::new("0.1.0"),
            bundle_id,
            created_at: "2024-01-01T12:00:00Z".to_string(),
            manifest,
            summary,
        })
    }
}

// ============================================================================
// Fixture Loaders
// ============================================================================

/// Loads a packet fixture from the fixtures directory.
pub fn load_packet_fixture(name: &str) -> Result<Packet, FixtureError> {
    let path = format!("fixtures/packets/{}.eb.json", name);
    let content = std::fs::read_to_string(&path)
        .map_err(|e| FixtureError::LoadFailed(path.clone(), e.to_string()))?;
    serde_json::from_str(&content).map_err(|e| FixtureError::InvalidFixture(path, e.to_string()))
}

/// Loads a bundle fixture from the examples directory.
pub fn load_bundle_fixture(name: &str) -> Result<Bundle, FixtureError> {
    let path = format!("examples/{}/bundle.eb.json", name);
    let content = std::fs::read_to_string(&path)
        .map_err(|e| FixtureError::LoadFailed(path.clone(), e.to_string()))?;
    serde_json::from_str(&content).map_err(|e| FixtureError::InvalidFixture(path, e.to_string()))
}

/// Loads an artifact file as bytes.
pub fn load_artifact(name: &str) -> Result<Vec<u8>, FixtureError> {
    let path = format!("fixtures/{}", name);
    std::fs::read(&path).map_err(|e| FixtureError::LoadFailed(path, e.to_string()))
}

// ============================================================================
// Malformed Packet Fixtures
// ============================================================================

/// Creates a malformed packet with missing required fields.
pub fn malformed_packet_missing_required() -> Value {
    serde_json::json!({
        "eb_version": "0.1.0",
        "packet_id": "test-packet",
        "producer": {
            "tool_name": "test-tool",
            "tool_version": "1.0.0"
        }
        // Missing: subject, summary
    })
}

/// Creates a malformed packet with an invalid status value.
pub fn malformed_packet_invalid_status() -> Value {
    serde_json::json!({
        "eb_version": "0.1.0",
        "packet_id": "test-packet",
        "producer": {
            "tool_name": "test-tool",
            "tool_version": "1.0.0"
        },
        "subject": {
            "vcs_kind": "git",
            "repo_identifier": "test/repo",
            "commit": "abc123",
            "head": "abc123"
        },
        "summary": {
            "status": "invalid_status",
            "title": "Test",
            "short_summary": "Test summary"
        },
        "projections": {}
    })
}

/// Creates a malformed packet with an invalid digest format.
pub fn malformed_packet_invalid_digest() -> Value {
    serde_json::json!({
        "eb_version": "0.1.0",
        "packet_id": "test-packet",
        "producer": {
            "tool_name": "test-tool",
            "tool_version": "1.0.0"
        },
        "subject": {
            "vcs_kind": "git",
            "repo_identifier": "test/repo",
            "commit": "abc123",
            "head": "abc123"
        },
        "summary": {
            "status": "pass",
            "title": "Test",
            "short_summary": "Test summary"
        },
        "projections": {
            "attachments": [{
                "role": "arbitrary_binary",
                "media_type": "application/json",
                "relative_path": "test.json",
                "sha256": "not-a-valid-digest"
            }]
        }
    })
}

/// Creates a malformed packet with a path traversal attempt.
pub fn malformed_packet_path_traversal() -> Value {
    serde_json::json!({
        "eb_version": "0.1.0",
        "packet_id": "test-packet",
        "producer": {
            "tool_name": "test-tool",
            "tool_version": "1.0.0"
        },
        "subject": {
            "vcs_kind": "git",
            "repo_identifier": "test/repo",
            "commit": "abc123",
            "head": "abc123"
        },
        "summary": {
            "status": "pass",
            "title": "Test",
            "short_summary": "Test summary"
        },
        "projections": {
            "attachments": [{
                "role": "arbitrary_binary",
                "media_type": "application/json",
                "relative_path": "../../../etc/passwd",
                "sha256": "0".repeat(64)
            }]
        }
    })
}

/// Creates a malformed packet with an absolute path.
pub fn malformed_packet_absolute_path() -> Value {
    serde_json::json!({
        "eb_version": "0.1.0",
        "packet_id": "test-packet",
        "producer": {
            "tool_name": "test-tool",
            "tool_version": "1.0.0"
        },
        "subject": {
            "vcs_kind": "git",
            "repo_identifier": "test/repo",
            "commit": "abc123",
            "head": "abc123"
        },
        "summary": {
            "status": "pass",
            "title": "Test",
            "short_summary": "Test summary"
        },
        "projections": {
            "attachments": [{
                "role": "arbitrary_binary",
                "media_type": "application/json",
                "relative_path": "/etc/passwd",
                "sha256": "0".repeat(64)
            }]
        }
    })
}

/// Creates malformed packets with duplicate IDs for testing deduplication.
pub fn malformed_packet_duplicate_id() -> Vec<Value> {
    let base_packet = serde_json::json!({
        "eb_version": "0.1.0",
        "packet_id": "duplicate-packet",
        "producer": {
            "tool_name": "test-tool",
            "tool_version": "1.0.0"
        },
        "subject": {
            "vcs_kind": "git",
            "repo_identifier": "test/repo",
            "commit": "abc123",
            "head": "abc123"
        },
        "summary": {
            "status": "pass",
            "title": "Test",
            "short_summary": "Test summary"
        },
        "projections": {}
    });

    let mut packet1 = base_packet.clone();
    packet1["summary"]["status"] = serde_json::json!("pass");

    let mut packet2 = base_packet;
    packet2["summary"]["status"] = serde_json::json!("fail");

    vec![packet1, packet2]
}

// ============================================================================
// Golden Test Helpers
// ============================================================================

/// Returns the path to a golden test file.
pub fn golden_path(name: &str) -> PathBuf {
    let mut path = PathBuf::from("fixtures/golden");
    path.push(name);
    path
}

/// Writes content to a golden test file.
pub fn write_golden(name: &str, content: &str) -> Result<(), FixtureError> {
    let path = golden_path(name);
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|e| FixtureError::WriteFailed(name.to_string(), e.to_string()))?;
    }
    std::fs::write(&path, content)
        .map_err(|e| FixtureError::WriteFailed(name.to_string(), e.to_string()))
}

/// Reads content from a golden test file.
pub fn read_golden(name: &str) -> Result<String, FixtureError> {
    let path = golden_path(name);
    std::fs::read_to_string(&path)
        .map_err(|e| FixtureError::LoadFailed(name.to_string(), e.to_string()))
}

/// Returns the path to a snapshot test file.
pub fn snapshot_path(name: &str) -> PathBuf {
    let mut path = PathBuf::from("fixtures/snapshots");
    path.push(name);
    path
}

/// Writes content to a snapshot test file.
pub fn write_snapshot(name: &str, content: &str) -> Result<(), FixtureError> {
    let path = snapshot_path(name);
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|e| FixtureError::WriteFailed(name.to_string(), e.to_string()))?;
    }
    std::fs::write(&path, content)
        .map_err(|e| FixtureError::WriteFailed(name.to_string(), e.to_string()))
}

/// Reads content from a snapshot test file.
pub fn read_snapshot(name: &str) -> Result<String, FixtureError> {
    let path = snapshot_path(name);
    std::fs::read_to_string(&path)
        .map_err(|e| FixtureError::LoadFailed(name.to_string(), e.to_string()))
}

// ============================================================================
// Test Scenarios - Valid Packets
// ============================================================================

/// Creates a minimal valid packet with Pass status.
pub fn simple_pass_packet() -> Packet {
    PacketBuilder::new()
        .with_id("simple-pass")
        .with_producer("test-tool", "1.0.0")
        .with_subject(VcsKind::Git, "test/repo", "abc123")
        .with_status(PacketStatus::Pass)
        .with_title("Simple Pass")
        .with_summary("A simple passing packet")
        .build()
        .unwrap()
}

/// Creates a minimal valid packet with Fail status.
pub fn simple_fail_packet() -> Packet {
    PacketBuilder::new()
        .with_id("simple-fail")
        .with_producer("test-tool", "1.0.0")
        .with_subject(VcsKind::Git, "test/repo", "abc123")
        .with_status(PacketStatus::Fail)
        .with_title("Simple Fail")
        .with_summary("A simple failing packet")
        .build()
        .unwrap()
}

/// Creates a rich packet with all projection types.
pub fn rich_packet_with_projections() -> Packet {
    PacketBuilder::new()
        .with_id("rich-packet")
        .with_producer("test-tool", "1.0.0")
        .with_subject(VcsKind::Git, "test/repo", "abc123")
        .with_status(PacketStatus::Warn)
        .with_title("Rich Packet")
        .with_summary("A packet with all projection types")
        .add_assertion("assertion-1", PacketStatus::Pass, "First assertion passed")
        .add_assertion("assertion-2", PacketStatus::Fail, "Second assertion failed")
        .add_finding("finding-1", FindingSeverity::Warning, "Warning finding")
        .add_finding("finding-2", FindingSeverity::Error, "Error finding")
        .add_metric("metric-1", 42.0, Some("count"))
        .add_metric("metric-2", 3.50, None)
        .add_attachment(
            AttachmentRole::ArbitraryBinary,
            "report.json",
            "application/json",
        )
        .add_attachment(AttachmentRole::ReportHtml, "report.html", "text/html")
        .add_native_payload("payload.json", "test.schema@1.0")
        .build()
        .unwrap()
}

/// Creates a packet with multiple attachments.
pub fn packet_with_attachments() -> Packet {
    PacketBuilder::new()
        .with_id("packet-attachments")
        .with_producer("test-tool", "1.0.0")
        .with_subject(VcsKind::Git, "test/repo", "abc123")
        .with_status(PacketStatus::Pass)
        .with_title("Packet with Attachments")
        .with_summary("A packet with multiple attachments")
        .add_attachment(
            AttachmentRole::ArbitraryBinary,
            "data.json",
            "application/json",
        )
        .add_attachment(AttachmentRole::ReportHtml, "index.html", "text/html")
        .add_attachment(AttachmentRole::StdoutLog, "stdout.log", "text/plain")
        .add_attachment(AttachmentRole::StderrLog, "stderr.log", "text/plain")
        .build()
        .unwrap()
}

/// Creates a packet with native payload reference.
pub fn packet_with_native_payload() -> Packet {
    PacketBuilder::new()
        .with_id("packet-native-payload")
        .with_producer("test-tool", "1.0.0")
        .with_subject(VcsKind::Git, "test/repo", "abc123")
        .with_status(PacketStatus::Pass)
        .with_title("Packet with Native Payload")
        .with_summary("A packet with native payload reference")
        .add_native_payload("native.json", "native.schema@1.0")
        .build()
        .unwrap()
}

// ============================================================================
// Test Scenarios - Valid Bundles
// ============================================================================

/// Creates a simple bundle with two packets.
pub fn simple_bundle() -> Bundle {
    let packet1 = simple_pass_packet();
    let packet2 = simple_fail_packet();

    BundleBuilder::new()
        .with_id("simple-bundle")
        .add_packet(packet1)
        .add_packet(packet2)
        .build()
        .unwrap()
}

/// Creates a bundle with artifact references.
pub fn bundle_with_artifacts() -> Bundle {
    let packet = packet_with_attachments();

    BundleBuilder::new()
        .with_id("bundle-artifacts")
        .add_packet(packet)
        .add_artifact(
            "packet-attachments",
            "data.json",
            AttachmentRole::ArbitraryBinary,
        )
        .add_artifact(
            "packet-attachments",
            "index.html",
            AttachmentRole::ReportHtml,
        )
        .add_artifact(
            "packet-attachments",
            "stdout.log",
            AttachmentRole::StdoutLog,
        )
        .add_artifact(
            "packet-attachments",
            "stderr.log",
            AttachmentRole::StderrLog,
        )
        .build()
        .unwrap()
}

// ============================================================================
// Test Scenarios - Invalid Packets
// ============================================================================

/// Creates a packet with an invalid schema version.
pub fn packet_with_invalid_schema_version() -> Value {
    let mut packet = serde_json::to_value(simple_pass_packet()).unwrap();
    packet["eb_version"] = serde_json::json!("invalid.version");
    packet
}

/// Creates a packet with a missing packet ID.
pub fn packet_with_missing_packet_id() -> Value {
    let mut packet = serde_json::to_value(simple_pass_packet()).unwrap();
    packet.as_object_mut().unwrap().remove("packet_id");
    packet
}

/// Creates a packet with an invalid digest format.
pub fn packet_with_invalid_digest_format() -> Value {
    let mut packet = serde_json::to_value(packet_with_attachments()).unwrap();
    if let Some(attachments) = packet["projections"]["attachments"].as_array_mut() {
        if let Some(attachment) = attachments.first_mut() {
            attachment["sha256"] = serde_json::json!("not-a-valid-digest");
        }
    }
    packet
}

// ============================================================================
// Legacy Fixture Functions (for backward compatibility)
// ============================================================================

/// Creates a perfgate packet fixture.
pub fn perfgate_packet() -> Packet {
    Packet {
        eb_version: SchemaVersion::new("0.1.0"),
        packet_id: PacketId::new("pkt-perfgate").unwrap(),
        producer: Producer::new("perfgate", "0.7.0").with_invocation_id("run-perfgate-001"),
        subject: Subject::new(
            VcsKind::Git,
            "EffortlessMetrics/example",
            "abc123",
            "def456",
        )
        .with_base("abc123")
        .with_path_scope("crates/example/src/lib.rs"),
        summary: Summary::new(
            PacketStatus::Pass,
            "Coverage gate passed",
            "Changed modules maintained coverage above the configured floor.",
        ),
        projections: Projections::new()
            .add_assertion(evidencebus_types::Assertion::new(
                "perfgate.coverage_floor",
                PacketStatus::Pass,
                Summary::new(
                    PacketStatus::Pass,
                    "Coverage floor",
                    "Coverage floor met for changed files.",
                ),
            ))
            .add_metric(
                Metric::new("coverage_percent", 91.2)
                    .with_unit("%")
                    .with_baseline(90.0),
            )
            .add_attachment(Attachment::new(
                AttachmentRole::ArbitraryBinary,
                "application/json",
                "report.json",
                Digest::new("0".repeat(64)).unwrap(),
            )),
        native_payloads: vec![],
        artifacts: vec![],
        links: None,
        labels: None,
        created_at: "2024-01-01T12:00:00Z".to_string(),
    }
}

/// Creates a faultline packet fixture.
pub fn faultline_packet() -> Packet {
    Packet {
        eb_version: SchemaVersion::new("0.1.0"),
        packet_id: PacketId::new("pkt-faultline").unwrap(),
        producer: Producer::new("faultline", "0.1.0").with_invocation_id("run-faultline-001"),
        subject: Subject::new(
            VcsKind::Git,
            "EffortlessMetrics/example",
            "good123",
            "bad456",
        )
        .with_base("good123")
        .with_path_scope("crates/parser/src/lib.rs"),
        summary: Summary::new(
            PacketStatus::Indeterminate,
            "Suspect window narrowed",
            "Skipped midpoint prevented exact first-bad localization.",
        ),
        projections: Projections::new()
            .add_assertion(evidencebus_types::Assertion::new(
                "faultline.localization",
                PacketStatus::Indeterminate,
                Summary::new(
                    PacketStatus::Indeterminate,
                    "Localization outcome",
                    "A suspect window of three commits remains.",
                ),
            ))
            .add_finding(
                evidencebus_types::Finding::new(
                    "faultline.suspect_window",
                    FindingSeverity::Warning,
                    "Suspect window remains",
                    "Read parser changes and workflow changes first.",
                )
                .with_location(Location::new("crates/parser/src/lib.rs")),
            )
            .add_metric(Metric::new("suspect_window_commits", 3.0).with_unit("count"))
            .add_attachment(
                Attachment::new(
                    AttachmentRole::ArbitraryBinary,
                    "application/json",
                    "faultline/analysis.json",
                    Digest::new("1".repeat(64)).unwrap(),
                )
                .with_schema_id("faultline.analysis@0.1"),
            )
            .add_attachment(Attachment::new(
                AttachmentRole::ReportHtml,
                "text/html",
                "faultline/index.html",
                Digest::new("2".repeat(64)).unwrap(),
            ))
            .add_attachment(Attachment::new(
                AttachmentRole::StderrLog,
                "text/plain",
                "logs/stderr.log",
                Digest::new("3".repeat(64)).unwrap(),
            )),
        native_payloads: vec![],
        artifacts: vec![],
        links: None,
        labels: None,
        created_at: "2024-01-01T12:00:00Z".to_string(),
    }
}

/// Creates a test bundle with both packets.
pub fn test_bundle() -> Bundle {
    let packet1 = perfgate_packet();
    let packet2 = faultline_packet();

    let mut packet_digests = HashMap::new();
    packet_digests.insert(
        packet1.packet_id.clone(),
        Digest::new("0".repeat(64)).unwrap(),
    );
    packet_digests.insert(
        packet2.packet_id.clone(),
        Digest::new("1".repeat(64)).unwrap(),
    );

    let mut artifact_digests = HashMap::new();
    artifact_digests.insert(
        "report.json".to_string(),
        Digest::new("0".repeat(64)).unwrap(),
    );
    artifact_digests.insert(
        "faultline/analysis.json".to_string(),
        Digest::new("1".repeat(64)).unwrap(),
    );
    artifact_digests.insert(
        "faultline/index.html".to_string(),
        Digest::new("2".repeat(64)).unwrap(),
    );
    artifact_digests.insert(
        "logs/stderr.log".to_string(),
        Digest::new("3".repeat(64)).unwrap(),
    );

    Bundle {
        eb_version: SchemaVersion::new("0.1.0"),
        bundle_id: PacketId::new("test-bundle").unwrap(),
        created_at: "2024-01-01T12:00:00Z".to_string(),
        manifest: BundleManifest::new(
            vec![
                PacketInventoryEntry::new(
                    packet1.packet_id.clone(),
                    "packets/pkt-perfgate/packet.eb.json",
                    Digest::new("0".repeat(64)).unwrap(),
                ),
                PacketInventoryEntry::new(
                    packet2.packet_id.clone(),
                    "packets/pkt-faultline/packet.eb.json",
                    Digest::new("1".repeat(64)).unwrap(),
                ),
            ],
            vec![
                ArtifactInventoryEntry::new(
                    packet1.packet_id.clone(),
                    "report.json",
                    AttachmentRole::ArbitraryBinary,
                    Digest::new("0".repeat(64)).unwrap(),
                ),
                ArtifactInventoryEntry::new(
                    packet2.packet_id.clone(),
                    "faultline/analysis.json",
                    AttachmentRole::ArbitraryBinary,
                    Digest::new("1".repeat(64)).unwrap(),
                ),
                ArtifactInventoryEntry::new(
                    packet2.packet_id.clone(),
                    "faultline/index.html",
                    AttachmentRole::ReportHtml,
                    Digest::new("2".repeat(64)).unwrap(),
                ),
                ArtifactInventoryEntry::new(
                    packet2.packet_id.clone(),
                    "logs/stderr.log",
                    AttachmentRole::StderrLog,
                    Digest::new("3".repeat(64)).unwrap(),
                ),
            ],
            IntegrityMetadata::new(
                Digest::new("4".repeat(64)).unwrap(),
                packet_digests,
                artifact_digests,
            ),
        ),
        summary: BundleSummary::new(
            2,
            4,
            StatusCounts {
                pass: 1,
                fail: 0,
                warn: 0,
                indeterminate: 1,
                error: 0,
            },
            SeverityCounts {
                note: 0,
                warning: 1,
                error: 0,
            },
        ),
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // ------------------------------------------------------------------------
    // Packet Builder Tests
    // ------------------------------------------------------------------------

    #[test]
    fn test_packet_builder_minimal() {
        let packet = PacketBuilder::new()
            .with_id("test-packet")
            .with_producer("test-tool", "1.0.0")
            .with_subject(VcsKind::Git, "test/repo", "abc123")
            .with_status(PacketStatus::Pass)
            .with_title("Test Title")
            .with_summary("Test Summary")
            .build()
            .unwrap();

        assert_eq!(packet.packet_id.as_str(), "test-packet");
        assert_eq!(packet.producer.tool_name, "test-tool");
        assert_eq!(packet.summary.status, PacketStatus::Pass);
        assert_eq!(packet.summary.title, "Test Title");
    }

    #[test]
    fn test_packet_builder_with_assertions() {
        let packet = PacketBuilder::new()
            .with_id("test-packet")
            .with_producer("test-tool", "1.0.0")
            .with_subject(VcsKind::Git, "test/repo", "abc123")
            .with_status(PacketStatus::Pass)
            .with_title("Test Title")
            .with_summary("Test Summary")
            .add_assertion("assert-1", PacketStatus::Pass, "Assertion 1")
            .add_assertion("assert-2", PacketStatus::Fail, "Assertion 2")
            .build()
            .unwrap();

        assert_eq!(packet.projections.assertions.len(), 2);
        assert_eq!(packet.projections.assertions[0].id, "assert-1");
        assert_eq!(packet.projections.assertions[1].id, "assert-2");
    }

    #[test]
    fn test_packet_builder_with_findings() {
        let packet = PacketBuilder::new()
            .with_id("test-packet")
            .with_producer("test-tool", "1.0.0")
            .with_subject(VcsKind::Git, "test/repo", "abc123")
            .with_status(PacketStatus::Pass)
            .with_title("Test Title")
            .with_summary("Test Summary")
            .add_finding("find-1", FindingSeverity::Warning, "Finding 1")
            .add_finding("find-2", FindingSeverity::Error, "Finding 2")
            .build()
            .unwrap();

        assert_eq!(packet.projections.findings.len(), 2);
        assert_eq!(packet.projections.findings[0].id, "find-1");
        assert_eq!(
            packet.projections.findings[0].severity,
            FindingSeverity::Warning
        );
    }

    #[test]
    fn test_packet_builder_with_metrics() {
        let packet = PacketBuilder::new()
            .with_id("test-packet")
            .with_producer("test-tool", "1.0.0")
            .with_subject(VcsKind::Git, "test/repo", "abc123")
            .with_status(PacketStatus::Pass)
            .with_title("Test Title")
            .with_summary("Test Summary")
            .add_metric("metric-1", 42.0, Some("count"))
            .add_metric("metric-2", 3.50, None)
            .build()
            .unwrap();

        assert_eq!(packet.projections.metrics.len(), 2);
        assert_eq!(packet.projections.metrics[0].name, "metric-1");
        assert_eq!(packet.projections.metrics[0].value, 42.0);
        assert_eq!(
            packet.projections.metrics[0].unit,
            Some("count".to_string())
        );
    }

    #[test]
    fn test_packet_builder_with_attachments() {
        let packet = PacketBuilder::new()
            .with_id("test-packet")
            .with_producer("test-tool", "1.0.0")
            .with_subject(VcsKind::Git, "test/repo", "abc123")
            .with_status(PacketStatus::Pass)
            .with_title("Test Title")
            .with_summary("Test Summary")
            .add_attachment(
                AttachmentRole::ArbitraryBinary,
                "data.json",
                "application/json",
            )
            .add_attachment(AttachmentRole::ReportHtml, "report.html", "text/html")
            .build()
            .unwrap();

        assert_eq!(packet.projections.attachments.len(), 2);
        assert_eq!(
            packet.projections.attachments[0].role,
            AttachmentRole::ArbitraryBinary
        );
        assert_eq!(
            packet.projections.attachments[1].role,
            AttachmentRole::ReportHtml
        );
    }

    #[test]
    fn test_packet_builder_missing_required_field() {
        let result = PacketBuilder::new()
            .with_id("test-packet")
            .with_producer("test-tool", "1.0.0")
            // Missing subject
            .with_status(PacketStatus::Pass)
            .with_title("Test Title")
            .with_summary("Test Summary")
            .build();

        assert!(matches!(result, Err(BuildError::MissingRequiredField(_))));
    }

    // ------------------------------------------------------------------------
    // Bundle Builder Tests
    // ------------------------------------------------------------------------

    #[test]
    fn test_bundle_builder() {
        let packet1 = simple_pass_packet();
        let packet2 = simple_fail_packet();

        let bundle = BundleBuilder::new()
            .with_id("test-bundle")
            .add_packet(packet1.clone())
            .add_packet(packet2)
            .build()
            .unwrap();

        assert_eq!(bundle.bundle_id.as_str(), "test-bundle");
        assert_eq!(bundle.summary.total_packets, 2);
        assert_eq!(bundle.manifest.packets.len(), 2);
    }

    #[test]
    fn test_bundle_builder_with_artifacts() {
        let packet = packet_with_attachments();

        let bundle = BundleBuilder::new()
            .with_id("test-bundle")
            .add_packet(packet)
            .add_artifact(
                "packet-attachments",
                "data.json",
                AttachmentRole::ArbitraryBinary,
            )
            .add_artifact(
                "packet-attachments",
                "report.html",
                AttachmentRole::ReportHtml,
            )
            .build()
            .unwrap();

        assert_eq!(bundle.summary.total_artifacts, 2);
        assert_eq!(bundle.manifest.artifacts.len(), 2);
    }

    #[test]
    fn test_bundle_builder_no_packets() {
        let result = BundleBuilder::new().with_id("test-bundle").build();
        assert!(matches!(result, Err(BuildError::MissingRequiredField(_))));
    }

    // ------------------------------------------------------------------------
    // Malformed Packet Tests
    // ------------------------------------------------------------------------

    #[test]
    fn test_malformed_packet_missing_required() {
        let packet = malformed_packet_missing_required();
        assert!(packet.get("subject").is_none());
        assert!(packet.get("summary").is_none());
    }

    #[test]
    fn test_malformed_packet_invalid_status() {
        let packet = malformed_packet_invalid_status();
        let status = packet["summary"]["status"].as_str().unwrap();
        assert_eq!(status, "invalid_status");
    }

    #[test]
    fn test_malformed_packet_invalid_digest() {
        let packet = malformed_packet_invalid_digest();
        let digest = packet["projections"]["attachments"][0]["sha256"]
            .as_str()
            .unwrap();
        assert_eq!(digest, "not-a-valid-digest");
    }

    #[test]
    fn test_malformed_packet_path_traversal() {
        let packet = malformed_packet_path_traversal();
        let path = packet["projections"]["attachments"][0]["relative_path"]
            .as_str()
            .unwrap();
        assert!(path.contains(".."));
    }

    #[test]
    fn test_malformed_packet_absolute_path() {
        let packet = malformed_packet_absolute_path();
        let path = packet["projections"]["attachments"][0]["relative_path"]
            .as_str()
            .unwrap();
        assert!(path.starts_with('/'));
    }

    #[test]
    fn test_malformed_packet_duplicate_id() {
        let packets = malformed_packet_duplicate_id();
        assert_eq!(packets.len(), 2);
        assert_eq!(packets[0]["packet_id"], packets[1]["packet_id"]);
    }

    // ------------------------------------------------------------------------
    // Golden Path Tests
    // ------------------------------------------------------------------------

    #[test]
    fn test_golden_path() {
        let path = golden_path("markdown/simple-packet.md");
        assert!(path.ends_with("fixtures/golden/markdown/simple-packet.md"));
    }

    #[test]
    fn test_snapshot_path() {
        let path = snapshot_path("sarif/simple-packet.sarif.json");
        assert!(path.ends_with("fixtures/snapshots/sarif/simple-packet.sarif.json"));
    }

    // ------------------------------------------------------------------------
    // Test Scenario Tests
    // ------------------------------------------------------------------------

    #[test]
    fn test_simple_pass_packet() {
        let packet = simple_pass_packet();
        assert_eq!(packet.packet_id.as_str(), "simple-pass");
        assert_eq!(packet.summary.status, PacketStatus::Pass);
    }

    #[test]
    fn test_simple_fail_packet() {
        let packet = simple_fail_packet();
        assert_eq!(packet.packet_id.as_str(), "simple-fail");
        assert_eq!(packet.summary.status, PacketStatus::Fail);
    }

    #[test]
    fn test_rich_packet_with_projections() {
        let packet = rich_packet_with_projections();
        assert_eq!(packet.packet_id.as_str(), "rich-packet");
        assert_eq!(packet.projections.assertions.len(), 2);
        assert_eq!(packet.projections.findings.len(), 2);
        assert_eq!(packet.projections.metrics.len(), 2);
        assert_eq!(packet.projections.attachments.len(), 2);
        assert_eq!(packet.native_payloads.len(), 1);
    }

    #[test]
    fn test_packet_with_attachments() {
        let packet = packet_with_attachments();
        assert_eq!(packet.packet_id.as_str(), "packet-attachments");
        assert_eq!(packet.projections.attachments.len(), 4);
    }

    #[test]
    fn test_packet_with_native_payload() {
        let packet = packet_with_native_payload();
        assert_eq!(packet.packet_id.as_str(), "packet-native-payload");
        assert_eq!(packet.native_payloads.len(), 1);
    }

    #[test]
    fn test_simple_bundle() {
        let bundle = simple_bundle();
        assert_eq!(bundle.bundle_id.as_str(), "simple-bundle");
        assert_eq!(bundle.summary.total_packets, 2);
    }

    #[test]
    fn test_bundle_with_artifacts() {
        let bundle = bundle_with_artifacts();
        assert_eq!(bundle.bundle_id.as_str(), "bundle-artifacts");
        assert_eq!(bundle.summary.total_artifacts, 4);
    }

    #[test]
    fn test_packet_with_invalid_schema_version() {
        let packet = packet_with_invalid_schema_version();
        assert_eq!(packet["eb_version"], "invalid.version");
    }

    #[test]
    fn test_packet_with_missing_packet_id() {
        let packet = packet_with_missing_packet_id();
        assert!(packet.get("packet_id").is_none());
    }

    #[test]
    fn test_packet_with_invalid_digest_format() {
        let packet = packet_with_invalid_digest_format();
        let digest = packet["projections"]["attachments"][0]["sha256"]
            .as_str()
            .unwrap();
        assert_eq!(digest, "not-a-valid-digest");
    }

    // ------------------------------------------------------------------------
    // Legacy Fixture Tests
    // ------------------------------------------------------------------------

    #[test]
    fn test_perfgate_packet() {
        let packet = perfgate_packet();
        assert_eq!(packet.packet_id.as_str(), "pkt-perfgate");
        assert_eq!(packet.producer.tool_name, "perfgate");
        assert_eq!(packet.summary.status, PacketStatus::Pass);
        assert_eq!(packet.projections.assertions.len(), 1);
        assert_eq!(packet.projections.metrics.len(), 1);
    }

    #[test]
    fn test_faultline_packet() {
        let packet = faultline_packet();
        assert_eq!(packet.packet_id.as_str(), "pkt-faultline");
        assert_eq!(packet.producer.tool_name, "faultline");
        assert_eq!(packet.summary.status, PacketStatus::Indeterminate);
        assert_eq!(packet.projections.assertions.len(), 1);
        assert_eq!(packet.projections.findings.len(), 1);
        assert_eq!(packet.projections.metrics.len(), 1);
        assert_eq!(packet.projections.attachments.len(), 3);
    }

    #[test]
    fn test_bundle_fixture() {
        let bundle = test_bundle();
        assert_eq!(bundle.bundle_id.as_str(), "test-bundle");
        assert_eq!(bundle.summary.total_packets, 2);
        assert_eq!(bundle.summary.total_artifacts, 4);
        assert_eq!(bundle.manifest.packets.len(), 2);
        assert_eq!(bundle.manifest.artifacts.len(), 4);
    }
}
