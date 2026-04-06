//! Core types for evidencebus packets and bundles.
//!
//! This crate provides the foundational data structures for representing evidence packets,
//! bundles, attachments, and related metadata.

use evidencebus_codes::{FindingSeverity, PacketStatus};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fmt;

/// A wrapper around a String representing a packet ID with validation.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct PacketId(String);

impl PacketId {
    /// Creates a new PacketId, validating the input.
    ///
    /// # Errors
    /// Returns an error if the ID is empty, contains only whitespace,
    /// or contains path traversal characters.
    pub fn new(id: impl Into<String>) -> Result<Self, PacketIdError> {
        let id = id.into();

        if id.trim().is_empty() {
            return Err(PacketIdError::Empty);
        }

        if id.contains("..") || id.contains('\\') || id.starts_with('/') {
            return Err(PacketIdError::InvalidChars);
        }

        Ok(PacketId(id))
    }

    /// Returns the underlying string value.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Consumes the PacketId and returns the underlying string.
    pub fn into_inner(self) -> String {
        self.0
    }
}

impl fmt::Display for PacketId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl AsRef<str> for PacketId {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

/// Error type for PacketId validation.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum PacketIdError {
    #[error("packet ID cannot be empty")]
    Empty,
    #[error("packet ID contains invalid characters")]
    InvalidChars,
}

/// A version string for the schema (e.g., "0.1.0").
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct SchemaVersion(String);

impl SchemaVersion {
    /// Creates a new SchemaVersion.
    pub fn new(version: impl Into<String>) -> Self {
        SchemaVersion(version.into())
    }

    /// Returns the underlying string value.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for SchemaVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl AsRef<str> for SchemaVersion {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

/// A SHA-256 hex digest string wrapper.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Digest(String);

impl Digest {
    /// Creates a new Digest, validating that it's a valid SHA-256 hex string.
    ///
    /// # Errors
    /// Returns an error if the digest is not a valid 64-character hex string.
    pub fn new(digest: impl Into<String>) -> Result<Self, DigestError> {
        let digest = digest.into();

        if digest.len() != 64 {
            return Err(DigestError::InvalidLength);
        }

        if !digest.chars().all(|c| c.is_ascii_hexdigit()) {
            return Err(DigestError::InvalidHex);
        }

        Ok(Digest(digest))
    }

    /// Returns the underlying string value.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for Digest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl AsRef<str> for Digest {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

/// Error type for Digest validation.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum DigestError {
    #[error("digest must be exactly 64 characters")]
    InvalidLength,
    #[error("digest contains invalid hex characters")]
    InvalidHex,
}

/// Producer metadata describing the tool that created the packet.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Producer {
    /// The name of the tool.
    pub tool_name: String,
    /// The version of the tool.
    pub tool_version: String,
    /// An optional invocation identifier.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub invocation_id: Option<String>,
}

impl Producer {
    /// Creates a new Producer.
    pub fn new(tool_name: impl Into<String>, tool_version: impl Into<String>) -> Self {
        Self {
            tool_name: tool_name.into(),
            tool_version: tool_version.into(),
            invocation_id: None,
        }
    }

    /// Sets the invocation ID.
    pub fn with_invocation_id(mut self, id: impl Into<String>) -> Self {
        self.invocation_id = Some(id.into());
        self
    }
}

/// VCS kind for subject metadata.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum VcsKind {
    Git,
    /// Placeholder for future VCS types.
    #[serde(other)]
    Other,
}

/// Subject metadata describing what the packet is about.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Subject {
    /// The version control system kind.
    pub vcs_kind: VcsKind,
    /// The repository identifier (e.g., owner/repo).
    pub repo_identifier: String,
    /// The commit hash.
    pub commit: String,
    /// The base commit (optional, for comparison).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub base: Option<String>,
    /// The head commit or branch.
    pub head: String,
    /// Optional path scope for the subject.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub path_scope: Option<String>,
    /// Optional workspace scope for the subject.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub workspace_scope: Option<String>,
}

impl Subject {
    /// Creates a new Subject.
    pub fn new(
        vcs_kind: VcsKind,
        repo_identifier: impl Into<String>,
        commit: impl Into<String>,
        head: impl Into<String>,
    ) -> Self {
        Self {
            vcs_kind,
            repo_identifier: repo_identifier.into(),
            commit: commit.into(),
            base: None,
            head: head.into(),
            path_scope: None,
            workspace_scope: None,
        }
    }

    /// Sets the base commit.
    pub fn with_base(mut self, base: impl Into<String>) -> Self {
        self.base = Some(base.into());
        self
    }

    /// Sets the path scope.
    pub fn with_path_scope(mut self, scope: impl Into<String>) -> Self {
        self.path_scope = Some(scope.into());
        self
    }

    /// Sets the workspace scope.
    pub fn with_workspace_scope(mut self, scope: impl Into<String>) -> Self {
        self.workspace_scope = Some(scope.into());
        self
    }
}

/// A summary of the packet's outcome.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Summary {
    /// The overall status.
    pub status: PacketStatus,
    /// A short title.
    pub title: String,
    /// A brief summary description.
    pub short_summary: String,
}

impl Summary {
    /// Creates a new Summary.
    pub fn new(
        status: PacketStatus,
        title: impl Into<String>,
        short_summary: impl Into<String>,
    ) -> Self {
        Self {
            status,
            title: title.into(),
            short_summary: short_summary.into(),
        }
    }
}

/// An assertion projection.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Assertion {
    /// The assertion ID.
    pub id: String,
    /// The assertion status.
    pub status: PacketStatus,
    /// The assertion summary.
    pub summary: Summary,
    /// Optional details.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub details: Option<String>,
}

impl Assertion {
    /// Creates a new Assertion.
    pub fn new(id: impl Into<String>, status: PacketStatus, summary: Summary) -> Self {
        Self {
            id: id.into(),
            status,
            summary,
            details: None,
        }
    }

    /// Sets the details.
    pub fn with_details(mut self, details: impl Into<String>) -> Self {
        self.details = Some(details.into());
        self
    }
}

/// A location reference for a finding.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Location {
    /// The file path.
    pub path: String,
    /// The line number (1-indexed).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub line: Option<u32>,
    /// The column number (1-indexed).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub column: Option<u32>,
}

impl Location {
    /// Creates a new Location.
    pub fn new(path: impl Into<String>) -> Self {
        Self {
            path: path.into(),
            line: None,
            column: None,
        }
    }

    /// Sets the line number.
    pub fn with_line(mut self, line: u32) -> Self {
        self.line = Some(line);
        self
    }

    /// Sets the column number.
    pub fn with_column(mut self, column: u32) -> Self {
        self.column = Some(column);
        self
    }
}

/// A finding projection.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Finding {
    /// The finding ID.
    pub id: String,
    /// The finding severity.
    pub severity: FindingSeverity,
    /// The finding title.
    pub title: String,
    /// The finding message.
    pub message: String,
    /// Optional location.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub location: Option<Location>,
}

impl Finding {
    /// Creates a new Finding.
    pub fn new(
        id: impl Into<String>,
        severity: FindingSeverity,
        title: impl Into<String>,
        message: impl Into<String>,
    ) -> Self {
        Self {
            id: id.into(),
            severity,
            title: title.into(),
            message: message.into(),
            location: None,
        }
    }

    /// Sets the location.
    pub fn with_location(mut self, location: Location) -> Self {
        self.location = Some(location);
        self
    }
}

/// A metric projection.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Metric {
    /// The metric name.
    pub name: String,
    /// The metric value.
    pub value: f64,
    /// Optional unit.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub unit: Option<String>,
    /// Optional baseline value.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub baseline: Option<f64>,
}

impl Metric {
    /// Creates a new Metric.
    pub fn new(name: impl Into<String>, value: f64) -> Self {
        Self {
            name: name.into(),
            value,
            unit: None,
            baseline: None,
        }
    }

    /// Sets the unit.
    pub fn with_unit(mut self, unit: impl Into<String>) -> Self {
        self.unit = Some(unit.into());
        self
    }

    /// Sets the baseline.
    pub fn with_baseline(mut self, baseline: f64) -> Self {
        self.baseline = Some(baseline);
        self
    }
}

/// Relation kind for packet relations.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RelationKind {
    /// This packet is derived from the target.
    DerivedFrom,
    /// This packet supports the target.
    Supports,
    /// This packet supersedes the target.
    Supersedes,
}

/// A relation projection linking this packet to another.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Relation {
    /// The relation kind.
    pub kind: RelationKind,
    /// The target packet ID.
    pub target_packet_id: PacketId,
    /// Optional details.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub details: Option<String>,
}

impl Relation {
    /// Creates a new Relation.
    pub fn new(kind: RelationKind, target_packet_id: PacketId) -> Self {
        Self {
            kind,
            target_packet_id,
            details: None,
        }
    }

    /// Sets the details.
    pub fn with_details(mut self, details: impl Into<String>) -> Self {
        self.details = Some(details.into());
        self
    }
}

/// Attachment role describing the purpose of an attachment.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AttachmentRole {
    /// The native payload of the packet.
    NativePayload,
    /// An HTML report.
    ReportHtml,
    /// Standard output log.
    StdoutLog,
    /// Standard error log.
    StderrLog,
    /// Plain text content.
    PlainText,
    /// Arbitrary binary data.
    ArbitraryBinary,
}

/// An attachment reference.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Attachment {
    /// The attachment role.
    pub role: AttachmentRole,
    /// The media type (MIME type).
    pub media_type: String,
    /// The relative path to the attachment.
    pub relative_path: String,
    /// The SHA-256 digest of the attachment.
    pub sha256: Digest,
    /// Optional size in bytes.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub size: Option<u64>,
    /// Optional schema ID for structured attachments.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub schema_id: Option<String>,
}

impl Attachment {
    /// Creates a new Attachment.
    pub fn new(
        role: AttachmentRole,
        media_type: impl Into<String>,
        relative_path: impl Into<String>,
        sha256: Digest,
    ) -> Self {
        Self {
            role,
            media_type: media_type.into(),
            relative_path: relative_path.into(),
            sha256,
            size: None,
            schema_id: None,
        }
    }

    /// Sets the size.
    pub fn with_size(mut self, size: u64) -> Self {
        self.size = Some(size);
        self
    }

    /// Sets the schema ID.
    pub fn with_schema_id(mut self, schema_id: impl Into<String>) -> Self {
        self.schema_id = Some(schema_id.into());
        self
    }
}

/// Platform information for provenance.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PlatformInfo {
    /// The operating system.
    pub os: String,
    /// The architecture.
    pub arch: String,
}

impl PlatformInfo {
    /// Creates a new PlatformInfo.
    pub fn new(os: impl Into<String>, arch: impl Into<String>) -> Self {
        Self {
            os: os.into(),
            arch: arch.into(),
        }
    }
}

/// Provenance metadata for the packet.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Provenance {
    /// The command that was run.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub command: Option<String>,
    /// Environment fingerprint (hash of relevant env vars).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub environment_fingerprint: Option<String>,
    /// Platform information.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub platform_info: Option<PlatformInfo>,
}

impl Default for Provenance {
    fn default() -> Self {
        Self::new()
    }
}

impl Provenance {
    /// Creates a new Provenance.
    pub fn new() -> Self {
        Self {
            command: None,
            environment_fingerprint: None,
            platform_info: None,
        }
    }

    /// Sets the command.
    pub fn with_command(mut self, command: impl Into<String>) -> Self {
        self.command = Some(command.into());
        self
    }

    /// Sets the environment fingerprint.
    pub fn with_environment_fingerprint(mut self, fingerprint: impl Into<String>) -> Self {
        self.environment_fingerprint = Some(fingerprint.into());
        self
    }

    /// Sets the platform info.
    pub fn with_platform_info(mut self, platform_info: PlatformInfo) -> Self {
        self.platform_info = Some(platform_info);
        self
    }
}

/// All projections for a packet.
#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize)]
pub struct Projections {
    /// Assertions.
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub assertions: Vec<Assertion>,
    /// Findings.
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub findings: Vec<Finding>,
    /// Metrics.
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub metrics: Vec<Metric>,
    /// Relations.
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub relations: Vec<Relation>,
    /// Attachments.
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub attachments: Vec<Attachment>,
}

impl Projections {
    /// Creates a new Projections.
    pub fn new() -> Self {
        Self::default()
    }

    /// Adds an assertion.
    pub fn add_assertion(mut self, assertion: Assertion) -> Self {
        self.assertions.push(assertion);
        self
    }

    /// Adds a finding.
    pub fn add_finding(mut self, finding: Finding) -> Self {
        self.findings.push(finding);
        self
    }

    /// Adds a metric.
    pub fn add_metric(mut self, metric: Metric) -> Self {
        self.metrics.push(metric);
        self
    }

    /// Adds a relation.
    pub fn add_relation(mut self, relation: Relation) -> Self {
        self.relations.push(relation);
        self
    }

    /// Adds an attachment.
    pub fn add_attachment(mut self, attachment: Attachment) -> Self {
        self.attachments.push(attachment);
        self
    }
}

/// An evidence packet.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Packet {
    /// The evidencebus schema version.
    pub eb_version: SchemaVersion,
    /// The unique packet ID.
    pub packet_id: PacketId,
    /// Producer metadata.
    pub producer: Producer,
    /// Subject metadata.
    pub subject: Subject,
    /// Summary.
    pub summary: Summary,
    /// Projections.
    pub projections: Projections,
    /// Native payload attachments (paths to native payload files).
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub native_payloads: Vec<String>,
    /// Artifact attachments (paths to artifact files).
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub artifacts: Vec<String>,
    /// Optional external links.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub links: Option<HashMap<String, String>>,
    /// Optional labels.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub labels: Option<HashMap<String, String>>,
    /// Creation timestamp (ISO 8601).
    pub created_at: String,
}

impl Packet {
    /// Creates a new Packet.
    pub fn new(
        eb_version: SchemaVersion,
        packet_id: PacketId,
        producer: Producer,
        subject: Subject,
        summary: Summary,
    ) -> Self {
        Self {
            eb_version,
            packet_id,
            producer,
            subject,
            summary,
            projections: Projections::default(),
            native_payloads: Vec::new(),
            artifacts: Vec::new(),
            links: None,
            labels: None,
            created_at: chrono::Utc::now().to_rfc3339(),
        }
    }

    /// Sets the projections.
    pub fn with_projections(mut self, projections: Projections) -> Self {
        self.projections = projections;
        self
    }

    /// Adds a native payload.
    pub fn add_native_payload(mut self, path: impl Into<String>) -> Self {
        self.native_payloads.push(path.into());
        self
    }

    /// Adds an artifact.
    pub fn add_artifact(mut self, path: impl Into<String>) -> Self {
        self.artifacts.push(path.into());
        self
    }

    /// Sets the links.
    pub fn with_links(mut self, links: HashMap<String, String>) -> Self {
        self.links = Some(links);
        self
    }

    /// Sets the labels.
    pub fn with_labels(mut self, labels: HashMap<String, String>) -> Self {
        self.labels = Some(labels);
        self
    }

    /// Sets the creation timestamp.
    pub fn with_created_at(mut self, created_at: impl Into<String>) -> Self {
        self.created_at = created_at.into();
        self
    }
}

/// A packet inventory entry in the bundle manifest.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PacketInventoryEntry {
    /// The packet ID.
    pub packet_id: PacketId,
    /// The relative path to the packet file.
    pub relative_path: String,
    /// The SHA-256 digest of the packet.
    pub sha256: Digest,
}

impl PacketInventoryEntry {
    /// Creates a new PacketInventoryEntry.
    pub fn new(packet_id: PacketId, relative_path: impl Into<String>, sha256: Digest) -> Self {
        Self {
            packet_id,
            relative_path: relative_path.into(),
            sha256,
        }
    }
}

/// An artifact inventory entry in the bundle manifest.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ArtifactInventoryEntry {
    /// The packet ID this artifact belongs to.
    pub packet_id: PacketId,
    /// The relative path to the artifact file.
    pub relative_path: String,
    /// The role of this artifact.
    pub role: AttachmentRole,
    /// The SHA-256 digest of the artifact.
    pub sha256: Digest,
}

impl ArtifactInventoryEntry {
    /// Creates a new ArtifactInventoryEntry.
    pub fn new(
        packet_id: PacketId,
        relative_path: impl Into<String>,
        role: AttachmentRole,
        sha256: Digest,
    ) -> Self {
        Self {
            packet_id,
            relative_path: relative_path.into(),
            role,
            sha256,
        }
    }
}

/// Integrity metadata for the bundle.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IntegrityMetadata {
    /// The digest of the manifest itself.
    pub manifest_digest: Digest,
    /// Digests of all packets (packet_id -> digest).
    pub packet_digests: HashMap<PacketId, Digest>,
    /// Digests of all artifacts (relative_path -> digest).
    pub artifact_digests: HashMap<String, Digest>,
}

impl IntegrityMetadata {
    /// Creates a new IntegrityMetadata.
    pub fn new(
        manifest_digest: Digest,
        packet_digests: HashMap<PacketId, Digest>,
        artifact_digests: HashMap<String, Digest>,
    ) -> Self {
        Self {
            manifest_digest,
            packet_digests,
            artifact_digests,
        }
    }
}

/// The bundle manifest.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BundleManifest {
    /// All packets in the bundle.
    pub packets: Vec<PacketInventoryEntry>,
    /// All artifacts in the bundle.
    pub artifacts: Vec<ArtifactInventoryEntry>,
    /// Integrity metadata.
    pub integrity: IntegrityMetadata,
}

impl BundleManifest {
    /// Creates a new BundleManifest.
    pub fn new(
        packets: Vec<PacketInventoryEntry>,
        artifacts: Vec<ArtifactInventoryEntry>,
        integrity: IntegrityMetadata,
    ) -> Self {
        Self {
            packets,
            artifacts,
            integrity,
        }
    }
}

/// Status counts for the bundle summary.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct StatusCounts {
    /// Number of passing packets.
    pub pass: u32,
    /// Number of failing packets.
    pub fail: u32,
    /// Number of warning packets.
    pub warn: u32,
    /// Number of indeterminate packets.
    pub indeterminate: u32,
    /// Number of error packets.
    pub error: u32,
}

impl StatusCounts {
    /// Creates a new StatusCounts.
    pub fn new() -> Self {
        Self::default()
    }

    /// Increments the count for a status.
    pub fn increment(&mut self, status: PacketStatus) {
        match status {
            PacketStatus::Pass => self.pass += 1,
            PacketStatus::Fail => self.fail += 1,
            PacketStatus::Warn => self.warn += 1,
            PacketStatus::Indeterminate => self.indeterminate += 1,
            PacketStatus::Error => self.error += 1,
        }
    }

    /// Returns the total count.
    pub fn total(&self) -> u32 {
        self.pass + self.fail + self.warn + self.indeterminate + self.error
    }
}

/// Severity counts for the bundle summary.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct SeverityCounts {
    /// Number of note findings.
    pub note: u32,
    /// Number of warning findings.
    pub warning: u32,
    /// Number of error findings.
    pub error: u32,
}

impl SeverityCounts {
    /// Creates a new SeverityCounts.
    pub fn new() -> Self {
        Self::default()
    }

    /// Increments the count for a severity.
    pub fn increment(&mut self, severity: FindingSeverity) {
        match severity {
            FindingSeverity::Note => self.note += 1,
            FindingSeverity::Warning => self.warning += 1,
            FindingSeverity::Error => self.error += 1,
        }
    }

    /// Returns the total count.
    pub fn total(&self) -> u32 {
        self.note + self.warning + self.error
    }
}

/// The bundle summary.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BundleSummary {
    /// Total number of packets.
    pub total_packets: u32,
    /// Total number of artifacts.
    pub total_artifacts: u32,
    /// Status counts.
    pub status_counts: StatusCounts,
    /// Severity counts.
    pub severity_counts: SeverityCounts,
}

impl BundleSummary {
    /// Creates a new BundleSummary.
    pub fn new(
        total_packets: u32,
        total_artifacts: u32,
        status_counts: StatusCounts,
        severity_counts: SeverityCounts,
    ) -> Self {
        Self {
            total_packets,
            total_artifacts,
            status_counts,
            severity_counts,
        }
    }
}

/// An evidence bundle.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Bundle {
    /// The evidencebus schema version.
    pub eb_version: SchemaVersion,
    /// The unique bundle ID.
    pub bundle_id: PacketId,
    /// Creation timestamp (ISO 8601).
    pub created_at: String,
    /// The bundle manifest.
    pub manifest: BundleManifest,
    /// The bundle summary.
    pub summary: BundleSummary,
}

impl Bundle {
    /// Creates a new Bundle.
    pub fn new(
        eb_version: SchemaVersion,
        bundle_id: PacketId,
        created_at: impl Into<String>,
        manifest: BundleManifest,
        summary: BundleSummary,
    ) -> Self {
        Self {
            eb_version,
            bundle_id,
            created_at: created_at.into(),
            manifest,
            summary,
        }
    }

    /// Creates a new Bundle with the current timestamp.
    pub fn with_current_timestamp(
        eb_version: SchemaVersion,
        bundle_id: PacketId,
        manifest: BundleManifest,
        summary: BundleSummary,
    ) -> Self {
        Self::new(
            eb_version,
            bundle_id,
            chrono::Utc::now().to_rfc3339(),
            manifest,
            summary,
        )
    }
}

/// An artifact reference for bundle building.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Artifact {
    /// The packet ID this artifact belongs to.
    pub packet_id: PacketId,
    /// The relative path to the artifact.
    pub relative_path: String,
    /// The role of this artifact.
    pub role: AttachmentRole,
    /// The artifact data.
    pub data: Vec<u8>,
}

impl Artifact {
    /// Creates a new Artifact.
    pub fn new(
        packet_id: PacketId,
        relative_path: impl Into<String>,
        role: AttachmentRole,
        data: Vec<u8>,
    ) -> Self {
        Self {
            packet_id,
            relative_path: relative_path.into(),
            role,
            data,
        }
    }
}

/// A conflict detected between packets.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Conflict {
    /// The packet ID with the conflict.
    pub packet_id: PacketId,
    /// The first digest encountered.
    pub first_digest: Digest,
    /// The conflicting digest.
    pub conflicting_digest: Digest,
}

impl Conflict {
    /// Creates a new Conflict.
    pub fn new(packet_id: PacketId, first_digest: Digest, conflicting_digest: Digest) -> Self {
        Self {
            packet_id,
            first_digest,
            conflicting_digest,
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn test_packet_id_valid() {
        let id = PacketId::new("valid-packet-id").unwrap();
        assert_eq!(id.as_str(), "valid-packet-id");
    }

    #[test]
    fn test_packet_id_empty() {
        let result = PacketId::new("");
        assert!(matches!(result, Err(PacketIdError::Empty)));
    }

    #[test]
    fn test_packet_id_whitespace() {
        let result = PacketId::new("   ");
        assert!(matches!(result, Err(PacketIdError::Empty)));
    }

    #[test]
    fn test_packet_id_path_traversal() {
        let result = PacketId::new("../etc/passwd");
        assert!(matches!(result, Err(PacketIdError::InvalidChars)));
    }

    #[test]
    fn test_packet_id_backslash() {
        let result = PacketId::new("path\\to\\file");
        assert!(matches!(result, Err(PacketIdError::InvalidChars)));
    }

    #[test]
    fn test_packet_id_leading_slash() {
        let result = PacketId::new("/absolute/path");
        assert!(matches!(result, Err(PacketIdError::InvalidChars)));
    }

    #[test]
    fn test_digest_valid() {
        let hex = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        let digest = Digest::new(hex).unwrap();
        assert_eq!(digest.as_str(), hex);
    }

    #[test]
    fn test_digest_invalid_length() {
        let result = Digest::new("short");
        assert!(matches!(result, Err(DigestError::InvalidLength)));
    }

    #[test]
    fn test_digest_invalid_hex() {
        let hex = "gggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggg";
        let result = Digest::new(hex);
        assert!(matches!(result, Err(DigestError::InvalidHex)));
    }

    #[test]
    fn test_producer_builder() {
        let producer = Producer::new("test-tool", "1.0.0").with_invocation_id("inv-123");
        assert_eq!(producer.tool_name, "test-tool");
        assert_eq!(producer.tool_version, "1.0.0");
        assert_eq!(producer.invocation_id, Some("inv-123".to_string()));
    }

    #[test]
    fn test_subject_builder() {
        let subject = Subject::new(VcsKind::Git, "owner/repo", "abc123", "main")
            .with_base("def456")
            .with_path_scope("src/")
            .with_workspace_scope("workspace/");
        assert_eq!(subject.vcs_kind, VcsKind::Git);
        assert_eq!(subject.base, Some("def456".to_string()));
        assert_eq!(subject.path_scope, Some("src/".to_string()));
    }

    #[test]
    fn test_projections_builder() {
        let projection = Projections::new()
            .add_assertion(Assertion::new(
                "assert-1",
                PacketStatus::Pass,
                Summary::new(PacketStatus::Pass, "Test", "Test summary"),
            ))
            .add_finding(Finding::new(
                "find-1",
                FindingSeverity::Warning,
                "Warning",
                "Warning message",
            ));
        assert_eq!(projection.assertions.len(), 1);
        assert_eq!(projection.findings.len(), 1);
    }

    #[test]
    fn test_status_counts() {
        let mut counts = StatusCounts::new();
        counts.increment(PacketStatus::Pass);
        counts.increment(PacketStatus::Pass);
        counts.increment(PacketStatus::Fail);
        assert_eq!(counts.pass, 2);
        assert_eq!(counts.fail, 1);
        assert_eq!(counts.total(), 3);
    }

    #[test]
    fn test_severity_counts() {
        let mut counts = SeverityCounts::new();
        counts.increment(FindingSeverity::Note);
        counts.increment(FindingSeverity::Warning);
        counts.increment(FindingSeverity::Error);
        counts.increment(FindingSeverity::Error);
        assert_eq!(counts.note, 1);
        assert_eq!(counts.warning, 1);
        assert_eq!(counts.error, 2);
        assert_eq!(counts.total(), 4);
    }

    #[test]
    fn test_packet_serialization() {
        let packet = create_test_packet();
        let json = serde_json::to_string_pretty(&packet).unwrap();
        let deserialized: Packet = serde_json::from_str(&json).unwrap();
        assert_eq!(packet, deserialized);
    }

    #[test]
    fn test_bundle_serialization() {
        let bundle = create_test_bundle();
        let json = serde_json::to_string_pretty(&bundle).unwrap();
        let deserialized: Bundle = serde_json::from_str(&json).unwrap();
        assert_eq!(bundle, deserialized);
    }

    fn create_test_packet() -> Packet {
        Packet::new(
            SchemaVersion::new("0.1.0"),
            PacketId::new("test-packet").unwrap(),
            Producer::new("test-tool", "1.0.0"),
            Subject::new(VcsKind::Git, "owner/repo", "abc123", "main"),
            Summary::new(PacketStatus::Pass, "Test", "Test summary"),
        )
    }

    fn create_test_bundle() -> Bundle {
        Bundle::new(
            SchemaVersion::new("0.1.0"),
            PacketId::new("test-bundle").unwrap(),
            "2024-01-01T00:00:00Z",
            BundleManifest::new(
                vec![],
                vec![],
                IntegrityMetadata::new(
                    Digest::new("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
                        .unwrap(),
                    HashMap::new(),
                    HashMap::new(),
                ),
            ),
            BundleSummary::new(0, 0, StatusCounts::new(), SeverityCounts::new()),
        )
    }
}
