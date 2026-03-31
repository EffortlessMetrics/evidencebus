use std::collections::BTreeMap;

use evidencebus_codes::{IssueLevel, Severity, Status, ValidationCode, VcsKind};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use thiserror::Error;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Packet {
    pub eb_version: String,
    pub packet_id: String,
    pub producer: Producer,
    pub subject: Subject,
    pub summary: PacketSummary,
    pub projections: Projections,
    pub provenance: Provenance,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub labels: BTreeMap<String, String>,
}

impl Packet {
    pub fn canonicalized(&self) -> Self {
        let mut cloned = self.clone();
        cloned.canonicalize_in_place();
        cloned
    }

    pub fn canonicalize_in_place(&mut self) {
        self.subject.paths.sort();
        self.subject.paths.dedup();
        self.subject.workspace_scope.sort();
        self.subject.workspace_scope.dedup();
        self.projections.canonicalize_in_place();
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Producer {
    pub tool: String,
    pub version: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub invocation_id: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Subject {
    pub vcs: VcsKind,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub repo: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub base: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub head: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub paths: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub workspace_scope: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PacketSummary {
    pub status: Status,
    pub title: String,
    pub summary: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Projections {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub assertions: Vec<Assertion>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub findings: Vec<Finding>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub metrics: Vec<Metric>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub relations: Vec<Relation>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub attachments: Vec<AttachmentRef>,
}

impl Projections {
    pub fn canonicalize_in_place(&mut self) {
        self.assertions
            .sort_by(|left, right| left.id.cmp(&right.id).then(left.title.cmp(&right.title)));
        self.findings
            .sort_by(|left, right| left.id.cmp(&right.id).then(left.title.cmp(&right.title)));
        self.metrics.sort_by(|left, right| {
            left.name
                .cmp(&right.name)
                .then(left.unit.cmp(&right.unit))
                .then(left.value.to_string().cmp(&right.value.to_string()))
        });
        self.relations.sort_by(|left, right| {
            left.kind
                .cmp(&right.kind)
                .then(left.target.cmp(&right.target))
                .then(left.summary.cmp(&right.summary))
        });
        self.attachments.sort_by(|left, right| {
            left.role
                .cmp(&right.role)
                .then(left.relative_path.cmp(&right.relative_path))
                .then(left.schema_id.cmp(&right.schema_id))
        });
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Assertion {
    pub id: String,
    pub status: Status,
    pub title: String,
    pub summary: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Finding {
    pub id: String,
    pub severity: Severity,
    pub title: String,
    pub summary: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub location: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Metric {
    pub name: String,
    pub value: Value,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub unit: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub baseline: Option<Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Relation {
    pub kind: String,
    pub target: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub summary: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AttachmentRef {
    pub role: String,
    pub media_type: String,
    pub relative_path: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sha256: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub size_bytes: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub schema_id: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct Provenance {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub command: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub environment_fingerprint: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub platform: Option<PlatformInfo>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PlatformInfo {
    pub os: String,
    pub arch: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hostname: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BundleManifest {
    pub eb_version: String,
    pub bundle_id: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub packets: Vec<BundlePacketEntry>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub artifacts: Vec<BundleArtifactEntry>,
    pub summary: BundleSummary,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BundlePacketEntry {
    pub packet_id: String,
    pub tool: String,
    pub packet_path: String,
    pub sha256: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BundleArtifactEntry {
    pub packet_id: String,
    pub role: String,
    pub relative_path: String,
    pub sha256: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub size_bytes: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct BundleSummary {
    pub packet_count: usize,
    pub pass_count: usize,
    pub fail_count: usize,
    pub warn_count: usize,
    pub indeterminate_count: usize,
    pub error_count: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ValidationIssue {
    pub level: IssueLevel,
    pub code: ValidationCode,
    pub message: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub location: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct ValidationReport {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub issues: Vec<ValidationIssue>,
}

impl ValidationReport {
    pub fn push(&mut self, issue: ValidationIssue) {
        self.issues.push(issue);
    }

    pub fn push_error(
        &mut self,
        code: ValidationCode,
        message: impl Into<String>,
        location: impl Into<Option<String>>,
    ) {
        self.issues.push(ValidationIssue {
            level: IssueLevel::Error,
            code,
            message: message.into(),
            location: location.into(),
        });
    }

    pub fn push_warning(
        &mut self,
        code: ValidationCode,
        message: impl Into<String>,
        location: impl Into<Option<String>>,
    ) {
        self.issues.push(ValidationIssue {
            level: IssueLevel::Warning,
            code,
            message: message.into(),
            location: location.into(),
        });
    }

    pub fn merge(&mut self, other: Self) {
        self.issues.extend(other.issues);
    }

    pub fn is_valid(&self) -> bool {
        self.issues.iter().all(|issue| issue.level != IssueLevel::Error)
    }

    pub fn error_count(&self) -> usize {
        self.issues
            .iter()
            .filter(|issue| issue.level == IssueLevel::Error)
            .count()
    }
}

#[derive(Debug, Error)]
pub enum TypesError {
    #[error("schema version mismatch: expected {expected}, found {found}")]
    SchemaVersionMismatch { expected: String, found: String },
}
