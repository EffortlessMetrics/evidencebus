use serde::{Deserialize, Serialize};

pub const EVIDENCEBUS_VERSION: &str = "0.1.0";

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Status {
    Pass,
    Fail,
    Warn,
    Indeterminate,
    Error,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Severity {
    Note,
    Warning,
    Error,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IssueLevel {
    Warning,
    Error,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ValidationMode {
    SchemaOnly,
    Strict,
}

impl Default for ValidationMode {
    fn default() -> Self {
        Self::Strict
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ValidationCode {
    InvalidSchemaVersion,
    MissingField,
    InvalidEnum,
    InvalidDigest,
    InvalidPath,
    UnsafePath,
    DuplicateAttachmentPath,
    MissingNativePayloadSchema,
    MissingArtifact,
    DigestMismatch,
    DuplicatePacketId,
    PacketConflict,
    InvalidBundleManifest,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VcsKind {
    Git,
    Other,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(i32)]
pub enum ExitCode {
    Success = 0,
    ValidationFailed = 2,
    Conflict = 3,
    Io = 4,
    InvalidInput = 5,
    ExportFailed = 6,
    Internal = 70,
}

impl ExitCode {
    pub const fn code(self) -> i32 {
        self as i32
    }
}
