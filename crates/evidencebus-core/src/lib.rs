use std::collections::HashSet;
use std::path::{Component, Path};

use evidencebus_codes::{Status, ValidationCode, ValidationMode, EVIDENCEBUS_VERSION};
use evidencebus_types::{
    AttachmentRef, BundleManifest, BundleSummary, Packet, ValidationReport,
};
use sha2::{Digest, Sha256};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum CoreError {
    #[error("json serialization failed: {0}")]
    Serialize(#[from] serde_json::Error),
}

pub fn validate_packet(packet: &Packet, _mode: ValidationMode) -> ValidationReport {
    let mut report = ValidationReport::default();

    if packet.eb_version != EVIDENCEBUS_VERSION {
        report.push_error(
            ValidationCode::InvalidSchemaVersion,
            format!(
                "expected eb_version {}, found {}",
                EVIDENCEBUS_VERSION, packet.eb_version
            ),
            Some("eb_version".to_string()),
        );
    }

    if packet.packet_id.trim().is_empty() {
        report.push_error(
            ValidationCode::MissingField,
            "packet_id must not be empty",
            Some("packet_id".to_string()),
        );
    }

    if packet.producer.tool.trim().is_empty() {
        report.push_error(
            ValidationCode::MissingField,
            "producer.tool must not be empty",
            Some("producer.tool".to_string()),
        );
    }

    if packet.producer.version.trim().is_empty() {
        report.push_error(
            ValidationCode::MissingField,
            "producer.version must not be empty",
            Some("producer.version".to_string()),
        );
    }

    if packet.summary.title.trim().is_empty() {
        report.push_error(
            ValidationCode::MissingField,
            "summary.title must not be empty",
            Some("summary.title".to_string()),
        );
    }

    if packet.summary.summary.trim().is_empty() {
        report.push_error(
            ValidationCode::MissingField,
            "summary.summary must not be empty",
            Some("summary.summary".to_string()),
        );
    }

    let mut seen_paths = HashSet::new();
    for attachment in &packet.projections.attachments {
        validate_attachment(attachment, &mut report);
        if !seen_paths.insert(attachment.relative_path.clone()) {
            report.push_error(
                ValidationCode::DuplicateAttachmentPath,
                format!("duplicate attachment path {}", attachment.relative_path),
                Some(format!("projections.attachments[{}]", attachment.relative_path)),
            );
        }
    }

    report
}

fn validate_attachment(attachment: &AttachmentRef, report: &mut ValidationReport) {
    if attachment.role.trim().is_empty() {
        report.push_error(
            ValidationCode::MissingField,
            "attachment role must not be empty",
            Some(format!("attachment:{}", attachment.relative_path)),
        );
    }

    if attachment.media_type.trim().is_empty() {
        report.push_error(
            ValidationCode::MissingField,
            "attachment media_type must not be empty",
            Some(format!("attachment:{}", attachment.relative_path)),
        );
    }

    if !is_safe_relative_path(&attachment.relative_path) {
        report.push_error(
            ValidationCode::UnsafePath,
            format!("attachment path is unsafe: {}", attachment.relative_path),
            Some(format!("attachment:{}", attachment.relative_path)),
        );
    }

    if attachment.role == "native_payload" && attachment.schema_id.is_none() {
        report.push_error(
            ValidationCode::MissingNativePayloadSchema,
            "native_payload attachments require schema_id",
            Some(format!("attachment:{}", attachment.relative_path)),
        );
    }

    if let Some(digest) = &attachment.sha256 {
        if !is_sha256_hex(digest) {
            report.push_error(
                ValidationCode::InvalidDigest,
                format!("invalid sha256 digest: {}", digest),
                Some(format!("attachment:{}", attachment.relative_path)),
            );
        }
    }
}

pub fn validate_bundle_manifest(bundle: &BundleManifest) -> ValidationReport {
    let mut report = ValidationReport::default();

    if bundle.eb_version != EVIDENCEBUS_VERSION {
        report.push_error(
            ValidationCode::InvalidSchemaVersion,
            format!(
                "expected eb_version {}, found {}",
                EVIDENCEBUS_VERSION, bundle.eb_version
            ),
            Some("eb_version".to_string()),
        );
    }

    if bundle.bundle_id.trim().is_empty() {
        report.push_error(
            ValidationCode::MissingField,
            "bundle_id must not be empty",
            Some("bundle_id".to_string()),
        );
    }

    let mut packet_ids = HashSet::new();
    for entry in &bundle.packets {
        if !packet_ids.insert(entry.packet_id.clone()) {
            report.push_error(
                ValidationCode::DuplicatePacketId,
                format!("duplicate packet id {}", entry.packet_id),
                Some(entry.packet_path.clone()),
            );
        }

        if !is_safe_relative_path(&entry.packet_path) {
            report.push_error(
                ValidationCode::UnsafePath,
                format!("unsafe packet path {}", entry.packet_path),
                Some(entry.packet_path.clone()),
            );
        }

        if !is_sha256_hex(&entry.sha256) {
            report.push_error(
                ValidationCode::InvalidDigest,
                format!("invalid packet digest {}", entry.sha256),
                Some(entry.packet_path.clone()),
            );
        }
    }

    let mut artifact_paths = HashSet::new();
    for artifact in &bundle.artifacts {
        if !artifact_paths.insert(artifact.relative_path.clone()) {
            report.push_error(
                ValidationCode::DuplicateAttachmentPath,
                format!("duplicate bundle artifact path {}", artifact.relative_path),
                Some(artifact.relative_path.clone()),
            );
        }

        if !is_safe_relative_path(&artifact.relative_path) {
            report.push_error(
                ValidationCode::UnsafePath,
                format!("unsafe bundle artifact path {}", artifact.relative_path),
                Some(artifact.relative_path.clone()),
            );
        }

        if !is_sha256_hex(&artifact.sha256) {
            report.push_error(
                ValidationCode::InvalidDigest,
                format!("invalid artifact digest {}", artifact.sha256),
                Some(artifact.relative_path.clone()),
            );
        }
    }

    report
}

pub fn canonical_packet_bytes(packet: &Packet) -> Result<Vec<u8>, CoreError> {
    let canonical = packet.canonicalized();
    serde_json::to_vec_pretty(&canonical).map_err(CoreError::from)
}

pub fn digest_packet(packet: &Packet) -> Result<String, CoreError> {
    let bytes = canonical_packet_bytes(packet)?;
    Ok(digest_bytes(&bytes))
}

pub fn digest_bytes(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hex::encode(hasher.finalize())
}

pub fn summarize_packets(packets: &[Packet]) -> BundleSummary {
    let mut summary = BundleSummary::default();
    summary.packet_count = packets.len();

    for packet in packets {
        match packet.summary.status {
            Status::Pass => summary.pass_count += 1,
            Status::Fail => summary.fail_count += 1,
            Status::Warn => summary.warn_count += 1,
            Status::Indeterminate => summary.indeterminate_count += 1,
            Status::Error => summary.error_count += 1,
        }
    }

    summary
}

pub fn stable_bundle_id(packet_digests: &[(String, String)]) -> String {
    let mut joined = String::new();
    for (packet_id, digest) in packet_digests {
        joined.push_str(packet_id);
        joined.push(':');
        joined.push_str(digest);
        joined.push('\n');
    }
    digest_bytes(joined.as_bytes())
}

pub fn is_safe_relative_path(path: &str) -> bool {
    if path.trim().is_empty() {
        return false;
    }

    let candidate = Path::new(path);
    if candidate.is_absolute() {
        return false;
    }

    !candidate.components().any(|component| {
        matches!(
            component,
            Component::ParentDir | Component::RootDir | Component::Prefix(_)
        )
    })
}

pub fn is_sha256_hex(candidate: &str) -> bool {
    candidate.len() == 64 && candidate.bytes().all(|byte| byte.is_ascii_hexdigit())
}

#[cfg(test)]
mod tests {
    use evidencebus_codes::{ValidationCode, ValidationMode};
    use evidencebus_fixtures::{faultline_packet, perfgate_packet};

    use super::{stable_bundle_id, summarize_packets, validate_packet};

    #[test]
    fn duplicate_attachment_paths_fail_validation() {
        let mut packet = perfgate_packet();
        packet
            .projections
            .attachments
            .push(packet.projections.attachments[0].clone());

        let report = validate_packet(&packet, ValidationMode::Strict);

        assert!(
            report
                .issues
                .iter()
                .any(|issue| issue.code == ValidationCode::DuplicateAttachmentPath)
        );
    }

    #[test]
    fn native_payload_requires_schema_id() {
        let mut packet = faultline_packet();
        if let Some(first) = packet.projections.attachments.first_mut() {
            first.schema_id = None;
        }

        let report = validate_packet(&packet, ValidationMode::Strict);

        assert!(
            report
                .issues
                .iter()
                .any(|issue| issue.code == ValidationCode::MissingNativePayloadSchema)
        );
    }

    #[test]
    fn summary_counts_follow_packet_status() {
        let packets = vec![perfgate_packet(), faultline_packet()];
        let summary = summarize_packets(&packets);

        assert_eq!(summary.packet_count, 2);
        assert_eq!(summary.pass_count, 1);
        assert_eq!(summary.indeterminate_count, 1);
    }

    #[test]
    fn stable_bundle_id_changes_when_digest_changes() {
        let left = stable_bundle_id(&[
            ("a".to_string(), "0".repeat(64)),
            ("b".to_string(), "1".repeat(64)),
        ]);
        let right = stable_bundle_id(&[
            ("a".to_string(), "0".repeat(64)),
            ("b".to_string(), "2".repeat(64)),
        ]);

        assert_ne!(left, right);
    }
}
