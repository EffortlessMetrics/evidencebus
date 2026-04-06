//! Core bundle construction and semantics for evidencebus.
//!
//! This crate provides pure functions for building bundles, manifests, and summaries,
//! as well as deduplicating packets and detecting conflicts.

use evidencebus_canonicalization::{canonicalize_json, CanonicalizationError};
use evidencebus_digest::compute_sha256;
use evidencebus_types::{
    Artifact, ArtifactInventoryEntry, BundleManifest, BundleSummary, Conflict, Digest, DigestError,
    IntegrityMetadata, Packet, PacketId, PacketInventoryEntry, SeverityCounts, StatusCounts,
};
use std::collections::HashMap;
use thiserror::Error;

/// Error type for core operations.
#[derive(Debug, Error)]
pub enum CoreError {
    #[error("conflict detected: {0}")]
    Conflict(String),
    #[error("canonicalization failed: {0}")]
    Canonicalization(#[from] CanonicalizationError),
    #[error("invalid digest: {0}")]
    InvalidDigest(#[from] DigestError),
    #[error("JSON serialization failed: {0}")]
    Serialization(#[from] serde_json::Error),
}

/// Legacy alias for backwards compatibility.
pub type DedupeError = CoreError;

/// Deduplicates packets by digest, keeping the first occurrence.
///
/// # Errors
/// Returns a `DedupeError` if conflicts are detected.
pub fn dedupe_packets(packets: Vec<Packet>) -> Result<Vec<Packet>, CoreError> {
    let mut seen = HashMap::new();
    let mut result = Vec::new();

    for packet in packets {
        let json = canonicalize_json(&packet)?;
        let digest = Digest::new(compute_sha256(json.as_bytes()))?;

        if let Some(existing_id) = seen.get(&digest) {
            if existing_id != &packet.packet_id {
                return Err(CoreError::Conflict(format!(
                    "different packets with same digest: {} and {}",
                    existing_id, packet.packet_id
                )));
            }
            // Duplicate packet with same ID, skip
        } else {
            seen.insert(digest, packet.packet_id.clone());
            result.push(packet);
        }
    }

    Ok(result)
}

/// Detects conflicts between packets (same ID, different content).
pub fn detect_conflicts(packets: &[Packet]) -> Vec<Conflict> {
    let mut seen: HashMap<PacketId, Digest> = HashMap::new();
    let mut conflicts = Vec::new();

    for packet in packets {
        let json = match canonicalize_json(&packet) {
            Ok(j) => j,
            Err(_) => continue, // Skip packets that can't be canonicalized
        };
        let digest = match Digest::new(compute_sha256(json.as_bytes())) {
            Ok(d) => d,
            Err(_) => continue, // Skip packets with invalid digests
        };

        if let Some(existing_digest) = seen.get(&packet.packet_id) {
            if existing_digest != &digest {
                conflicts.push(Conflict::new(
                    packet.packet_id.clone(),
                    existing_digest.clone(),
                    digest,
                ));
            }
        } else {
            seen.insert(packet.packet_id.clone(), digest);
        }
    }

    conflicts
}

/// Builds a bundle manifest from packets and artifacts.
///
/// # Errors
/// Returns a `CoreError` if canonicalization, digest computation, or serialization fails.
pub fn build_bundle_manifest(
    packets: &[Packet],
    artifacts: &[Artifact],
) -> Result<BundleManifest, CoreError> {
    let mut packet_entries = Vec::new();
    let mut artifact_entries = Vec::new();
    let mut packet_digests = HashMap::new();
    let mut artifact_digests = HashMap::new();

    // Process packets
    for packet in packets {
        let json = canonicalize_json(packet)?;
        let digest = Digest::new(compute_sha256(json.as_bytes()))?;

        let entry = PacketInventoryEntry::new(
            packet.packet_id.clone(),
            format!("packets/{}/packet.eb.json", packet.packet_id),
            digest.clone(),
        );

        packet_entries.push(entry);
        packet_digests.insert(packet.packet_id.clone(), digest);
    }

    // Sort packet entries by packet_id for determinism
    packet_entries.sort_by(|a, b| a.packet_id.as_str().cmp(b.packet_id.as_str()));

    // Process artifacts
    for artifact in artifacts {
        let digest = Digest::new(compute_sha256(&artifact.data))?;

        let relative_path = format!(
            "packets/{}/artifacts/{}",
            artifact.packet_id, artifact.relative_path
        );
        let entry = ArtifactInventoryEntry::new(
            artifact.packet_id.clone(),
            relative_path.clone(),
            artifact.role,
            digest.clone(),
        );

        artifact_entries.push(entry);
        artifact_digests.insert(relative_path, digest);
    }

    // Sort artifact entries by packet_id, then relative_path
    artifact_entries.sort_by(|a, b| {
        a.packet_id
            .as_str()
            .cmp(b.packet_id.as_str())
            .then_with(|| a.relative_path.cmp(&b.relative_path))
    });

    // Compute manifest digest
    let manifest_data = serde_json::to_vec(&(&packet_entries, &artifact_entries))?;
    let manifest_digest = Digest::new(compute_sha256(&manifest_data))?;

    let integrity = IntegrityMetadata::new(manifest_digest, packet_digests, artifact_digests);

    Ok(BundleManifest::new(
        packet_entries,
        artifact_entries,
        integrity,
    ))
}

/// Builds a bundle summary from packets.
pub fn build_bundle_summary(packets: &[Packet]) -> BundleSummary {
    let mut status_counts = StatusCounts::new();
    let mut severity_counts = SeverityCounts::new();
    let mut total_artifacts = 0u32;

    for packet in packets {
        // Count status
        status_counts.increment(packet.summary.status);

        // Count findings by severity
        for finding in &packet.projections.findings {
            severity_counts.increment(finding.severity);
        }

        // Count artifacts
        total_artifacts += packet.artifacts.len() as u32;
        total_artifacts += packet.projections.attachments.len() as u32;
    }

    BundleSummary::new(
        packets.len() as u32,
        total_artifacts,
        status_counts,
        severity_counts,
    )
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use evidencebus_codes::FindingSeverity;
    use evidencebus_types::{AttachmentRole, Finding, Producer, Subject, Summary};

    fn create_test_packet(id: &str) -> Packet {
        Packet::new(
            evidencebus_types::SchemaVersion::new("0.1.0"),
            PacketId::new(id).unwrap(),
            Producer::new("test-tool", "1.0.0"),
            Subject::new(
                evidencebus_types::VcsKind::Git,
                "owner/repo",
                "abc123",
                "main",
            ),
            Summary::new(
                evidencebus_codes::PacketStatus::Pass,
                "Test",
                "Test summary",
            ),
        )
    }

    #[test]
    fn test_dedupe_packets() {
        // Create packets with same ID and content (same timestamp)
        let timestamp = "2024-01-01T00:00:00Z";
        let mut packet1 = create_test_packet("test-packet");
        packet1.created_at = timestamp.to_string();

        let mut packet2 = create_test_packet("test-packet"); // Duplicate
        packet2.created_at = timestamp.to_string();

        let packet3 = create_test_packet("other-packet");

        let result = dedupe_packets(vec![packet1, packet2, packet3]).unwrap();
        assert_eq!(result.len(), 2);
        assert_eq!(result[0].packet_id.as_str(), "test-packet");
        assert_eq!(result[1].packet_id.as_str(), "other-packet");
    }

    #[test]
    fn test_detect_conflicts() {
        let packet1 = create_test_packet("test-packet");
        let mut packet2 = create_test_packet("test-packet");
        packet2.summary = Summary::new(
            evidencebus_codes::PacketStatus::Fail,
            "Different",
            "Different summary",
        );

        let conflicts = detect_conflicts(&[packet1, packet2]);
        assert_eq!(conflicts.len(), 1);
        assert_eq!(conflicts[0].packet_id.as_str(), "test-packet");
    }

    #[test]
    fn test_build_bundle_summary() {
        let mut packet1 = create_test_packet("packet-1");
        packet1.projections.findings.push(Finding::new(
            "f1",
            FindingSeverity::Error,
            "Error",
            "Error message",
        ));

        let mut packet2 = create_test_packet("packet-2");
        packet2.summary = Summary::new(
            evidencebus_codes::PacketStatus::Fail,
            "Fail",
            "Fail summary",
        );
        packet2.projections.findings.push(Finding::new(
            "f2",
            FindingSeverity::Warning,
            "Warning",
            "Warning message",
        ));

        let summary = build_bundle_summary(&[packet1, packet2]);
        assert_eq!(summary.total_packets, 2);
        assert_eq!(summary.status_counts.pass, 1);
        assert_eq!(summary.status_counts.fail, 1);
        assert_eq!(summary.severity_counts.error, 1);
        assert_eq!(summary.severity_counts.warning, 1);
    }

    #[test]
    fn test_build_bundle_manifest() {
        let packet1 = create_test_packet("packet-1");
        let packet2 = create_test_packet("packet-2");

        let artifact1 = Artifact::new(
            PacketId::new("packet-1").unwrap(),
            "report.json",
            AttachmentRole::ReportHtml,
            b"artifact data".to_vec(),
        );

        let manifest = build_bundle_manifest(&[packet1, packet2], &[artifact1]).unwrap();

        assert_eq!(manifest.packets.len(), 2);
        assert_eq!(manifest.artifacts.len(), 1);
        assert_eq!(manifest.packets[0].packet_id.as_str(), "packet-1");
        assert_eq!(manifest.packets[1].packet_id.as_str(), "packet-2");
    }
}
