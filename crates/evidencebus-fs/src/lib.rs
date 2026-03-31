use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use evidencebus_codes::{ValidationCode, ValidationMode, EVIDENCEBUS_VERSION};
use evidencebus_core::{
    canonical_packet_bytes, digest_bytes, digest_packet, stable_bundle_id, summarize_packets,
    validate_bundle_manifest, validate_packet, CoreError,
};
use evidencebus_types::{
    BundleArtifactEntry, BundleManifest, BundlePacketEntry, Packet, ValidationReport,
};
use thiserror::Error;

#[derive(Debug)]
pub struct LoadedBundle {
    pub manifest: BundleManifest,
    pub packets: Vec<Packet>,
}

#[derive(Debug)]
pub enum LoadedTarget {
    Packet(Packet),
    Bundle(LoadedBundle),
}

#[derive(Debug, Error)]
pub enum FsError {
    #[error("io error at {path}: {source}")]
    Io {
        path: String,
        #[source]
        source: std::io::Error,
    },
    #[error("json error at {path}: {source}")]
    Json {
        path: String,
        #[source]
        source: serde_json::Error,
    },
    #[error("validation failed: {0:?}")]
    Validation(ValidationReport),
    #[error(transparent)]
    Core(#[from] CoreError),
    #[error("invalid input: {0}")]
    InvalidInput(String),
}

pub fn load_packet(path: &Path) -> Result<Packet, FsError> {
    let contents = read_to_string(path)?;
    serde_json::from_str(&contents).map_err(|source| FsError::Json {
        path: path.display().to_string(),
        source,
    })
}

pub fn write_packet(path: &Path, packet: &Packet) -> Result<(), FsError> {
    if let Some(parent) = path.parent().filter(|parent| !parent.as_os_str().is_empty()) {
        fs::create_dir_all(parent).map_err(|source| FsError::Io {
            path: parent.display().to_string(),
            source,
        })?;
    }
    let bytes = canonical_packet_bytes(packet)?;
    fs::write(path, bytes).map_err(|source| FsError::Io {
        path: path.display().to_string(),
        source,
    })
}

pub fn load_bundle(dir: &Path) -> Result<LoadedBundle, FsError> {
    let manifest_path = dir.join("bundle.eb.json");
    let manifest_contents = read_to_string(&manifest_path)?;
    let manifest: BundleManifest = serde_json::from_str(&manifest_contents).map_err(|source| {
        FsError::Json {
            path: manifest_path.display().to_string(),
            source,
        }
    })?;

    let mut packets = Vec::new();
    for entry in &manifest.packets {
        let packet_path = dir.join(&entry.packet_path);
        packets.push(load_packet(&packet_path)?);
    }

    Ok(LoadedBundle { manifest, packets })
}

pub fn load_target(path: &Path) -> Result<LoadedTarget, FsError> {
    if path.is_dir() {
        Ok(LoadedTarget::Bundle(load_bundle(path)?))
    } else {
        Ok(LoadedTarget::Packet(load_packet(path)?))
    }
}

pub fn validate_target(path: &Path, mode: ValidationMode) -> Result<ValidationReport, FsError> {
    if path.is_dir() {
        validate_bundle_dir(path, mode)
    } else {
        validate_packet_file(path, mode)
    }
}

pub fn validate_packet_file(path: &Path, mode: ValidationMode) -> Result<ValidationReport, FsError> {
    let packet = load_packet(path)?;
    let mut report = validate_packet(&packet, mode);

    if mode == ValidationMode::Strict {
        let base_dir = path
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
            .map(Path::to_path_buf)
            .unwrap_or_else(|| PathBuf::from("."));

        for attachment in &packet.projections.attachments {
            let artifact_path = base_dir.join(&attachment.relative_path);
            if !artifact_path.is_file() {
                report.push_error(
                    ValidationCode::MissingArtifact,
                    format!("missing artifact {}", artifact_path.display()),
                    Some(attachment.relative_path.clone()),
                );
                continue;
            }

            if let Some(expected_digest) = &attachment.sha256 {
                let bytes = read_bytes(&artifact_path)?;
                let actual_digest = digest_bytes(&bytes);
                if &actual_digest != expected_digest {
                    report.push_error(
                        ValidationCode::DigestMismatch,
                        format!(
                            "digest mismatch for {}: expected {}, found {}",
                            artifact_path.display(),
                            expected_digest,
                            actual_digest
                        ),
                        Some(attachment.relative_path.clone()),
                    );
                }
            }
        }
    }

    Ok(report)
}

pub fn validate_bundle_dir(dir: &Path, mode: ValidationMode) -> Result<ValidationReport, FsError> {
    let LoadedBundle { manifest, packets } = load_bundle(dir)?;
    let mut report = validate_bundle_manifest(&manifest);

    let mut packet_entries = BTreeMap::new();
    for entry in &manifest.packets {
        packet_entries.insert(entry.packet_id.clone(), entry);
    }

    for packet in &packets {
        report.merge(validate_packet(packet, mode));

        let packet_entry = if let Some(entry) = packet_entries.get(&packet.packet_id) {
            *entry
        } else {
            report.push_error(
                ValidationCode::InvalidBundleManifest,
                format!("manifest missing packet entry for {}", packet.packet_id),
                Some(packet.packet_id.clone()),
            );
            continue;
        };

        let packet_path = dir.join(&packet_entry.packet_path);
        let bytes = read_bytes(&packet_path)?;
        let actual_digest = digest_bytes(&bytes);
        if actual_digest != packet_entry.sha256 {
            report.push_error(
                ValidationCode::DigestMismatch,
                format!(
                    "packet digest mismatch for {}: expected {}, found {}",
                    packet_entry.packet_path, packet_entry.sha256, actual_digest
                ),
                Some(packet_entry.packet_path.clone()),
            );
        }

        if mode == ValidationMode::Strict {
            let packet_dir = packet_path.parent().ok_or_else(|| FsError::InvalidInput(format!(
                "bundle packet path {} has no parent",
                packet_path.display()
            )))?;
            for attachment in &packet.projections.attachments {
                let artifact_path = packet_dir.join(&attachment.relative_path);
                if !artifact_path.is_file() {
                    report.push_error(
                        ValidationCode::MissingArtifact,
                        format!("missing bundle artifact {}", artifact_path.display()),
                        Some(attachment.relative_path.clone()),
                    );
                    continue;
                }

                if let Some(expected_digest) = &attachment.sha256 {
                    let bytes = read_bytes(&artifact_path)?;
                    let actual_digest = digest_bytes(&bytes);
                    if &actual_digest != expected_digest {
                        report.push_error(
                            ValidationCode::DigestMismatch,
                            format!(
                                "digest mismatch for {}: expected {}, found {}",
                                artifact_path.display(),
                                expected_digest,
                                actual_digest
                            ),
                            Some(attachment.relative_path.clone()),
                        );
                    }
                }
            }
        }
    }

    let actual_summary = summarize_packets(&packets);
    if manifest.summary != actual_summary {
        report.push_error(
            ValidationCode::InvalidBundleManifest,
            "bundle summary does not match packet contents",
            Some("summary".to_string()),
        );
    }

    Ok(report)
}

pub fn build_bundle(packet_paths: &[PathBuf], output_dir: &Path) -> Result<BundleManifest, FsError> {
    if packet_paths.is_empty() {
        return Err(FsError::InvalidInput(
            "bundle requires at least one packet path".to_string(),
        ));
    }

    if output_dir.exists() {
        return Err(FsError::InvalidInput(format!(
            "output directory {} already exists",
            output_dir.display()
        )));
    }

    let mut packet_reports = ValidationReport::default();
    let mut deduped: BTreeMap<String, (Packet, PathBuf, String)> = BTreeMap::new();

    for path in packet_paths {
        let packet = load_packet(path)?;
        let report = validate_packet_file(path, ValidationMode::Strict)?;
        packet_reports.merge(report);

        let digest = digest_packet(&packet)?;
        match deduped.get(&packet.packet_id) {
            Some((_, _, existing_digest)) => {
                if existing_digest != &digest {
                    packet_reports.push_error(
                        ValidationCode::PacketConflict,
                        format!("conflicting packet content for id {}", packet.packet_id),
                        Some(path.display().to_string()),
                    );
                }
            }
            None => {
                deduped.insert(packet.packet_id.clone(), (packet, path.clone(), digest));
            }
        }
    }

    if !packet_reports.is_valid() {
        return Err(FsError::Validation(packet_reports));
    }

    fs::create_dir_all(output_dir.join("packets")).map_err(|source| FsError::Io {
        path: output_dir.join("packets").display().to_string(),
        source,
    })?;

    let mut bundled_packets: Vec<Packet> = Vec::new();
    let mut packet_entries: Vec<BundlePacketEntry> = Vec::new();
    let mut artifact_entries: Vec<BundleArtifactEntry> = Vec::new();
    let mut packet_digests: Vec<(String, String)> = Vec::new();

    for (packet_id, (packet, source_path, _digest_before_copy)) in deduped {
        let packet_root = source_path
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
            .map(Path::to_path_buf)
            .unwrap_or_else(|| PathBuf::from("."));
        let sanitized_id = sanitize_component(&packet_id);
        let mut bundled_packet = packet.canonicalized();

        for attachment in &mut bundled_packet.projections.attachments {
            let original_attachment_path = packet_root.join(&attachment.relative_path);
            let bundle_artifact_path = PathBuf::from("packets")
                .join(&sanitized_id)
                .join("artifacts")
                .join(Path::new(&attachment.relative_path));
            let destination_path = output_dir.join(&bundle_artifact_path);

            if let Some(parent) = destination_path.parent() {
                fs::create_dir_all(parent).map_err(|source| FsError::Io {
                    path: parent.display().to_string(),
                    source,
                })?;
            }

            fs::copy(&original_attachment_path, &destination_path).map_err(|source| FsError::Io {
                path: destination_path.display().to_string(),
                source,
            })?;

            let bytes = read_bytes(&destination_path)?;
            let digest = digest_bytes(&bytes);
            let size_bytes = Some(bytes.len() as u64);

            artifact_entries.push(BundleArtifactEntry {
                packet_id: packet_id.clone(),
                role: attachment.role.clone(),
                relative_path: to_forward_slash(&bundle_artifact_path),
                sha256: digest.clone(),
                size_bytes,
            });

            attachment.sha256 = Some(digest);
            attachment.size_bytes = size_bytes;
            attachment.relative_path =
                to_forward_slash(&PathBuf::from("artifacts").join(Path::new(&attachment.relative_path)));
        }

        let bundled_packet_path = PathBuf::from("packets")
            .join(sanitize_component(&packet_id))
            .join("packet.eb.json");
        let bundled_packet_abs = output_dir.join(&bundled_packet_path);
        write_packet(&bundled_packet_abs, &bundled_packet)?;
        let packet_bytes = read_bytes(&bundled_packet_abs)?;
        let packet_digest = digest_bytes(&packet_bytes);

        packet_entries.push(BundlePacketEntry {
            packet_id: packet_id.clone(),
            tool: bundled_packet.producer.tool.clone(),
            packet_path: to_forward_slash(&bundled_packet_path),
            sha256: packet_digest.clone(),
        });
        packet_digests.push((packet_id.clone(), packet_digest));
        bundled_packets.push(bundled_packet);
    }

    bundled_packets.sort_by(|left, right| left.packet_id.cmp(&right.packet_id));
    packet_entries.sort_by(|left, right| left.packet_id.cmp(&right.packet_id));
    artifact_entries.sort_by(|left, right| {
        left.packet_id
            .cmp(&right.packet_id)
            .then(left.relative_path.cmp(&right.relative_path))
    });

    let manifest = BundleManifest {
        eb_version: EVIDENCEBUS_VERSION.to_string(),
        bundle_id: stable_bundle_id(&packet_digests),
        packets: packet_entries,
        artifacts: artifact_entries,
        summary: summarize_packets(&bundled_packets),
    };

    let manifest_bytes =
        serde_json::to_vec_pretty(&manifest).map_err(|source| FsError::Json {
            path: output_dir.join("bundle.eb.json").display().to_string(),
            source,
        })?;
    fs::write(output_dir.join("bundle.eb.json"), manifest_bytes).map_err(|source| FsError::Io {
        path: output_dir.join("bundle.eb.json").display().to_string(),
        source,
    })?;

    Ok(manifest)
}

pub fn to_forward_slash(path: &Path) -> String {
    path.iter()
        .map(|component| component.to_string_lossy().to_string())
        .collect::<Vec<_>>()
        .join("/")
}

fn sanitize_component(value: &str) -> String {
    let mut output = String::with_capacity(value.len());
    for ch in value.chars() {
        if ch.is_ascii_alphanumeric() || matches!(ch, '-' | '_' | '.') {
            output.push(ch);
        } else {
            output.push('_');
        }
    }
    output
}

fn read_to_string(path: &Path) -> Result<String, FsError> {
    fs::read_to_string(path).map_err(|source| FsError::Io {
        path: path.display().to_string(),
        source,
    })
}

fn read_bytes(path: &Path) -> Result<Vec<u8>, FsError> {
    fs::read(path).map_err(|source| FsError::Io {
        path: path.display().to_string(),
        source,
    })
}

#[cfg(test)]
mod tests {
    use std::fs;

    use evidencebus_codes::{ValidationCode, ValidationMode};
    use evidencebus_fixtures::perfgate_packet;
    use tempfile::tempdir;

    use super::{build_bundle, load_bundle, validate_bundle_dir, write_packet};

    #[test]
    fn fs_bundle_round_trip() -> Result<(), Box<dyn std::error::Error>> {
        let dir = tempdir()?;
        let packet_dir = dir.path().join("packet");
        fs::create_dir_all(&packet_dir)?;

        let packet = perfgate_packet();
        let packet_path = packet_dir.join("pkt-perfgate.eb.json");
        let artifact_path = packet_dir.join("report.json");
        write_packet(&packet_path, &packet)?;
        fs::write(&artifact_path, br#"{"coverage": 0.91}"#)?;

        let out_dir = dir.path().join("bundle");
        build_bundle(&[packet_path.clone()], &out_dir)?;

        let loaded = load_bundle(&out_dir)?;
        assert_eq!(loaded.packets.len(), 1);

        let report = validate_bundle_dir(&out_dir, ValidationMode::Strict)?;
        assert!(report.is_valid(), "{report:?}");
        Ok(())
    }

    #[test]
    fn missing_artifact_fails_strict_validation() -> Result<(), Box<dyn std::error::Error>> {
        let dir = tempdir()?;
        let packet_dir = dir.path().join("packet");
        fs::create_dir_all(&packet_dir)?;

        let packet = perfgate_packet();
        let packet_path = packet_dir.join("pkt-perfgate.eb.json");
        write_packet(&packet_path, &packet)?;

        let report = super::validate_packet_file(&packet_path, ValidationMode::Strict)?;
        assert!(
            report
                .issues
                .iter()
                .any(|issue| issue.code == ValidationCode::MissingArtifact)
        );
        Ok(())
    }
}
