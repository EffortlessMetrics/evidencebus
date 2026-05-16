#![allow(clippy::unwrap_used)]
//! BDD-style tests for `BundleBuilder::add_packet` and `finalize`.
//!
//! These tests cover the attachment-copy path inside `add_packet`, the
//! additional artifact-copy path with `(source, relative_dest)` tuples, and
//! the manifest produced by `finalize`.

use std::env;
use std::fs;
use std::path::PathBuf;
use std::sync::Mutex;

use evidencebus_codes::PacketStatus;
use evidencebus_digest::compute_sha256;
use evidencebus_fixtures::PacketBuilder;
use evidencebus_fs::{read_bundle_manifest, BundleBuilder};
use evidencebus_types::{Attachment, AttachmentRole, Digest, Packet, Projections, VcsKind};
use tempfile::tempdir;

// Tests in this file change the process working directory because
// `BundleBuilder::add_packet` reads attachment payloads from
// `Path::new(&attachment.relative_path)`, which is CWD-relative. The mutex
// keeps these tests from running in parallel within this test binary.
static CWD_LOCK: Mutex<()> = Mutex::new(());

/// Runs `f` with the process working directory set to `tempdir`, restoring the
/// previous directory on exit.
fn with_cwd<F: FnOnce()>(tempdir: &std::path::Path, f: F) {
    let _guard = CWD_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let previous = env::current_dir().unwrap();
    env::set_current_dir(tempdir).unwrap();
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(f));
    env::set_current_dir(&previous).unwrap();
    if let Err(payload) = result {
        std::panic::resume_unwind(payload);
    }
}

fn make_packet_with_attachment(id: &str, relative_path: &str, content: &[u8]) -> Packet {
    let packet = PacketBuilder::new()
        .with_id(id)
        .with_producer("test-tool", "1.0.0")
        .with_subject(VcsKind::Git, "owner/repo", "abc123")
        .with_status(PacketStatus::Pass)
        .with_title("Test Packet")
        .with_summary("Test summary")
        .build()
        .unwrap();

    let digest = compute_sha256(content);

    Packet {
        projections: Projections {
            attachments: vec![Attachment {
                role: AttachmentRole::PlainText,
                relative_path: relative_path.to_string(),
                media_type: "text/plain".to_string(),
                sha256: Digest::new(digest).unwrap(),
                size: Some(content.len() as u64),
                schema_id: None,
            }],
            ..packet.projections
        },
        ..packet
    }
}

#[test]
fn bdd_given_packet_with_attachment_when_add_packet_then_copies_attachment_into_bundle() {
    // Given: A tempdir containing an attachment file and a bundle to populate
    let workdir = tempdir().unwrap();
    let content = b"attachment payload";
    let attachment_rel = "attached.txt";

    with_cwd(workdir.path(), || {
        fs::write(attachment_rel, content).unwrap();

        let bundle_path = workdir.path().join("attachment-bundle");
        let mut builder = BundleBuilder::new(&bundle_path).unwrap();
        let packet = make_packet_with_attachment("pkt-attached", attachment_rel, content);

        // When: The packet is added to the bundle
        builder.add_packet(packet, vec![]).unwrap();

        // And: The bundle is finalized
        let manifest = builder.finalize().unwrap();

        // Then: The attachment is written into the bundle's packet directory
        let copied = bundle_path.join("packets/pkt-attached/attached.txt");
        assert!(copied.is_file(), "attachment should be copied into bundle");
        assert_eq!(fs::read(&copied).unwrap(), content);

        // And: The manifest exposes the packet and one artifact entry. The
        // manifest builder always prefixes artifact paths with
        // `packets/{id}/artifacts/`, which is layered on top of the artifact's
        // own relative path computed by `BundleBuilder::add_packet`.
        assert_eq!(manifest.packets.len(), 1);
        assert_eq!(manifest.packets[0].packet_id.as_str(), "pkt-attached");
        assert_eq!(manifest.artifacts.len(), 1);
        assert_eq!(
            manifest.artifacts[0].relative_path,
            "packets/pkt-attached/artifacts/packets/pkt-attached/attached.txt"
        );

        // And: The manifest written to disk matches what finalize returned
        let read_manifest = read_bundle_manifest(&bundle_path).unwrap();
        assert_eq!(read_manifest.packets.len(), 1);
        assert_eq!(read_manifest.artifacts.len(), 1);
    });
}

#[test]
fn bdd_given_extra_artifacts_when_add_packet_then_copies_extras_into_bundle() {
    // Given: A packet with no attachments and a pair of additional artifacts
    let workdir = tempdir().unwrap();
    let extras_dir = workdir.path().join("extras");
    fs::create_dir_all(&extras_dir).unwrap();
    let extra1 = extras_dir.join("extra1.txt");
    let extra2 = extras_dir.join("extra2.bin");
    fs::write(&extra1, b"extra one").unwrap();
    fs::write(&extra2, b"extra two").unwrap();

    let bundle_path = workdir.path().join("extras-bundle");
    let mut builder = BundleBuilder::new(&bundle_path).unwrap();
    let packet = PacketBuilder::new()
        .with_id("pkt-extras")
        .with_producer("test-tool", "1.0.0")
        .with_subject(VcsKind::Git, "owner/repo", "abc123")
        .with_status(PacketStatus::Pass)
        .with_title("Has extras")
        .with_summary("Adds extra artifacts via builder")
        .build()
        .unwrap();

    let extras: Vec<(PathBuf, PathBuf)> = vec![
        (extra1.clone(), PathBuf::from("extra1.txt")),
        (extra2.clone(), PathBuf::from("nested/extra2.bin")),
    ];

    // When: The packet is added with the additional artifacts
    builder.add_packet(packet, extras).unwrap();

    // And: The bundle is finalized
    let manifest = builder.finalize().unwrap();

    // Then: Both extras are copied under the packet's artifacts directory
    let copied1 = bundle_path.join("packets/pkt-extras/artifacts/extra1.txt");
    let copied2 = bundle_path.join("packets/pkt-extras/artifacts/nested/extra2.bin");
    assert!(copied1.is_file());
    assert!(copied2.is_file());
    assert_eq!(fs::read(&copied1).unwrap(), b"extra one");
    assert_eq!(fs::read(&copied2).unwrap(), b"extra two");

    // And: The manifest lists both artifacts. The `build_bundle_manifest`
    // helper prefixes each artifact path with `packets/{id}/artifacts/` on top
    // of the bundle-relative path that `BundleBuilder::add_packet` records,
    // which itself starts with `packets/{id}/artifacts/`.
    assert_eq!(manifest.artifacts.len(), 2);
    let paths: Vec<&str> = manifest
        .artifacts
        .iter()
        .map(|a| a.relative_path.as_str())
        .collect();
    assert!(paths.contains(&"packets/pkt-extras/artifacts/packets/pkt-extras/artifacts/extra1.txt"));
    assert!(paths
        .contains(&"packets/pkt-extras/artifacts/packets/pkt-extras/artifacts/nested/extra2.bin"));

    // And: The bundle on disk has the manifest file written by finalize
    assert!(bundle_path.join("bundle.eb.json").is_file());
}

#[test]
fn bdd_given_missing_extra_artifact_when_add_packet_then_returns_artifact_copy_failed() {
    // Given: A packet and an extras list referencing a non-existent source file
    let workdir = tempdir().unwrap();
    let bundle_path = workdir.path().join("missing-extra-bundle");
    let mut builder = BundleBuilder::new(&bundle_path).unwrap();

    let packet = PacketBuilder::new()
        .with_id("pkt-missing-extra")
        .with_producer("test-tool", "1.0.0")
        .with_subject(VcsKind::Git, "owner/repo", "abc123")
        .with_status(PacketStatus::Pass)
        .with_title("Missing extra")
        .with_summary("Extra artifact source does not exist")
        .build()
        .unwrap();

    let extras = vec![(
        workdir.path().join("not-there.txt"),
        PathBuf::from("dest.txt"),
    )];

    // When: The packet is added with a missing extra artifact source
    let result = builder.add_packet(packet, extras);

    // Then: ArtifactCopyFailed is returned (propagated from copy_artifact_to_bundle)
    match result {
        Err(evidencebus_fs::FsError::ArtifactCopyFailed(msg)) => {
            assert!(msg.contains("not-there.txt"));
        }
        other => panic!("Expected ArtifactCopyFailed, got {other:?}"),
    }
}

#[test]
fn bdd_given_attachment_with_wrong_digest_when_add_packet_then_returns_digest_error() {
    // Given: An attachment file whose contents do not match the declared sha256
    let workdir = tempdir().unwrap();
    let attachment_rel = "mismatch.txt";
    let actual_content = b"actual bytes";

    with_cwd(workdir.path(), || {
        fs::write(attachment_rel, actual_content).unwrap();

        let bundle_path = workdir.path().join("mismatch-bundle");
        let mut builder = BundleBuilder::new(&bundle_path).unwrap();
        // Use a different payload to compute the (wrong) declared digest
        let packet = make_packet_with_attachment("pkt-mismatch", attachment_rel, b"different");

        // When: The packet is added
        let result = builder.add_packet(packet, vec![]);

        // Then: A digest error is returned
        assert!(result.is_err(), "expected digest verification failure");
        match result.unwrap_err() {
            evidencebus_fs::FsError::DigestError(_) => {}
            other => panic!("Expected DigestError, got {other:?}"),
        }
    });
}
