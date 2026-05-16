#![allow(clippy::unwrap_used)]

//! BDD tests covering builder/constructor methods for PlatformInfo,
//! Provenance, and Packet.

use std::collections::HashMap;

use evidencebus_codes::PacketStatus;
use evidencebus_types::{
    Assertion, Packet, PacketId, PlatformInfo, Producer, Projections, Provenance, SchemaVersion,
    Subject, Summary, VcsKind,
};

fn make_packet() -> Packet {
    Packet::new(
        SchemaVersion::new("0.1.0"),
        PacketId::new("test-packet").unwrap(),
        Producer::new("test-tool", "1.0.0"),
        Subject::new(VcsKind::Git, "owner/repo", "abc123", "main"),
        Summary::new(PacketStatus::Pass, "Test", "Test summary"),
    )
}

#[test]
fn bdd_given_os_and_arch_when_platform_info_new_called_then_fields_set() {
    let info = PlatformInfo::new("linux", "x86_64");
    assert_eq!(info.os, "linux");
    assert_eq!(info.arch, "x86_64");
}

#[test]
fn bdd_given_no_args_when_provenance_default_called_then_all_fields_none() {
    let p = Provenance::default();
    assert!(p.command.is_none());
    assert!(p.environment_fingerprint.is_none());
    assert!(p.platform_info.is_none());
}

#[test]
fn bdd_given_no_args_when_provenance_new_called_then_all_fields_none() {
    let p = Provenance::new();
    assert!(p.command.is_none());
    assert!(p.environment_fingerprint.is_none());
    assert!(p.platform_info.is_none());
}

#[test]
fn bdd_given_default_provenance_when_setting_command_then_command_is_set() {
    let p = Provenance::new().with_command("cargo test");
    assert_eq!(p.command.as_deref(), Some("cargo test"));
}

#[test]
fn bdd_given_default_provenance_when_setting_env_fingerprint_then_field_is_set() {
    let p = Provenance::new().with_environment_fingerprint("abc123");
    assert_eq!(p.environment_fingerprint.as_deref(), Some("abc123"));
}

#[test]
fn bdd_given_default_provenance_when_setting_platform_info_then_field_is_set() {
    let info = PlatformInfo::new("macos", "aarch64");
    let p = Provenance::new().with_platform_info(info.clone());
    assert_eq!(p.platform_info, Some(info));
}

#[test]
fn bdd_given_packet_when_with_projections_called_then_projections_replaced() {
    let projections = Projections::new().add_assertion(Assertion::new(
        "assert-1",
        PacketStatus::Pass,
        Summary::new(PacketStatus::Pass, "ok", "all good"),
    ));
    let packet = make_packet().with_projections(projections);
    assert_eq!(packet.projections.assertions.len(), 1);
    assert_eq!(packet.projections.assertions[0].id, "assert-1");
}

#[test]
fn bdd_given_packet_when_add_native_payload_called_then_path_appended() {
    let packet = make_packet()
        .add_native_payload("payloads/one.json")
        .add_native_payload("payloads/two.json");
    assert_eq!(
        packet.native_payloads,
        vec![
            "payloads/one.json".to_string(),
            "payloads/two.json".to_string()
        ]
    );
}

#[test]
fn bdd_given_packet_when_add_artifact_called_then_path_appended() {
    let packet = make_packet()
        .add_artifact("artifacts/log.txt")
        .add_artifact("artifacts/report.html");
    assert_eq!(
        packet.artifacts,
        vec![
            "artifacts/log.txt".to_string(),
            "artifacts/report.html".to_string()
        ]
    );
}

#[test]
fn bdd_given_packet_when_with_links_called_then_links_field_set() {
    let mut links = HashMap::new();
    links.insert("docs".to_string(), "https://example.com/docs".to_string());
    let packet = make_packet().with_links(links.clone());
    assert_eq!(packet.links, Some(links));
}

#[test]
fn bdd_given_packet_when_with_labels_called_then_labels_field_set() {
    let mut labels = HashMap::new();
    labels.insert("env".to_string(), "prod".to_string());
    let packet = make_packet().with_labels(labels.clone());
    assert_eq!(packet.labels, Some(labels));
}

#[test]
fn bdd_given_packet_when_with_created_at_called_then_timestamp_replaced() {
    let packet = make_packet().with_created_at("2024-06-01T12:00:00Z");
    assert_eq!(packet.created_at, "2024-06-01T12:00:00Z");
}
