#![allow(clippy::unwrap_used)]

//! BDD tests covering wrapper newtypes: PacketId, SchemaVersion, Digest.

use evidencebus_types::{Digest, PacketId, SchemaVersion};

#[test]
fn bdd_given_valid_packet_id_when_into_inner_called_then_returns_owned_string() {
    let id = PacketId::new("packet-42").unwrap();
    let owned: String = id.into_inner();
    assert_eq!(owned, "packet-42");
}

#[test]
fn bdd_given_packet_id_when_as_ref_str_used_then_returns_underlying_slice() {
    let id = PacketId::new("packet-99").unwrap();
    let borrowed: &str = id.as_ref();
    assert_eq!(borrowed, "packet-99");
}

#[test]
fn bdd_given_packet_id_when_display_called_then_renders_inner_value() {
    let id = PacketId::new("display-me").unwrap();
    assert_eq!(format!("{id}"), "display-me");
}

#[test]
fn bdd_given_schema_version_when_display_called_then_renders_inner_value() {
    let version = SchemaVersion::new("0.1.0");
    assert_eq!(format!("{version}"), "0.1.0");
}

#[test]
fn bdd_given_schema_version_when_as_ref_str_used_then_returns_underlying_slice() {
    let version = SchemaVersion::new("1.2.3");
    let borrowed: &str = version.as_ref();
    assert_eq!(borrowed, "1.2.3");
}

#[test]
fn bdd_given_schema_version_when_as_str_called_then_matches_as_ref() {
    let version = SchemaVersion::new("2.0.0");
    assert_eq!(version.as_str(), AsRef::<str>::as_ref(&version));
}

#[test]
fn bdd_given_valid_digest_when_as_ref_str_used_then_returns_underlying_slice() {
    let hex = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    let digest = Digest::new(hex).unwrap();
    let borrowed: &str = digest.as_ref();
    assert_eq!(borrowed, hex);
}

#[test]
fn bdd_given_valid_digest_when_display_called_then_renders_hex() {
    let hex = "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210";
    let digest = Digest::new(hex).unwrap();
    assert_eq!(format!("{digest}"), hex);
}
