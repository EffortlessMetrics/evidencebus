#![allow(clippy::unwrap_used, clippy::expect_used)]
//! Integration tests for evidencebus CLI

use std::fs;
use std::path::PathBuf;
use std::process::Command;

const CLI_BIN: &str = "evidencebus";

fn fixture_path(path: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join("fixtures")
        .join(path)
}

fn run_cli(args: &[&str]) -> (String, String, i32) {
    let output = Command::new(CLI_BIN)
        .args(args)
        .output()
        .expect("Failed to execute CLI");

    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();
    let code = output.status.code().unwrap_or(-1);

    (stdout, stderr, code)
}

#[test]
fn test_validate_valid_packet() {
    let packet_path = fixture_path("packets/perfgate/pkt-perfgate.eb.json");
    let (stdout, _stderr, code) = run_cli(&["validate", packet_path.to_str().unwrap()]);

    assert_eq!(code, 0);
    assert!(stdout.contains("Valid"));
}

#[test]
fn test_validate_invalid_packet() {
    let packet_path = fixture_path("packets/malformed/invalid-status.json");
    let (_stdout, stderr, code) = run_cli(&["validate", packet_path.to_str().unwrap()]);

    assert_eq!(code, 1);
    assert!(stderr.contains("Invalid"));
}

#[test]
fn test_validate_bundle() {
    let bundle_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join("examples")
        .join("demo-bundle");
    let (_stdout, _stderr, code) = run_cli(&["validate", bundle_path.to_str().unwrap()]);

    assert_eq!(code, 0);
}

#[test]
fn test_validate_demo_bundle_test() {
    let bundle_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join("examples")
        .join("demo-bundle-test");
    let (_stdout, _stderr, code) = run_cli(&["validate", bundle_path.to_str().unwrap()]);

    assert_eq!(code, 0);
}

#[test]
fn test_validate_schema_only() {
    let packet_path = fixture_path("packets/perfgate/pkt-perfgate.eb.json");
    let (stdout, _stderr, code) =
        run_cli(&["validate", "--schema-only", packet_path.to_str().unwrap()]);

    assert_eq!(code, 0);
    assert!(stdout.contains("Valid"));
}

#[test]
fn test_bundle_multiple_packets() {
    let temp_dir = tempfile::tempdir().unwrap();
    let bundle_path = temp_dir.path().join("test-bundle");

    let packet1 = fixture_path("packets/perfgate/pkt-perfgate.eb.json");
    let packet2 = fixture_path("packets/faultline/pkt-faultline.eb.json");

    let (stdout, _stderr, code) = run_cli(&[
        "bundle",
        "-o",
        bundle_path.to_str().unwrap(),
        packet1.to_str().unwrap(),
        packet2.to_str().unwrap(),
    ]);

    assert_eq!(code, 0);
    assert!(stdout.contains("Bundle created"));
    assert!(bundle_path.exists());
    assert!(bundle_path.join("bundle.eb.json").exists());

    // Cleanup
    temp_dir.close().unwrap();
}

#[test]
fn test_inspect_packet_text() {
    let packet_path = fixture_path("packets/perfgate/pkt-perfgate.eb.json");
    let (stdout, _stderr, code) = run_cli(&["inspect", packet_path.to_str().unwrap()]);

    assert_eq!(code, 0);
    assert!(stdout.contains("Packet:"));
    assert!(stdout.contains("Producer:"));
    assert!(stdout.contains("Status:"));
}

#[test]
fn test_inspect_packet_json() {
    let packet_path = fixture_path("packets/perfgate/pkt-perfgate.eb.json");
    let (stdout, _stderr, code) =
        run_cli(&["inspect", "--format", "json", packet_path.to_str().unwrap()]);

    assert_eq!(code, 0);
    assert!(stdout.starts_with('{'));
    assert!(stdout.contains("packet_id"));
}

#[test]
fn test_inspect_bundle() {
    let bundle_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join("examples")
        .join("demo-bundle");

    let (stdout, _stderr, code) = run_cli(&["inspect", bundle_path.to_str().unwrap()]);

    assert_eq!(code, 0);
    assert!(stdout.contains("Bundle:") || stdout.contains("packets"));
    assert!(stdout.contains("Packets:") || stdout.contains("packets"));
    assert!(stdout.contains("Artifacts:") || stdout.contains("artifacts"));
}

#[test]
fn test_emit_markdown() {
    let temp_dir = tempfile::tempdir().unwrap();
    let output_path = temp_dir.path().join("output.md");
    let packet_path = fixture_path("packets/perfgate/pkt-perfgate.eb.json");

    let (stdout, _stderr, code) = run_cli(&[
        "emit",
        "--format",
        "markdown",
        "--out",
        output_path.to_str().unwrap(),
        packet_path.to_str().unwrap(),
    ]);

    assert_eq!(code, 0);
    assert!(stdout.contains("Wrote:"));
    assert!(output_path.exists());

    let content = fs::read_to_string(&output_path).unwrap();
    assert!(content.contains("# ") || content.contains("## "));

    temp_dir.close().unwrap();
}

#[test]
fn test_emit_sarif() {
    let temp_dir = tempfile::tempdir().unwrap();
    let output_path = temp_dir.path().join("output.sarif.json");
    let packet_path = fixture_path("packets/perfgate/pkt-perfgate.eb.json");

    let (stdout, _stderr, code) = run_cli(&[
        "emit",
        "--format",
        "sarif",
        "--out",
        output_path.to_str().unwrap(),
        packet_path.to_str().unwrap(),
    ]);

    assert_eq!(code, 0);
    assert!(stdout.contains("Wrote:"));
    assert!(output_path.exists());

    let content = fs::read_to_string(&output_path).unwrap();
    assert!(content.contains("\"version\""));
    assert!(content.contains("\"$schema\""));

    temp_dir.close().unwrap();
}

#[test]
fn test_emit_stdout() {
    let packet_path = fixture_path("packets/perfgate/pkt-perfgate.eb.json");

    let (stdout, _stderr, code) = run_cli(&[
        "emit",
        "--format",
        "markdown",
        packet_path.to_str().unwrap(),
    ]);

    assert_eq!(code, 0);
    assert!(!stdout.is_empty());
}

#[test]
fn test_schema_packet() {
    let (stdout, _stderr, code) = run_cli(&["schema", "packet"]);

    assert_eq!(code, 0);
    assert!(stdout.contains("\"$schema\""));
    assert!(stdout.contains("packet"));
}

#[test]
fn test_schema_bundle() {
    let (stdout, _stderr, code) = run_cli(&["schema", "bundle"]);

    assert_eq!(code, 0);
    assert!(stdout.contains("\"$schema\""));
    assert!(stdout.contains("bundle"));
}

#[test]
fn test_schema_json_format() {
    let (stdout, _stderr, code) = run_cli(&["schema", "--format", "json", "packet"]);

    assert_eq!(code, 0);
    assert!(stdout.contains("\"$schema\""));
}

#[test]
fn test_invalid_format() {
    let packet_path = fixture_path("packets/perfgate/pkt-perfgate.eb.json");
    let (_stdout, _stderr, code) =
        run_cli(&["emit", "--format", "invalid", packet_path.to_str().unwrap()]);

    assert_eq!(code, 3); // Invalid arguments
}

#[test]
fn test_invalid_schema() {
    let (_stdout, _stderr, code) = run_cli(&["schema", "invalid"]);

    assert_eq!(code, 3); // Invalid arguments
}

#[test]
fn test_help() {
    let (stdout, _stderr, code) = run_cli(&["--help"]);

    assert_eq!(code, 0);
    assert!(stdout.contains("evidencebus"));
    assert!(stdout.contains("validate"));
    assert!(stdout.contains("bundle"));
    assert!(stdout.contains("inspect"));
    assert!(stdout.contains("emit"));
    assert!(stdout.contains("schema"));
}

#[test]
fn test_validate_help() {
    let (stdout, _stderr, code) = run_cli(&["validate", "--help"]);

    assert_eq!(code, 0);
    assert!(stdout.contains("Validate"));
    assert!(stdout.contains("--schema-only"));
}

#[test]
fn test_bundle_help() {
    let (stdout, _stderr, code) = run_cli(&["bundle", "--help"]);

    assert_eq!(code, 0);
    assert!(stdout.contains("Create a bundle"));
    assert!(stdout.contains("--out"));
}

#[test]
fn test_inspect_help() {
    let (stdout, _stderr, code) = run_cli(&["inspect", "--help"]);

    assert_eq!(code, 0);
    assert!(stdout.contains("Inspect"));
    assert!(stdout.contains("--format"));
}

#[test]
fn test_emit_help() {
    let (stdout, _stderr, code) = run_cli(&["emit", "--help"]);

    assert_eq!(code, 0);
    assert!(stdout.contains("Export"));
    assert!(stdout.contains("--format"));
    assert!(stdout.contains("--out"));
    assert!(stdout.contains("--details"));
    assert!(stdout.contains("--artifacts"));
}

#[test]
fn test_schema_help() {
    let (stdout, _stderr, code) = run_cli(&["schema", "--help"]);

    assert_eq!(code, 0);
    assert!(stdout.contains("Display schema"));
    assert!(stdout.contains("--format"));
}
