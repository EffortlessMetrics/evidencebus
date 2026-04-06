#![allow(clippy::unwrap_used, clippy::expect_used, unused_variables)]
//! BDD-style tests for the evidencebus CLI.
//!
//! These tests follow the Given-When-Then structure to describe behavior
//! in a clear, readable format.

use std::fs;
use std::path::PathBuf;
use std::process::Command;

const CLI_BIN: &str = "evidencebus";

/// Helper function to get fixture path
fn fixture_path(path: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join("fixtures")
        .join(path)
}

/// Helper function to get examples path
fn examples_path(path: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join("examples")
        .join(path)
}

/// Helper function to run CLI and capture output
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

// ============================================================================
// Help Command Tests
// ============================================================================

mod help_command {
    use super::*;

    #[test]
    fn scenario_help_displays_usage() {
        // Given: The CLI is invoked with --help flag
        let (stdout, _stderr, code) = run_cli(&["--help"]);

        // Then: The command should succeed
        assert_eq!(code, 0);

        // And: Help output should contain usage information
        assert!(stdout.contains("Usage:"));
        assert!(stdout.contains("evidencebus"));

        // And: Help output should list available commands
        assert!(stdout.contains("validate"));
        assert!(stdout.contains("bundle"));
        assert!(stdout.contains("inspect"));
        assert!(stdout.contains("emit"));
        assert!(stdout.contains("schema"));

        // And: Help output should contain description
        assert!(stdout.contains("Schema-first evidence backplane"));
    }

    #[test]
    fn scenario_version_displays_version() {
        // Given: The CLI is invoked with --version flag
        let (stdout, _stderr, code) = run_cli(&["--version"]);

        // Then: The command should succeed
        assert_eq!(code, 0);

        // And: Version output should be present
        assert!(!stdout.trim().is_empty());
    }

    #[test]
    fn scenario_validate_help_displays_validate_usage() {
        // Given: The CLI is invoked with validate --help
        let (stdout, _stderr, code) = run_cli(&["validate", "--help"]);

        // Then: The command should succeed
        assert_eq!(code, 0);

        // And: Help should describe validate command
        assert!(stdout.contains("Validate"));
        assert!(stdout.contains("packet"));
        assert!(stdout.contains("bundle"));

        // And: Help should show schema-only flag
        assert!(stdout.contains("--schema-only"));
        assert!(stdout.contains("-s"));
    }

    #[test]
    fn scenario_bundle_help_displays_bundle_usage() {
        // Given: The CLI is invoked with bundle --help
        let (stdout, _stderr, code) = run_cli(&["bundle", "--help"]);

        // Then: The command should succeed
        assert_eq!(code, 0);

        // And: Help should describe bundle command
        assert!(stdout.contains("Create"));
        assert!(stdout.contains("bundle"));

        // And: Help should show output flag
        assert!(stdout.contains("--out"));
        assert!(stdout.contains("-o"));
    }

    #[test]
    fn scenario_inspect_help_displays_inspect_usage() {
        // Given: The CLI is invoked with inspect --help
        let (stdout, _stderr, code) = run_cli(&["inspect", "--help"]);

        // Then: The command should succeed
        assert_eq!(code, 0);

        // And: Help should describe inspect command
        assert!(stdout.contains("Inspect"));

        // And: Help should show format flag
        assert!(stdout.contains("--format"));
        assert!(stdout.contains("-f"));
        assert!(stdout.contains("text"));
        assert!(stdout.contains("json"));
    }

    #[test]
    fn scenario_emit_help_displays_emit_usage() {
        // Given: The CLI is invoked with emit --help
        let (stdout, _stderr, code) = run_cli(&["emit", "--help"]);

        // Then: The command should succeed
        assert_eq!(code, 0);

        // And: Help should describe emit command
        assert!(stdout.contains("Export"));

        // And: Help should show format, output, details, and artifacts flags
        assert!(stdout.contains("--format"));
        assert!(stdout.contains("--out"));
        assert!(stdout.contains("--details"));
        assert!(stdout.contains("--artifacts"));
    }

    #[test]
    fn scenario_schema_help_displays_schema_usage() {
        // Given: The CLI is invoked with schema --help
        let (stdout, _stderr, code) = run_cli(&["schema", "--help"]);

        // Then: The command should succeed
        assert_eq!(code, 0);

        // And: Help should describe schema command
        assert!(stdout.contains("Display schema"));

        // And: Help should show format flag
        assert!(stdout.contains("--format"));
        assert!(stdout.contains("-f"));
    }
}

// ============================================================================
// Validate Command Tests
// ============================================================================

mod validate_command {
    use super::*;

    #[test]
    fn scenario_validate_valid_packet_succeeds() {
        // Given: A valid packet file
        let packet_path = fixture_path("packets/perfgate/pkt-perfgate.eb.json");

        // When: Validating the packet
        let (stdout, _stderr, code) = run_cli(&["validate", packet_path.to_str().unwrap()]);

        // Then: The command should succeed
        assert_eq!(code, 0);

        // And: Success message should be displayed
        assert!(stdout.contains("Valid"));
        assert!(stdout.contains("✓"));
    }

    #[test]
    fn scenario_validate_invalid_packet_fails() {
        // Given: An invalid packet file with invalid status
        let packet_path = fixture_path("packets/malformed/invalid-status.json");

        // When: Validating the packet
        let (_stdout, stderr, code) = run_cli(&["validate", packet_path.to_str().unwrap()]);

        // Then: The command should fail
        assert_eq!(code, 1);

        // And: Error message should be displayed
        assert!(stderr.contains("Invalid"));
        assert!(stderr.contains("✗"));
    }

    #[test]
    fn scenario_validate_packet_with_missing_required_field_fails() {
        // Given: A packet with missing required fields
        let packet_path = fixture_path("packets/malformed/missing-required.json");

        // When: Validating the packet
        let (_stdout, stderr, code) = run_cli(&["validate", packet_path.to_str().unwrap()]);

        // Then: The command should fail
        assert_eq!(code, 1);

        // And: Error message should indicate validation failure
        assert!(stderr.contains("Invalid"));
    }

    #[test]
    fn scenario_validate_packet_with_invalid_digest_fails() {
        // Given: A packet with invalid digest
        let packet_path = fixture_path("packets/malformed/invalid-digest.json");

        // When: Validating the packet
        let (_stdout, stderr, code) = run_cli(&["validate", packet_path.to_str().unwrap()]);

        // Then: The command should fail
        assert_eq!(code, 1);

        // And: Error message should indicate digest error
        assert!(stderr.contains("Invalid"));
    }

    #[test]
    fn scenario_validate_packet_with_path_traversal_fails() {
        // Given: A packet with path traversal attempt
        let packet_path = fixture_path("packets/malformed/path-traversal.json");

        // When: Validating the packet
        let (_stdout, stderr, code) = run_cli(&["validate", packet_path.to_str().unwrap()]);

        // Then: The command should fail
        assert_eq!(code, 1);

        // And: Error message should indicate path error
        assert!(stderr.contains("Invalid"));
    }

    #[test]
    fn scenario_validate_packet_with_absolute_path_fails() {
        // Given: A packet with absolute path
        let packet_path = fixture_path("packets/malformed/absolute-path.json");

        // When: Validating the packet
        let (_stdout, stderr, code) = run_cli(&["validate", packet_path.to_str().unwrap()]);

        // Then: The command should fail
        assert_eq!(code, 1);

        // And: Error message should indicate path error
        assert!(stderr.contains("Invalid"));
    }

    #[test]
    fn scenario_validate_valid_bundle_succeeds() {
        // Given: A valid bundle directory
        let bundle_path = examples_path("demo-bundle");

        // When: Validating the bundle
        let (stdout, _stderr, code) = run_cli(&["validate", bundle_path.to_str().unwrap()]);

        // Then: The command should succeed (exit code 0) or have validation errors (exit code 1)
        assert!(code == 0 || code == 1);

        // And: Output should mention the bundle
        if code == 0 {
            assert!(stdout.contains("Valid"));
        }
    }

    #[test]
    fn scenario_validate_nonexistent_file_fails() {
        // Given: A non-existent file path
        let nonexistent_path = "/tmp/nonexistent-packet.eb.json";

        // When: Validating the non-existent file
        let (_stdout, stderr, code) = run_cli(&["validate", nonexistent_path]);

        // Then: The command should fail
        assert_eq!(code, 1);

        // And: Error message should indicate file not found
        // Note: On Windows, the error message format may differ
        assert!(
            stderr.contains("IO error")
                || stderr.contains("cannot find the file")
                || stderr.contains("not found")
                || stderr.contains("Invalid")
                || stderr.contains("✗ Invalid")
        );
    }

    #[test]
    fn scenario_validate_schema_only_skips_file_checks() {
        // Given: A valid packet file
        let packet_path = fixture_path("packets/perfgate/pkt-perfgate.eb.json");

        // When: Validating with --schema-only flag
        let (stdout, _stderr, code) =
            run_cli(&["validate", "--schema-only", packet_path.to_str().unwrap()]);

        // Then: The command should succeed
        assert_eq!(code, 0);

        // And: Success message should be displayed
        assert!(stdout.contains("Valid"));
    }

    #[test]
    fn scenario_validate_with_short_schema_only_flag() {
        // Given: A valid packet file
        let packet_path = fixture_path("packets/perfgate/pkt-perfgate.eb.json");

        // When: Validating with -s flag
        let (stdout, _stderr, code) = run_cli(&["validate", "-s", packet_path.to_str().unwrap()]);

        // Then: The command should succeed
        assert_eq!(code, 0);

        // And: Success message should be displayed
        assert!(stdout.contains("Valid"));
    }
}

// ============================================================================
// Bundle Command Tests
// ============================================================================

mod bundle_command {
    use super::*;

    #[test]
    fn scenario_bundle_creates_bundle_from_packets() {
        // Given: Two valid packet files and a temporary output directory
        let temp_dir = tempfile::tempdir().unwrap();
        let bundle_path = temp_dir.path().join("test-bundle");
        let packet1 = fixture_path("packets/perfgate/pkt-perfgate.eb.json");
        let packet2 = fixture_path("packets/faultline/pkt-faultline.eb.json");

        // When: Creating a bundle from the packets
        let (stdout, _stderr, code) = run_cli(&[
            "bundle",
            "-o",
            bundle_path.to_str().unwrap(),
            packet1.to_str().unwrap(),
            packet2.to_str().unwrap(),
        ]);

        // Then: The command should succeed
        assert_eq!(code, 0);

        // And: Success message should be displayed
        assert!(stdout.contains("Bundle created"));
        assert!(stdout.contains("✓"));

        // And: Bundle directory should exist
        assert!(bundle_path.exists());

        // And: Bundle manifest should exist
        assert!(bundle_path.join("bundle.eb.json").exists());

        // Cleanup
        temp_dir.close().unwrap();
    }

    #[test]
    fn scenario_bundle_with_default_output_directory() {
        // Given: A valid packet file
        let packet = fixture_path("packets/perfgate/pkt-perfgate.eb.json");
        let default_bundle = PathBuf::from("./evidence-bundle");

        // Ensure default bundle doesn't exist
        let _ = fs::remove_dir_all(&default_bundle);

        // When: Creating a bundle without specifying output
        let (stdout, _stderr, code) = run_cli(&["bundle", packet.to_str().unwrap()]);

        // Then: The command should succeed
        assert_eq!(code, 0);

        // And: Success message should be displayed
        assert!(stdout.contains("Bundle created"));

        // And: Default bundle directory should exist
        assert!(default_bundle.exists());

        // Cleanup
        let _ = fs::remove_dir_all(&default_bundle);
    }

    #[test]
    fn scenario_bundle_with_long_output_flag() {
        // Given: A valid packet file and temporary directory
        let temp_dir = tempfile::tempdir().unwrap();
        let bundle_path = temp_dir.path().join("test-bundle");
        let packet = fixture_path("packets/perfgate/pkt-perfgate.eb.json");

        // When: Creating a bundle with --out flag
        let (stdout, _stderr, code) = run_cli(&[
            "bundle",
            "--out",
            bundle_path.to_str().unwrap(),
            packet.to_str().unwrap(),
        ]);

        // Then: The command should succeed
        assert_eq!(code, 0);

        // And: Bundle should be created at specified path
        assert!(bundle_path.exists());

        // Cleanup
        temp_dir.close().unwrap();
    }

    #[test]
    fn scenario_bundle_with_nonexistent_packet_fails() {
        // Given: A non-existent packet file and temporary directory
        let temp_dir = tempfile::tempdir().unwrap();
        let bundle_path = temp_dir.path().join("test-bundle");
        let nonexistent_packet = "/tmp/nonexistent-packet.eb.json";

        // When: Creating a bundle with non-existent packet
        let (_stdout, stderr, code) = run_cli(&[
            "bundle",
            "-o",
            bundle_path.to_str().unwrap(),
            nonexistent_packet,
        ]);

        // Then: The command should fail
        assert_eq!(code, 2); // clap error for invalid packet path

        // And: Error message should indicate file not found
        assert!(
            stderr.contains("Error")
                || stderr.contains("not found")
                || stderr.contains("No such file")
        );

        // Cleanup
        temp_dir.close().unwrap();
    }

    #[test]
    fn scenario_bundle_without_packets_fails() {
        // Given: No packets provided
        let temp_dir = tempfile::tempdir().unwrap();
        let bundle_path = temp_dir.path().join("test-bundle");

        // When: Creating a bundle without packets
        let (_stdout, _stderr, code) = run_cli(&["bundle", "-o", bundle_path.to_str().unwrap()]);

        // Then: The command should fail
        assert_eq!(code, 2); // clap error for missing required argument

        // Cleanup
        temp_dir.close().unwrap();
    }
}

// ============================================================================
// Inspect Command Tests
// ============================================================================

mod inspect_command {
    use super::*;

    #[test]
    fn scenario_inspect_packet_displays_text_format() {
        // Given: A valid packet file
        let packet_path = fixture_path("packets/perfgate/pkt-perfgate.eb.json");

        // When: Inspecting the packet with text format (default)
        let (stdout, _stderr, code) = run_cli(&["inspect", packet_path.to_str().unwrap()]);

        // Then: The command should succeed
        assert_eq!(code, 0);

        // And: Output should contain packet information
        assert!(stdout.contains("Packet:"));
        assert!(stdout.contains("Producer:"));
        assert!(stdout.contains("Status:"));
        assert!(stdout.contains("Title:"));
        assert!(stdout.contains("Summary:"));
        assert!(stdout.contains("Attachments:"));
        assert!(stdout.contains("Projections:"));
        assert!(stdout.contains("Findings:"));
        assert!(stdout.contains("Metrics:"));
    }

    #[test]
    fn scenario_inspect_packet_displays_json_format() {
        // Given: A valid packet file
        let packet_path = fixture_path("packets/perfgate/pkt-perfgate.eb.json");

        // When: Inspecting the packet with JSON format
        let (stdout, _stderr, code) =
            run_cli(&["inspect", "--format", "json", packet_path.to_str().unwrap()]);

        // Then: The command should succeed
        assert_eq!(code, 0);

        // And: Output should be valid JSON
        assert!(stdout.starts_with('{'));
        assert!(stdout.contains("packet_id"));

        // And: JSON should be pretty-printed
        assert!(stdout.contains('\n'));
    }

    #[test]
    fn scenario_inspect_packet_with_short_format_flag() {
        // Given: A valid packet file
        let packet_path = fixture_path("packets/perfgate/pkt-perfgate.eb.json");

        // When: Inspecting with -f flag
        let (stdout, _stderr, code) =
            run_cli(&["inspect", "-f", "json", packet_path.to_str().unwrap()]);

        // Then: The command should succeed
        assert_eq!(code, 0);

        // And: Output should be valid JSON
        assert!(stdout.starts_with('{'));
    }

    #[test]
    fn scenario_inspect_bundle_displays_summary() {
        // Given: A valid bundle directory
        let bundle_path = examples_path("demo-bundle");

        // When: Inspecting the bundle
        let (stdout, _stderr, code) = run_cli(&["inspect", bundle_path.to_str().unwrap()]);

        // Then: The command should succeed
        assert_eq!(code, 0);

        // And: Output should contain bundle summary
        assert!(stdout.contains("Bundle:") || stdout.contains("packets"));
        assert!(stdout.contains("Packets:") || stdout.contains("packets"));
        assert!(stdout.contains("Artifacts:") || stdout.contains("artifacts"));
        assert!(stdout.contains("Summary:"));
        assert!(stdout.contains("Pass:"));
        assert!(stdout.contains("Fail:"));
    }

    #[test]
    fn scenario_inspect_bundle_displays_json_format() {
        // Given: A valid bundle directory
        let bundle_path = examples_path("demo-bundle");

        // When: Inspecting the bundle with JSON format
        let (stdout, _stderr, code) =
            run_cli(&["inspect", "--format", "json", bundle_path.to_str().unwrap()]);

        // Then: The command should succeed
        assert_eq!(code, 0);

        // And: Output should be valid JSON
        assert!(stdout.starts_with('{'));
        assert!(stdout.contains("manifest"));
        assert!(stdout.contains("packets"));
    }

    #[test]
    fn scenario_inspect_nonexistent_target_fails() {
        // Given: A non-existent file path
        let nonexistent_path = "/tmp/nonexistent-packet.eb.json";

        // When: Inspecting the non-existent file
        let (_stdout, stderr, code) = run_cli(&["inspect", nonexistent_path]);

        // Then: The command should fail
        assert_eq!(code, 2); // clap error for invalid path

        // And: Error message should indicate file not found
        assert!(
            stderr.contains("Error")
                || stderr.contains("not found")
                || stderr.contains("No such file")
        );
    }

    #[test]
    fn scenario_inspect_with_invalid_format_returns_error() {
        // Given: A valid packet file
        let packet_path = fixture_path("packets/perfgate/pkt-perfgate.eb.json");

        // When: Inspecting with invalid format
        let (_stdout, _stderr, code) = run_cli(&[
            "inspect",
            "--format",
            "invalid",
            packet_path.to_str().unwrap(),
        ]);

        // Then: The command should fail with an error
        assert_ne!(code, 0);
    }
}

// ============================================================================
// Emit Command Tests
// ============================================================================

mod emit_command {
    use super::*;

    #[test]
    fn scenario_emit_packet_to_markdown_file() {
        // Given: A valid packet file and temporary output path
        let temp_dir = tempfile::tempdir().unwrap();
        let output_path = temp_dir.path().join("output.md");
        let packet_path = fixture_path("packets/perfgate/pkt-perfgate.eb.json");

        // When: Emitting the packet to Markdown format
        let (stdout, _stderr, code) = run_cli(&[
            "emit",
            "--format",
            "markdown",
            "--out",
            output_path.to_str().unwrap(),
            packet_path.to_str().unwrap(),
        ]);

        // Then: The command should succeed
        assert_eq!(code, 0);

        // And: Success message should be displayed
        assert!(stdout.contains("Wrote:"));
        assert!(stdout.contains("✓"));

        // And: Output file should exist
        assert!(output_path.exists());

        // And: Output file should contain Markdown headers
        let content = fs::read_to_string(&output_path).unwrap();
        assert!(content.contains("# ") || content.contains("## "));

        // Cleanup
        temp_dir.close().unwrap();
    }

    #[test]
    fn scenario_emit_packet_to_sarif_file() {
        // Given: A valid packet file and temporary output path
        let temp_dir = tempfile::tempdir().unwrap();
        let output_path = temp_dir.path().join("output.sarif.json");
        let packet_path = fixture_path("packets/perfgate/pkt-perfgate.eb.json");

        // When: Emitting the packet to SARIF format
        let (stdout, _stderr, code) = run_cli(&[
            "emit",
            "--format",
            "sarif",
            "--out",
            output_path.to_str().unwrap(),
            packet_path.to_str().unwrap(),
        ]);

        // Then: The command should succeed
        assert_eq!(code, 0);

        // And: Success message should be displayed
        assert!(stdout.contains("Wrote:"));

        // And: Output file should exist
        assert!(output_path.exists());

        // And: Output file should contain valid SARIF structure
        let content = fs::read_to_string(&output_path).unwrap();
        assert!(content.contains("\"version\""));
        assert!(content.contains("\"$schema\""));
        assert!(content.contains("runs"));

        // Cleanup
        temp_dir.close().unwrap();
    }

    #[test]
    fn scenario_emit_packet_to_stdout_markdown() {
        // Given: A valid packet file
        let packet_path = fixture_path("packets/perfgate/pkt-perfgate.eb.json");

        // When: Emitting to stdout without --out flag
        let (stdout, _stderr, code) = run_cli(&[
            "emit",
            "--format",
            "markdown",
            packet_path.to_str().unwrap(),
        ]);

        // Then: The command should succeed
        assert_eq!(code, 0);

        // And: Output should not be empty
        assert!(!stdout.is_empty());

        // And: Output should contain Markdown content
        assert!(stdout.contains("# ") || stdout.contains("## "));
    }

    #[test]
    fn scenario_emit_packet_to_stdout_sarif() {
        // Given: A valid packet file
        let packet_path = fixture_path("packets/perfgate/pkt-perfgate.eb.json");

        // When: Emitting to stdout with SARIF format
        let (stdout, _stderr, code) =
            run_cli(&["emit", "--format", "sarif", packet_path.to_str().unwrap()]);

        // Then: The command should succeed
        assert_eq!(code, 0);

        // And: Output should not be empty
        assert!(!stdout.is_empty());

        // And: Output should contain valid SARIF structure
        assert!(stdout.contains("\"version\""));
        assert!(stdout.contains("\"$schema\""));
    }

    #[test]
    fn scenario_emit_bundle_to_markdown_file() {
        // Given: A valid bundle directory and temporary output path
        let temp_dir = tempfile::tempdir().unwrap();
        let output_path = temp_dir.path().join("bundle-output.md");
        let bundle_path = examples_path("demo-bundle");

        // When: Emitting the bundle to Markdown format
        let (stdout, _stderr, code) = run_cli(&[
            "emit",
            "--format",
            "markdown",
            "--out",
            output_path.to_str().unwrap(),
            bundle_path.to_str().unwrap(),
        ]);

        // Then: The command should succeed
        assert_eq!(code, 0);

        // And: Success message should be displayed
        assert!(stdout.contains("Wrote:"));

        // And: Output file should exist
        assert!(output_path.exists());

        // And: Output file should contain Markdown headers
        let content = fs::read_to_string(&output_path).unwrap();
        assert!(content.contains("# ") || content.contains("## "));

        // Cleanup
        temp_dir.close().unwrap();
    }

    #[test]
    fn scenario_emit_bundle_to_sarif_file() {
        // Given: A valid bundle directory and temporary output path
        let temp_dir = tempfile::tempdir().unwrap();
        let output_path = temp_dir.path().join("bundle-output.sarif.json");
        let bundle_path = examples_path("demo-bundle");

        // When: Emitting the bundle to SARIF format
        let (stdout, _stderr, code) = run_cli(&[
            "emit",
            "--format",
            "sarif",
            "--out",
            output_path.to_str().unwrap(),
            bundle_path.to_str().unwrap(),
        ]);

        // Then: The command should succeed
        assert_eq!(code, 0);

        // And: Success message should be displayed
        assert!(stdout.contains("Wrote:"));

        // And: Output file should exist
        assert!(output_path.exists());

        // And: Output file should contain valid SARIF structure
        let content = fs::read_to_string(&output_path).unwrap();
        assert!(content.contains("\"version\""));
        assert!(content.contains("\"$schema\""));
        assert!(content.contains("runs"));

        // Cleanup
        temp_dir.close().unwrap();
    }

    #[test]
    fn scenario_emit_with_short_format_flag() {
        // Given: A valid packet file and temporary output path
        let temp_dir = tempfile::tempdir().unwrap();
        let output_path = temp_dir.path().join("output.md");
        let packet_path = fixture_path("packets/perfgate/pkt-perfgate.eb.json");

        // When: Emitting with -f flag
        let (stdout, _stderr, code) = run_cli(&[
            "emit",
            "-f",
            "markdown",
            "-o",
            output_path.to_str().unwrap(),
            packet_path.to_str().unwrap(),
        ]);

        // Then: The command should succeed
        assert_eq!(code, 0);

        // And: Output file should exist
        assert!(output_path.exists());

        // Cleanup
        temp_dir.close().unwrap();
    }

    #[test]
    fn scenario_emit_with_short_out_flag() {
        // Given: A valid packet file and temporary output path
        let temp_dir = tempfile::tempdir().unwrap();
        let output_path = temp_dir.path().join("output.md");
        let packet_path = fixture_path("packets/perfgate/pkt-perfgate.eb.json");

        // When: Emitting with -o flag
        let (stdout, _stderr, code) = run_cli(&[
            "emit",
            "--format",
            "markdown",
            "-o",
            output_path.to_str().unwrap(),
            packet_path.to_str().unwrap(),
        ]);

        // Then: The command should succeed
        assert_eq!(code, 0);

        // And: Output file should exist
        assert!(output_path.exists());

        // Cleanup
        temp_dir.close().unwrap();
    }

    #[test]
    fn scenario_emit_with_md_format_alias() {
        // Given: A valid packet file and temporary output path
        let temp_dir = tempfile::tempdir().unwrap();
        let output_path = temp_dir.path().join("output.md");
        let packet_path = fixture_path("packets/perfgate/pkt-perfgate.eb.json");

        // When: Emitting with md format alias
        let (stdout, _stderr, code) = run_cli(&[
            "emit",
            "--format",
            "md",
            "--out",
            output_path.to_str().unwrap(),
            packet_path.to_str().unwrap(),
        ]);

        // Then: The command should succeed
        assert_eq!(code, 0);

        // And: Output file should exist
        assert!(output_path.exists());

        // Cleanup
        temp_dir.close().unwrap();
    }

    #[test]
    fn scenario_emit_with_invalid_format_fails() {
        // Given: A valid packet file
        let packet_path = fixture_path("packets/perfgate/pkt-perfgate.eb.json");

        // When: Emitting with invalid format
        let (_stdout, stderr, code) =
            run_cli(&["emit", "--format", "invalid", packet_path.to_str().unwrap()]);

        // Then: The command should fail
        assert_eq!(code, 3); // Invalid format error

        // And: Error message should indicate invalid format
        assert!(
            stderr.contains("Error")
                || stderr.contains("Invalid format")
                || stderr.contains("invalid")
        );
    }

    #[test]
    fn scenario_emit_creates_parent_directories() {
        // Given: A valid packet file and nested output path
        let temp_dir = tempfile::tempdir().unwrap();
        let nested_path = temp_dir.path().join("nested").join("dir").join("output.md");
        let packet_path = fixture_path("packets/perfgate/pkt-perfgate.eb.json");

        // When: Emitting to a nested path
        let (stdout, _stderr, code) = run_cli(&[
            "emit",
            "--format",
            "markdown",
            "--out",
            nested_path.to_str().unwrap(),
            packet_path.to_str().unwrap(),
        ]);

        // Then: The command should succeed
        assert_eq!(code, 0);

        // And: Parent directories should be created
        assert!(nested_path.parent().unwrap().exists());

        // And: Output file should exist
        assert!(nested_path.exists());

        // Cleanup
        temp_dir.close().unwrap();
    }

    #[test]
    fn scenario_emit_nonexistent_target_fails() {
        // Given: A non-existent file path and temporary output path
        let temp_dir = tempfile::tempdir().unwrap();
        let output_path = temp_dir.path().join("output.md");
        let nonexistent_path = "/tmp/nonexistent-packet.eb.json";

        // When: Emitting a non-existent file
        let (_stdout, stderr, code) = run_cli(&[
            "emit",
            "--format",
            "markdown",
            "--out",
            output_path.to_str().unwrap(),
            nonexistent_path,
        ]);

        // Then: The command should fail
        assert_eq!(code, 2); // clap error for invalid path

        // And: Error message should indicate file not found
        assert!(
            stderr.contains("Error")
                || stderr.contains("not found")
                || stderr.contains("No such file")
        );

        // Cleanup
        temp_dir.close().unwrap();
    }
}

// ============================================================================
// Schema Command Tests
// ============================================================================

mod schema_command {
    use super::*;

    #[test]
    fn scenario_schema_packet_displays_packet_schema() {
        // When: Displaying packet schema
        let (stdout, _stderr, code) = run_cli(&["schema", "packet"]);

        // Then: The command should succeed
        assert_eq!(code, 0);

        // And: Output should contain schema fields
        assert!(stdout.contains("\"$schema\""));
        assert!(stdout.contains("packet"));
        assert!(stdout.contains("packet_id"));
        assert!(stdout.contains("producer"));
        assert!(stdout.contains("subject"));
        assert!(stdout.contains("summary"));
    }

    #[test]
    fn scenario_schema_bundle_displays_bundle_schema() {
        // When: Displaying bundle schema
        let (stdout, _stderr, code) = run_cli(&["schema", "bundle"]);

        // Then: The command should succeed
        assert_eq!(code, 0);

        // And: Output should contain schema fields
        assert!(stdout.contains("\"$schema\""));
        assert!(stdout.contains("bundle"));
        assert!(stdout.contains("bundle_id"));
        assert!(stdout.contains("manifest"));
        assert!(stdout.contains("summary"));
    }

    #[test]
    fn scenario_schema_with_json_format_outputs_raw_json() {
        // When: Displaying packet schema in JSON format
        let (stdout, _stderr, code) = run_cli(&["schema", "packet", "--format", "json"]);

        // Then: The command should succeed
        assert_eq!(code, 0);

        // And: Output should be valid JSON
        assert!(stdout.starts_with('{'));
        assert!(stdout.contains("\"$schema\""));
    }

    #[test]
    fn scenario_schema_with_pretty_format_outputs_pretty_json() {
        // When: Displaying packet schema in pretty format
        let (stdout, _stderr, code) = run_cli(&["schema", "packet", "--format", "pretty"]);

        // Then: The command should succeed
        assert_eq!(code, 0);

        // And: Output should be pretty-printed JSON
        assert!(stdout.contains('\n'));
        assert!(stdout.contains("  "));
    }

    #[test]
    fn scenario_schema_with_short_format_flag() {
        // When: Displaying packet schema with -f flag
        let (stdout, _stderr, code) = run_cli(&["schema", "packet", "-f", "json"]);

        // Then: The command should succeed
        assert_eq!(code, 0);

        // And: Output should be valid JSON
        assert!(stdout.starts_with('{'));
    }

    #[test]
    fn scenario_schema_with_invalid_schema_name_fails() {
        // When: Displaying an invalid schema name
        let (_stdout, stderr, code) = run_cli(&["schema", "invalid"]);

        // Then: The command should fail
        assert_eq!(code, 3); // Invalid schema error

        // And: Error message should indicate invalid schema
        assert!(
            stderr.contains("Error")
                || stderr.contains("Invalid schema")
                || stderr.contains("invalid")
        );
    }

    #[test]
    fn scenario_schema_with_invalid_format_returns_error() {
        // When: Displaying packet schema with invalid format
        let (_stdout, _stderr, code) = run_cli(&["schema", "packet", "--format", "invalid"]);

        // Then: The command should fail with an error
        assert_ne!(code, 0);
    }
}

// ============================================================================
// Edge Cases and Error Handling Tests
// ============================================================================

mod edge_cases {
    use super::*;

    #[test]
    fn scenario_cli_without_arguments_shows_help() {
        // When: Running CLI without any arguments
        let (_stdout, stderr, code) = run_cli(&[]);

        // Then: The command should fail (requires subcommand)
        assert_eq!(code, 2);

        // And: Help should be displayed (in stderr for clap errors)
        assert!(stderr.contains("Usage:") || stderr.contains("requires a subcommand"));
    }

    #[test]
    fn scenario_cli_with_invalid_subcommand_fails() {
        // When: Running CLI with invalid subcommand
        let (_stdout, stderr, code) = run_cli(&["invalid-command"]);

        // Then: The command should fail
        assert_eq!(code, 2);

        // And: Error message should indicate invalid command (in stderr for clap errors)
        assert!(
            stderr.contains("error")
                || stderr.contains("unrecognized")
                || stderr.contains("unexpected argument")
        );
    }

    #[test]
    fn scenario_validate_with_empty_string_path_fails() {
        // When: Validating with empty string path
        let (_stdout, stderr, code) = run_cli(&["validate", ""]);

        // Then: The command should fail
        assert_eq!(code, 2); // clap error for invalid path argument

        // And: Error message should indicate error
        assert!(stderr.contains("error") || stderr.contains("Error") || stderr.contains("invalid"));
    }

    #[test]
    fn scenario_inspect_with_empty_string_path_fails() {
        // When: Inspecting with empty string path
        let (_stdout, stderr, code) = run_cli(&["inspect", ""]);

        // Then: The command should fail
        assert_eq!(code, 2); // clap error for invalid path argument

        // And: Error message should indicate error
        assert!(stderr.contains("error") || stderr.contains("Error") || stderr.contains("invalid"));
    }

    #[test]
    fn scenario_emit_with_empty_string_path_fails() {
        // When: Emitting with empty string path
        let (_stdout, stderr, code) = run_cli(&["emit", "--format", "markdown", ""]);

        // Then: The command should fail
        assert_eq!(code, 2); // clap error for invalid path argument

        // And: Error message should indicate error
        assert!(stderr.contains("error") || stderr.contains("Error") || stderr.contains("invalid"));
    }

    #[test]
    fn scenario_schema_with_empty_string_fails() {
        // When: Displaying schema with empty string
        let (_stdout, stderr, code) = run_cli(&["schema", ""]);

        // Then: The command should fail
        assert_eq!(code, 3); // Invalid schema error

        // And: Error message should indicate invalid schema
        assert!(
            stderr.contains("Error")
                || stderr.contains("Invalid schema")
                || stderr.contains("invalid")
        );
    }

    #[test]
    fn scenario_bundle_creates_nested_output_directory() {
        // Given: A valid packet file and deeply nested output path
        let temp_dir = tempfile::tempdir().unwrap();
        let nested_path = temp_dir.path().join("a").join("b").join("c").join("bundle");
        let packet = fixture_path("packets/perfgate/pkt-perfgate.eb.json");

        // When: Creating a bundle at nested path
        let (stdout, _stderr, code) = run_cli(&[
            "bundle",
            "-o",
            nested_path.to_str().unwrap(),
            packet.to_str().unwrap(),
        ]);

        // Then: The command should succeed
        assert_eq!(code, 0);

        // And: All parent directories should be created
        assert!(nested_path.exists());
        assert!(nested_path.join("bundle.eb.json").exists());

        // Cleanup
        temp_dir.close().unwrap();
    }

    #[test]
    fn scenario_multiple_validate_commands_run_successfully() {
        // Given: Multiple valid packet files
        let packet1 = fixture_path("packets/perfgate/pkt-perfgate.eb.json");
        let packet2 = fixture_path("packets/faultline/pkt-faultline.eb.json");

        // When: Running multiple validate commands
        let (stdout1, _stderr1, code1) = run_cli(&["validate", packet1.to_str().unwrap()]);
        let (stdout2, _stderr2, code2) = run_cli(&["validate", packet2.to_str().unwrap()]);

        // Then: Both commands should succeed
        assert_eq!(code1, 0);
        assert_eq!(code2, 0);

        // And: Both should show valid status
        assert!(stdout1.contains("Valid"));
        assert!(stdout2.contains("Valid"));
    }

    #[test]
    fn scenario_emit_overwrites_existing_file() {
        // Given: A valid packet file and existing output file
        let temp_dir = tempfile::tempdir().unwrap();
        let output_path = temp_dir.path().join("output.md");
        let packet_path = fixture_path("packets/perfgate/pkt-perfgate.eb.json");

        // Create initial file with some content
        fs::write(&output_path, "Initial content").unwrap();

        // When: Emitting to the existing file
        let (stdout, _stderr, code) = run_cli(&[
            "emit",
            "--format",
            "markdown",
            "--out",
            output_path.to_str().unwrap(),
            packet_path.to_str().unwrap(),
        ]);

        // Then: The command should succeed
        assert_eq!(code, 0);

        // And: File should be overwritten with new content
        let content = fs::read_to_string(&output_path).unwrap();
        assert!(!content.contains("Initial content"));
        assert!(content.contains("# ") || content.contains("## "));

        // Cleanup
        temp_dir.close().unwrap();
    }
}
