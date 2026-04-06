//! evidencebus CLI - Schema-first evidence backplane for repo operations
//!
//! This CLI provides commands for validating packets/bundles, creating bundles,
//! inspecting content, exporting to Markdown/SARIF, and displaying schema information.

use std::fs;
use std::io::{self, Write};
use std::path::PathBuf;

use clap::{Parser, Subcommand};
use evidencebus_codes::{ExitCode, FindingSeverity, PacketStatus, ValidationMode};
use evidencebus_export::{
    export_bundle_markdown, export_packet_markdown, export_packets_sarif, ExportError,
};
use evidencebus_fs::{build_bundle, load_target, validate_target, FsError, LoadedTarget};
use evidencebus_types::{
    Bundle, BundleSummary, Packet, PacketId, SchemaVersion, SeverityCounts, StatusCounts,
};
use miette::Diagnostic;
use serde::Serialize;
use termcolor::{Color, ColorSpec, StandardStream, WriteColor};

const PACKET_SCHEMA: &str = include_str!("../../../schemas/packet.schema.json");
const BUNDLE_SCHEMA: &str = include_str!("../../../schemas/bundle.schema.json");

/// Schema-first evidence backplane for repo operations
#[derive(Parser)]
#[command(name = "evidencebus")]
#[command(version, about, long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Validate a packet or bundle
    Validate {
        /// Path to packet file or bundle directory
        target: PathBuf,
        /// Validate schema only, skip file existence checks
        #[arg(short = 's', long)]
        schema_only: bool,
    },

    /// Create a bundle from packet files
    Bundle {
        /// Packet files to include in bundle
        #[arg(required = true)]
        packets: Vec<PathBuf>,
        /// Output directory for bundle
        #[arg(short = 'o', long, default_value = "./evidence-bundle")]
        out: PathBuf,
    },

    /// Inspect a packet or bundle
    Inspect {
        /// Path to packet file or bundle directory
        target: PathBuf,
        /// Output format (text, json)
        #[arg(short = 'f', long, default_value = "text")]
        format: String,
    },

    /// Export a packet or bundle
    Emit {
        /// Path to packet file or bundle directory
        target: PathBuf,
        /// Output format (markdown, sarif)
        #[arg(short = 'f', long, required = true)]
        format: String,
        /// Output file
        #[arg(short = 'o', long)]
        out: Option<PathBuf>,
        /// Include detailed output
        #[arg(short = 'd', long)]
        details: bool,
        /// Include artifacts in output
        #[arg(short = 'a', long)]
        artifacts: bool,
    },

    /// Display schema information
    Schema {
        /// Schema to display (packet, bundle)
        schema: String,
        /// Output format (json, pretty)
        #[arg(short = 'f', long, default_value = "pretty")]
        format: String,
    },
}

/// JSON representation of LoadedTarget for CLI output
#[derive(Debug, Serialize)]
#[serde(untagged)]
#[allow(clippy::large_enum_variant)]
enum LoadedTargetJson {
    Packet(Packet),
    Bundle {
        manifest: serde_json::Value,
        packets: Vec<Packet>,
    },
}

/// CLI error type with miette support
#[derive(Debug, Diagnostic, thiserror::Error)]
enum CliError {
    #[error("IO error: {0}")]
    #[diagnostic(code(evidencebus::cli::io))]
    Io(#[from] std::io::Error),

    #[error("Filesystem error: {0}")]
    #[diagnostic(code(evidencebus::cli::fs))]
    Fs(#[from] FsError),

    #[error("Export error: {0}")]
    #[diagnostic(code(evidencebus::cli::export))]
    Export(#[from] ExportError),

    #[error("JSON error: {0}")]
    #[diagnostic(code(evidencebus::cli::json))]
    Json(#[from] serde_json::Error),

    #[error("Invalid format: {0}")]
    #[diagnostic(code(evidencebus::cli::invalid_format))]
    InvalidFormat(String),

    #[error("Invalid schema: {0}")]
    #[diagnostic(code(evidencebus::cli::invalid_schema))]
    InvalidSchema(String),

    #[error("Target not found: {0}")]
    #[diagnostic(code(evidencebus::cli::not_found))]
    #[allow(dead_code)]
    NotFound(PathBuf),
}

impl From<CliError> for ExitCode {
    fn from(err: CliError) -> Self {
        match err {
            CliError::Fs(FsError::ValidationError(_))
            | CliError::Fs(FsError::BundleValidationError(_))
            | CliError::Fs(FsError::DigestError(_))
            | CliError::Fs(FsError::InvalidInput(_)) => ExitCode::ValidationFailed,
            CliError::Io(_) | CliError::Fs(FsError::IoError { .. }) => ExitCode::Io,
            CliError::Fs(FsError::InvalidJson { .. }) => ExitCode::InvalidInput,
            CliError::Export(_) => ExitCode::ExportFailed,
            CliError::Json(_) => ExitCode::InvalidInput,
            CliError::InvalidFormat(_) | CliError::InvalidSchema(_) => ExitCode::InvalidInput,
            CliError::NotFound(_) => ExitCode::Io,
            CliError::Fs(FsError::PathError(_))
            | CliError::Fs(FsError::BundleCreationFailed(_))
            | CliError::Fs(FsError::ArtifactCopyFailed(_))
            | CliError::Fs(FsError::CanonicalizationError(_))
            | CliError::Fs(FsError::CoreError(_)) => ExitCode::Internal,
        }
    }
}

/// Helper for colored terminal output
struct TermWriter {
    stdout: StandardStream,
    stderr: StandardStream,
}

impl TermWriter {
    fn new() -> Self {
        Self {
            stdout: StandardStream::stdout(termcolor::ColorChoice::Auto),
            stderr: StandardStream::stderr(termcolor::ColorChoice::Auto),
        }
    }

    fn write_color<F>(&mut self, color: Color, f: F) -> io::Result<()>
    where
        F: FnOnce(&mut StandardStream) -> io::Result<()>,
    {
        self.stdout
            .set_color(ColorSpec::new().set_fg(Some(color)))?;
        f(&mut self.stdout)?;
        self.stdout.reset()?;
        Ok(())
    }

    fn write_success(&mut self, msg: &str) -> io::Result<()> {
        self.write_color(Color::Green, |w| writeln!(w, "{}", msg))
    }

    fn write_error(&mut self, msg: &str) -> io::Result<()> {
        self.stderr
            .set_color(ColorSpec::new().set_fg(Some(Color::Red)))?;
        writeln!(self.stderr, "{}", msg)?;
        self.stderr.reset()?;
        Ok(())
    }

    #[allow(dead_code)]
    fn write_warn(&mut self, msg: &str) -> io::Result<()> {
        self.write_color(Color::Yellow, |w| writeln!(w, "{}", msg))
    }

    fn write_info(&mut self, msg: &str) -> io::Result<()> {
        self.write_color(Color::Cyan, |w| writeln!(w, "{}", msg))
    }

    fn write(&mut self, msg: &str) -> io::Result<()> {
        writeln!(self.stdout, "{}", msg)
    }
}

fn main() {
    let cli = Cli::parse();
    let result = run(cli);

    match result {
        Ok(exit_code) => {
            std::process::exit(exit_code.code());
        }
        Err(err) => {
            let mut term = TermWriter::new();
            let _ = term.write_error(&format!("Error: {}", err));
            let exit_code: ExitCode = err.into();
            std::process::exit(exit_code.code());
        }
    }
}

fn run(cli: Cli) -> Result<ExitCode, CliError> {
    match cli.command {
        Commands::Validate {
            target,
            schema_only,
        } => cmd_validate(target, schema_only),
        Commands::Bundle { packets, out } => cmd_bundle(packets, out),
        Commands::Inspect { target, format } => cmd_inspect(target, &format),
        Commands::Emit {
            target,
            format,
            out,
            details,
            artifacts,
        } => cmd_emit(target, &format, out, details, artifacts),
        Commands::Schema { schema, format } => cmd_schema(&schema, &format),
    }
}

/// Validate a packet or bundle
fn cmd_validate(target: PathBuf, schema_only: bool) -> Result<ExitCode, CliError> {
    let mode = if schema_only {
        ValidationMode::SchemaOnly
    } else {
        ValidationMode::Strict
    };

    let mut term = TermWriter::new();

    match validate_target(&target, mode) {
        Ok(()) => {
            term.write_success(&format!("✓ Valid: {}", target.display()))?;
            Ok(ExitCode::Success)
        }
        Err(e) => {
            term.write_error(&format!("✗ Invalid: {}", target.display()))?;
            term.write(&format!("  {}", e))?;
            Ok(ExitCode::ValidationFailed)
        }
    }
}

/// Create a bundle from packet files
fn cmd_bundle(packets: Vec<PathBuf>, out: PathBuf) -> Result<ExitCode, CliError> {
    let mut term = TermWriter::new();

    term.write_info(&format!(
        "Creating bundle from {} packet(s)...",
        packets.len()
    ))?;

    let manifest = build_bundle(&packets, &out)?;

    term.write_success(&format!("✓ Bundle created: {}", out.display()))?;
    term.write(&format!("  Packets: {}", manifest.packets.len()))?;
    term.write(&format!("  Artifacts: {}", manifest.artifacts.len()))?;

    Ok(ExitCode::Success)
}

/// Inspect a packet or bundle
fn cmd_inspect(target: PathBuf, format: &str) -> Result<ExitCode, CliError> {
    let loaded = load_target(&target)?;

    match format.to_lowercase().as_str() {
        "json" => {
            let json = match loaded {
                LoadedTarget::Packet(packet) => {
                    serde_json::to_value(LoadedTargetJson::Packet(packet))?
                }
                LoadedTarget::Bundle(bundle) => {
                    let manifest_json = serde_json::to_value(&bundle.manifest)?;
                    serde_json::to_value(LoadedTargetJson::Bundle {
                        manifest: manifest_json,
                        packets: bundle.packets,
                    })?
                }
            };
            println!("{}", serde_json::to_string_pretty(&json)?);
        }
        "text" => {
            let mut term = TermWriter::new();

            match loaded {
                LoadedTarget::Packet(packet) => {
                    term.write(&format!("Packet: {}", packet.packet_id))?;
                    term.write(&format!(
                        "  Producer: {} {}",
                        packet.producer.tool_name, packet.producer.tool_version
                    ))?;
                    term.write(&format!("  Status: {:?}", packet.summary.status))?;
                    term.write(&format!("  Title: {}", packet.summary.title))?;
                    term.write(&format!("  Summary: {}", packet.summary.short_summary))?;
                    term.write(&format!(
                        "  Attachments: {}",
                        packet.projections.attachments.len()
                    ))?;
                    term.write("  Projections:")?;
                    term.write(&format!(
                        "    Findings: {}",
                        packet.projections.findings.len()
                    ))?;
                    term.write(&format!(
                        "    Metrics: {}",
                        packet.projections.metrics.len()
                    ))?;
                }
                LoadedTarget::Bundle(bundle) => {
                    // Calculate summary from packets
                    let mut pass_count = 0;
                    let mut fail_count = 0;
                    let mut warn_count = 0;
                    let mut indeterminate_count = 0;
                    let mut error_count = 0;

                    for packet in &bundle.packets {
                        match packet.summary.status {
                            PacketStatus::Pass => pass_count += 1,
                            PacketStatus::Fail => fail_count += 1,
                            PacketStatus::Warn => warn_count += 1,
                            PacketStatus::Indeterminate => indeterminate_count += 1,
                            PacketStatus::Error => error_count += 1,
                        }
                    }

                    term.write(&format!("Bundle: {} packets", bundle.packets.len()))?;
                    term.write(&format!("  Packets: {}", bundle.manifest.packets.len()))?;
                    term.write(&format!("  Artifacts: {}", bundle.manifest.artifacts.len()))?;
                    term.write("  Summary:")?;
                    term.write(&format!("    Pass: {}", pass_count))?;
                    term.write(&format!("    Fail: {}", fail_count))?;
                    term.write(&format!("    Warn: {}", warn_count))?;
                    term.write(&format!("    Indeterminate: {}", indeterminate_count))?;
                    term.write(&format!("    Error: {}", error_count))?;
                }
            }
        }
        other => return Err(CliError::InvalidFormat(other.to_string())),
    }

    Ok(ExitCode::Success)
}

/// Calculate status and severity counts from packets
fn calculate_counts(packets: &[Packet]) -> (StatusCounts, SeverityCounts) {
    let mut status_counts = StatusCounts {
        pass: 0,
        fail: 0,
        warn: 0,
        indeterminate: 0,
        error: 0,
    };
    let mut severity_counts = SeverityCounts {
        note: 0,
        warning: 0,
        error: 0,
    };

    for packet in packets {
        match packet.summary.status {
            PacketStatus::Pass => status_counts.pass += 1,
            PacketStatus::Fail => status_counts.fail += 1,
            PacketStatus::Warn => status_counts.warn += 1,
            PacketStatus::Indeterminate => status_counts.indeterminate += 1,
            PacketStatus::Error => status_counts.error += 1,
        }

        for finding in &packet.projections.findings {
            match finding.severity {
                FindingSeverity::Note => severity_counts.note += 1,
                FindingSeverity::Warning => severity_counts.warning += 1,
                FindingSeverity::Error => severity_counts.error += 1,
            }
        }
    }

    (status_counts, severity_counts)
}

/// Export a packet or bundle
fn cmd_emit(
    target: PathBuf,
    format: &str,
    out: Option<PathBuf>,
    _details: bool,
    _artifacts: bool,
) -> Result<ExitCode, CliError> {
    let loaded = load_target(&target)?;
    let mut term = TermWriter::new();

    let rendered = match format.to_lowercase().as_str() {
        "markdown" | "md" => match loaded {
            LoadedTarget::Packet(packet) => export_packet_markdown(&packet)?,
            LoadedTarget::Bundle(bundle) => {
                // Create a Bundle from loaded data
                let (status_counts, severity_counts) = calculate_counts(&bundle.packets);
                let bundle_id = match bundle.manifest.packets.first() {
                    Some(e) => e.packet_id.clone(),
                    None => PacketId::new("unknown").map_err(|e| {
                        CliError::InvalidFormat(format!("invalid fallback packet id: {e}"))
                    })?,
                };
                let total_artifacts = bundle.manifest.artifacts.len() as u32;
                let bundle_obj = Bundle {
                    eb_version: SchemaVersion::new("1.0"),
                    bundle_id,
                    created_at: chrono::Utc::now().to_rfc3339(),
                    manifest: bundle.manifest,
                    summary: BundleSummary {
                        total_packets: bundle.packets.len() as u32,
                        total_artifacts,
                        status_counts,
                        severity_counts,
                    },
                };
                export_bundle_markdown(&bundle_obj)?
            }
        },
        "sarif" => match loaded {
            LoadedTarget::Packet(packet) => {
                let sarif = export_packets_sarif(&[packet])?;
                serde_json::to_string_pretty(&sarif)?
            }
            LoadedTarget::Bundle(bundle) => {
                let sarif = export_packets_sarif(&bundle.packets)?;
                serde_json::to_string_pretty(&sarif)?
            }
        },
        _ => return Err(CliError::InvalidFormat(format.to_string())),
    };

    match out {
        Some(output_path) => {
            if let Some(parent) = output_path
                .parent()
                .filter(|parent| !parent.as_os_str().is_empty())
            {
                fs::create_dir_all(parent)?;
            }
            fs::write(&output_path, rendered)?;
            term.write_success(&format!("✓ Wrote: {}", output_path.display()))?;
        }
        None => {
            print!("{}", rendered);
        }
    }

    Ok(ExitCode::Success)
}

/// Display schema information
fn cmd_schema(schema: &str, format: &str) -> Result<ExitCode, CliError> {
    let schema_content = match schema.to_lowercase().as_str() {
        "packet" => PACKET_SCHEMA,
        "bundle" => BUNDLE_SCHEMA,
        _ => return Err(CliError::InvalidSchema(schema.to_string())),
    };

    match format.to_lowercase().as_str() {
        "json" => {
            println!("{}", schema_content);
        }
        "pretty" => {
            let parsed: serde_json::Value = serde_json::from_str(schema_content)?;
            let pretty = serde_json::to_string_pretty(&parsed)?;
            println!("{}", pretty);
        }
        other => return Err(CliError::InvalidFormat(other.to_string())),
    }

    Ok(ExitCode::Success)
}
