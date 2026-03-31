use std::fs;
use std::path::PathBuf;

use clap::{Args, Parser, Subcommand, ValueEnum};
use evidencebus_codes::{ExitCode, ValidationMode};
use evidencebus_export::{
    render_markdown_bundle, render_markdown_packet, render_sarif_bundle, render_sarif_packet,
};
use evidencebus_fs::{build_bundle, load_target, validate_target, FsError, LoadedTarget};

const PACKET_SCHEMA: &str = include_str!("../../../schemas/packet.schema.json");
const BUNDLE_SCHEMA: &str = include_str!("../../../schemas/bundle.schema.json");

#[derive(Debug, Parser)]
#[command(name = "evidencebus")]
#[command(about = "Schema-first evidence backplane for repo operations")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    Validate(ValidateArgs),
    Bundle(BundleArgs),
    Inspect(TargetPath),
    Emit(EmitArgs),
    Schema(SchemaArgs),
}

#[derive(Debug, Args)]
struct TargetPath {
    target: PathBuf,
}

#[derive(Debug, Args)]
struct ValidateArgs {
    target: PathBuf,
    #[arg(long, value_enum, default_value_t = ValidationModeArg::Strict)]
    mode: ValidationModeArg,
}

#[derive(Debug, Args)]
struct BundleArgs {
    #[arg(required = true)]
    packets: Vec<PathBuf>,
    #[arg(long)]
    out: PathBuf,
}

#[derive(Debug, Args)]
struct EmitArgs {
    #[arg(value_enum)]
    format: EmitFormat,
    target: PathBuf,
    #[arg(long)]
    out: PathBuf,
}

#[derive(Debug, Args)]
struct SchemaArgs {
    #[arg(value_enum)]
    kind: SchemaKind,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum ValidationModeArg {
    SchemaOnly,
    Strict,
}

impl From<ValidationModeArg> for ValidationMode {
    fn from(value: ValidationModeArg) -> Self {
        match value {
            ValidationModeArg::SchemaOnly => ValidationMode::SchemaOnly,
            ValidationModeArg::Strict => ValidationMode::Strict,
        }
    }
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum EmitFormat {
    Markdown,
    Sarif,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum SchemaKind {
    Packet,
    Bundle,
}

fn main() {
    let cli = Cli::parse();
    let exit = match run(cli) {
        Ok(code) => code,
        Err(error) => {
            eprintln!("{error}");
            match &error {
                CliError::Fs(FsError::Validation(_)) => ExitCode::ValidationFailed,
                CliError::Fs(FsError::InvalidInput(_)) => ExitCode::InvalidInput,
                CliError::Fs(FsError::Io { .. }) | CliError::Io(_) => ExitCode::Io,
                CliError::Fs(FsError::Json { .. }) => ExitCode::InvalidInput,
                CliError::Fs(FsError::Core(_)) => ExitCode::Internal,
                CliError::Export(_) => ExitCode::ExportFailed,
            }
        }
    };

    std::process::exit(exit.code());
}

fn run(cli: Cli) -> Result<ExitCode, CliError> {
    match cli.command {
        Command::Validate(args) => {
            let report = validate_target(&args.target, args.mode.into())?;
            if report.is_valid() {
                println!("valid: {}", args.target.display());
                return Ok(ExitCode::Success);
            }

            for issue in &report.issues {
                match &issue.location {
                    Some(location) => {
                        println!(
                            "{:?}: {:?}: {} ({})",
                            issue.level, issue.code, issue.message, location
                        );
                    }
                    None => {
                        println!("{:?}: {:?}: {}", issue.level, issue.code, issue.message);
                    }
                }
            }

            Ok(ExitCode::ValidationFailed)
        }
        Command::Bundle(args) => {
            let manifest = build_bundle(&args.packets, &args.out)?;
            println!(
                "bundle created: {} ({} packets)",
                args.out.display(),
                manifest.summary.packet_count
            );
            Ok(ExitCode::Success)
        }
        Command::Inspect(args) => {
            match load_target(&args.target)? {
                LoadedTarget::Packet(packet) => {
                    println!("packet: {}", packet.packet_id);
                    println!("tool: {} {}", packet.producer.tool, packet.producer.version);
                    println!("status: {:?}", packet.summary.status);
                    println!("attachments: {}", packet.projections.attachments.len());
                }
                LoadedTarget::Bundle(bundle) => {
                    println!("bundle: {}", bundle.manifest.bundle_id);
                    println!("packets: {}", bundle.manifest.summary.packet_count);
                    println!(
                        "summary: pass={} fail={} warn={} indeterminate={} error={}",
                        bundle.manifest.summary.pass_count,
                        bundle.manifest.summary.fail_count,
                        bundle.manifest.summary.warn_count,
                        bundle.manifest.summary.indeterminate_count,
                        bundle.manifest.summary.error_count,
                    );
                }
            }
            Ok(ExitCode::Success)
        }
        Command::Emit(args) => {
            let rendered = match (args.format, load_target(&args.target)?) {
                (EmitFormat::Markdown, LoadedTarget::Packet(packet)) => {
                    render_markdown_packet(&packet)
                }
                (EmitFormat::Markdown, LoadedTarget::Bundle(bundle)) => {
                    render_markdown_bundle(&bundle.manifest, &bundle.packets)
                }
                (EmitFormat::Sarif, LoadedTarget::Packet(packet)) => {
                    render_sarif_packet(&packet)?
                }
                (EmitFormat::Sarif, LoadedTarget::Bundle(bundle)) => {
                    render_sarif_bundle(&bundle.manifest, &bundle.packets)?
                }
            };

            if let Some(parent) = args
                .out
                .parent()
                .filter(|parent| !parent.as_os_str().is_empty())
            {
                fs::create_dir_all(parent)?;
            }
            fs::write(&args.out, rendered)?;
            println!("wrote {}", args.out.display());
            Ok(ExitCode::Success)
        }
        Command::Schema(args) => {
            match args.kind {
                SchemaKind::Packet => print!("{PACKET_SCHEMA}"),
                SchemaKind::Bundle => print!("{BUNDLE_SCHEMA}"),
            }
            Ok(ExitCode::Success)
        }
    }
}

#[derive(Debug, thiserror::Error)]
enum CliError {
    #[error(transparent)]
    Fs(#[from] FsError),
    #[error(transparent)]
    Export(#[from] evidencebus_export::ExportError),
    #[error(transparent)]
    Io(#[from] std::io::Error),
}
