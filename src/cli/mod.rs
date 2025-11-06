//! Command-line interface definitions for safetar.
use std::path::PathBuf;

use camino::Utf8PathBuf;
use clap::{Args, Parser, Subcommand, ValueHint};

const CLI_EXAMPLES: &str = "Examples:\n  safetar create -f backup.tar ./src\n  safetar extract -f backup.tar -C ./restore --strict\n  safetar list -f backup.tar --json\n";

/// Top-level CLI parser.
#[derive(Debug, Parser)]
#[command(
    name = "safetar",
    version,
    about = "Secure-by-default tar-compatible archiver",
    long_about = "A drop-in tar replacement that enables strict safety policies by default.",
    after_help = CLI_EXAMPLES,
    arg_required_else_help = true
)]
pub struct Cli {
    /// Command to execute.
    #[command(subcommand)]
    pub command: Commands,
}

/// Supported subcommands.
#[derive(Debug, Subcommand)]
pub enum Commands {
    /// Create an archive from files or directories.
    #[command(alias = "c")]
    Create(CreateArgs),
    /// Extract files from an archive.
    #[command(alias = "x")]
    Extract(ExtractArgs),
    /// List archive contents.
    #[command(alias = "t")]
    List(ListArgs),
}

/// Compression flags shared by multiple subcommands.
#[derive(Debug, Clone, Copy, Default)]
pub struct CompressionFlags {
    pub gzip: bool,
    pub xz: bool,
    pub zstd: bool,
}

impl CompressionFlags {
    /// Resolve the desired compression scheme from CLI flags.
    #[must_use]
    pub fn resolve(self) -> CompressionChoice {
        match (self.gzip, self.xz, self.zstd) {
            (true, false, false) => CompressionChoice::Gzip,
            (false, true, false) => CompressionChoice::Xz,
            (false, false, true) => CompressionChoice::Zstd,
            (false, false, false) => CompressionChoice::None,
            _ => CompressionChoice::Auto,
        }
    }
}

/// User-selected compression.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CompressionChoice {
    None,
    Gzip,
    Xz,
    Zstd,
    /// Multiple flags set; let the library reconcile with defaults.
    Auto,
}

/// Resource limit overrides shared by create/extract.
#[derive(Debug, Args, Clone, Default)]
pub struct LimitArgs {
    /// Maximum number of filesystem entries processed.
    #[arg(long = "max-files")]
    pub max_files: Option<u64>,
    /// Maximum total uncompressed bytes processed.
    #[arg(long = "max-total-bytes")]
    pub max_total_bytes: Option<u64>,
    /// Maximum single file size allowed.
    #[arg(long = "max-single-file")]
    pub max_single_file: Option<u64>,
    /// Maximum directory depth relative to the root.
    #[arg(long = "max-depth")]
    pub max_depth: Option<u32>,
}

/// Arguments for the `create` subcommand.
#[derive(Debug, Args)]
pub struct CreateArgs {
    /// Archive path to write.
    #[arg(short = 'f', long = "file", value_hint = ValueHint::FilePath)]
    pub file: Utf8PathBuf,
    /// Change to this directory before resolving inputs.
    #[arg(short = 'C', long = "directory", value_hint = ValueHint::DirPath)]
    pub directory: Option<Utf8PathBuf>,
    /// Emit verbose progress.
    #[arg(short = 'v', long = "verbose")]
    pub verbose: bool,
    /// Reduce output to errors only.
    #[arg(long = "quiet")]
    pub quiet: bool,
    /// Enable gzip compression.
    #[arg(short = 'z', long = "gzip")]
    pub gzip: bool,
    /// Enable xz compression.
    #[arg(short = 'J', long = "xz")]
    pub xz: bool,
    /// Enable zstd compression.
    #[arg(long = "zstd")]
    pub zstd: bool,
    /// Exclude entries matching these glob patterns.
    #[arg(long = "exclude")]
    pub exclude: Vec<String>,
    /// Read exclude patterns from these files.
    #[arg(long = "exclude-from", value_hint = ValueHint::FilePath)]
    pub exclude_from: Vec<PathBuf>,
    /// Write a manifest JSON file describing archive contents.
    #[arg(long = "manifest-out", value_hint = ValueHint::FilePath)]
    pub manifest_out: Option<Utf8PathBuf>,
    /// Track numeric owner values.
    #[arg(long = "numeric-owner")]
    pub numeric_owner: bool,
    /// Do not attempt to restore owners.
    #[arg(long = "no-same-owner")]
    pub no_same_owner: bool,
    /// Preview entries without writing the archive.
    #[arg(long = "print-plan")]
    pub print_plan: bool,
    /// Override resource limits.
    #[command(flatten)]
    pub limits: LimitArgs,
    /// Inputs to archive.
    #[arg(value_name = "PATH", required = true, value_hint = ValueHint::AnyPath)]
    pub inputs: Vec<Utf8PathBuf>,
}

impl CreateArgs {
    /// Collect compression flags into a helper struct.
    #[must_use]
    pub fn compression_flags(&self) -> CompressionFlags {
        CompressionFlags {
            gzip: self.gzip,
            xz: self.xz,
            zstd: self.zstd,
        }
    }
}

/// Arguments for the `extract` subcommand.
#[derive(Debug, Args)]
pub struct ExtractArgs {
    /// Archive to extract.
    #[arg(short = 'f', long = "file", value_hint = ValueHint::FilePath)]
    pub file: Utf8PathBuf,
    /// Destination directory (default: current directory).
    #[arg(short = 'C', long = "directory", value_hint = ValueHint::DirPath)]
    pub directory: Option<Utf8PathBuf>,
    /// Emit verbose progress.
    #[arg(short = 'v', long = "verbose")]
    pub verbose: bool,
    /// Reduce output to errors only.
    #[arg(long = "quiet")]
    pub quiet: bool,
    /// Fail on any policy violation.
    #[arg(long = "strict")]
    pub strict: bool,
    /// Explicit manifest to verify.
    #[arg(long = "manifest", value_hint = ValueHint::FilePath)]
    pub manifest: Option<Utf8PathBuf>,
    /// Allow additional files when verifying manifests.
    #[arg(long = "manifest-relaxed")]
    pub manifest_relaxed: bool,
    /// Assume numeric owner values from the archive.
    #[arg(long = "numeric-owner")]
    pub numeric_owner: bool,
    /// Do not attempt to restore owners.
    #[arg(long = "no-same-owner")]
    pub no_same_owner: bool,
    /// Override resource limits.
    #[command(flatten)]
    pub limits: LimitArgs,
}

/// Arguments for the `list` subcommand.
#[derive(Debug, Args)]
pub struct ListArgs {
    /// Archive to inspect.
    #[arg(short = 'f', long = "file", value_hint = ValueHint::FilePath)]
    pub file: Utf8PathBuf,
    /// Emit verbose metadata.
    #[arg(short = 'v', long = "verbose")]
    pub verbose: bool,
    /// Reduce output to errors only.
    #[arg(long = "quiet")]
    pub quiet: bool,
    /// Emit machine-readable JSON.
    #[arg(long = "json")]
    pub json: bool,
}
