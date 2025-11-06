//! safetar library entry points.

pub mod archive;
pub mod cli;
pub mod error;
pub mod io;
pub mod manifest;
pub mod policy;

use anyhow::{anyhow, Result};
use camino::Utf8PathBuf;

use crate::archive::{
    create_archive, extract_archive, list_archive, CreateOptions, ExtractOptions, ListOptions,
};
use crate::cli::{Cli, Commands, CreateArgs, ExtractArgs, ListArgs};
use crate::io::Compression;
use crate::policy::SecurityPolicy;

/// Execute the command represented by the parsed CLI input.
pub fn run(cli: Cli) -> Result<()> {
    match cli.command {
        Commands::Create(args) => handle_create(args),
        Commands::Extract(args) => handle_extract(args),
        Commands::List(args) => handle_list(args),
    }
}

fn handle_create(args: CreateArgs) -> Result<()> {
    let compression = choose_compression(args.compression_flags());
    let policy = base_policy(
        args.limits.max_files,
        args.limits.max_total_bytes,
        args.limits.max_single_file,
        args.limits.max_depth,
    );
    let exclude_from = args
        .exclude_from
        .into_iter()
        .map(|path| {
            Utf8PathBuf::from_path_buf(path).map_err(|_| anyhow!("exclude path must be UTF-8"))
        })
        .collect::<Result<Vec<_>>>()?;
    let options = CreateOptions {
        archive_path: args.file,
        inputs: args.inputs,
        work_dir: args.directory,
        compression,
        verbose: args.verbose,
        quiet: args.quiet,
        print_plan: args.print_plan,
        excludes: args.exclude,
        exclude_from,
        manifest_out: args.manifest_out,
        numeric_owner: args.numeric_owner,
        no_same_owner: args.no_same_owner,
    };
    let manifest = create_archive(&options, &policy)?;
    if options.verbose && !options.quiet {
        for entry in manifest {
            println!("added {} ({} bytes)", entry.path, entry.size);
        }
    }
    Ok(())
}

fn handle_extract(args: ExtractArgs) -> Result<()> {
    let policy = base_policy(
        args.limits.max_files,
        args.limits.max_total_bytes,
        args.limits.max_single_file,
        args.limits.max_depth,
    );
    let dest = args.directory.unwrap_or_else(|| Utf8PathBuf::from("."));
    let options = ExtractOptions {
        archive_path: args.file,
        destination: dest,
        verbose: args.verbose,
        quiet: args.quiet,
        strict: args.strict,
        manifest: args.manifest,
        manifest_relaxed: args.manifest_relaxed,
        numeric_owner: args.numeric_owner,
        no_same_owner: args.no_same_owner,
    };
    let manifest = extract_archive(&options, &policy)?;
    if options.verbose && !options.quiet {
        for entry in manifest {
            println!("extracted {} ({} bytes)", entry.path, entry.size);
        }
    }
    Ok(())
}

fn handle_list(args: ListArgs) -> Result<()> {
    let options = ListOptions {
        archive_path: args.file,
        verbose: args.verbose,
        quiet: args.quiet,
        json: args.json,
    };
    let manifest = list_archive(&options)?;
    if options.verbose && !options.json && !options.quiet {
        println!("total entries: {}", manifest.len());
    }
    Ok(())
}

fn choose_compression(flags: crate::cli::CompressionFlags) -> Compression {
    match flags.resolve() {
        crate::cli::CompressionChoice::None => Compression::None,
        crate::cli::CompressionChoice::Gzip => Compression::Gzip,
        crate::cli::CompressionChoice::Xz => Compression::Xz,
        crate::cli::CompressionChoice::Zstd => Compression::Zstd,
        crate::cli::CompressionChoice::Auto => Compression::Zstd,
    }
}

fn base_policy(
    max_files: Option<u64>,
    max_total_bytes: Option<u64>,
    max_single_file: Option<u64>,
    max_depth: Option<u32>,
) -> SecurityPolicy {
    SecurityPolicy::new()
        .with_max_files(max_files)
        .with_max_total_bytes(max_total_bytes)
        .with_max_single_file(max_single_file)
        .with_max_depth(max_depth)
}
