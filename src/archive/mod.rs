//! Archive creation, extraction, and listing logic.

use std::borrow::Cow;
use std::fs::{self, File};
use std::io::{self, Read};
use std::time::Duration;

use anyhow::{anyhow, Context, Result};
use camino::{Utf8Path, Utf8PathBuf};
use globset::{Glob, GlobSet, GlobSetBuilder};
use sha2::{Digest, Sha256};
use tar::{Archive, Builder, EntryType, HeaderMode};
use walkdir::WalkDir;

use self::pax as pax_mod;
use crate::archive::header::classify_entry_type;
use crate::error::UserInputError;
use crate::io::dec::wrap_reader;
use crate::io::enc::wrap_writer;
use crate::io::Compression;
use crate::manifest::{self, ManifestEntry, ManifestItem, ManifestKind};
use crate::policy::{LinkType, PolicyError, SecurityPolicy, UsageTracker};
use indicatif::{ProgressBar, ProgressStyle};

pub mod header;
pub mod pax;

/// Options that steer archive creation.
#[derive(Debug, Clone)]
pub struct CreateOptions {
    pub archive_path: Utf8PathBuf,
    pub inputs: Vec<Utf8PathBuf>,
    pub work_dir: Option<Utf8PathBuf>,
    pub compression: Compression,
    pub verbose: bool,
    pub quiet: bool,
    pub print_plan: bool,
    pub excludes: Vec<String>,
    pub exclude_from: Vec<Utf8PathBuf>,
    pub manifest_out: Option<Utf8PathBuf>,
    pub numeric_owner: bool,
    pub no_same_owner: bool,
}

/// Options that steer archive extraction.
#[derive(Debug, Clone)]
pub struct ExtractOptions {
    pub archive_path: Utf8PathBuf,
    pub destination: Utf8PathBuf,
    pub verbose: bool,
    pub quiet: bool,
    pub strict: bool,
    pub manifest: Option<Utf8PathBuf>,
    pub manifest_relaxed: bool,
    pub numeric_owner: bool,
    pub no_same_owner: bool,
}

/// Options for listing archives.
#[derive(Debug, Clone)]
pub struct ListOptions {
    pub archive_path: Utf8PathBuf,
    pub verbose: bool,
    pub quiet: bool,
    pub json: bool,
}

/// Create an archive.
pub fn create_archive(
    options: &CreateOptions,
    policy: &SecurityPolicy,
) -> Result<Vec<ManifestEntry>> {
    let base = resolve_base(options.work_dir.as_ref())?;
    let base_utf8 = Utf8PathBuf::from_path_buf(base.clone())
        .map_err(|_| anyhow!("working directory not valid UTF-8: {}", base.display()))?;
    let exclude_set = compile_excludes(&options.excludes, &options.exclude_from)?;
    let mut usage = policy.usage();

    let mut entries = Vec::new();

    for input in &options.inputs {
        let abs_input = canonicalize_input(&base_utf8, input)?;
        let metadata = fs::metadata(abs_input.as_std_path())
            .with_context(|| format!("failed to stat input {}", abs_input))?;
        let trim_prefix = if metadata.is_dir() {
            Some(abs_input.clone())
        } else {
            None
        };
        walk_input(
            &base_utf8,
            &abs_input,
            trim_prefix.as_ref().map(|p| p.as_ref()),
            &exclude_set,
            policy,
            &mut usage,
            &mut entries,
        )?;
    }

    if options.print_plan && !options.quiet {
        for entry in &entries {
            println!("{}\t{}", entry.kind_label(), entry.relative);
        }
    }

    let manifest_inputs: Vec<_> = entries
        .iter()
        .map(|entry| entry.to_manifest_item())
        .collect();
    let manifest_entries = manifest::collect_manifest(&manifest_inputs)?;

    if options.print_plan {
        return Ok(manifest_entries);
    }

    let progress = if options.verbose && !options.quiet {
        let pb = ProgressBar::new(entries.len() as u64);
        let style = ProgressStyle::default_bar()
            .template("{spinner:.green} [{bar:40.cyan/blue}] {pos}/{len} {msg}")
            .unwrap_or_else(|_| ProgressStyle::default_bar());
        pb.set_style(style);
        Some(pb)
    } else {
        None
    };

    let archive_file = File::create(&options.archive_path)
        .with_context(|| format!("failed to create archive {}", options.archive_path))?;
    let writer = wrap_writer(archive_file, options.compression)
        .with_context(|| format!("failed to initialise {:?} compressor", options.compression))?;
    let mut builder = Builder::new(writer);
    builder.follow_symlinks(policy.follow_symlinks());
    builder.mode(HeaderMode::Deterministic);

    for entry in &entries {
        if let Some(pb) = &progress {
            pb.inc(1);
            pb.set_message(entry.relative.as_str().to_owned());
        } else if options.verbose && !options.quiet {
            println!("adding {} ({})", entry.relative, entry.kind_label());
        }
        match entry.kind {
            EntryKind::Directory => builder
                .append_dir(entry.relative.as_str(), entry.absolute.as_std_path())
                .with_context(|| format!("failed to append directory {}", entry.relative))?,
            EntryKind::File => {
                let mut file = File::open(entry.absolute.as_std_path())
                    .with_context(|| format!("failed to open {}", entry.absolute))?;
                builder
                    .append_file(entry.relative.as_str(), &mut file)
                    .with_context(|| format!("failed to append file {}", entry.relative))?;
            }
            EntryKind::Symlink => append_symlink(&mut builder, entry)?,
        }
    }

    if let Some(pb) = progress {
        pb.finish_with_message("create complete");
    }

    builder.finish().context("failed to finalise tar archive")?;
    let writer = builder
        .into_inner()
        .context("failed to finalise tar builder")?;
    writer
        .finish()
        .context("failed to finish compressed writer")?;

    if let Some(manifest_path) = &options.manifest_out {
        manifest::write_manifest_json(&manifest_entries, manifest_path)?;
    }

    Ok(manifest_entries)
}

/// Extract an archive.
pub fn extract_archive(
    options: &ExtractOptions,
    policy: &SecurityPolicy,
) -> Result<Vec<ManifestEntry>> {
    let archive_file = File::open(&options.archive_path)
        .with_context(|| format!("failed to open archive {}", options.archive_path))?;
    let reader = wrap_reader(archive_file).context("failed to detect archive compression")?;
    let mut archive = Archive::new(reader);

    let destination = resolve_destination(&options.destination)?;
    fs::create_dir_all(&destination)
        .with_context(|| format!("failed to prepare destination {}", destination.display()))?;
    let dest_utf8 = Utf8PathBuf::from_path_buf(destination.clone())
        .map_err(|_| anyhow!("destination not valid UTF-8: {}", destination.display()))?;
    let mut usage = policy.usage();
    let mut manifest_items = Vec::new();

    let progress = if options.verbose && !options.quiet {
        let pb = ProgressBar::new_spinner();
        pb.enable_steady_tick(Duration::from_millis(120));
        pb.set_message("extracting");
        Some(pb)
    } else {
        None
    };

    for entry_result in archive.entries()? {
        let mut entry = entry_result?;
        let header = entry.header().clone();
        let entry_type = classify_entry_type(&header);
        let path = entry_path_utf8(&entry)?;
        let validated = policy
            .normalize_and_validate(path.as_ref(), &dest_utf8)
            .map_err(|err| map_policy_error(err, options.strict))?;
        usage
            .observe(&validated, header.size().unwrap_or_default())
            .map_err(|err| map_policy_error(err, options.strict))?;

        if let Some(pb) = &progress {
            pb.set_message(format!("{entry_type:?} {}", validated.rel));
            pb.inc(1);
        } else if options.verbose && !options.quiet {
            println!("extracting {} ({entry_type:?})", validated.rel);
        }

        match entry_type {
            EntryKind::Directory => {
                let target_path = validated.abs.as_std_path();
                fs::create_dir_all(target_path)
                    .with_context(|| format!("failed to create directory {}", validated.abs))?;
                manifest_items.push(ManifestItem {
                    relative: validated.rel.clone(),
                    absolute: validated.abs.clone(),
                    kind: ManifestKind::Directory,
                    link_target: None,
                    size: 0,
                    mtime: header
                        .mtime()
                        .ok()
                        .map(|secs| std::time::UNIX_EPOCH + std::time::Duration::from_secs(secs)),
                });
            }
            EntryKind::File => {
                ensure_parent_exists(&validated)?;
                entry
                    .unpack_in(dest_utf8.as_std_path())
                    .with_context(|| format!("failed to extract {}", validated.rel))?;
                manifest_items.push(ManifestItem {
                    relative: validated.rel.clone(),
                    absolute: validated.abs.clone(),
                    kind: ManifestKind::File,
                    link_target: None,
                    size: header.size().unwrap_or_default(),
                    mtime: header
                        .mtime()
                        .ok()
                        .map(|secs| std::time::UNIX_EPOCH + std::time::Duration::from_secs(secs)),
                });
            }
            EntryKind::Symlink => {
                ensure_parent_exists(&validated)?;
                let link_target = entry.link_name().with_context(|| {
                    format!("failed to read symlink target for {}", validated.rel)
                })?;
                let target_utf8 = link_target
                    .clone()
                    .map(|cow| {
                        let owned = cow.into_owned();
                        Utf8PathBuf::from_path_buf(owned)
                            .map_err(|_| anyhow!("symlink target not UTF-8: {}", validated.rel))
                    })
                    .transpose()?;
                if let Some(target) = &target_utf8 {
                    enforce_link(policy, &dest_utf8, &validated, target)?;
                }
                entry
                    .unpack_in(dest_utf8.as_std_path())
                    .with_context(|| format!("failed to extract {}", validated.rel))?;
                manifest_items.push(ManifestItem {
                    relative: validated.rel.clone(),
                    absolute: validated.abs.clone(),
                    kind: ManifestKind::Symlink,
                    link_target: target_utf8.clone(),
                    size: 0,
                    mtime: header
                        .mtime()
                        .ok()
                        .map(|secs| std::time::UNIX_EPOCH + std::time::Duration::from_secs(secs)),
                });
            }
        }
    }

    if let Some(pb) = progress {
        pb.finish_with_message("extract complete");
    }

    let manifest_entries = manifest::collect_manifest(&manifest_items)?;
    if let Some(path) = &options.manifest {
        let expected = manifest::read_manifest_json(path)?;
        manifest::verify_manifest(&expected, &manifest_entries, options.manifest_relaxed)?;
    }
    Ok(manifest_entries)
}

/// List archive contents.
pub fn list_archive(options: &ListOptions) -> Result<Vec<ManifestEntry>> {
    let archive_file = File::open(&options.archive_path)
        .with_context(|| format!("failed to open archive {}", options.archive_path))?;
    let reader = wrap_reader(archive_file).context("failed to detect archive compression")?;
    let mut archive = Archive::new(reader);
    let mut manifest_entries = Vec::new();

    for entry_result in archive.entries()? {
        let mut entry = entry_result?;
        let header = entry.header().clone();
        let entry_type = classify_entry_type(&header);
        let path = entry_path_utf8(&entry)?;
        if options.verbose && !options.quiet {
            let size = header.size().unwrap_or_default();
            let pax_meta = pax_mod::extract_pax_extensions(&header);
            if pax_meta.is_empty() {
                println!("{:?}\t{}\t{}", entry_type, size, path);
            } else {
                println!("{:?}\t{}\t{}\t{:?}", entry_type, size, path, pax_meta);
            }
        } else if !options.quiet {
            println!("{}", path);
        }

        let mtime = header
            .mtime()
            .ok()
            .map(|secs| std::time::UNIX_EPOCH + std::time::Duration::from_secs(secs));

        let manifest_entry = match entry_type {
            EntryKind::File => {
                let hash = hash_entry_data(&mut entry)?;
                ManifestEntry {
                    path: path.to_string(),
                    size: header.size().unwrap_or_default(),
                    sha256: hash,
                    kind: ManifestKind::File,
                    target: None,
                    mtime: mtime.map(|t| {
                        t.duration_since(std::time::UNIX_EPOCH)
                            .unwrap_or_default()
                            .as_secs()
                    }),
                }
            }
            EntryKind::Directory => ManifestEntry::for_directory(&path, mtime),
            EntryKind::Symlink => {
                let target = entry
                    .link_name()
                    .with_context(|| format!("failed to read symlink target for {path}"))?;
                let target_str = target
                    .clone()
                    .map(|cow| {
                        let owned = cow.into_owned();
                        Utf8PathBuf::from_path_buf(owned)
                            .map_err(|_| anyhow!("symlink target not UTF-8: {path}"))
                            .map(|p| p.to_string())
                    })
                    .transpose()?;
                ManifestEntry {
                    path: path.to_string(),
                    size: 0,
                    sha256: target_str
                        .as_ref()
                        .map(|s| digest_bytes_prefilled(s.as_bytes()))
                        .unwrap_or_else(|| digest_bytes_prefilled(&[])),
                    kind: ManifestKind::Symlink,
                    target: target_str,
                    mtime: None,
                }
            }
        };
        manifest_entries.push(manifest_entry);
    }

    if options.json && !options.quiet {
        serde_json::to_writer_pretty(std::io::stdout(), &manifest_entries)
            .context("failed to render manifest")?;
        println!();
    }

    Ok(manifest_entries)
}

fn append_symlink<W>(builder: &mut Builder<W>, entry: &ArchiveEntry) -> Result<()>
where
    W: io::Write,
{
    let target = entry
        .link_target
        .as_ref()
        .ok_or_else(|| anyhow!("missing symlink target for {}", entry.relative))?;
    let mut header = tar::Header::new_gnu();
    header.set_path(entry.relative.as_str())?;
    header.set_size(0);
    header.set_entry_type(EntryType::Symlink);
    header.set_mode(0o777);
    header.set_link_name(target.as_str())?;
    header.set_mtime(
        entry
            .mtime
            .map(|time| {
                time.duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs()
            })
            .unwrap_or_default(),
    );
    header.set_uid(0);
    header.set_gid(0);
    header.set_cksum();
    builder
        .append(&header, io::empty())
        .with_context(|| format!("failed to append symlink {}", entry.relative))?;
    Ok(())
}

fn walk_input(
    base: &Utf8Path,
    input: &Utf8Path,
    trim_prefix: Option<&Utf8Path>,
    excludes: &Option<GlobSet>,
    policy: &SecurityPolicy,
    usage: &mut UsageTracker,
    entries: &mut Vec<ArchiveEntry>,
) -> Result<()> {
    let walkdir = WalkDir::new(input.as_std_path()).follow_links(policy.follow_symlinks());
    let mut iter = walkdir.into_iter();
    while let Some(entry_result) = iter.next() {
        let entry = entry_result?;
        let abs_path = Utf8PathBuf::from_path_buf(entry.path().to_path_buf())
            .map_err(|_| anyhow!("path not valid UTF-8: {}", entry.path().display()))?;
        let allowed_root = trim_prefix.unwrap_or(base);
        let rel = abs_path
            .strip_prefix(allowed_root)
            .map(Utf8Path::to_owned)
            .map_err(|_| {
                anyhow!(UserInputError::new(format!(
                    "input {} escapes base {}",
                    abs_path, allowed_root
                )))
            })?;

        if entry.file_type().is_dir() && is_excluded(excludes, &rel) {
            iter.skip_current_dir();
            continue;
        }

        if is_excluded(excludes, &rel) {
            continue;
        }

        let metadata = entry.metadata()?;
        let kind = if metadata.is_file() {
            EntryKind::File
        } else if metadata.is_dir() {
            EntryKind::Directory
        } else if metadata.file_type().is_symlink() {
            EntryKind::Symlink
        } else {
            continue;
        };
        let size = if kind == EntryKind::File {
            metadata.len()
        } else {
            0
        };

        let link_target = if kind == EntryKind::Symlink {
            let target = fs::read_link(entry.path())?;
            let target = Utf8PathBuf::from_path_buf(target)
                .map_err(|_| anyhow!("symlink target not UTF-8: {}", entry.path().display()))?;
            let resolved = if target.is_absolute() {
                target.clone()
            } else if let Some(parent) = abs_path.parent() {
                parent.join(&target)
            } else {
                allowed_root.join(&target)
            };
            policy
                .enforce_link_policy(resolved.as_ref(), allowed_root, LinkType::Symlink)
                .map_err(map_policy_error_for_create)?;
            Some(target)
        } else {
            None
        };

        let stored_rel = if let Some(prefix) = trim_prefix {
            match abs_path.strip_prefix(prefix) {
                Ok(trimmed) => trimmed.to_owned(),
                Err(_) => rel.clone(),
            }
        } else {
            rel.clone()
        };

        if stored_rel.as_str().is_empty() {
            continue;
        }

        let validated = policy
            .normalize_and_validate(stored_rel.as_ref(), allowed_root)
            .map_err(map_policy_error_for_create)?;

        usage
            .observe(&validated, size)
            .map_err(map_policy_error_for_create)?;

        entries.push(ArchiveEntry {
            absolute: validated.abs,
            relative: stored_rel,
            kind,
            size,
            link_target,
            mtime: metadata.modified().ok(),
        });
    }
    Ok(())
}

fn compile_excludes(patterns: &[String], files: &[Utf8PathBuf]) -> Result<Option<GlobSet>> {
    if patterns.is_empty() && files.is_empty() {
        return Ok(None);
    }
    let mut builder = GlobSetBuilder::new();
    for pattern in patterns {
        builder.add(Glob::new(pattern)?);
    }
    for file in files {
        if !file.exists() {
            continue;
        }
        let content = fs::read_to_string(file)
            .with_context(|| format!("failed to read exclude file {file}"))?;
        for line in content.lines() {
            let trimmed = line.trim();
            if trimmed.is_empty() || trimmed.starts_with('#') {
                continue;
            }
            builder.add(Glob::new(trimmed)?);
        }
    }
    Ok(Some(builder.build()?))
}

fn is_excluded(set: &Option<GlobSet>, rel: &Utf8Path) -> bool {
    set.as_ref()
        .map(|set| set.is_match(rel.as_str()))
        .unwrap_or(false)
}

fn resolve_base(dir: Option<&Utf8PathBuf>) -> Result<std::path::PathBuf> {
    let base = match dir {
        Some(dir) => dir.clone(),
        None => Utf8PathBuf::from_path_buf(std::env::current_dir()?)
            .map_err(|_| anyhow!("current directory not valid UTF-8"))?,
    };
    let canonical = fs::canonicalize(base.as_std_path())
        .with_context(|| format!("failed to canonicalize {}", base))?;
    Ok(canonical)
}

fn canonicalize_input(base: &Utf8Path, input: &Utf8Path) -> Result<Utf8PathBuf> {
    let joined = if input.is_absolute() {
        input.to_owned()
    } else {
        base.join(input)
    };
    let canonical = match fs::canonicalize(joined.as_std_path()) {
        Ok(path) => path,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
            return Err(
                UserInputError::new(format!("input path does not exist: {}", joined)).into(),
            );
        }
        Err(err) => {
            return Err(anyhow!(err).context(format!("failed to canonicalize {joined}")));
        }
    };
    Utf8PathBuf::from_path_buf(canonical).map_err(|_| anyhow!("path not UTF-8: {joined}"))
}

fn resolve_destination(dir: &Utf8Path) -> Result<std::path::PathBuf> {
    match fs::canonicalize(dir.as_std_path()) {
        Ok(path) => Ok(path),
        Err(err) if err.kind() == io::ErrorKind::NotFound => {
            if dir.is_absolute() {
                Ok(dir.as_std_path().to_path_buf())
            } else {
                let mut cwd = std::env::current_dir()?;
                cwd.push(dir.as_std_path());
                Ok(cwd)
            }
        }
        Err(err) => Err(anyhow!(err).context(format!("failed to prepare destination {dir}"))),
    }
}

fn ensure_parent_exists(validated: &crate::policy::ValidatedPath) -> Result<()> {
    if let Some(parent) = validated.abs.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("failed to create parent {}", parent))?;
    }
    Ok(())
}

fn entry_path_utf8(
    entry: &tar::Entry<'_, crate::io::dec::CompressionReader>,
) -> Result<Utf8PathBuf> {
    let path = entry.path()?;
    match path {
        Cow::Borrowed(path) => Utf8PathBuf::from_path_buf(path.to_path_buf())
            .map_err(|_| anyhow!("entry path not UTF-8: {}", path.display())),
        Cow::Owned(path) => {
            Utf8PathBuf::from_path_buf(path).map_err(|_| anyhow!("entry path not UTF-8"))
        }
    }
}

fn enforce_link(
    policy: &SecurityPolicy,
    root: &Utf8Path,
    validated: &crate::policy::ValidatedPath,
    target: &Utf8Path,
) -> Result<()> {
    if target.is_absolute() {
        policy
            .enforce_link_policy(target, root, LinkType::Symlink)
            .map_err(map_policy_error_for_create)?;
    } else if let Some(parent) = validated.abs.parent() {
        let resolved = parent.join(target);
        policy
            .enforce_link_policy(resolved.as_ref(), root, LinkType::Symlink)
            .map_err(map_policy_error_for_create)?;
    }
    Ok(())
}

fn map_policy_error(err: PolicyError, strict: bool) -> anyhow::Error {
    if strict {
        anyhow!(err)
    } else {
        anyhow!(err)
    }
}

fn map_policy_error_for_create(err: PolicyError) -> anyhow::Error {
    anyhow!(err)
}

#[derive(Debug, Clone)]
struct ArchiveEntry {
    absolute: Utf8PathBuf,
    relative: Utf8PathBuf,
    kind: EntryKind,
    size: u64,
    link_target: Option<Utf8PathBuf>,
    mtime: Option<std::time::SystemTime>,
}

impl ArchiveEntry {
    fn kind_label(&self) -> &'static str {
        match self.kind {
            EntryKind::File => "file",
            EntryKind::Directory => "dir",
            EntryKind::Symlink => "symlink",
        }
    }

    fn to_manifest_item(&self) -> ManifestItem {
        ManifestItem {
            relative: self.relative.clone(),
            absolute: self.absolute.clone(),
            kind: match self.kind {
                EntryKind::File => ManifestKind::File,
                EntryKind::Directory => ManifestKind::Directory,
                EntryKind::Symlink => ManifestKind::Symlink,
            },
            link_target: self.link_target.clone(),
            size: self.size,
            mtime: self.mtime,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum EntryKind {
    File,
    Directory,
    Symlink,
}

fn hash_entry_data<R: Read>(entry: &mut tar::Entry<'_, R>) -> Result<String> {
    let mut hasher = Sha256::new();
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let read = entry.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    Ok(hex::encode(hasher.finalize()))
}

fn digest_bytes_prefilled(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hex::encode(hasher.finalize())
}
