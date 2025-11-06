//! Manifest collection and verification helpers.

use std::collections::BTreeMap;
use std::fs::File;
use std::io::{BufReader, BufWriter, Read, Write};
use std::time::SystemTime;

use anyhow::{Context, Result};
use camino::{Utf8Path, Utf8PathBuf};
use rayon::prelude::*;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

/// Entry describing a filesystem object stored in the manifest.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ManifestEntry {
    pub path: String,
    pub size: u64,
    pub sha256: String,
    pub kind: ManifestKind,
    pub target: Option<String>,
    pub mtime: Option<u64>,
}

impl ManifestEntry {
    #[must_use]
    pub fn for_directory(path: &Utf8Path, mtime: Option<SystemTime>) -> Self {
        Self {
            path: path.to_string(),
            size: 0,
            sha256: digest_bytes(&[]),
            kind: ManifestKind::Directory,
            target: None,
            mtime: mtime.and_then(to_unix_secs),
        }
    }

    #[must_use]
    pub fn for_symlink(path: &Utf8Path, target: &Utf8Path) -> Self {
        Self {
            path: path.to_string(),
            size: 0,
            sha256: digest_bytes(target.as_str().as_bytes()),
            kind: ManifestKind::Symlink,
            target: Some(target.to_string()),
            mtime: None,
        }
    }
}

/// Source item used to compute a manifest.
#[derive(Debug, Clone)]
pub struct ManifestItem {
    pub relative: Utf8PathBuf,
    pub absolute: Utf8PathBuf,
    pub kind: ManifestKind,
    pub link_target: Option<Utf8PathBuf>,
    pub size: u64,
    pub mtime: Option<SystemTime>,
}

/// Types of entries captured in the manifest.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum ManifestKind {
    File,
    Directory,
    Symlink,
}

/// Collect manifest entries for the provided items (hashed in parallel).
pub fn collect_manifest(items: &[ManifestItem]) -> Result<Vec<ManifestEntry>> {
    let entries: Result<Vec<_>> = items
        .par_iter()
        .map(|item| match item.kind {
            ManifestKind::File => {
                let hash = hash_file(&item.absolute)?;
                Ok(ManifestEntry {
                    path: item.relative.to_string(),
                    size: item.size,
                    sha256: hash,
                    kind: ManifestKind::File,
                    target: None,
                    mtime: item.mtime.and_then(to_unix_secs),
                })
            }
            ManifestKind::Directory => Ok(ManifestEntry::for_directory(&item.relative, item.mtime)),
            ManifestKind::Symlink => {
                let target = item
                    .link_target
                    .as_ref()
                    .map(|p| p.to_string())
                    .unwrap_or_default();
                Ok(ManifestEntry {
                    path: item.relative.to_string(),
                    size: 0,
                    sha256: digest_bytes(target.as_bytes()),
                    kind: ManifestKind::Symlink,
                    target: item.link_target.as_ref().map(|p| p.to_string()),
                    mtime: item.mtime.and_then(to_unix_secs),
                })
            }
        })
        .collect();

    let mut entries = entries?;
    entries.sort_by(|a, b| a.path.cmp(&b.path));
    Ok(entries)
}

/// Write manifest entries to JSON.
pub fn write_manifest_json(entries: &[ManifestEntry], path: &Utf8Path) -> Result<()> {
    let file = File::create(path).with_context(|| format!("failed to create manifest {path}"))?;
    let mut writer = BufWriter::new(file);
    serde_json::to_writer_pretty(&mut writer, entries)
        .with_context(|| format!("failed to encode manifest {path}"))?;
    writer.flush().context("failed to flush manifest writer")
}

/// Read manifest entries from JSON.
pub fn read_manifest_json(path: &Utf8Path) -> Result<Vec<ManifestEntry>> {
    let file = File::open(path).with_context(|| format!("failed to open manifest {path}"))?;
    let reader = BufReader::new(file);
    let entries: Vec<ManifestEntry> = serde_json::from_reader(reader)
        .with_context(|| format!("failed to decode manifest {path}"))?;
    Ok(entries)
}

/// Verify manifest contents against expectation.
pub fn verify_manifest(
    expected: &[ManifestEntry],
    actual: &[ManifestEntry],
    relaxed: bool,
) -> Result<()> {
    let expected_map = as_map(expected);
    let actual_map = as_map(actual);

    for (path, entry) in &expected_map {
        let Some(actual_entry) = actual_map.get(path) else {
            return Err(ManifestError::MissingEntry(path.clone()).into());
        };
        if entry.sha256 != actual_entry.sha256 || entry.kind != actual_entry.kind {
            return Err(ManifestError::Mismatch {
                path: path.clone(),
                expected: entry.sha256.clone(),
                actual: actual_entry.sha256.clone(),
            }
            .into());
        }
    }

    if !relaxed {
        for path in actual_map.keys() {
            if !expected_map.contains_key(path) {
                return Err(ManifestError::UnexpectedEntry(path.clone()).into());
            }
        }
    }

    Ok(())
}

fn hash_file(path: &Utf8Path) -> Result<String> {
    let mut file = File::open(path).with_context(|| format!("failed to open {path}"))?;
    let mut hasher = Sha256::new();
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let read = file.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    Ok(hex::encode(hasher.finalize()))
}

fn digest_bytes(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hex::encode(hasher.finalize())
}

fn to_unix_secs(time: SystemTime) -> Option<u64> {
    time.duration_since(SystemTime::UNIX_EPOCH)
        .ok()
        .map(|duration| duration.as_secs())
}

fn as_map(entries: &[ManifestEntry]) -> BTreeMap<String, ManifestEntry> {
    entries
        .iter()
        .cloned()
        .map(|entry| (entry.path.clone(), entry))
        .collect()
}

/// Manifest verification errors.
#[derive(Debug, Error)]
pub enum ManifestError {
    #[error("manifest missing entry: {0}")]
    MissingEntry(String),
    #[error("manifest entry mismatch for {path}: expected {expected}, actual {actual}")]
    Mismatch {
        path: String,
        expected: String,
        actual: String,
    },
    #[error("manifest contains unexpected entry: {0}")]
    UnexpectedEntry(String),
}
