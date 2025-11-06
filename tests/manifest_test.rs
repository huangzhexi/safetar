//! Manifest collection and verification tests.

use std::fs;

use anyhow::Result;
use camino::Utf8PathBuf;
use safetar::manifest::{self, ManifestItem, ManifestKind};
use tempfile::tempdir;

#[test]
fn write_and_read_manifest() -> Result<()> {
    let temp = tempdir()?;
    let file_path = temp.path().join("file.txt");
    fs::write(&file_path, b"hello")?;
    let dir_path = temp.path().join("dir");
    fs::create_dir(&dir_path)?;

    let file_abs = Utf8PathBuf::from_path_buf(file_path.clone()).unwrap();
    let dir_abs = Utf8PathBuf::from_path_buf(dir_path.clone()).unwrap();

    let metadata = fs::metadata(&file_path)?;
    let file_item = ManifestItem {
        relative: Utf8PathBuf::from("file.txt"),
        absolute: file_abs.clone(),
        kind: ManifestKind::File,
        link_target: None,
        size: metadata.len(),
        mtime: metadata.modified().ok(),
    };
    let dir_item = ManifestItem {
        relative: Utf8PathBuf::from("dir"),
        absolute: dir_abs,
        kind: ManifestKind::Directory,
        link_target: None,
        size: 0,
        mtime: None,
    };

    let entries = manifest::collect_manifest(&[file_item, dir_item])?;

    let manifest_path = Utf8PathBuf::from_path_buf(temp.path().join("manifest.json")).unwrap();
    manifest::write_manifest_json(&entries, &manifest_path)?;
    let reloaded = manifest::read_manifest_json(&manifest_path)?;
    assert_eq!(entries, reloaded);
    Ok(())
}

#[test]
fn manifest_verification_detects_mismatch() -> Result<()> {
    let temp = tempdir()?;
    let expected_file = temp.path().join("expected.txt");
    fs::write(&expected_file, b"hello")?;
    let actual_file = temp.path().join("actual.txt");
    fs::write(&actual_file, b"world")?;

    let expected_item = ManifestItem {
        relative: Utf8PathBuf::from("file.txt"),
        absolute: Utf8PathBuf::from_path_buf(expected_file.clone()).unwrap(),
        kind: ManifestKind::File,
        link_target: None,
        size: fs::metadata(&expected_file)?.len(),
        mtime: None,
    };
    let actual_item = ManifestItem {
        relative: Utf8PathBuf::from("file.txt"),
        absolute: Utf8PathBuf::from_path_buf(actual_file.clone()).unwrap(),
        kind: ManifestKind::File,
        link_target: None,
        size: fs::metadata(&actual_file)?.len(),
        mtime: None,
    };

    let expected = manifest::collect_manifest(&[expected_item])?;
    let actual = manifest::collect_manifest(&[actual_item])?;
    let result = manifest::verify_manifest(&expected, &actual, false);
    assert!(result.is_err());
    Ok(())
}

#[test]
fn relaxed_manifest_allows_new_entries() -> Result<()> {
    let temp = tempdir()?;
    let base = base_utf8_path(&temp, "base");
    fs::create_dir_all(base.as_std_path())?;
    let expected_file = base.join("expected.txt");
    fs::write(expected_file.as_std_path(), b"hello")?;
    let actual_extra = base.join("extra.txt");
    fs::write(actual_extra.as_std_path(), b"world")?;

    let expected_item = ManifestItem {
        relative: Utf8PathBuf::from("expected.txt"),
        absolute: expected_file.clone(),
        kind: ManifestKind::File,
        link_target: None,
        size: fs::metadata(expected_file.as_std_path())?.len(),
        mtime: None,
    };
    let extra_item = ManifestItem {
        relative: Utf8PathBuf::from("extra.txt"),
        absolute: actual_extra.clone(),
        kind: ManifestKind::File,
        link_target: None,
        size: fs::metadata(actual_extra.as_std_path())?.len(),
        mtime: None,
    };

    let expected = manifest::collect_manifest(std::slice::from_ref(&expected_item))?;
    let actual = manifest::collect_manifest(&[expected_item, extra_item])?;
    manifest::verify_manifest(&expected, &actual, true)?;
    Ok(())
}

fn base_utf8_path(dir: &tempfile::TempDir, segment: &str) -> Utf8PathBuf {
    Utf8PathBuf::from_path_buf(dir.path().join(segment)).expect("utf8 temp path")
}
