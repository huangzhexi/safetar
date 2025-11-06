//! CLI smoke tests covering create/extract behaviour.

use std::fs;
use std::io::Write;

use assert_cmd::cargo::cargo_bin_cmd;
use camino::Utf8PathBuf;
use predicates::prelude::*;
use sha2::{Digest, Sha256};
use tempfile::tempdir;
use walkdir::WalkDir;

#[test]
fn create_extract_roundtrip() -> anyhow::Result<()> {
    let temp = tempdir()?;
    let input_dir = temp.path().join("input");
    fs::create_dir_all(&input_dir)?;
    let nested = input_dir.join("nested");
    fs::create_dir_all(&nested)?;

    let file_path = nested.join("hello.txt");
    let mut file = fs::File::create(&file_path)?;
    writeln!(file, "safetar makes archives safe")?;

    let archive_path = temp.path().join("archive.sta");

    let mut create_cmd = cargo_bin_cmd!("safetar");
    create_cmd
        .arg("create")
        .arg("--file")
        .arg(&archive_path)
        .arg(&input_dir);
    create_cmd.assert().success();

    let extract_dir = temp.path().join("extract");
    let mut extract_cmd = cargo_bin_cmd!("safetar");
    extract_cmd
        .arg("extract")
        .arg("--file")
        .arg(&archive_path)
        .arg("--directory")
        .arg(&extract_dir);
    extract_cmd.assert().success();

    let original_files = collect_files(&input_dir);
    let extracted_files = collect_files(&extract_dir);

    assert_eq!(original_files.len(), extracted_files.len());
    for (original, extracted) in original_files.iter().zip(extracted_files.iter()) {
        assert_eq!(original.0, extracted.0);
        assert_eq!(original.1, extracted.1);
    }

    Ok(())
}

#[test]
fn list_outputs_paths() -> anyhow::Result<()> {
    let temp = tempdir()?;
    let input_dir = temp.path().join("input");
    fs::create_dir_all(&input_dir)?;
    fs::write(input_dir.join("file.bin"), b"abc123")?;
    let archive_path = temp.path().join("bundle.sta");

    cargo_bin_cmd!("safetar")
        .args(["create", "--file"])
        .arg(&archive_path)
        .arg(&input_dir)
        .assert()
        .success();

    cargo_bin_cmd!("safetar")
        .args(["list", "--file"])
        .arg(&archive_path)
        .assert()
        .success()
        .stdout(predicate::str::contains("file.bin"));

    Ok(())
}

fn collect_files(root: &std::path::Path) -> Vec<(Utf8PathBuf, String)> {
    let mut entries = Vec::new();
    for entry in WalkDir::new(root).into_iter().filter_map(Result::ok) {
        if entry.file_type().is_file() {
            let relative = entry
                .path()
                .strip_prefix(root)
                .map(|p| Utf8PathBuf::from_path_buf(p.to_path_buf()).expect("utf8"))
                .expect("relative path");
            let data = fs::read(entry.path()).expect("read file");
            let mut hasher = Sha256::new();
            hasher.update(&data);
            let digest = hex::encode(hasher.finalize());
            entries.push((relative, digest));
        }
    }
    entries.sort_by(|a, b| a.0.cmp(&b.0));
    entries
}
