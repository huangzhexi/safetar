//! Archive-level integration checks.

use std::fs;

use anyhow::Result;
use camino::Utf8PathBuf;
use safetar::archive::{create_archive, extract_archive, CreateOptions, ExtractOptions};
use safetar::io::Compression;
use safetar::manifest::ManifestKind;
use safetar::policy::SecurityPolicy;
use tempfile::tempdir;

fn temp_utf8_path(dir: &tempfile::TempDir, segment: &str) -> Utf8PathBuf {
    Utf8PathBuf::from_path_buf(dir.path().join(segment)).expect("utf8 temp path")
}

fn base_workdir(dir: &tempfile::TempDir) -> Utf8PathBuf {
    Utf8PathBuf::from_path_buf(dir.path().to_path_buf()).expect("utf8 temp dir")
}

#[test]
fn create_respects_excludes() -> Result<()> {
    let temp = tempdir()?;
    let workdir = base_workdir(&temp);
    let input_dir = temp_utf8_path(&temp, "input");
    fs::create_dir_all(input_dir.join("nested").as_std_path())?;
    fs::write(input_dir.join("nested/keep.txt").as_std_path(), b"keep")?;
    fs::write(input_dir.join("nested/skip.log").as_std_path(), b"skip")?;

    let archive_path = workdir.join("archive.tar");

    let options = CreateOptions {
        archive_path: archive_path.clone(),
        inputs: vec![Utf8PathBuf::from("input")],
        work_dir: Some(workdir.clone()),
        compression: Compression::None,
        verbose: false,
        quiet: true,
        print_plan: false,
        excludes: vec!["*.log".into()],
        exclude_from: Vec::new(),
        manifest_out: None,
        numeric_owner: false,
        no_same_owner: true,
    };

    let manifest = create_archive(&options, &SecurityPolicy::new())?;
    assert!(
        !manifest
            .iter()
            .any(|entry| entry.path.ends_with("skip.log")),
        "manifest should omit excluded file"
    );

    let extract_dir = workdir.join("extract");
    let extract_opts = ExtractOptions {
        archive_path,
        destination: extract_dir.clone(),
        verbose: false,
        quiet: true,
        strict: true,
        manifest: None,
        manifest_relaxed: false,
        numeric_owner: false,
        no_same_owner: true,
    };

    extract_archive(&extract_opts, &SecurityPolicy::new())?;

    assert!(extract_dir.join("nested/keep.txt").exists());
    assert!(!extract_dir.join("nested/skip.log").exists());

    Ok(())
}

#[test]
fn print_plan_does_not_emit_archive() -> Result<()> {
    let temp = tempdir()?;
    let workdir = base_workdir(&temp);
    let input_dir = temp_utf8_path(&temp, "input");
    fs::create_dir_all(input_dir.as_std_path())?;
    fs::write(input_dir.join("file.txt").as_std_path(), b"content")?;

    let archive_path = workdir.join("plan.tar");
    let options = CreateOptions {
        archive_path: archive_path.clone(),
        inputs: vec![Utf8PathBuf::from("input")],
        work_dir: Some(workdir.clone()),
        compression: Compression::None,
        verbose: false,
        quiet: true,
        print_plan: true,
        excludes: Vec::new(),
        exclude_from: Vec::new(),
        manifest_out: None,
        numeric_owner: false,
        no_same_owner: true,
    };

    let manifest = create_archive(&options, &SecurityPolicy::new())?;
    assert!(manifest
        .iter()
        .any(|entry| entry.kind == ManifestKind::File));
    assert!(
        !archive_path.exists(),
        "archive file should not be created in plan mode"
    );

    Ok(())
}

fn roundtrip(codec: Compression) -> Result<()> {
    let temp = tempdir()?;
    let workdir = base_workdir(&temp);
    let input_dir = temp_utf8_path(&temp, "input");
    fs::create_dir_all(input_dir.join("nested").as_std_path())?;
    fs::write(input_dir.join("nested/file.txt").as_std_path(), b"payload")?;

    let archive_name = Utf8PathBuf::from(format!("bundle_{codec:?}.tar"));
    let archive_path = workdir.join(&archive_name);

    let create_opts = CreateOptions {
        archive_path: archive_path.clone(),
        inputs: vec![Utf8PathBuf::from("input")],
        work_dir: Some(workdir.clone()),
        compression: codec,
        verbose: false,
        quiet: true,
        print_plan: false,
        excludes: Vec::new(),
        exclude_from: Vec::new(),
        manifest_out: None,
        numeric_owner: false,
        no_same_owner: true,
    };
    create_archive(&create_opts, &SecurityPolicy::new())?;

    let extract_name = Utf8PathBuf::from(format!("extract_{codec:?}"));
    let extract_dir = workdir.join(&extract_name);
    let extract_opts = ExtractOptions {
        archive_path: archive_path.clone(),
        destination: extract_dir.clone(),
        verbose: false,
        quiet: true,
        strict: true,
        manifest: None,
        manifest_relaxed: false,
        numeric_owner: false,
        no_same_owner: true,
    };
    extract_archive(&extract_opts, &SecurityPolicy::new())?;

    let extracted = fs::read_to_string(extract_dir.join("nested/file.txt").as_std_path())?;
    assert_eq!(extracted, "payload");

    Ok(())
}

#[test]
fn roundtrip_no_compression() -> Result<()> {
    roundtrip(Compression::None)
}

#[test]
fn roundtrip_gzip() -> Result<()> {
    roundtrip(Compression::Gzip)
}

#[test]
fn roundtrip_xz() -> Result<()> {
    roundtrip(Compression::Xz)
}

#[test]
fn roundtrip_zstd() -> Result<()> {
    roundtrip(Compression::Zstd)
}

#[cfg(unix)]
#[test]
fn preserves_symlinks() -> Result<()> {
    use std::os::unix::fs::symlink;

    let temp = tempdir()?;
    let workdir = base_workdir(&temp);
    let input_dir = temp_utf8_path(&temp, "input");
    fs::create_dir_all(input_dir.join("dir").as_std_path())?;
    fs::write(input_dir.join("dir/file.txt").as_std_path(), b"hello")?;
    symlink("file.txt", input_dir.join("dir/file.link").as_std_path())?;

    let archive_path = workdir.join("symlink.tar");
    let create_opts = CreateOptions {
        archive_path: archive_path.clone(),
        inputs: vec![Utf8PathBuf::from("input")],
        work_dir: Some(workdir.clone()),
        compression: Compression::None,
        verbose: false,
        quiet: true,
        print_plan: false,
        excludes: Vec::new(),
        exclude_from: Vec::new(),
        manifest_out: None,
        numeric_owner: false,
        no_same_owner: true,
    };
    create_archive(&create_opts, &SecurityPolicy::new())?;

    let extract_dir = workdir.join("symlink_extract");
    let extract_opts = ExtractOptions {
        archive_path: archive_path.clone(),
        destination: extract_dir.clone(),
        verbose: false,
        quiet: true,
        strict: true,
        manifest: None,
        manifest_relaxed: false,
        numeric_owner: false,
        no_same_owner: true,
    };
    extract_archive(&extract_opts, &SecurityPolicy::new())?;

    let link_target = std::fs::read_link(extract_dir.join("dir/file.link"))?;
    assert_eq!(link_target, std::path::PathBuf::from("file.txt"));
    Ok(())
}

#[cfg(unix)]
#[test]
fn rejects_symlink_escape() -> Result<()> {
    use std::os::unix::fs::symlink;

    let temp = tempdir()?;
    let workdir = base_workdir(&temp);
    let input_dir = temp_utf8_path(&temp, "input");
    fs::create_dir_all(input_dir.as_std_path())?;
    symlink("../outside", input_dir.join("escape.link").as_std_path())?;

    let archive_path = workdir.join("reject.tar");
    let create_opts = CreateOptions {
        archive_path,
        inputs: vec![Utf8PathBuf::from("input")],
        work_dir: Some(workdir.clone()),
        compression: Compression::None,
        verbose: false,
        quiet: true,
        print_plan: false,
        excludes: Vec::new(),
        exclude_from: Vec::new(),
        manifest_out: None,
        numeric_owner: false,
        no_same_owner: true,
    };

    let err = create_archive(&create_opts, &SecurityPolicy::new())
        .expect_err("symlink escape should be rejected");
    assert!(err.to_string().contains("link target escapes root"));
    Ok(())
}
