//! End-to-end policy assertions.

use anyhow::{anyhow, Result};
use camino::Utf8PathBuf;
use safetar::policy::{PolicyError, SecurityPolicy};
use tempfile::tempdir;

#[test]
fn rejects_absolute_path() -> Result<()> {
    let temp = tempdir()?;
    let root = Utf8PathBuf::from_path_buf(temp.path().to_path_buf())
        .map_err(|_| anyhow!("tempdir path not utf8"))?;
    let policy = SecurityPolicy::new();
    let abs = Utf8PathBuf::from("/tmp/escape");
    let result = policy.normalize_and_validate(abs.as_ref(), &root);
    assert!(matches!(result, Err(PolicyError::AbsolutePath(_))));
    Ok(())
}

#[test]
fn rejects_parent_components() -> Result<()> {
    let temp = tempdir()?;
    let root = Utf8PathBuf::from_path_buf(temp.path().to_path_buf())
        .map_err(|_| anyhow!("tempdir path not utf8"))?;
    let policy = SecurityPolicy::new();
    let result = policy.normalize_and_validate(Utf8PathBuf::from("../escape").as_ref(), &root);
    assert!(matches!(
        result,
        Err(PolicyError::ParentTraversal(_)) | Err(PolicyError::RootEscape(_))
    ));
    Ok(())
}

#[test]
fn enforces_limits() -> Result<()> {
    let temp = tempdir()?;
    let root = Utf8PathBuf::from_path_buf(temp.path().to_path_buf())
        .map_err(|_| anyhow!("tempdir path not utf8"))?;
    let policy = SecurityPolicy::new().with_max_files(Some(1));
    let validated = policy.normalize_and_validate(Utf8PathBuf::from("file.txt").as_ref(), &root)?;
    let mut usage = policy.usage();
    usage.observe(&validated, 10)?;
    let second = policy.normalize_and_validate(Utf8PathBuf::from("other.txt").as_ref(), &root)?;
    let result = usage.observe(&second, 10);
    assert!(matches!(result, Err(PolicyError::FileCountExceeded { .. })));
    Ok(())
}
