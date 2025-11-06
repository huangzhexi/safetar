//! Default-on security policy enforcement utilities.
use camino::{Utf8Component, Utf8Path, Utf8PathBuf};
use path_clean::PathClean;
use std::fmt;
use thiserror::Error;

/// Resource limits enforced by [`SecurityPolicy`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PolicyLimits {
    pub max_files: u64,
    pub max_total_bytes: u64,
    pub max_single_file: u64,
    pub max_depth: u32,
}

impl Default for PolicyLimits {
    fn default() -> Self {
        Self {
            max_files: 200_000,
            max_total_bytes: 8u64 << 30,
            max_single_file: 2u64 << 30,
            max_depth: 64,
        }
    }
}

/// Types of links enforced by the policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LinkType {
    Symlink,
    Hardlink,
}

/// Security policy configuration.
#[derive(Debug, Clone, Default)]
pub struct SecurityPolicy {
    limits: PolicyLimits,
    allow_absolute: bool,
    allow_parent_components: bool,
    follow_symlinks: bool,
    allow_symlink_outside_root: bool,
    allow_hardlink_outside_root: bool,
}

impl SecurityPolicy {
    /// Create a new policy using default settings.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Replace built-in limits with the supplied values.
    #[must_use]
    pub fn with_limits(mut self, limits: PolicyLimits) -> Self {
        self.limits = limits;
        self
    }

    /// Return the active limits.
    #[must_use]
    pub fn limits(&self) -> PolicyLimits {
        self.limits
    }

    /// Adjust maximum files.
    #[must_use]
    pub fn with_max_files(mut self, value: Option<u64>) -> Self {
        if let Some(value) = value {
            self.limits.max_files = value;
        }
        self
    }

    /// Adjust maximum total bytes.
    #[must_use]
    pub fn with_max_total_bytes(mut self, value: Option<u64>) -> Self {
        if let Some(value) = value {
            self.limits.max_total_bytes = value;
        }
        self
    }

    /// Adjust maximum single file size.
    #[must_use]
    pub fn with_max_single_file(mut self, value: Option<u64>) -> Self {
        if let Some(value) = value {
            self.limits.max_single_file = value;
        }
        self
    }

    /// Adjust maximum depth.
    #[must_use]
    pub fn with_max_depth(mut self, value: Option<u32>) -> Self {
        if let Some(value) = value {
            self.limits.max_depth = value;
        }
        self
    }

    /// Normalise and validate `path` against `root`.
    pub fn normalize_and_validate(
        &self,
        path: &Utf8Path,
        root: &Utf8Path,
    ) -> Result<ValidatedPath, PolicyError> {
        if path.as_str().is_empty() {
            return Err(PolicyError::EmptyPath);
        }

        if path.is_absolute() && !self.allow_absolute {
            return Err(PolicyError::AbsolutePath(path.to_owned()));
        }

        let joined = if path.is_absolute() {
            path.to_owned()
        } else {
            root.join(path)
        };

        let cleaned_std = joined.as_std_path().to_path_buf().clean();
        let cleaned = Utf8PathBuf::from_path_buf(cleaned_std)
            .map_err(|_| PolicyError::InvalidUtf8(path.to_owned()))?;

        for component in cleaned.components() {
            match component {
                Utf8Component::ParentDir if !self.allow_parent_components => {
                    return Err(PolicyError::ParentTraversal(cleaned.clone()));
                }
                Utf8Component::RootDir | Utf8Component::Prefix(_) if !self.allow_absolute => {
                    // If allow_absolute is false, any root/prefix that isn't the archive root rejects.
                    if !cleaned.starts_with(root) {
                        return Err(PolicyError::RootEscape(cleaned.clone()));
                    }
                }
                _ => {}
            }
        }

        if !cleaned.starts_with(root) {
            return Err(PolicyError::RootEscape(cleaned));
        }

        let rel = cleaned
            .strip_prefix(root)
            .map(Utf8Path::to_owned)
            .unwrap_or_else(|_| Utf8PathBuf::new());

        Ok(ValidatedPath { rel, abs: cleaned })
    }

    /// Enforce link targets remain within `root`.
    pub fn enforce_link_policy(
        &self,
        target: &Utf8Path,
        root: &Utf8Path,
        kind: LinkType,
    ) -> Result<(), PolicyError> {
        let allow_outside = match kind {
            LinkType::Symlink => self.allow_symlink_outside_root,
            LinkType::Hardlink => self.allow_hardlink_outside_root,
        };

        if allow_outside {
            return Ok(());
        }

        if target.is_absolute() {
            let cleaned_std = target.as_std_path().to_path_buf().clean();
            let cleaned = Utf8PathBuf::from_path_buf(cleaned_std)
                .map_err(|_| PolicyError::LinkOutsideRoot(target.to_owned()))?;
            if cleaned.starts_with(root) {
                return Ok(());
            }
            return Err(PolicyError::LinkOutsideRoot(target.to_owned()));
        }

        let normalized = self
            .normalize_and_validate(target, root)
            .map_err(|_| PolicyError::LinkOutsideRoot(target.to_owned()))?;

        if normalized.abs.starts_with(root) {
            Ok(())
        } else {
            Err(PolicyError::LinkOutsideRoot(target.to_owned()))
        }
    }

    /// Create a usage tracker that enforces quota counters.
    #[must_use]
    pub fn usage(&self) -> UsageTracker {
        UsageTracker {
            policy: self.clone(),
            files_seen: 0,
            total_bytes: 0,
            max_depth_observed: 0,
        }
    }

    /// Whether the policy follows symlinks during traversal.
    #[must_use]
    pub fn follow_symlinks(&self) -> bool {
        self.follow_symlinks
    }
}

/// Validated absolute and relative paths.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidatedPath {
    pub rel: Utf8PathBuf,
    pub abs: Utf8PathBuf,
}

impl fmt::Display for ValidatedPath {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.rel.as_str().is_empty() {
            write!(f, ". → {}", self.abs)
        } else {
            write!(f, "{} → {}", self.rel, self.abs)
        }
    }
}

/// Tracks resource usage against enforced limits.
#[derive(Debug, Clone)]
pub struct UsageTracker {
    policy: SecurityPolicy,
    files_seen: u64,
    total_bytes: u64,
    max_depth_observed: u32,
}

impl UsageTracker {
    /// Record an entry with the provided size.
    pub fn observe(&mut self, validated: &ValidatedPath, size: u64) -> Result<(), PolicyError> {
        let depth = depth_of(&validated.rel)?;
        let limits = self.policy.limits;

        if size > limits.max_single_file {
            return Err(PolicyError::SingleFileTooLarge {
                path: validated.rel.clone(),
                actual: size,
                limit: limits.max_single_file,
            });
        }

        if depth > limits.max_depth {
            return Err(PolicyError::DepthExceeded {
                path: validated.rel.clone(),
                actual: depth,
                limit: limits.max_depth,
            });
        }
        self.max_depth_observed = self.max_depth_observed.max(depth);

        self.files_seen = self.files_seen.saturating_add(1);
        if self.files_seen > limits.max_files {
            return Err(PolicyError::FileCountExceeded {
                limit: limits.max_files,
                actual: self.files_seen,
            });
        }

        self.total_bytes = self.total_bytes.saturating_add(size);
        if self.total_bytes > limits.max_total_bytes {
            return Err(PolicyError::TotalBytesExceeded {
                limit: limits.max_total_bytes,
                actual: self.total_bytes,
            });
        }

        Ok(())
    }

    /// Files accounted so far.
    #[must_use]
    pub fn files_seen(&self) -> u64 {
        self.files_seen
    }

    /// Total bytes accounted so far.
    #[must_use]
    pub fn total_bytes(&self) -> u64 {
        self.total_bytes
    }
}

#[derive(Debug, Error)]
pub enum PolicyError {
    #[error("path is empty")]
    EmptyPath,
    #[error("absolute path rejected: {0}")]
    AbsolutePath(Utf8PathBuf),
    #[error("path escapes archive root: {0}")]
    RootEscape(Utf8PathBuf),
    #[error("path contains parent traversal: {0}")]
    ParentTraversal(Utf8PathBuf),
    #[error("path contains invalid UTF-8: {0}")]
    InvalidUtf8(Utf8PathBuf),
    #[error("link target escapes root: {0}")]
    LinkOutsideRoot(Utf8PathBuf),
    #[error("file count exceeded (limit {limit}, actual {actual})")]
    FileCountExceeded { limit: u64, actual: u64 },
    #[error("total bytes exceeded (limit {limit}, actual {actual})")]
    TotalBytesExceeded { limit: u64, actual: u64 },
    #[error("single file too large for {path} (limit {limit}, actual {actual})")]
    SingleFileTooLarge {
        path: Utf8PathBuf,
        actual: u64,
        limit: u64,
    },
    #[error("directory depth exceeded for {path} (limit {limit}, actual {actual})")]
    DepthExceeded {
        path: Utf8PathBuf,
        actual: u32,
        limit: u32,
    },
}

fn depth_of(path: &Utf8Path) -> Result<u32, PolicyError> {
    let mut depth = 0u32;
    for component in path.components() {
        if matches!(component, Utf8Component::Normal(_)) {
            depth = depth
                .checked_add(1)
                .ok_or_else(|| PolicyError::DepthExceeded {
                    path: path.to_owned(),
                    actual: u32::MAX,
                    limit: u32::MAX,
                })?;
        }
        if matches!(component, Utf8Component::ParentDir) {
            // Parent components should have been rejected earlier, but double check.
            return Err(PolicyError::ParentTraversal(path.to_owned()));
        }
    }
    Ok(depth)
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;
    use tempfile::tempdir;

    #[test]
    fn rejects_absolute_path() {
        let tmp = tempdir().expect("tempdir");
        let root = Utf8PathBuf::from_path_buf(tmp.path().to_path_buf()).expect("utf8");
        let policy = SecurityPolicy::new();
        let path = Utf8Path::new("/etc/passwd");
        let err = policy
            .normalize_and_validate(path, &root)
            .expect_err("expected rejection");
        assert!(matches!(err, PolicyError::AbsolutePath(_)));
    }

    #[test]
    fn rejects_parent_traversal() {
        let tmp = tempdir().expect("tempdir");
        let root = Utf8PathBuf::from_path_buf(tmp.path().to_path_buf()).expect("utf8");
        let policy = SecurityPolicy::new();
        let path = Utf8Path::new("../escape");
        let err = policy
            .normalize_and_validate(path, &root)
            .expect_err("expected rejection");
        assert!(matches!(
            err,
            PolicyError::RootEscape(_) | PolicyError::ParentTraversal(_)
        ));
    }

    #[test]
    fn validates_relative_path() {
        let tmp = tempdir().expect("tempdir");
        let root = Utf8PathBuf::from_path_buf(tmp.path().to_path_buf()).expect("utf8");
        let policy = SecurityPolicy::new();
        let rel = Utf8Path::new("subdir/file.txt");
        let validated = policy
            .normalize_and_validate(rel, &root)
            .expect("valid path");
        assert!(validated.abs.starts_with(&root));
        assert_eq!(validated.rel, Utf8PathBuf::from("subdir/file.txt"));
    }

    #[test]
    fn link_policy_blocks_escape() {
        let tmp = tempdir().expect("tempdir");
        let root = Utf8PathBuf::from_path_buf(tmp.path().to_path_buf()).expect("utf8");
        let policy = SecurityPolicy::new();
        let target = Utf8Path::new("../../etc/passwd");
        let err = policy
            .enforce_link_policy(target, &root, LinkType::Symlink)
            .expect_err("expected escape rejection");
        assert!(matches!(err, PolicyError::LinkOutsideRoot(_)));
    }

    #[test]
    fn usage_tracker_enforces_limits() {
        let tmp = tempdir().expect("tempdir");
        let root = Utf8PathBuf::from_path_buf(tmp.path().to_path_buf()).expect("utf8");
        let limits = PolicyLimits {
            max_files: 1,
            max_total_bytes: 10,
            max_single_file: 8,
            max_depth: 1,
        };
        let policy = SecurityPolicy::new().with_limits(limits);
        let validated = policy
            .normalize_and_validate(Utf8Path::new("item"), &root)
            .unwrap();
        let mut usage = policy.usage();
        usage.observe(&validated, 4).unwrap();
        let second = policy
            .normalize_and_validate(Utf8Path::new("other"), &root)
            .unwrap();
        let err = usage.observe(&second, 2).expect_err("limit exceeded");
        assert!(matches!(err, PolicyError::FileCountExceeded { .. }));
    }

    proptest! {
        #[test]
        fn normalized_paths_stay_within_root(
            segments in prop::collection::vec(
                prop_oneof![
                    "[a-z0-9]{1,6}".prop_map(|s| s),
                    Just("..".to_string()),
                    Just(".".to_string()),
                ],
                1..6,
            )
        ) {
            let raw = segments.join("/");
            let tmp = tempdir().expect("tempdir");
            let root = Utf8PathBuf::from_path_buf(tmp.path().to_path_buf()).expect("utf8");
            let policy = SecurityPolicy::new();
            let path = Utf8PathBuf::from(raw);
            let result = policy.normalize_and_validate(&path, &root);
            if let Ok(validated) = result {
                prop_assert!(validated.abs.starts_with(&root));
            }
        }
    }
}
