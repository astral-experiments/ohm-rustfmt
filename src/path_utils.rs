use std::fs::{File, Metadata};
use std::io;
use std::path::{Path, PathBuf};
use std::time::UNIX_EPOCH;

pub(crate) const CONFIG_FILE_NAMES: [&str; 2] = [".rustfmt.toml", "rustfmt.toml"];

/// Directories searched for a root's formatting configuration, in precedence order.
pub(crate) fn configuration_directories(directory: &Path) -> impl Iterator<Item = PathBuf> + '_ {
    directory
        .ancestors()
        .map(Path::to_owned)
        .chain(global_configuration_directories())
}

/// Fallback configuration locations shared by rustfmt and cargo-fmt.
pub(crate) fn global_configuration_directories() -> impl Iterator<Item = PathBuf> {
    std::iter::once_with(dirs::home_dir).flatten().chain(
        std::iter::once_with(dirs::config_dir)
            .flatten()
            .map(|dir| dir.join("rustfmt")),
    )
}

/// Delimits each root's canonical configuration and content hash. An empty
/// identity represents the built-in defaults.
pub(crate) fn hash_configuration(digest: &mut sha2::Sha256, identity: &str) {
    use sha2::Digest;
    digest.update(identity);
    digest.update([0]);
}

/// Source versions used to format a direct module in its real crate-root context.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct LeafInputs {
    pub(crate) root: SourceFingerprint,
    pub(crate) leaf: SourceFingerprint,
}

/// Source identity for incremental formatting. Like Ruff, this trusts filesystem
/// metadata. On Unix, restoring the modification time normally changes the
/// status change time. Filesystems that restore or coarsen both timestamps
/// can still hide edits within a single file.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(into = "StoredFingerprint", from = "StoredFingerprint")]
pub(crate) struct SourceFingerprint {
    pub(crate) modified_seconds: i64,
    pub(crate) modified_nanoseconds: u32,
    pub(crate) permissions_mode: u32,
    /// Device and inode on Unix. Swapping directories can preserve both timestamps.
    pub(crate) file_id: (u64, u64),
    /// None when identical to the modification time or unavailable.
    pub(crate) changed: Option<(i64, i64)>,
}

// Avoid repeating field names and two usually identical timestamps for every
// source in the versioned cache and module manifest.
type StoredFingerprint = (i64, u32, u32, u64, u64, Option<(i64, i64)>);

impl From<SourceFingerprint> for StoredFingerprint {
    fn from(source: SourceFingerprint) -> Self {
        (
            source.modified_seconds,
            source.modified_nanoseconds,
            source.permissions_mode,
            source.file_id.0,
            source.file_id.1,
            source.changed,
        )
    }
}

impl From<StoredFingerprint> for SourceFingerprint {
    fn from(stored: StoredFingerprint) -> Self {
        let (modified_seconds, modified_nanoseconds, permissions_mode, dev, ino, changed) = stored;
        Self {
            modified_seconds,
            modified_nanoseconds,
            permissions_mode,
            file_id: (dev, ino),
            changed,
        }
    }
}

impl SourceFingerprint {
    /// Encodes precise modification time and permissions without reading source contents.
    pub(crate) fn from_metadata(metadata: &Metadata) -> io::Result<Self> {
        let modified = metadata.modified()?;
        let nanoseconds = match modified.duration_since(UNIX_EPOCH) {
            Ok(duration) => {
                i128::from(duration.as_secs()) * 1_000_000_000 + i128::from(duration.subsec_nanos())
            }
            Err(error) => {
                let duration = error.duration();
                -(i128::from(duration.as_secs()) * 1_000_000_000
                    + i128::from(duration.subsec_nanos()))
            }
        };
        let modified_seconds =
            i64::try_from(nanoseconds.div_euclid(1_000_000_000)).map_err(io::Error::other)?;
        let modified_nanoseconds =
            u32::try_from(nanoseconds.rem_euclid(1_000_000_000)).map_err(io::Error::other)?;

        #[cfg(unix)]
        let permissions_mode = {
            use std::os::unix::fs::PermissionsExt;

            metadata.permissions().mode()
        };
        #[cfg(not(unix))]
        let permissions_mode = u32::from(metadata.permissions().readonly());

        #[cfg(unix)]
        let changed = {
            use std::os::unix::fs::MetadataExt;
            let time = (metadata.ctime(), metadata.ctime_nsec());
            (time != (modified_seconds, i64::from(modified_nanoseconds))).then_some(time)
        };
        #[cfg(not(unix))]
        let changed = None;

        #[cfg(unix)]
        let file_id = {
            use std::os::unix::fs::MetadataExt;
            (metadata.dev(), metadata.ino())
        };
        #[cfg(not(unix))]
        let file_id = (0, 0);

        Ok(Self {
            file_id,
            changed,
            modified_seconds,
            modified_nanoseconds,
            permissions_mode,
        })
    }
}

/// Resolves paths without walking every component in userspace when Linux proves
/// that an absolute path contains no symlinks. Every call checks the filesystem;
/// aliases, parent components, and unsupported kernels use normal canonicalization.
pub(crate) fn canonicalize(path: &Path) -> io::Result<PathBuf> {
    canonicalize_with_handle(path).map(|(canonical, _)| canonical)
}

/// Uses the same file handle for resolution and metadata when the platform supports it.
pub(crate) fn canonicalize_with_metadata(path: &Path) -> io::Result<(PathBuf, Metadata)> {
    let (canonical, handle) = canonicalize_with_handle(path)?;
    let metadata = match handle {
        Some(handle) => handle.metadata()?,
        None => std::fs::metadata(&canonical)?,
    };
    Ok((canonical, metadata))
}

/// Retains Linux's fresh symlink-free path handle for metadata queries when available.
/// Standard canonicalization remains the fallback and returns no handle.
pub(crate) fn canonicalize_with_handle(path: &Path) -> io::Result<(PathBuf, Option<File>)> {
    #[cfg(target_os = "linux")]
    {
        use std::os::unix::ffi::OsStrExt;

        use rustix::fs::{CWD, Mode, OFlags, ResolveFlags, openat2};

        if let Some(tail) = path.as_os_str().as_bytes().strip_prefix(b"/") {
            // On Linux only dots and redundant separators need normalization.
            // Keep parent traversal on the standard resolution path.
            let mut normalized = true;
            for part in tail.split(|&byte| byte == b'/') {
                match part {
                    b".." => return path.canonicalize().map(|canonical| (canonical, None)),
                    b"" | b"." => normalized = false,
                    _ => {}
                }
            }
            if let Ok(handle) = openat2(
                CWD,
                path,
                OFlags::PATH | OFlags::CLOEXEC,
                Mode::empty(),
                ResolveFlags::NO_SYMLINKS,
            ) {
                let canonical = if normalized {
                    path.to_owned()
                } else {
                    path.components().collect()
                };
                return Ok((canonical, Some(File::from(handle))));
            }
        }
    }

    path.canonicalize().map(|canonical| (canonical, None))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn canonical_paths_and_errors_match_standard_resolution() -> io::Result<()> {
        let temporary = tempfile::tempdir()?;
        let root = temporary.path().canonicalize()?;
        fs::create_dir(root.join("nested"))?;
        fs::write(root.join("file.rs"), "fn main() {}")?;

        for path in [
            root.clone(),
            root.join("file.rs"),
            root.join("nested/./"),
            root.join("nested//"),
            root.join("./file.rs"),
            root.join("nested/../file.rs"),
            root.join("nested//../file.rs"),
            root.join("missing.rs"),
            root.join("missing/../file.rs"),
            root.join("file.rs/"),
            PathBuf::from("."),
        ] {
            match fs::canonicalize(&path) {
                Ok(expected) => {
                    assert_eq!(canonicalize(&path)?, expected, "{path:?}");
                    let (canonical, handle) = canonicalize_with_handle(&path)?;
                    assert_eq!(canonical.as_os_str(), expected.as_os_str(), "{path:?}");
                    if let Some(handle) = handle {
                        let observed = handle.metadata()?;
                        let expected = fs::metadata(&expected)?;
                        assert_eq!(observed.file_type(), expected.file_type(), "{path:?}");
                        assert_eq!(observed.len(), expected.len(), "{path:?}");
                        assert_eq!(observed.modified()?, expected.modified()?, "{path:?}");
                        assert_eq!(observed.permissions(), expected.permissions(), "{path:?}");
                    }
                }
                Err(expected) => {
                    assert_eq!(
                        canonicalize(&path).unwrap_err().raw_os_error(),
                        expected.raw_os_error(),
                        "{path:?}",
                    );
                    assert_eq!(
                        canonicalize_with_handle(&path).unwrap_err().raw_os_error(),
                        expected.raw_os_error(),
                        "{path:?}",
                    );
                }
            }
        }
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn symlinks_and_retargeted_ancestors_use_current_destinations() -> io::Result<()> {
        use std::os::unix::fs::symlink;

        let temporary = tempfile::tempdir()?;
        let root = temporary.path().canonicalize()?;
        for directory in ["first", "second"] {
            fs::create_dir(root.join(directory))?;
            fs::write(root.join(directory).join("file.rs"), "fn main() {}")?;
        }
        let alias = root.join("alias");
        symlink(root.join("first"), &alias)?;
        symlink(alias.join("file.rs"), root.join("file.rs"))?;
        for directory in ["first", "second"] {
            if directory == "second" {
                fs::remove_file(&alias)?;
                symlink(root.join(directory), &alias)?;
            }
            for path in [alias.join("file.rs"), root.join("file.rs")] {
                let expected = root.join(directory).join("file.rs");
                assert_eq!(canonicalize(&path)?, expected);
                let (canonical, handle) = canonicalize_with_handle(&path)?;
                assert_eq!(canonical, expected);
                assert!(handle.is_none());
            }
            assert_eq!(canonicalize(&alias.join(".."))?, root);
        }
        fs::remove_file(root.join("second/file.rs"))?;
        assert_eq!(
            canonicalize(&root.join("file.rs")).unwrap_err().kind(),
            io::ErrorKind::NotFound,
        );
        Ok(())
    }
}
