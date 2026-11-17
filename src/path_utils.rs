use std::fs::File;
use std::io;
use std::path::{Path, PathBuf};

/// Resolves paths without walking every component in userspace when Linux proves
/// that an absolute path contains no symlinks. Every call checks the filesystem;
/// aliases, parent components, and unsupported kernels use normal canonicalization.
pub(crate) fn canonicalize(path: &Path) -> io::Result<PathBuf> {
    canonicalize_with_handle(path).map(|(canonical, _)| canonical)
}

/// Retains Linux's fresh symlink-free path handle for metadata queries when available.
/// Standard canonicalization remains the fallback and returns no handle.
pub(crate) fn canonicalize_with_handle(path: &Path) -> io::Result<(PathBuf, Option<File>)> {
    #[cfg(target_os = "linux")]
    {
        use std::path::Component;

        use rustix::fs::{CWD, Mode, OFlags, ResolveFlags, openat2};

        if path.is_absolute() && !path.components().any(|part| part == Component::ParentDir) {
            if let Ok(handle) = openat2(
                CWD,
                path,
                OFlags::PATH | OFlags::CLOEXEC,
                Mode::empty(),
                ResolveFlags::NO_SYMLINKS,
            ) {
                return Ok((path.components().collect(), Some(File::from(handle))));
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
                    assert_eq!(canonical, expected, "{path:?}");
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
