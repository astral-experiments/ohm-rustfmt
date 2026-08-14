// Integration tests for cargo-fmt.

use std::env;
use std::fs;
use std::path::Path;
use std::process::Command;

use rustfmt_config_proc_macro::rustfmt_only_ci_test;
use sha2::{Digest, Sha256};

/// Runs the paired cargo-fmt and rustfmt executables from the local target directory.
fn cargo_fmt_command() -> Command {
    let mut bin_dir = env::current_exe().unwrap();
    bin_dir.pop(); // chop off test exe name
    if bin_dir.ends_with("deps") {
        bin_dir.pop();
    }
    let cmd = bin_dir.join(format!("cargo-fmt{}", env::consts::EXE_SUFFIX));

    // Ensure cargo-fmt runs the rustfmt binary from the local target dir.
    let path = env::var_os("PATH").unwrap_or_default();
    let mut paths = env::split_paths(&path).collect::<Vec<_>>();
    paths.insert(0, bin_dir);
    let new_path = env::join_paths(paths).unwrap();

    let mut command = Command::new(cmd);
    command.env("PATH", new_path);
    command
}

/// Run the cargo-fmt executable and return its output.
fn cargo_fmt(args: &[&str]) -> (String, String) {
    let mut command = cargo_fmt_command();
    command.args(args);
    match command.output() {
        Ok(output) => (
            String::from_utf8(output.stdout).expect("utf-8"),
            String::from_utf8(output.stderr).expect("utf-8"),
        ),
        Err(e) => panic!("failed to run `{command:?} {args:?}`: {e}"),
    }
}

macro_rules! assert_that {
    ($args:expr, $check:ident $check_args:tt) => {
        let (stdout, stderr) = cargo_fmt($args);
        if !stdout.$check$check_args {
            panic!(
                "Output not expected for cargo-fmt {:?}\n\
                 expected: {}{}\n\
                 actual stdout:\n{}\n\
                 actual stderr:\n{}",
                $args,
                stringify!($check),
                stringify!($check_args),
                stdout,
                stderr
            );
        }
    };
}

#[rustfmt_only_ci_test]
#[test]
fn version() {
    assert_that!(&["--version"], starts_with("rustfmt "));
    assert_that!(&["--version"], starts_with("rustfmt "));
    assert_that!(&["--", "-V"], starts_with("rustfmt "));
    assert_that!(&["--", "--version"], starts_with("rustfmt "));
}

#[rustfmt_only_ci_test]
#[test]
fn print_config() {
    assert_that!(
        &["--", "--print-config", "current", "."],
        contains("max_width = ")
    );
}

#[rustfmt_only_ci_test]
#[test]
fn rustfmt_help() {
    assert_that!(&["--", "--help"], contains("Format Rust code"));
    assert_that!(&["--", "-h"], contains("Format Rust code"));
    assert_that!(&["--", "--help=config"], contains("Configuration Options:"));
}

#[rustfmt_only_ci_test]
#[test]
fn cargo_fmt_out_of_line_test_modules() {
    // See also https://github.com/rust-lang/rustfmt/issues/5119
    let expected_modified_files = [
        "tests/mod-resolver/test-submodule-issue-5119/src/lib.rs",
        "tests/mod-resolver/test-submodule-issue-5119/tests/test1.rs",
        "tests/mod-resolver/test-submodule-issue-5119/tests/test1/sub1.rs",
        "tests/mod-resolver/test-submodule-issue-5119/tests/test1/sub2.rs",
        "tests/mod-resolver/test-submodule-issue-5119/tests/test1/sub3/sub4.rs",
    ];
    let args = [
        "-v",
        "--check",
        "--manifest-path",
        "tests/mod-resolver/test-submodule-issue-5119/Cargo.toml",
    ];
    let (stdout, _) = cargo_fmt(&args);
    for file in expected_modified_files {
        let path = Path::new(file).canonicalize().unwrap();
        assert!(stdout.contains(&format!("Diff in {}", path.display())));
    }
}

#[rustfmt_only_ci_test]
#[test]
fn cargo_fmt_emits_error_on_line_overflow_true() {
    // See also https://github.com/rust-lang/rustfmt/issues/3164
    let args = [
        "--check",
        "--manifest-path",
        "tests/cargo-fmt/source/issue_3164/Cargo.toml",
        "--",
        "--config",
        "error_on_line_overflow=true",
    ];

    let (_stdout, stderr) = cargo_fmt(&args);
    assert!(stderr.contains(
        "line formatted, but exceeded maximum width (maximum: 100 (see `max_width` option)"
    ))
}

#[test]
fn cargo_fmt_never_inherits_internal_module_handoffs() -> std::io::Result<()> {
    let directory = tempfile::tempdir()?;
    let package = directory.path().canonicalize()?;
    let sources = package.join("src");
    fs::create_dir(&sources)?;
    let manifest = package.join("Cargo.toml");
    let leaf = sources.join("child.rs");
    let sibling = sources.join("sibling.rs");
    let untrusted_manifest = package.join("untrusted-modules.json");
    fs::write(
        &manifest,
        "[package]\nname = \"handoff-isolation\"\nversion = \"0.1.0\"\nedition = \"2021\"\n",
    )?;
    fs::write(sources.join("lib.rs"), "mod child;\nmod sibling;\n")?;
    fs::write(&leaf, "fn child() {}\n")?;
    fs::write(&sibling, "fn sibling( ){ }\n")?;

    let mut topology = Sha256::new();
    topology.update(b"ohm.rustfmt.module-topology.v1\0");
    topology.update(0_u64.to_le_bytes());
    let topology = format!("{:x}", topology.finalize());

    for enabled in ["0", "1"] {
        let output = cargo_fmt_command()
            .arg("--check")
            .arg("--manifest-path")
            .arg(&manifest)
            .env("OHM_INCREMENTAL_FMT", enabled)
            .env("OHM_INCREMENTAL_FMT_CACHE_DIR", package.join("cache"))
            .env("OHM_RUSTFMT_MODULE_MANIFEST", &untrusted_manifest)
            .env("OHM_RUSTFMT_CHANGED_MODULE", &leaf)
            .env("OHM_RUSTFMT_MODULE_TOPOLOGY", &topology)
            .output()?;

        assert_eq!(
            output.status.code(),
            Some(1),
            "incremental={enabled}\nstdout:\n{}\nstderr:\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr),
        );
        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(stdout.contains(sibling.to_string_lossy().as_ref()));
        assert!(!untrusted_manifest.exists());
    }
    Ok(())
}

#[test]
fn cargo_fmt_logging_preserves_root_and_sibling_events_after_a_leaf_edit() -> std::io::Result<()> {
    let directory = tempfile::tempdir()?;
    let package = directory.path().canonicalize()?;
    let sources = package.join("src");
    fs::create_dir(&sources)?;
    let manifest = package.join("Cargo.toml");
    let leaf = sources.join("child.rs");
    fs::write(
        &manifest,
        "[package]\nname = \"formatter-logging\"\nversion = \"0.1.0\"\nedition = \"2021\"\n",
    )?;
    fs::write(
        sources.join("lib.rs"),
        "mod child;\nmod sibling;\n\npub fn root() {\n    let _root = 1;\n}\n",
    )?;
    fs::write(&leaf, "pub fn child() {\n    let _child = 1;\n}\n")?;
    fs::write(
        sources.join("sibling.rs"),
        "pub fn sibling() {\n    let _sibling = 2;\n}\n",
    )?;

    let run = |enabled: &str, trace: bool| {
        let mut command = cargo_fmt_command();
        command
            .arg("--check")
            .arg("--manifest-path")
            .arg(&manifest)
            .current_dir(&package)
            .env("OHM_INCREMENTAL_FMT", enabled)
            .env("OHM_INCREMENTAL_FMT_CACHE_DIR", package.join("cache"))
            .env("RUSTFMT_LOG", "rustfmt_nightly::visitor=debug");
        if trace {
            command.env("OHM_INCREMENTAL_FMT_TRACE", "1");
        } else {
            command.env_remove("OHM_INCREMENTAL_FMT_TRACE");
        }
        command.output()
    };

    let warmed = run("1", false)?;
    assert!(
        warmed.status.success(),
        "stdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&warmed.stdout),
        String::from_utf8_lossy(&warmed.stderr),
    );
    fs::write(
        &leaf,
        "pub fn child() {\n    let _changed_child = 333;\n}\n",
    )?;

    let incremental = run("1", true)?;
    let native = run("0", false)?;

    assert!(incremental.status.success());
    assert_eq!(incremental.status.code(), native.status.code());
    let incremental_stdout = String::from_utf8_lossy(&incremental.stdout);
    let native_stdout = String::from_utf8_lossy(&native.stdout);
    assert!(incremental_stdout.contains("child.rs"));
    assert!(incremental_stdout.contains("sibling.rs"));
    assert!(incremental_stdout.contains("lib.rs"));
    assert_eq!(
        incremental_stdout.matches("visit_stmt:").count(),
        native_stdout.matches("visit_stmt:").count(),
    );
    assert!(
        String::from_utf8_lossy(&incremental.stderr)
            .contains("formatting the complete target to preserve formatter logging")
    );
    Ok(())
}

#[cfg(unix)]
fn trusted_formatter_tools(
    package: &Path,
) -> std::io::Result<(std::path::PathBuf, std::path::PathBuf)> {
    let tools = package.join("tools");
    fs::create_dir(&tools)?;
    let executable = cargo_fmt_command().get_program().to_owned();
    let formatter = Path::new(&executable).with_file_name("rustfmt");
    fs::copy(&executable, tools.join("cargo-fmt"))?;
    fs::copy(formatter, tools.join("rustfmt"))?;
    let compiler = if let Some(compiler) = env::var_os("RUSTC") {
        std::path::PathBuf::from(compiler)
    } else {
        let sysroot = Command::new("rustc")
            .args(["--print", "sysroot"])
            .output()?;
        if !sysroot.status.success() {
            return Err(std::io::Error::other(
                "the integration compiler sysroot is unavailable",
            ));
        }
        let sysroot = std::str::from_utf8(&sysroot.stdout)
            .map_err(std::io::Error::other)?
            .trim();
        Path::new(sysroot).join("bin").join("rustc")
    };
    let compiler = compiler.canonicalize()?;
    let compiler_libraries = compiler
        .parent()
        .and_then(Path::parent)
        .ok_or_else(|| std::io::Error::other("the integration compiler has no sysroot"))?
        .join("lib");
    std::os::unix::fs::symlink(&compiler, tools.join("rustc"))?;
    Ok((tools, compiler_libraries))
}

#[cfg(unix)]
#[test]
fn cargo_fmt_caches_clean_checks_without_a_second_formatter_pass() -> std::io::Result<()> {
    let directory = tempfile::tempdir()?;
    let package = directory.path().canonicalize()?;
    let (tools, compiler_libraries) = trusted_formatter_tools(&package)?;
    let sources = package.join("src");
    fs::create_dir(&sources)?;
    let manifest = package.join("Cargo.toml");
    fs::write(
        &manifest,
        "[package]\nname = \"single-pass-check\"\nversion = \"0.1.0\"\nedition = \"2021\"\n",
    )?;
    fs::write(sources.join("lib.rs"), "pub fn formatted() {}\n")?;

    let run = || {
        Command::new(tools.join("cargo-fmt"))
            .arg("--check")
            .arg("--manifest-path")
            .arg(&manifest)
            .current_dir(&package)
            .env("OHM_INCREMENTAL_FMT", "1")
            .env("OHM_INCREMENTAL_FMT_TRACE", "1")
            .env("OHM_INCREMENTAL_FMT_CACHE_DIR", package.join("cache"))
            .env("DYLD_LIBRARY_PATH", &compiler_libraries)
            .env("LD_LIBRARY_PATH", &compiler_libraries)
            .env_remove("DYLD_FALLBACK_LIBRARY_PATH")
            .output()
    };

    let first = run()?;
    assert!(first.status.success());
    let first_trace = String::from_utf8_lossy(&first.stderr);
    assert!(
        first_trace.contains("caching a clean read-only formatter pass without reverification"),
        "{first_trace}",
    );

    let second = run()?;
    assert!(second.status.success());
    assert!(
        String::from_utf8_lossy(&second.stderr).contains("cache hit: 1 unchanged packages"),
        "{}",
        String::from_utf8_lossy(&second.stderr),
    );

    let format = || {
        Command::new(tools.join("cargo-fmt"))
            .arg("--manifest-path")
            .arg(&manifest)
            .current_dir(&package)
            .env("OHM_INCREMENTAL_FMT", "1")
            .env("OHM_INCREMENTAL_FMT_TRACE", "1")
            .env("OHM_INCREMENTAL_FMT_CACHE_DIR", package.join("cache"))
            .env("DYLD_LIBRARY_PATH", &compiler_libraries)
            .env("LD_LIBRARY_PATH", &compiler_libraries)
            .env_remove("DYLD_FALLBACK_LIBRARY_PATH")
            .output()
    };
    let checked_then_formatted = format()?;
    assert!(checked_then_formatted.status.success());
    assert!(
        String::from_utf8_lossy(&checked_then_formatted.stderr)
            .contains("cache hit: 1 unchanged packages"),
        "{}",
        String::from_utf8_lossy(&checked_then_formatted.stderr),
    );

    fs::write(sources.join("lib.rs"), "pub fn rewritten( ){ }\n")?;
    let rewritten = format()?;
    assert!(rewritten.status.success());
    assert_eq!(
        fs::read_to_string(sources.join("lib.rs"))?,
        "pub fn rewritten() {}\n",
    );

    let formatted_then_checked = run()?;
    assert!(formatted_then_checked.status.success());
    assert!(
        String::from_utf8_lossy(&formatted_then_checked.stderr)
            .contains("cache hit: 1 unchanged packages"),
        "{}",
        String::from_utf8_lossy(&formatted_then_checked.stderr),
    );

    let with_file_emission = |check: bool, inline: bool| {
        let mut command = Command::new(tools.join("cargo-fmt"));
        command
            .arg("--manifest-path")
            .arg(&manifest)
            .current_dir(&package)
            .env("OHM_INCREMENTAL_FMT", "1")
            .env("OHM_INCREMENTAL_FMT_TRACE", "1")
            .env("OHM_INCREMENTAL_FMT_CACHE_DIR", package.join("cache"))
            .env("DYLD_LIBRARY_PATH", &compiler_libraries)
            .env("LD_LIBRARY_PATH", &compiler_libraries)
            .env_remove("DYLD_FALLBACK_LIBRARY_PATH");
        if check {
            command.arg("--check");
        }
        command.arg("--");
        if inline {
            command.arg("--emit=files");
        } else {
            command.args(["--emit", "files"]);
        }
        command.output()
    };

    for inline in [false, true] {
        let formatted = with_file_emission(false, inline)?;
        assert!(formatted.status.success());

        let rejected = with_file_emission(true, inline)?;
        assert_eq!(rejected.status.code(), Some(1));
        let error = String::from_utf8_lossy(&rejected.stderr);
        assert!(
            error.contains("Invalid to use `--emit` and `--check`"),
            "{error}"
        );
        assert!(!error.contains("cache hit"), "{error}");
    }
    Ok(())
}

#[cfg(unix)]
#[test]
fn cargo_fmt_batches_clean_leaves_without_hiding_multiple_formatting_errors() -> std::io::Result<()>
{
    let directory = tempfile::tempdir()?;
    let package = directory.path().canonicalize()?;
    let (tools, compiler_libraries) = trusted_formatter_tools(&package)?;
    let sources = package.join("src");
    fs::create_dir(&sources)?;
    let manifest = package.join("Cargo.toml");
    fs::write(
        &manifest,
        "[package]\nname = \"multiple-leaf-check\"\nversion = \"0.1.0\"\nedition = \"2021\"\n",
    )?;
    fs::write(
        sources.join("lib.rs"),
        concat!(
            "mod first;\nmod second;\nmod unchanged_first;\n",
            "mod unchanged_second;\nmod unchanged_third;\n",
        ),
    )?;
    let first = sources.join("first.rs");
    let second = sources.join("second.rs");
    fs::write(&first, "pub fn first() {}\n")?;
    fs::write(&second, "pub fn second() {}\n")?;
    for name in ["unchanged_first", "unchanged_second", "unchanged_third"] {
        fs::write(
            sources.join(format!("{name}.rs")),
            format!("pub fn {name}() {{}}\n"),
        )?;
    }

    let run = |enabled: &str| {
        Command::new(tools.join("cargo-fmt"))
            .arg("--check")
            .arg("--manifest-path")
            .arg(&manifest)
            .current_dir(&package)
            .env("OHM_INCREMENTAL_FMT", enabled)
            .env("OHM_INCREMENTAL_FMT_TRACE", "1")
            .env("OHM_INCREMENTAL_FMT_CACHE_DIR", package.join("cache"))
            .env("DYLD_LIBRARY_PATH", &compiler_libraries)
            .env("LD_LIBRARY_PATH", &compiler_libraries)
            .env_remove("DYLD_FALLBACK_LIBRARY_PATH")
            .output()
    };

    assert!(run("1")?.status.success());
    fs::write(&first, "pub fn changed_first() {}\n")?;
    fs::write(&second, "pub fn changed_second() {}\n")?;
    let changed = std::time::UNIX_EPOCH + std::time::Duration::from_secs(2_000_000_000);
    for source in [&first, &second] {
        fs::OpenOptions::new()
            .write(true)
            .open(source)?
            .set_times(fs::FileTimes::new().set_modified(changed))?;
    }
    let batched = run("1")?;
    assert!(batched.status.success());
    assert!(
        String::from_utf8_lossy(&batched.stderr).contains("formatted 2 unchanged direct leaves"),
        "{}",
        String::from_utf8_lossy(&batched.stderr),
    );

    fs::write(&first, "pub fn first( ){ }\n")?;
    fs::write(&second, "pub fn second( ){ }\n")?;
    let incremental = run("1")?;
    let native = run("0")?;
    assert_eq!(incremental.status.code(), Some(1));
    assert_eq!(incremental.status.code(), native.status.code());
    assert_eq!(incremental.stdout, native.stdout);
    let stdout = String::from_utf8_lossy(&incremental.stdout);
    assert!(stdout.contains("first.rs"));
    assert!(stdout.contains("second.rs"));
    Ok(())
}
