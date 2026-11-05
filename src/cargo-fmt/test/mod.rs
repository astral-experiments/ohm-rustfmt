use super::*;

mod message_format;
mod targets;

#[cfg(target_os = "linux")]
#[test]
fn oversized_module_environment_falls_back_to_the_full_target() -> io::Result<()> {
    let mut command = Command::new(env::current_exe()?);
    command
        .arg("--list")
        .stdout(std::process::Stdio::null())
        .env(CHANGED_MODULE_ENVIRONMENT, "x".repeat(4 * 1024 * 1024))
        .env(MODULE_TOPOLOGY_ENVIRONMENT, "topology")
        .env(MODULE_WRITE_ENVIRONMENT, "1");

    assert_eq!(
        spawn_rustfmt(&mut command, false).unwrap_err().kind(),
        io::ErrorKind::ArgumentListTooLong
    );
    assert!(spawn_rustfmt(&mut command, true)?.wait()?.success());
    for name in [
        CHANGED_MODULE_ENVIRONMENT,
        MODULE_TOPOLOGY_ENVIRONMENT,
        MODULE_WRITE_ENVIRONMENT,
    ] {
        assert!(
            !command
                .get_envs()
                .any(|(key, value)| key == name && value.is_some())
        );
    }
    Ok(())
}

#[test]
fn default_options() {
    let empty: Vec<String> = vec![];
    let o = Opts::parse_from(&empty);
    assert_eq!(false, o.quiet);
    assert_eq!(false, o.verbose);
    assert_eq!(false, o.version);
    assert_eq!(false, o.check);
    assert_eq!(empty, o.packages);
    assert_eq!(empty, o.rustfmt_options);
    assert_eq!(false, o.format_all);
    assert_eq!(None, o.manifest_path);
    assert_eq!(None, o.message_format);
}

#[test]
fn good_options() {
    let o = Opts::parse_from([
        "test",
        "-q",
        "-p",
        "p1",
        "-p",
        "p2",
        "--message-format",
        "short",
        "--check",
        "--",
        "--edition",
        "2018",
    ]);
    assert_eq!(true, o.quiet);
    assert_eq!(false, o.verbose);
    assert_eq!(false, o.version);
    assert_eq!(true, o.check);
    assert_eq!(vec!["p1", "p2"], o.packages);
    assert_eq!(vec!["--edition", "2018"], o.rustfmt_options);
    assert_eq!(false, o.format_all);
    assert_eq!(Some(String::from("short")), o.message_format);
}

#[test]
fn unexpected_option() {
    assert!(
        Opts::command()
            .try_get_matches_from(["test", "unexpected"])
            .is_err()
    );
}

#[test]
fn unexpected_flag() {
    assert!(
        Opts::command()
            .try_get_matches_from(["test", "--flag"])
            .is_err()
    );
}

#[test]
fn mandatory_separator() {
    assert!(
        Opts::command()
            .try_get_matches_from(["test", "--emit"])
            .is_err()
    );
    assert!(
        Opts::command()
            .try_get_matches_from(["test", "--", "--emit"])
            .is_ok()
    );
}

#[test]
fn multiple_packages_one_by_one() {
    let o = Opts::parse_from([
        "test",
        "-p",
        "package1",
        "--package",
        "package2",
        "-p",
        "package3",
    ]);
    assert_eq!(3, o.packages.len());
}

#[test]
fn multiple_packages_grouped() {
    let o = Opts::parse_from([
        "test",
        "--package",
        "package1",
        "package2",
        "-p",
        "package3",
        "package4",
    ]);
    assert_eq!(4, o.packages.len());
}

#[test]
fn empty_packages_1() {
    assert!(
        Opts::command()
            .try_get_matches_from(["test", "-p"])
            .is_err()
    );
}

#[test]
fn empty_packages_2() {
    assert!(
        Opts::command()
            .try_get_matches_from(["test", "-p", "--", "--check"])
            .is_err()
    );
}

#[test]
fn empty_packages_3() {
    assert!(
        Opts::command()
            .try_get_matches_from(["test", "-p", "--verbose"])
            .is_err()
    );
}

#[test]
fn empty_packages_4() {
    assert!(
        Opts::command()
            .try_get_matches_from(["test", "-p", "--check"])
            .is_err()
    );
}
