use std::collections::btree_map::Entry;
use std::collections::{BTreeMap, BTreeSet};
use std::env;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read};
use std::path::{Path, PathBuf};
use std::time::UNIX_EPOCH;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use super::{
    RustfmtOutput, RustfmtOutputMode, SUCCESS, Target, Verbosity, run_rustfmt,
    run_rustfmt_with_output, rustfmt_command,
};

const CACHE_VERSION: u32 = 6;
const MODULE_MANIFEST_VERSION: u32 = 1;
const MODULE_MANIFEST_SCHEMA: &str = "ohm.rustfmt-files";
const MODULE_MANIFEST_ENVIRONMENT: &str = "OHM_RUSTFMT_MODULE_MANIFEST";
const ENABLE_ENVIRONMENT: &str = "OHM_INCREMENTAL_FMT";
const CACHE_ENVIRONMENT: &str = "OHM_INCREMENTAL_FMT_CACHE_DIR";
const TRACE_ENVIRONMENT: &str = "OHM_INCREMENTAL_FMT_TRACE";

type ModuleGraph = BTreeMap<String, BTreeSet<String>>;
type ProbeGraph = BTreeMap<String, BTreeMap<String, ProbeObservation>>;

/// Versioned proof that a specific invocation formatted every recorded package successfully.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Snapshot {
    version: u32,
    invocation: String,
    configuration: BTreeMap<String, String>,
    packages: BTreeMap<String, PackageSnapshot>,
}

/// Associates each target with its parser-loaded sources and native resolution probes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PackageSnapshot {
    targets: BTreeMap<String, BTreeMap<String, SourceFingerprint>>,
    probes: BTreeMap<String, BTreeMap<String, ProbeObservation>>,
}

/// Mirrors Ruff's source identity without reading the contents of cached files.
///
/// Like Ruff, this deliberately trusts filesystem modification timestamps. An
/// edit that also restores its previous timestamp and permissions is therefore
/// outside the cache's trust boundary.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SourceFingerprint {
    modified_seconds: i64,
    modified_nanoseconds: u32,
    permissions_mode: u32,
}

impl SourceFingerprint {
    /// Encodes precise modification time and permissions without reading source contents.
    fn from_metadata(metadata: &fs::Metadata) -> io::Result<Self> {
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

        Ok(Self {
            modified_seconds,
            modified_nanoseconds,
            permissions_mode,
        })
    }
}

/// Captures existence, symlink destination, and directory-sensitive module resolution.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ProbeObservation {
    canonical: Option<String>,
    exists: bool,
    is_directory: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ModuleManifest {
    schema: String,
    version: u32,
    roots: Vec<ModuleRoot>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ModuleRoot {
    path: String,
    files: Vec<String>,
    dependencies: Vec<String>,
    probes: Vec<ModuleProbe>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ModuleProbe {
    path: String,
    canonical: Option<String>,
    exists: bool,
    is_directory: bool,
}

/// Complete native source and probe graphs returned by one or more formatter processes.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Discovery {
    modules: ModuleGraph,
    probes: ProbeGraph,
}

/// Couples the previous successful snapshot with the current filesystem observations.
struct Plan {
    cache_path: PathBuf,
    previous: Option<Snapshot>,
    current: Snapshot,
}

/// Enables incremental formatting by default unless its switch explicitly opts out.
pub(super) fn enabled() -> bool {
    incremental_formatting_enabled(env::var(ENABLE_ENVIRONMENT))
}

/// Resolves the Ohm default without accepting malformed or non-Unicode overrides.
fn incremental_formatting_enabled(value: Result<String, env::VarError>) -> bool {
    match value {
        Ok(value) => matches!(value.as_str(), "1" | "true"),
        Err(env::VarError::NotPresent) => true,
        Err(env::VarError::NotUnicode(_)) => false,
    }
}

/// Formats only invalidated targets while preserving normal output and fail-closed semantics.
///
/// A successful cache update additionally requires a quiet authoritative second pass and
/// identical before/after snapshots, preventing concurrent edits from becoming false hits.
pub(super) fn format(
    targets: &BTreeSet<Target>,
    arguments: &[String],
    verbosity: Verbosity,
    manifest_path: Option<&Path>,
) -> Result<i32, io::Error> {
    if verbosity == Verbosity::Verbose || has_observable_emit_mode(arguments) {
        trace("falling back to complete formatting for observable output");
        return run_rustfmt(targets, arguments, verbosity);
    }

    let _cache_lock = match lock_cache(manifest_path) {
        Ok(lock) => lock,
        Err(error) => {
            trace(&format!("falling back to complete formatting: {error}"));
            return run_rustfmt(targets, arguments, verbosity);
        }
    };

    let plan = match Plan::prepare(targets, arguments, manifest_path) {
        Ok(plan) => plan,
        Err(error) => {
            trace(&format!("falling back to complete formatting: {error}"));
            return run_rustfmt(targets, arguments, verbosity);
        }
    };

    let mut changed_roots = plan.changed_targets();
    if changed_roots.is_empty() {
        trace(&format!(
            "cache hit: {} unchanged packages",
            plan.current.packages.len()
        ));
        return Ok(SUCCESS);
    }

    let mut changed_targets: BTreeSet<_> = targets
        .iter()
        .filter(|target| {
            target
                .path
                .to_str()
                .is_some_and(|path| changed_roots.contains(path))
        })
        .cloned()
        .collect();
    if changed_targets.len() != changed_roots.len() {
        trace("falling back to complete formatting for an ambiguous target");
        return run_rustfmt(targets, arguments, verbosity);
    }

    let changed_packages: BTreeSet<_> = changed_targets
        .iter()
        .map(|target| target.package_root.as_path())
        .collect();
    trace(&format!(
        "formatting {} of {} packages ({} of {} targets)",
        changed_packages.len(),
        plan.current.packages.len(),
        changed_targets.len(),
        targets.len()
    ));

    let Some(cache_directory) = plan.cache_path.parent() else {
        trace("falling back to complete formatting for an invalid cache path");
        return run_rustfmt(targets, arguments, verbosity);
    };
    let mut output = run_rustfmt_with_output(
        &changed_targets,
        arguments,
        verbosity,
        RustfmtOutputMode::Inherit,
        Some(cache_directory),
    )?;
    if output.status != SUCCESS {
        trace("retaining the previous cache after unsuccessful formatting");
        return Ok(output.status);
    }

    let mut discovered = match read_module_manifests(&output.module_manifests, &changed_targets) {
        Ok(discovered) => discovered,
        Err(error) => {
            trace(&format!(
                "not caching without a complete authoritative module manifest: {error}"
            ));
            return Ok(output.status);
        }
    };

    if discovers_new_shared_owner(
        &plan.current.module_graph(),
        &discovered.modules,
        &changed_roots,
    ) {
        trace("reformatting all targets after discovering a new shared module owner");
        changed_targets = targets.clone();
        changed_roots = plan
            .current
            .packages
            .values()
            .flat_map(|package| package.targets.keys().map(String::as_str))
            .collect();
        output = run_rustfmt_with_output(
            &changed_targets,
            arguments,
            verbosity,
            RustfmtOutputMode::Inherit,
            Some(cache_directory),
        )?;
        if output.status != SUCCESS {
            return Ok(output.status);
        }
        discovered = match read_module_manifests(&output.module_manifests, &changed_targets) {
            Ok(discovered) => discovered,
            Err(error) => {
                trace(&format!(
                    "not caching without a complete authoritative module manifest: {error}"
                ));
                return Ok(output.status);
            }
        };
    }

    let mut modules = plan.current.module_graph();
    let mut probes = plan.current.probe_graph();
    modules.extend(discovered.modules);
    probes.extend(discovered.probes);
    let check_only = arguments.iter().any(|argument| argument == "--check");
    match Snapshot::capture(targets, arguments, manifest_path, &modules, &probes, None) {
        Ok(updated)
            if plan.can_record(&updated, &changed_roots, check_only)
                && updated.probe_graph() == probes =>
        {
            let verification =
                verify_formatted_targets(&changed_targets, arguments, cache_directory)?;
            if verification.emitted_diagnostics {
                trace("not caching a formatter invocation that emitted diagnostics");
                return Ok(output.status);
            }
            if verification.status != SUCCESS {
                trace("not caching files changed concurrently with formatting");
                return Ok(output.status);
            }
            let verification_discovery =
                match read_module_manifests(&verification.module_manifests, &changed_targets) {
                    Ok(discovery) => discovery,
                    Err(error) => {
                        trace(&format!(
                            "not caching without a complete verification module manifest: {error}"
                        ));
                        return Ok(output.status);
                    }
                };
            if !discovery_matches(&verification_discovery, &modules, &probes) {
                trace("not caching a module graph changed concurrently with formatting");
                return Ok(output.status);
            }

            let verified =
                match Snapshot::capture(targets, arguments, manifest_path, &modules, &probes, None)
                {
                    Ok(verified) if verified == updated => verified,
                    Ok(_) => {
                        trace("not caching files changed concurrently with formatting");
                        return Ok(output.status);
                    }
                    Err(error) => {
                        trace(&format!("could not verify formatted files: {error}"));
                        return Ok(output.status);
                    }
                };

            if let Err(error) = write_cache(&plan.cache_path, &verified) {
                trace(&format!("could not update the formatting cache: {error}"));
            }
        }
        Ok(_) => trace("not caching files changed concurrently with formatting"),
        Err(error) => trace(&format!("could not verify formatted files: {error}")),
    }

    Ok(output.status)
}

/// Serializes cache discovery, formatting, verification, and publication across processes.
fn lock_cache(manifest_path: Option<&Path>) -> io::Result<File> {
    let directory = cache_directory(manifest_path)?;
    fs::create_dir_all(&directory)?;
    let lock = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(directory.join(".lock"))?;
    lock.lock()?;
    Ok(lock)
}

/// Silently rechecks formatted targets and obtains a second authoritative module graph.
fn verify_formatted_targets(
    targets: &BTreeSet<Target>,
    arguments: &[String],
    manifest_directory: &Path,
) -> io::Result<RustfmtOutput> {
    let check_arguments = verification_arguments(arguments);
    run_rustfmt_with_output(
        targets,
        &check_arguments,
        Verbosity::Quiet,
        RustfmtOutputMode::CaptureQuietly,
        Some(manifest_directory),
    )
}

/// Rejects verification graphs whose parsed files or logical resolution probes changed.
fn discovery_matches(discovered: &Discovery, modules: &ModuleGraph, probes: &ProbeGraph) -> bool {
    discovered.modules.len() == discovered.probes.len()
        && discovered.modules.iter().all(|(root, files)| {
            modules.get(root) == Some(files) && discovered.probes.get(root) == probes.get(root)
        })
}

/// Detects newly discovered modules that also belong to a previously unselected target.
fn discovers_new_shared_owner(
    previous: &ModuleGraph,
    discovered: &ModuleGraph,
    selected: &BTreeSet<&str>,
) -> bool {
    discovered.iter().any(|(root, files)| {
        let old_files = previous.get(root);
        files.iter().any(|file| {
            !old_files.is_some_and(|previous| previous.contains(file))
                && previous.iter().any(|(other_root, other_files)| {
                    !selected.contains(other_root.as_str()) && other_files.contains(file)
                })
        })
    })
}

/// Normalizes file-emission options before appending the otherwise incompatible `--check`.
fn verification_arguments(arguments: &[String]) -> Vec<String> {
    let mut normalized = Vec::with_capacity(arguments.len() + 1);
    let mut arguments = arguments.iter();
    while let Some(argument) = arguments.next() {
        if argument == "--emit" {
            if let Some(mode) = arguments.next().filter(|mode| mode.as_str() != "files") {
                normalized.push(argument.clone());
                normalized.push(mode.clone());
            }
        } else if argument != "--emit=files" {
            normalized.push(argument.clone());
        }
    }

    if !normalized.iter().any(|argument| argument == "--check") {
        normalized.push(String::from("--check"));
    }
    normalized
}

impl Plan {
    /// Restores a matching snapshot, falling back to root-only discovery if its graph vanished.
    fn prepare(
        targets: &BTreeSet<Target>,
        arguments: &[String],
        manifest_path: Option<&Path>,
    ) -> io::Result<Self> {
        if targets.is_empty() {
            return Err(unsupported("there are no formatter targets to cache"));
        }
        if env::var_os(MODULE_MANIFEST_ENVIRONMENT).is_some() {
            return Err(unsupported(
                "an external module manifest request cannot be cached safely",
            ));
        }

        let invocation = invocation_key(targets, arguments)?;
        let directory = cache_directory(manifest_path)?;
        let cache_path = directory.join(format!("{invocation}.json"));
        let previous: Option<Snapshot> = match File::open(&cache_path) {
            Ok(file) => serde_json::from_reader(file).ok(),
            Err(error) if error.kind() == io::ErrorKind::NotFound => None,
            Err(error) => return Err(error),
        };
        let mut previous = previous.filter(|snapshot| {
            snapshot.version == CACHE_VERSION && snapshot.invocation == invocation
        });
        let modules = previous
            .as_ref()
            .map(Snapshot::module_graph)
            .unwrap_or_default();
        let probes = previous
            .as_ref()
            .map(Snapshot::probe_graph)
            .unwrap_or_default();
        let current = match Snapshot::capture(
            targets,
            arguments,
            manifest_path,
            &modules,
            &probes,
            Some(&invocation),
        ) {
            Ok(current) => current,
            Err(_) if previous.is_some() => {
                trace("rediscovering an unavailable cached module graph");
                previous = None;
                Snapshot::capture(
                    targets,
                    arguments,
                    manifest_path,
                    &ModuleGraph::new(),
                    &ProbeGraph::new(),
                    Some(&invocation),
                )?
            }
            Err(error) => return Err(error),
        };

        Ok(Self {
            cache_path,
            previous,
            current,
        })
    }

    /// Expands invalidations transitively across targets that share parser-loaded files.
    fn changed_targets(&self) -> BTreeSet<&str> {
        let all = || {
            self.current
                .packages
                .values()
                .flat_map(|package| package.targets.keys().map(String::as_str))
                .collect()
        };

        let Some(previous) = self.previous.as_ref() else {
            return all();
        };
        if previous.version != CACHE_VERSION
            || previous.invocation != self.current.invocation
            || previous.configuration != self.current.configuration
            || previous.packages.len() != self.current.packages.len()
        {
            return all();
        }

        let mut changed: BTreeSet<_> = self
            .current
            .packages
            .iter()
            .flat_map(|(package_path, package)| {
                package.targets.iter().filter_map(|(target_path, files)| {
                    let previous_package = previous.packages.get(package_path);
                    let previous_files =
                        previous_package.and_then(|previous| previous.targets.get(target_path));
                    let previous_probes =
                        previous_package.and_then(|previous| previous.probes.get(target_path));
                    let current_probes = package.probes.get(target_path);
                    (previous_files != Some(files) || previous_probes != current_probes)
                        .then_some(target_path.as_str())
                })
            })
            .collect();

        loop {
            let shared_files: BTreeSet<_> = self
                .current
                .packages
                .values()
                .flat_map(|package| {
                    package
                        .targets
                        .iter()
                        .filter(|(target, _)| changed.contains(target.as_str()))
                        .flat_map(|(_, files)| files.keys().map(String::as_str))
                })
                .collect();
            let additional: Vec<_> = self
                .current
                .packages
                .values()
                .flat_map(|package| {
                    package.targets.iter().filter_map(|(target, files)| {
                        (!changed.contains(target.as_str())
                            && files
                                .keys()
                                .any(|path| shared_files.contains(path.as_str())))
                        .then_some(target.as_str())
                    })
                })
                .collect();
            if additional.is_empty() {
                return changed;
            }
            changed.extend(additional);
        }
    }

    /// Rejects concurrent source/configuration changes while allowing newly discovered configs.
    fn can_record(
        &self,
        updated: &Snapshot,
        changed_targets: &BTreeSet<&str>,
        check_only: bool,
    ) -> bool {
        if updated.version != CACHE_VERSION
            || updated.invocation != self.current.invocation
            || self
                .current
                .configuration
                .iter()
                .any(|(path, digest)| updated.configuration.get(path) != Some(digest))
            || updated.packages.len() != self.current.packages.len()
        {
            return false;
        }

        self.current.packages.iter().all(|(package_path, package)| {
            let Some(updated_package) = updated.packages.get(package_path) else {
                return false;
            };
            if package.targets.len() != updated_package.targets.len() {
                return false;
            }
            if package.probes.len() != updated_package.probes.len() {
                return false;
            }

            package.targets.iter().all(|(target_path, files)| {
                let Some(updated_files) = updated_package.targets.get(target_path) else {
                    return false;
                };
                if !changed_targets.contains(target_path.as_str()) {
                    return files == updated_files
                        && package.probes.get(target_path)
                            == updated_package.probes.get(target_path);
                }
                !check_only
                    || files
                        .iter()
                        .all(|(path, digest)| updated_files.get(path) == Some(digest))
            })
        })
    }
}

impl Snapshot {
    /// Observes authoritative sources once each and discovers all effective formatter settings.
    fn capture(
        targets: &BTreeSet<Target>,
        arguments: &[String],
        manifest_path: Option<&Path>,
        modules: &ModuleGraph,
        probes: &ProbeGraph,
        invocation: Option<&str>,
    ) -> io::Result<Self> {
        let mut packages = BTreeMap::new();
        let mut file_fingerprints = BTreeMap::new();
        let mut observed_probes = BTreeMap::new();
        let mut configuration_directories = BTreeSet::new();

        for target in targets {
            let package_path = path_string(&target.package_root)?;
            let target_path = path_string(&target.path)?;
            let paths = modules
                .get(&target_path)
                .cloned()
                .unwrap_or_else(|| BTreeSet::from([target_path.clone()]));
            if !paths.contains(&target_path) {
                return Err(unsupported(
                    "an authoritative module graph omits its target root",
                ));
            }

            configuration_directories.insert(target.package_root.clone());
            let mut sources = BTreeMap::new();
            for path in paths {
                let fingerprint = match file_fingerprints.entry(path.clone()) {
                    Entry::Occupied(entry) => *entry.get(),
                    Entry::Vacant(entry) => {
                        let (_, metadata) = canonical_module_file(&path)?;
                        *entry.insert(SourceFingerprint::from_metadata(&metadata)?)
                    }
                };
                if let Some(parent) = Path::new(&path).parent() {
                    configuration_directories.insert(parent.to_owned());
                }
                sources.insert(path, fingerprint);
            }

            let mut target_probes = BTreeMap::new();
            if let Some(expected) = probes.get(&target_path) {
                for path in expected.keys() {
                    let observation = match observed_probes.entry(path.clone()) {
                        Entry::Occupied(entry) => entry.into_mut(),
                        Entry::Vacant(entry) => entry.insert(observe_module_probe(path)?),
                    };
                    target_probes.insert(path.clone(), observation.clone());
                }
            }

            let package = packages
                .entry(package_path)
                .or_insert_with(|| PackageSnapshot {
                    targets: BTreeMap::new(),
                    probes: BTreeMap::new(),
                });
            package.targets.insert(target_path.clone(), sources);
            package.probes.insert(target_path, target_probes);
        }

        let current_directory = env::current_dir()?.canonicalize()?;
        configuration_directories.insert(current_directory);
        let mut configuration = BTreeMap::new();
        let mut visited_directories = BTreeSet::new();
        for directory in configuration_directories {
            collect_ancestor_configuration(
                &directory,
                &mut visited_directories,
                &mut configuration,
            )?;
        }
        collect_global_configuration(&mut configuration)?;
        collect_explicit_configuration(arguments, &mut configuration)?;
        if let Some(path) = manifest_path {
            collect_configuration_file(path, &mut configuration)?;
        }

        Ok(Self {
            version: CACHE_VERSION,
            invocation: match invocation {
                Some(invocation) => invocation.to_owned(),
                None => invocation_key(targets, arguments)?,
            },
            configuration,
            packages,
        })
    }

    fn module_graph(&self) -> ModuleGraph {
        self.packages
            .values()
            .flat_map(|package| {
                package.targets.iter().map(|(target, files)| {
                    (
                        target.clone(),
                        files.keys().cloned().collect::<BTreeSet<_>>(),
                    )
                })
            })
            .collect()
    }

    fn probe_graph(&self) -> ProbeGraph {
        self.packages
            .values()
            .flat_map(|package| {
                package
                    .probes
                    .iter()
                    .map(|(target, probes)| (target.clone(), probes.clone()))
            })
            .collect()
    }
}

/// Fingerprints targets, effective settings, the trusted formatter, and its real compiler driver.
fn invocation_key(targets: &BTreeSet<Target>, arguments: &[String]) -> io::Result<String> {
    let current_directory = env::current_dir()?.canonicalize()?;
    let (formatter_path, compiler_path) = trusted_formatter()?;
    let formatter_metadata = fs::metadata(&formatter_path)?;
    let formatter_fingerprint = SourceFingerprint::from_metadata(&formatter_metadata)?;
    let mut invocation = Sha256::new();
    hash_value(&mut invocation, env!("CARGO_PKG_VERSION"));
    hash_value(&mut invocation, &path_string(&current_directory)?);
    hash_value(&mut invocation, &path_string(&formatter_path)?);
    invocation.update(formatter_fingerprint.modified_seconds.to_le_bytes());
    invocation.update(formatter_fingerprint.modified_nanoseconds.to_le_bytes());
    invocation.update(formatter_fingerprint.permissions_mode.to_le_bytes());
    invocation.update(formatter_metadata.len().to_le_bytes());
    hash_compiler_driver(&mut invocation, &compiler_path)?;

    for variable in [
        "APPDATA",
        "CARGO_HOME",
        "DYLD_FALLBACK_LIBRARY_PATH",
        "DYLD_LIBRARY_PATH",
        "HOME",
        "LD_LIBRARY_PATH",
        "RUSTC_BOOTSTRAP",
        "RUSTFMT_LOG",
        "RUSTUP_HOME",
        "RUSTUP_TOOLCHAIN",
        "USERPROFILE",
        "XDG_CONFIG_HOME",
    ] {
        hash_environment(&mut invocation, variable)?;
    }
    #[cfg(windows)]
    hash_environment(&mut invocation, "PATH")?;

    for argument in arguments {
        hash_value(&mut invocation, argument);
    }
    for target in targets {
        hash_value(&mut invocation, &path_string(&target.path)?);
        hash_value(&mut invocation, &path_string(&target.package_root)?);
        hash_value(&mut invocation, target.edition.as_str());
        hash_value(&mut invocation, &target.kind);
    }

    Ok(format!("{:x}", invocation.finalize()))
}

/// Consumes every edition manifest after validating roots, loaded sources, and native probes.
fn read_module_manifests(paths: &[PathBuf], targets: &BTreeSet<Target>) -> io::Result<Discovery> {
    if paths.is_empty() {
        return Err(unsupported("rustfmt did not provide a module manifest"));
    }

    let expected: BTreeSet<_> = targets
        .iter()
        .map(|target| path_string(&target.path))
        .collect::<io::Result<_>>()?;
    let mut roots = ModuleGraph::new();
    let mut probe_roots = ProbeGraph::new();
    for path in paths {
        let manifest = read_module_manifest(path);
        let removal = fs::remove_file(path);
        let manifest = manifest?;
        removal?;

        if manifest.schema != MODULE_MANIFEST_SCHEMA || manifest.version != MODULE_MANIFEST_VERSION
        {
            return Err(unsupported("rustfmt produced an unknown module manifest"));
        }

        for root in manifest.roots {
            if !expected.contains(&root.path) || roots.contains_key(&root.path) {
                return Err(unsupported(
                    "the authoritative module manifest has an unexpected target",
                ));
            }
            canonical_module_path(&root.path)?;
            let mut files = BTreeSet::new();
            for path in root.files {
                canonical_module_path(&path)?;
                if !files.insert(path) {
                    return Err(unsupported(
                        "the authoritative module manifest repeats a source file",
                    ));
                }
            }
            let mut dependencies = BTreeSet::new();
            for path in root.dependencies {
                canonical_module_path(&path)?;
                if !dependencies.insert(path) {
                    return Err(unsupported(
                        "the authoritative module manifest repeats a parsed dependency",
                    ));
                }
            }
            if !files.contains(&root.path) || !dependencies.contains(&root.path) {
                return Err(unsupported(
                    "the authoritative module manifest omits its root source",
                ));
            }
            if !files.is_subset(&dependencies) {
                return Err(unsupported(
                    "the authoritative module manifest omits a formatted dependency",
                ));
            }

            let mut observations = BTreeMap::new();
            for probe in root.probes {
                let expected = ProbeObservation {
                    canonical: probe.canonical,
                    exists: probe.exists,
                    is_directory: probe.is_directory,
                };
                if expected.exists != expected.canonical.is_some()
                    || (!expected.exists && expected.is_directory)
                {
                    return Err(unsupported(
                        "an authoritative source probe has inconsistent existence",
                    ));
                }
                if observe_module_probe(&probe.path)? != expected {
                    return Err(unsupported(
                        "an authoritative source probe changed during formatting",
                    ));
                }
                if observations.insert(probe.path, expected).is_some() {
                    return Err(unsupported(
                        "the authoritative module manifest repeats a resolution probe",
                    ));
                }
            }
            if dependencies.iter().any(|dependency| {
                !observations.values().any(|observation| {
                    observation.exists && observation.canonical.as_ref() == Some(dependency)
                })
            }) {
                return Err(unsupported(
                    "the authoritative module manifest omits a loaded source probe",
                ));
            }
            files.extend(dependencies);
            probe_roots.insert(root.path.clone(), observations);
            roots.insert(root.path, files);
        }
    }

    if roots.keys().cloned().collect::<BTreeSet<_>>() != expected {
        return Err(unsupported(
            "the authoritative module manifest omits a formatter target",
        ));
    }

    Ok(Discovery {
        modules: roots,
        probes: probe_roots,
    })
}

/// Rejects symlinked and non-regular producer manifests before parsing their contents.
fn read_module_manifest(path: &Path) -> io::Result<ModuleManifest> {
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.file_type().is_file() {
        return Err(unsupported("the module manifest is not a regular file"));
    }
    let file = File::open(path)?;
    serde_json::from_reader(file).map_err(io::Error::other)
}

fn canonical_module_path(path: &str) -> io::Result<PathBuf> {
    canonical_module_file(path).map(|(canonical, _)| canonical)
}

/// Requires an absolute canonical regular source file before trusting manifest ownership.
fn canonical_module_file(path: &str) -> io::Result<(PathBuf, fs::Metadata)> {
    let path = Path::new(path);
    if !path.is_absolute() {
        return Err(unsupported("an authoritative module path is not absolute"));
    }
    let canonical = path.canonicalize()?;
    let metadata = fs::metadata(&canonical)?;
    if canonical != path || !metadata.is_file() {
        return Err(unsupported(
            "an authoritative module path is not a canonical source file",
        ));
    }
    Ok((canonical, metadata))
}

/// Replays native module lookup, preserving missing candidates, symlinks, and file kind.
fn observe_module_probe(path: &str) -> io::Result<ProbeObservation> {
    let path = Path::new(path);
    if !path.is_absolute() {
        return Err(unsupported("an authoritative source probe is not absolute"));
    }
    // `Path::exists` is exactly `fs::metadata(path).is_ok()`. Retaining the
    // metadata also records directory decisions without a second stat call.
    let metadata = fs::metadata(path);
    let exists = metadata.is_ok();
    let is_directory = metadata.as_ref().is_ok_and(fs::Metadata::is_dir);
    let canonical = if exists {
        Some(path_string(&path.canonicalize()?)?)
    } else {
        None
    };
    Ok(ProbeObservation {
        canonical,
        exists,
        is_directory,
    })
}

/// Discovers workspace, toolchain, Cargo, and formatter configuration in every ancestor.
fn collect_ancestor_configuration(
    directory: &Path,
    visited: &mut BTreeSet<PathBuf>,
    configuration: &mut BTreeMap<String, String>,
) -> io::Result<()> {
    for ancestor in directory.ancestors() {
        if !visited.insert(ancestor.to_owned()) {
            continue;
        }
        for name in [
            "rustfmt.toml",
            ".rustfmt.toml",
            "Cargo.toml",
            "Cargo.lock",
            "rust-toolchain",
            "rust-toolchain.toml",
            ".cargo/config",
            ".cargo/config.toml",
        ] {
            collect_configuration_file(&ancestor.join(name), configuration)?;
        }
    }

    Ok(())
}

/// Includes the home and platform-specific formatter configuration search locations.
fn collect_global_configuration(configuration: &mut BTreeMap<String, String>) -> io::Result<()> {
    for directory in [
        dirs::home_dir(),
        dirs::config_dir().map(|path| path.join("rustfmt")),
    ]
    .into_iter()
    .flatten()
    {
        for name in [".rustfmt.toml", "rustfmt.toml"] {
            collect_configuration_file(&directory.join(name), configuration)?;
        }
    }

    Ok(())
}

/// Resolves explicit configuration files/directories without losing observable-mode checks.
fn collect_explicit_configuration(
    arguments: &[String],
    configuration: &mut BTreeMap<String, String>,
) -> io::Result<()> {
    let mut arguments = arguments.iter();
    while let Some(argument) = arguments.next() {
        let path = if argument == "--config-path" {
            arguments.next().map(PathBuf::from)
        } else {
            argument.strip_prefix("--config-path=").map(PathBuf::from)
        };

        let Some(path) = path else {
            continue;
        };

        if path.is_dir() {
            collect_configuration_file(&path.join("rustfmt.toml"), configuration)?;
            collect_configuration_file(&path.join(".rustfmt.toml"), configuration)?;
        } else {
            reject_observable_formatter_configuration(&path)?;
            collect_configuration_file(&path, configuration)?;
        }
    }

    Ok(())
}

/// Hashes existing settings under their logical names so symlink precedence remains visible.
fn collect_configuration_file(
    path: &Path,
    configuration: &mut BTreeMap<String, String>,
) -> io::Result<()> {
    match fs::metadata(path) {
        Ok(metadata) if metadata.is_file() => {}
        Ok(_) => return Ok(()),
        Err(error)
            if matches!(
                error.kind(),
                io::ErrorKind::NotFound | io::ErrorKind::NotADirectory
            ) =>
        {
            return Ok(());
        }
        Err(error) => return Err(error),
    }

    if matches!(
        path.file_name().and_then(|name| name.to_str()),
        Some("rustfmt.toml" | ".rustfmt.toml")
    ) {
        reject_observable_formatter_configuration(path)?;
    }

    // Keep the searched name as well as its canonical destination: rustfmt
    // gives `.rustfmt.toml` precedence over `rustfmt.toml`, even when both are
    // symlinks to the same otherwise unchanged set of configuration files.
    let logical_path = if path.is_absolute() {
        path.to_owned()
    } else {
        env::current_dir()?.join(path)
    };
    let key = path_string(&logical_path)?;
    if !configuration.contains_key(&key) {
        let canonical_path = path.canonicalize()?;
        let canonical = path_string(&canonical_path)?;
        let digest = hash_configuration_file(&canonical_path)?;
        configuration.insert(key, format!("{canonical}:{digest}"));
    }
    Ok(())
}

/// Refuses settings that could make a skipped formatter invocation externally observable.
fn reject_observable_formatter_configuration(path: &Path) -> io::Result<()> {
    if !path.is_file() {
        return Ok(());
    }

    let configuration = fs::read(path)?;
    if configuration.contains(&b'\\')
        || [
            b"emit_mode".as_slice(),
            b"file_lines".as_slice(),
            b"verbose".as_slice(),
            b"print_misformatted_file_names".as_slice(),
            b"make_backup".as_slice(),
        ]
        .iter()
        .any(|setting| {
            configuration
                .windows(setting.len())
                .any(|candidate| candidate == *setting)
        })
    {
        return Err(unsupported(
            "a rustfmt configuration may select observable formatting behavior",
        ));
    }

    Ok(())
}

/// Streams configuration contents so even large lockfiles contribute exact cache identity.
fn hash_configuration_file(path: &Path) -> io::Result<String> {
    let mut file = File::open(path)?;
    let mut digest = Sha256::new();
    let mut buffer = [0; 16 * 1024];

    loop {
        let read = file.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        digest.update(&buffer[..read]);
    }

    Ok(format!("{:x}", digest.finalize()))
}

/// Accepts only native formatter/compiler siblings of the running cargo-fmt executable.
fn trusted_formatter() -> io::Result<(PathBuf, PathBuf)> {
    if env::var_os("RUSTFMT_WRAPPER").is_some() {
        return Err(unsupported(
            "a custom rustfmt wrapper cannot be cached safely",
        ));
    }
    if env::vars_os().any(|(variable, _)| {
        variable
            .to_str()
            .is_some_and(is_unsafe_dynamic_loader_variable)
    }) {
        return Err(unsupported(
            "dynamic loader instrumentation cannot be cached safely",
        ));
    }

    let path = PathBuf::from(rustfmt_command().get_program()).canonicalize()?;
    let expected_formatter = if cfg!(windows) {
        "rustfmt.exe"
    } else {
        "rustfmt"
    };
    let expected_compiler = if cfg!(windows) { "rustc.exe" } else { "rustc" };
    // The executing cargo-fmt and its sibling tools form one trusted bundle.
    // Other installed or linked toolchains may contain opaque native wrappers.
    let executable = env::current_exe()?.canonicalize()?;
    let directory = executable
        .parent()
        .ok_or_else(|| unsupported("the formatter toolchain has no binary directory"))?;
    if !is_sibling_formatter(&path, directory, expected_formatter) {
        return Err(unsupported(
            "a custom rustfmt executable cannot be cached safely",
        ));
    }

    let compiler = directory.join(expected_compiler);
    if !is_native_executable(&path)? || !is_native_executable(&compiler)? {
        return Err(unsupported(
            "a custom formatter toolchain cannot be cached safely",
        ));
    }

    Ok((path, compiler.canonicalize()?))
}

/// Locates the compiler implementation loaded dynamically by rustfmt.
///
/// The neighboring compiler can itself be a symlink, as in bootstrap tool
/// bundles, so its canonical location determines the actual runtime sysroot.
fn compiler_driver(compiler: &Path) -> io::Result<PathBuf> {
    let compiler = compiler.canonicalize()?;
    let sysroot = compiler
        .parent()
        .and_then(Path::parent)
        .ok_or_else(|| unsupported("the formatter compiler has no runtime sysroot"))?;
    let library_directory = sysroot.join(if cfg!(windows) { "bin" } else { "lib" });
    let prefix = format!("{}rustc_driver-", env::consts::DLL_PREFIX);
    let suffix = env::consts::DLL_SUFFIX;
    let mut driver = None;

    for entry in fs::read_dir(&library_directory)? {
        let entry = entry?;
        let name = entry.file_name();
        let Some(name) = name.to_str() else {
            continue;
        };
        if !name.starts_with(&prefix)
            || !name.ends_with(suffix)
            || name.len() == prefix.len() + suffix.len()
        {
            continue;
        }
        if driver.is_some() {
            return Err(unsupported(
                "the formatter toolchain has multiple rustc driver libraries",
            ));
        }

        let path = entry.path().canonicalize()?;
        if !fs::metadata(&path)?.is_file() {
            return Err(unsupported(
                "the formatter toolchain's rustc driver is not a regular file",
            ));
        }
        File::open(&path)?;
        driver = Some(path);
    }

    driver.ok_or_else(|| unsupported("the formatter toolchain has no rustc driver library"))
}

/// Fingerprints the real compiler implementation without reading its contents.
fn hash_compiler_driver(digest: &mut Sha256, compiler: &Path) -> io::Result<()> {
    let path = compiler_driver(compiler)?;
    validate_compiler_driver_search_paths(&path)?;
    let metadata = fs::metadata(&path)?;
    let fingerprint = SourceFingerprint::from_metadata(&metadata)?;

    hash_value(digest, &path_string(&path)?);
    digest.update(fingerprint.modified_seconds.to_le_bytes());
    digest.update(fingerprint.modified_nanoseconds.to_le_bytes());
    digest.update(fingerprint.permissions_mode.to_le_bytes());
    digest.update(metadata.len().to_le_bytes());

    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;

        digest.update(metadata.dev().to_le_bytes());
        digest.update(metadata.ino().to_le_bytes());
        digest.update(metadata.ctime().to_le_bytes());
        digest.update(metadata.ctime_nsec().to_le_bytes());
    }

    Ok(())
}

/// Rejects dynamic-loader directories that can replace the trusted driver.
///
/// Hashing only the search-path environment string cannot detect a library
/// appearing inside an otherwise unchanged directory after a cache is warmed.
fn validate_compiler_driver_search_paths(driver: &Path) -> io::Result<()> {
    for variable in [
        "DYLD_LIBRARY_PATH",
        "DYLD_FALLBACK_LIBRARY_PATH",
        "LD_LIBRARY_PATH",
    ] {
        if let Some(paths) = env::var_os(variable) {
            for directory in env::split_paths(&paths) {
                validate_compiler_driver_search_directory(driver, &directory)?;
            }
        }
    }

    #[cfg(windows)]
    if let Some(paths) = env::var_os("PATH") {
        for directory in env::split_paths(&paths) {
            validate_compiler_driver_search_directory(driver, &directory)?;
        }
    }

    Ok(())
}

/// Allows absent candidates or aliases of the verified driver, rejecting replacements.
fn validate_compiler_driver_search_directory(driver: &Path, directory: &Path) -> io::Result<()> {
    let name = driver
        .file_name()
        .ok_or_else(|| unsupported("the formatter compiler driver has no filename"))?;
    // Empty search-path components denote the current directory. Joining a
    // relative filename preserves that native dynamic-loader behavior.
    let candidate = directory.join(name);
    match fs::metadata(&candidate) {
        Ok(metadata) if metadata.is_file() && candidate.canonicalize()? == driver => Ok(()),
        Ok(_) => Err(unsupported(
            "a dynamic library search path can replace the formatter compiler driver",
        )),
        Err(error)
            if matches!(
                error.kind(),
                io::ErrorKind::NotFound | io::ErrorKind::NotADirectory
            ) =>
        {
            Ok(())
        }
        Err(error) => Err(error),
    }
}

/// Rejects loader instrumentation while permitting explicitly verified library search paths.
fn is_unsafe_dynamic_loader_variable(variable: &str) -> bool {
    (variable.starts_with("LD_") && variable != "LD_LIBRARY_PATH")
        || (variable.starts_with("DYLD_")
            && variable != "DYLD_LIBRARY_PATH"
            && variable != "DYLD_FALLBACK_LIBRARY_PATH")
}

/// Confirms the resolved formatter is the canonical sibling of this cargo-fmt binary.
fn is_sibling_formatter(path: &Path, directory: &Path, expected_formatter: &str) -> bool {
    path.file_name().and_then(|name| name.to_str()) == Some(expected_formatter)
        && directory
            .join(expected_formatter)
            .canonicalize()
            .is_ok_and(|formatter| formatter == path)
}

/// Rejects shell-script wrappers by recognizing native ELF, Mach-O, and PE headers.
fn is_native_executable(path: &Path) -> io::Result<bool> {
    let mut file = File::open(path)?;
    let mut prefix = [0; 4];
    file.read_exact(&mut prefix)?;
    Ok(prefix == *b"\x7fELF"
        || prefix[..2] == *b"MZ"
        || matches!(
            prefix,
            [0xcf, 0xfa, 0xed, 0xfe]
                | [0xfe, 0xed, 0xfa, 0xcf]
                | [0xca, 0xfe, 0xba, 0xbe]
                | [0xbe, 0xba, 0xfe, 0xca]
                | [0xca, 0xfe, 0xba, 0xbf]
        ))
}

/// Length-prefixes values so adjacent invocation fields cannot collide by concatenation.
fn hash_value(digest: &mut Sha256, value: &str) {
    digest.update(value.len().to_le_bytes());
    digest.update(value.as_bytes());
}

/// Distinguishes missing environment values and rejects non-UTF-8 invocation identity.
fn hash_environment(digest: &mut Sha256, variable: &str) -> io::Result<()> {
    hash_value(digest, variable);
    let Some(value) = env::var_os(variable) else {
        hash_value(digest, "<unset>");
        return Ok(());
    };
    let Some(value) = value.to_str() else {
        return Err(unsupported(
            "a formatter environment value is not valid UTF-8",
        ));
    };
    hash_value(digest, value);
    Ok(())
}

fn path_string(path: &Path) -> io::Result<String> {
    path.to_str()
        .map(str::to_owned)
        .ok_or_else(|| unsupported("a package path is not valid UTF-8"))
}

/// Honors the explicit cache override before Cargo's target directory and workspace defaults.
fn cache_directory(manifest_path: Option<&Path>) -> io::Result<PathBuf> {
    if let Some(path) = env::var_os(CACHE_ENVIRONMENT) {
        return Ok(PathBuf::from(path));
    }

    if let Some(path) = env::var_os("CARGO_TARGET_DIR") {
        return Ok(PathBuf::from(path).join("ohm-rustfmt"));
    }

    let directory = if let Some(path) = manifest_path {
        path.parent()
            .map(Path::to_owned)
            .unwrap_or(env::current_dir()?)
    } else {
        env::current_dir()?
    };

    Ok(directory.join("target").join("ohm-rustfmt"))
}

/// Publishes a fully serialized snapshot with an atomic same-directory rename.
fn write_cache(path: &Path, snapshot: &Snapshot) -> io::Result<()> {
    let Some(parent) = path.parent() else {
        return Err(unsupported("the cache path has no parent directory"));
    };

    fs::create_dir_all(parent)?;
    let temporary_path = path.with_extension(format!("{}.tmp", std::process::id()));
    let file = File::create(&temporary_path)?;
    serde_json::to_writer(file, snapshot).map_err(io::Error::other)?;
    fs::rename(temporary_path, path)
}

/// Conservatively disables caching for output-producing flags and unaudited inline settings.
fn has_observable_emit_mode(arguments: &[String]) -> bool {
    let mut arguments = arguments.iter();
    while let Some(argument) = arguments.next() {
        if matches!(
            argument.as_str(),
            "--print-config"
                | "--config-help"
                | "--help"
                | "-h"
                | "--version"
                | "-V"
                | "--verbose"
                | "-v"
                | "--file-lines"
        ) || argument.starts_with("--print-config=")
            || argument.starts_with("--help=")
            || argument.starts_with("--file-lines=")
            || argument == "--files-with-diff"
            || (argument.starts_with('-')
                && !argument.starts_with("--")
                && argument
                    .chars()
                    .skip(1)
                    .any(|flag| matches!(flag, 'v' | 'V' | 'h' | 'l')))
        {
            return true;
        } else if argument == "--emit" {
            if arguments.next().is_none_or(|mode| mode != "files") {
                return true;
            }
        } else if argument
            .strip_prefix("--emit=")
            .is_some_and(|mode| mode != "files")
        {
            return true;
        } else if argument == "--config" {
            if arguments
                .next()
                .is_none_or(|configuration| !is_safe_inline_configuration(configuration))
            {
                return true;
            }
        } else if argument
            .strip_prefix("--config=")
            .is_some_and(|configuration| !is_safe_inline_configuration(configuration))
        {
            return true;
        }
    }

    false
}

/// Allows only formatting-only import-granularity values used by the normal Codex workflow.
fn is_safe_inline_configuration(configuration: &str) -> bool {
    matches!(
        configuration,
        "imports_granularity=Preserve"
            | "imports_granularity=Crate"
            | "imports_granularity=Module"
            | "imports_granularity=Item"
            | "imports_granularity=One"
    )
}

fn trace(message: &str) {
    if matches!(env::var(TRACE_ENVIRONMENT).as_deref(), Ok("1" | "true")) {
        eprintln!("ohm incremental fmt: {message}");
    }
}

fn unsupported(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::Unsupported, message)
}

#[cfg(test)]
mod tests {
    use super::*;
    use cargo_metadata::Edition;

    fn fingerprint(value: &str) -> SourceFingerprint {
        SourceFingerprint {
            modified_seconds: value.bytes().fold(0_i64, |fingerprint, byte| {
                fingerprint.wrapping_mul(31).wrapping_add(i64::from(byte))
            }),
            modified_nanoseconds: 0,
            permissions_mode: 0o644,
        }
    }

    fn snapshot(files: &[(&str, &[(&str, &str)])]) -> Snapshot {
        Snapshot {
            version: CACHE_VERSION,
            invocation: String::from("formatter-and-arguments"),
            configuration: BTreeMap::from([(
                String::from("/workspace/rustfmt.toml"),
                String::from("original-config"),
            )]),
            packages: files
                .iter()
                .map(|(package, sources)| {
                    let root = format!("{package}/src/lib.rs");
                    let files = sources
                        .iter()
                        .map(|(path, identity)| {
                            let path = if Path::new(path).is_absolute() {
                                String::from(*path)
                            } else {
                                format!("{package}/{path}")
                            };
                            (path, fingerprint(identity))
                        })
                        .collect();
                    (
                        String::from(*package),
                        PackageSnapshot {
                            targets: BTreeMap::from([(root.clone(), files)]),
                            probes: BTreeMap::from([(root, BTreeMap::new())]),
                        },
                    )
                })
                .collect(),
        }
    }

    fn plan(previous: Option<Snapshot>, current: Snapshot) -> Plan {
        Plan {
            cache_path: PathBuf::from("unused-cache.json"),
            previous,
            current,
        }
    }

    fn target(root: &Path, package: &Path) -> Target {
        Target {
            path: root.to_owned(),
            package_root: package.to_owned(),
            kind: String::from("lib"),
            edition: Edition::E2021,
        }
    }

    fn write_manifest(path: &Path, manifest: &ModuleManifest) -> io::Result<()> {
        let file = File::create(path)?;
        serde_json::to_writer(file, manifest).map_err(io::Error::other)
    }

    fn probe(path: &Path) -> io::Result<ModuleProbe> {
        let path = path_string(path)?;
        let observation = observe_module_probe(&path)?;
        Ok(ModuleProbe {
            path,
            canonical: observation.canonical,
            exists: observation.exists,
            is_directory: observation.is_directory,
        })
    }

    #[test]
    fn incremental_formatting_defaults_on_and_honors_explicit_opt_out() {
        assert!(incremental_formatting_enabled(Err(
            env::VarError::NotPresent
        )));

        for value in ["1", "true"] {
            assert!(
                incremental_formatting_enabled(Ok(String::from(value))),
                "{value:?} must preserve the existing explicit opt-in"
            );
        }

        for value in ["0", "false", "", "TRUE", "unexpected"] {
            assert!(
                !incremental_formatting_enabled(Ok(String::from(value))),
                "{value:?} must not enable incremental formatting"
            );
        }

        assert!(!incremental_formatting_enabled(Err(
            env::VarError::NotUnicode(std::ffi::OsString::from("invalid"))
        )));
    }

    #[test]
    fn source_fingerprints_follow_precise_modification_times() -> io::Result<()> {
        let directory = tempfile::tempdir()?;
        let path = directory.path().join("source.rs");
        fs::write(&path, "pub fn unchanged() {}\n")?;
        let file = OpenOptions::new().write(true).open(&path)?;
        let first_time = UNIX_EPOCH + std::time::Duration::new(1_700_000_000, 123_456_700);
        file.set_times(fs::FileTimes::new().set_modified(first_time))?;
        let before = SourceFingerprint::from_metadata(&fs::metadata(&path)?)?;

        let second_time = UNIX_EPOCH + std::time::Duration::new(1_700_000_002, 987_654_300);
        file.set_times(fs::FileTimes::new().set_modified(second_time))?;
        let metadata = fs::metadata(&path)?;
        let after = SourceFingerprint::from_metadata(&metadata)?;
        let actual = metadata
            .modified()?
            .duration_since(UNIX_EPOCH)
            .map_err(io::Error::other)?;

        assert_ne!(before, after);
        assert_eq!(after.modified_seconds, actual.as_secs() as i64);
        assert_eq!(after.modified_nanoseconds, actual.subsec_nanos());
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn source_fingerprints_include_permissions_without_reading_contents() -> io::Result<()> {
        use std::os::unix::fs::PermissionsExt;

        let directory = tempfile::tempdir()?;
        let path = directory.path().join("source.rs");
        fs::write(&path, "pub fn unchanged() {}\n")?;
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644))?;
        let before = SourceFingerprint::from_metadata(&fs::metadata(&path)?)?;

        fs::set_permissions(&path, fs::Permissions::from_mode(0o000))?;
        let after = SourceFingerprint::from_metadata(&fs::metadata(&path)?)?;

        assert_ne!(before.permissions_mode, after.permissions_mode);
        assert_eq!(before.modified_seconds, after.modified_seconds);
        assert_eq!(before.modified_nanoseconds, after.modified_nanoseconds);
        assert_eq!(after.permissions_mode & 0o777, 0);
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644))?;
        Ok(())
    }

    #[test]
    fn restored_timestamps_share_ruffs_documented_metadata_trust_boundary() -> io::Result<()> {
        let directory = tempfile::tempdir()?;
        let path = directory.path().join("source.rs");
        let timestamp = UNIX_EPOCH + std::time::Duration::from_secs(1_700_000_000);
        fs::write(&path, "pub fn first() {}\n")?;
        OpenOptions::new()
            .write(true)
            .open(&path)?
            .set_times(fs::FileTimes::new().set_modified(timestamp))?;
        let before = SourceFingerprint::from_metadata(&fs::metadata(&path)?)?;

        fs::write(&path, "pub fn deliberately_restored() {}\n")?;
        OpenOptions::new()
            .write(true)
            .open(&path)?
            .set_times(fs::FileTimes::new().set_modified(timestamp))?;
        let after = SourceFingerprint::from_metadata(&fs::metadata(&path)?)?;

        assert_eq!(before, after);
        Ok(())
    }

    #[test]
    fn unchanged_sources_hit_the_successful_format_cache() {
        let current = snapshot(&[("/workspace/first", &[("src/lib.rs", "formatted")])]);
        let plan = plan(Some(current.clone()), current);

        assert!(plan.changed_targets().is_empty());
    }

    #[test]
    fn changed_source_only_invalidates_its_authoritative_target() {
        let previous = snapshot(&[
            ("/workspace/first", &[("src/lib.rs", "before")]),
            ("/workspace/second", &[("src/lib.rs", "unchanged")]),
        ]);
        let current = snapshot(&[
            ("/workspace/first", &[("src/lib.rs", "after")]),
            ("/workspace/second", &[("src/lib.rs", "unchanged")]),
        ]);
        let plan = plan(Some(previous), current);

        assert_eq!(
            plan.changed_targets(),
            BTreeSet::from(["/workspace/first/src/lib.rs"])
        );
    }

    #[test]
    fn shared_external_modules_invalidate_every_owning_target() {
        let previous = snapshot(&[
            (
                "/workspace/first",
                &[("src/lib.rs", "root"), ("/workspace/shared.rs", "before")],
            ),
            (
                "/workspace/second",
                &[("src/lib.rs", "root"), ("/workspace/shared.rs", "before")],
            ),
            ("/workspace/third", &[("src/lib.rs", "unrelated")]),
        ]);
        let current = snapshot(&[
            (
                "/workspace/first",
                &[("src/lib.rs", "root"), ("/workspace/shared.rs", "after")],
            ),
            (
                "/workspace/second",
                &[("src/lib.rs", "root"), ("/workspace/shared.rs", "after")],
            ),
            ("/workspace/third", &[("src/lib.rs", "unrelated")]),
        ]);
        let plan = plan(Some(previous), current);

        assert_eq!(
            plan.changed_targets(),
            BTreeSet::from([
                "/workspace/first/src/lib.rs",
                "/workspace/second/src/lib.rs"
            ])
        );
    }

    #[test]
    fn newly_available_resolution_candidate_invalidates_its_target() {
        let mut previous = snapshot(&[("/workspace/first", &[("src/lib.rs", "unchanged")])]);
        if let Some(package) = previous.packages.get_mut("/workspace/first") {
            if let Some(probes) = package.probes.get_mut("/workspace/first/src/lib.rs") {
                probes.insert(
                    String::from("/workspace/first/src/nested/mod.rs"),
                    ProbeObservation {
                        canonical: None,
                        exists: false,
                        is_directory: false,
                    },
                );
            }
        }
        let mut current = previous.clone();
        if let Some(package) = current.packages.get_mut("/workspace/first") {
            if let Some(probes) = package.probes.get_mut("/workspace/first/src/lib.rs") {
                probes.insert(
                    String::from("/workspace/first/src/nested/mod.rs"),
                    ProbeObservation {
                        canonical: Some(String::from("/workspace/first/src/nested/mod.rs")),
                        exists: true,
                        is_directory: false,
                    },
                );
            }
        }

        let plan = plan(Some(previous), current);
        assert_eq!(
            plan.changed_targets(),
            BTreeSet::from(["/workspace/first/src/lib.rs"])
        );
    }

    #[test]
    fn retargeted_source_symlink_invalidates_its_target() {
        let mut previous = snapshot(&[("/workspace/first", &[("src/lib.rs", "unchanged")])]);
        if let Some(package) = previous.packages.get_mut("/workspace/first") {
            if let Some(probes) = package.probes.get_mut("/workspace/first/src/lib.rs") {
                probes.insert(
                    String::from("/workspace/first/src/linked.rs"),
                    ProbeObservation {
                        canonical: Some(String::from("/workspace/shared/old.rs")),
                        exists: true,
                        is_directory: false,
                    },
                );
            }
        }
        let mut current = previous.clone();
        if let Some(package) = current.packages.get_mut("/workspace/first") {
            if let Some(probes) = package.probes.get_mut("/workspace/first/src/lib.rs") {
                probes.insert(
                    String::from("/workspace/first/src/linked.rs"),
                    ProbeObservation {
                        canonical: Some(String::from("/workspace/shared/new.rs")),
                        exists: true,
                        is_directory: false,
                    },
                );
            }
        }

        let plan = plan(Some(previous), current);
        assert_eq!(
            plan.changed_targets(),
            BTreeSet::from(["/workspace/first/src/lib.rs"])
        );
    }

    #[test]
    fn concurrent_resolution_change_does_not_match_producer_probe_graph() {
        let mut snapshot = snapshot(&[("/workspace/first", &[("src/lib.rs", "unchanged")])]);
        let root = String::from("/workspace/first/src/lib.rs");
        let logical = String::from("/workspace/first/src/nested/mod.rs");
        let expected = ProbeGraph::from([(
            root.clone(),
            BTreeMap::from([(
                logical.clone(),
                ProbeObservation {
                    canonical: None,
                    exists: false,
                    is_directory: false,
                },
            )]),
        )]);
        if let Some(package) = snapshot.packages.get_mut("/workspace/first") {
            package.probes.insert(
                root,
                BTreeMap::from([(
                    logical.clone(),
                    ProbeObservation {
                        canonical: Some(logical),
                        exists: true,
                        is_directory: false,
                    },
                )]),
            );
        }

        assert_ne!(snapshot.probe_graph(), expected);
    }

    #[test]
    fn verification_rejects_concurrently_changed_module_and_probe_graphs() {
        let root = String::from("/workspace/first/src/lib.rs");
        let module = String::from("/workspace/first/src/nested.rs");
        let modules =
            ModuleGraph::from([(root.clone(), BTreeSet::from([root.clone(), module.clone()]))]);
        let probes = ProbeGraph::from([(
            root.clone(),
            BTreeMap::from([(
                module.clone(),
                ProbeObservation {
                    canonical: Some(module.clone()),
                    exists: true,
                    is_directory: false,
                },
            )]),
        )]);
        let discovery = Discovery {
            modules: modules.clone(),
            probes: probes.clone(),
        };
        assert!(discovery_matches(&discovery, &modules, &probes));

        let mut changed_modules = discovery.clone();
        if let Some(files) = changed_modules.modules.get_mut(&root) {
            files.insert(String::from("/workspace/first/src/replacement.rs"));
        }
        assert!(!discovery_matches(&changed_modules, &modules, &probes));

        let mut changed_probes = discovery;
        if let Some(observations) = changed_probes.probes.get_mut(&root) {
            observations.insert(
                String::from("/workspace/first/src/replacement.rs"),
                ProbeObservation {
                    canonical: None,
                    exists: false,
                    is_directory: false,
                },
            );
        }
        assert!(!discovery_matches(&changed_probes, &modules, &probes));
    }

    #[test]
    fn edited_root_also_reformats_every_transitively_shared_owner() {
        let previous = snapshot(&[
            (
                "/workspace/first",
                &[
                    ("src/lib.rs", "before"),
                    ("/workspace/first-shared.rs", "shared"),
                ],
            ),
            (
                "/workspace/second",
                &[
                    ("src/lib.rs", "unchanged"),
                    ("/workspace/first-shared.rs", "shared"),
                    ("/workspace/second-shared.rs", "shared"),
                ],
            ),
            (
                "/workspace/third",
                &[
                    ("src/lib.rs", "unchanged"),
                    ("/workspace/second-shared.rs", "shared"),
                ],
            ),
            ("/workspace/unrelated", &[("src/lib.rs", "unchanged")]),
        ]);
        let mut current = previous.clone();
        if let Some(package) = current.packages.get_mut("/workspace/first") {
            if let Some(files) = package.targets.get_mut("/workspace/first/src/lib.rs") {
                files.insert(
                    String::from("/workspace/first/src/lib.rs"),
                    fingerprint("after"),
                );
            }
        }

        let plan = plan(Some(previous), current);
        assert_eq!(
            plan.changed_targets(),
            BTreeSet::from([
                "/workspace/first/src/lib.rs",
                "/workspace/second/src/lib.rs",
                "/workspace/third/src/lib.rs",
            ])
        );
    }

    #[test]
    fn newly_discovered_shared_owner_requires_a_complete_second_pass() {
        let previous = ModuleGraph::from([
            (
                String::from("/workspace/first/src/lib.rs"),
                BTreeSet::from([String::from("/workspace/first/src/lib.rs")]),
            ),
            (
                String::from("/workspace/second/src/lib.rs"),
                BTreeSet::from([
                    String::from("/workspace/second/src/lib.rs"),
                    String::from("/workspace/second/src/shared.rs"),
                ]),
            ),
        ]);
        let discovered = ModuleGraph::from([(
            String::from("/workspace/first/src/lib.rs"),
            BTreeSet::from([
                String::from("/workspace/first/src/lib.rs"),
                String::from("/workspace/second/src/shared.rs"),
            ]),
        )]);

        assert!(discovers_new_shared_owner(
            &previous,
            &discovered,
            &BTreeSet::from(["/workspace/first/src/lib.rs"]),
        ));
        assert!(!discovers_new_shared_owner(
            &previous,
            &discovered,
            &BTreeSet::from([
                "/workspace/first/src/lib.rs",
                "/workspace/second/src/lib.rs",
            ]),
        ));
    }

    #[test]
    fn added_and_deleted_modules_invalidate_their_owner() {
        let previous = snapshot(&[("/workspace/first", &[("src/lib.rs", "unchanged")])]);
        let added = snapshot(&[(
            "/workspace/first",
            &[("src/lib.rs", "unchanged"), ("src/new.rs", "new")],
        )]);
        let addition = plan(Some(previous.clone()), added.clone());
        let deletion = plan(Some(added), previous);

        assert_eq!(
            addition.changed_targets(),
            BTreeSet::from(["/workspace/first/src/lib.rs"])
        );
        assert_eq!(
            deletion.changed_targets(),
            BTreeSet::from(["/workspace/first/src/lib.rs"])
        );
    }

    #[test]
    fn configuration_changes_invalidate_every_target() {
        let previous = snapshot(&[
            ("/workspace/first", &[("src/lib.rs", "unchanged")]),
            ("/workspace/second", &[("src/lib.rs", "unchanged")]),
        ]);
        let mut current = previous.clone();
        current.configuration.insert(
            String::from("/workspace/rustfmt.toml"),
            String::from("changed-config"),
        );
        let plan = plan(Some(previous), current);

        assert_eq!(
            plan.changed_targets(),
            BTreeSet::from([
                "/workspace/first/src/lib.rs",
                "/workspace/second/src/lib.rs"
            ])
        );
    }

    #[cfg(unix)]
    #[test]
    fn configuration_aliases_preserve_precedence_when_swapped() -> io::Result<()> {
        use std::os::unix::fs::symlink;

        let directory = tempfile::tempdir()?;
        let first = directory.path().join("first.toml");
        let second = directory.path().join("second.toml");
        let preferred = directory.path().join(".rustfmt.toml");
        let fallback = directory.path().join("rustfmt.toml");
        fs::write(&first, "max_width = 80\n")?;
        fs::write(&second, "max_width = 120\n")?;
        symlink(&first, &preferred)?;
        symlink(&second, &fallback)?;

        let mut before = BTreeMap::new();
        collect_configuration_file(&preferred, &mut before)?;
        collect_configuration_file(&fallback, &mut before)?;

        fs::remove_file(&preferred)?;
        fs::remove_file(&fallback)?;
        symlink(&second, &preferred)?;
        symlink(&first, &fallback)?;

        let mut after = BTreeMap::new();
        collect_configuration_file(&preferred, &mut after)?;
        collect_configuration_file(&fallback, &mut after)?;

        assert_eq!(before.len(), 2);
        assert_eq!(after.len(), 2);
        assert_ne!(before, after);
        assert_ne!(
            before.get(&path_string(&preferred)?),
            after.get(&path_string(&preferred)?)
        );
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn configuration_lookup_propagates_filesystem_errors() -> io::Result<()> {
        use std::os::unix::fs::symlink;

        let directory = tempfile::tempdir()?;
        let cycle = directory.path().join("rustfmt.toml");
        symlink(&cycle, &cycle)?;

        let error = collect_configuration_file(&cycle, &mut BTreeMap::new())
            .expect_err("a config symlink loop must not be mistaken for an absent file");
        assert!(!matches!(
            error.kind(),
            io::ErrorKind::NotFound | io::ErrorKind::NotADirectory
        ));
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn inaccessible_configuration_directories_are_not_silently_ignored() -> io::Result<()> {
        use std::os::unix::fs::PermissionsExt;

        let directory = tempfile::tempdir()?;
        let restricted = directory.path().join("configuration");
        fs::create_dir(&restricted)?;
        let configuration = restricted.join("rustfmt.toml");
        fs::write(&configuration, "max_width = 100\n")?;
        fs::set_permissions(&restricted, fs::Permissions::from_mode(0o000))?;
        let metadata_error = fs::metadata(&configuration).err();
        let result = collect_configuration_file(&configuration, &mut BTreeMap::new());
        fs::set_permissions(&restricted, fs::Permissions::from_mode(0o755))?;

        if metadata_error.is_some_and(|error| error.kind() == io::ErrorKind::PermissionDenied) {
            assert_eq!(
                result.map(|_| ()).err().map(|error| error.kind()),
                Some(io::ErrorKind::PermissionDenied)
            );
        }
        Ok(())
    }

    #[test]
    fn dynamic_loader_instrumentation_is_never_trusted() {
        for variable in [
            "DYLD_INSERT_LIBRARIES",
            "DYLD_FORCE_FLAT_NAMESPACE",
            "DYLD_IMAGE_SUFFIX",
            "LD_PRELOAD",
            "LD_AUDIT",
            "LD_PRELOAD_32",
        ] {
            assert!(is_unsafe_dynamic_loader_variable(variable));
        }
        assert!(!is_unsafe_dynamic_loader_variable("DYLD_LIBRARY_PATH"));
        assert!(!is_unsafe_dynamic_loader_variable(
            "DYLD_FALLBACK_LIBRARY_PATH"
        ));
        assert!(!is_unsafe_dynamic_loader_variable("LD_LIBRARY_PATH"));
        assert!(!is_unsafe_dynamic_loader_variable("RUSTFMT_LOG"));
    }

    #[test]
    fn only_the_executing_toolchains_sibling_formatter_is_trusted() -> io::Result<()> {
        let directory = tempfile::tempdir()?;
        let current = directory.path().join("current/bin");
        let other = directory.path().join("registered/bin");
        fs::create_dir_all(&current)?;
        fs::create_dir_all(&other)?;
        let expected = if cfg!(windows) {
            "rustfmt.exe"
        } else {
            "rustfmt"
        };
        let sibling = current.join(expected);
        let registered = other.join(expected);
        fs::write(&sibling, "trusted toolchain sibling")?;
        fs::write(&registered, "opaque registered toolchain wrapper")?;

        assert!(is_sibling_formatter(
            &sibling.canonicalize()?,
            &current,
            expected
        ));
        assert!(!is_sibling_formatter(
            &registered.canonicalize()?,
            &current,
            expected
        ));
        Ok(())
    }

    fn compiler_driver_fixture() -> io::Result<(tempfile::TempDir, PathBuf, PathBuf)> {
        let directory = tempfile::tempdir()?;
        let binaries = directory.path().join("bin");
        let libraries = directory
            .path()
            .join(if cfg!(windows) { "bin" } else { "lib" });
        fs::create_dir_all(&binaries)?;
        fs::create_dir_all(&libraries)?;
        let compiler = binaries.join(if cfg!(windows) { "rustc.exe" } else { "rustc" });
        fs::write(&compiler, "compiler launcher")?;
        let driver = libraries.join(format!(
            "{}rustc_driver-fixture{}",
            env::consts::DLL_PREFIX,
            env::consts::DLL_SUFFIX
        ));
        Ok((directory, compiler, driver))
    }

    #[test]
    fn exactly_one_runtime_compiler_driver_is_required() -> io::Result<()> {
        let (_directory, compiler, driver) = compiler_driver_fixture()?;
        assert_eq!(
            compiler_driver(&compiler).err().map(|error| error.kind()),
            Some(io::ErrorKind::Unsupported)
        );

        fs::write(&driver, "compiler implementation")?;
        assert_eq!(compiler_driver(&compiler)?, driver.canonicalize()?);

        let another = driver.with_file_name(format!(
            "{}rustc_driver-another{}",
            env::consts::DLL_PREFIX,
            env::consts::DLL_SUFFIX
        ));
        fs::write(&another, "ambiguous compiler implementation")?;
        assert_eq!(
            compiler_driver(&compiler).err().map(|error| error.kind()),
            Some(io::ErrorKind::Unsupported)
        );

        fs::remove_file(&another)?;
        fs::remove_file(&driver)?;
        fs::create_dir(&driver)?;
        assert_eq!(
            compiler_driver(&compiler).err().map(|error| error.kind()),
            Some(io::ErrorKind::Unsupported)
        );
        Ok(())
    }

    #[test]
    fn dynamic_library_search_directories_cannot_replace_compiler_drivers() -> io::Result<()> {
        let (directory, compiler, driver) = compiler_driver_fixture()?;
        fs::write(&driver, "expected compiler implementation")?;
        let driver = compiler_driver(&compiler)?;
        let search_directory = directory.path().join("search-directory");
        fs::create_dir(&search_directory)?;

        validate_compiler_driver_search_directory(&driver, &search_directory)?;
        validate_compiler_driver_search_directory(
            &driver,
            driver
                .parent()
                .ok_or_else(|| io::Error::other("driver has no library directory"))?,
        )?;
        validate_compiler_driver_search_directory(&driver, &directory.path().join("missing"))?;

        let alternate = search_directory.join(
            driver
                .file_name()
                .ok_or_else(|| io::Error::other("driver has no filename"))?,
        );
        fs::write(&alternate, "substituted compiler implementation")?;
        assert_eq!(
            validate_compiler_driver_search_directory(&driver, &search_directory)
                .err()
                .map(|error| error.kind()),
            Some(io::ErrorKind::Unsupported)
        );

        fs::remove_file(&alternate)?;
        fs::create_dir(&alternate)?;
        assert_eq!(
            validate_compiler_driver_search_directory(&driver, &search_directory)
                .err()
                .map(|error| error.kind()),
            Some(io::ErrorKind::Unsupported)
        );
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn dynamic_library_search_directories_can_link_the_trusted_compiler_driver() -> io::Result<()> {
        use std::os::unix::fs::symlink;

        let (directory, compiler, driver) = compiler_driver_fixture()?;
        fs::write(&driver, "expected compiler implementation")?;
        let driver = compiler_driver(&compiler)?;
        let search_directory = directory.path().join("search-directory");
        fs::create_dir(&search_directory)?;
        let alias = search_directory.join(
            driver
                .file_name()
                .ok_or_else(|| io::Error::other("driver has no filename"))?,
        );
        symlink(&driver, alias)?;

        validate_compiler_driver_search_directory(&driver, &search_directory)
    }

    #[cfg(unix)]
    #[test]
    fn linked_compilers_resolve_their_actual_runtime_sysroot() -> io::Result<()> {
        use std::os::unix::fs::symlink;

        let (directory, compiler, driver) = compiler_driver_fixture()?;
        fs::write(&driver, "compiler implementation")?;
        let bundle = directory.path().join("optimized-bundle");
        fs::create_dir(&bundle)?;
        let linked_compiler = bundle.join("rustc");
        symlink(&compiler, &linked_compiler)?;

        assert_eq!(compiler_driver(&linked_compiler)?, driver.canonicalize()?);
        Ok(())
    }

    #[test]
    fn compiler_driver_metadata_changes_invalidate_formatter_identity() -> io::Result<()> {
        let (_directory, compiler, driver) = compiler_driver_fixture()?;
        fs::write(&driver, "original compiler")?;
        let mut before = Sha256::new();
        hash_compiler_driver(&mut before, &compiler)?;

        fs::write(&driver, "updated compiler implementation")?;
        let mut after = Sha256::new();
        hash_compiler_driver(&mut after, &compiler)?;

        assert_ne!(before.finalize(), after.finalize());
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn replaced_compiler_driver_with_restored_mtime_changes_formatter_identity() -> io::Result<()> {
        let (_directory, compiler, driver) = compiler_driver_fixture()?;
        fs::write(&driver, "first-driver")?;
        let modified = fs::metadata(&driver)?.modified()?;
        let mut before = Sha256::new();
        hash_compiler_driver(&mut before, &compiler)?;

        let replacement = driver.with_extension("replacement");
        fs::write(&replacement, "other-driver")?;
        OpenOptions::new()
            .write(true)
            .open(&replacement)?
            .set_times(fs::FileTimes::new().set_modified(modified))?;
        fs::rename(&replacement, &driver)?;
        let mut after = Sha256::new();
        hash_compiler_driver(&mut after, &compiler)?;

        assert_ne!(before.finalize(), after.finalize());
        Ok(())
    }

    #[test]
    fn concurrently_changed_unformatted_targets_are_not_cached() {
        let current = snapshot(&[
            ("/workspace/first", &[("src/lib.rs", "before-formatting")]),
            ("/workspace/second", &[("src/lib.rs", "unchanged")]),
        ]);
        let updated = snapshot(&[
            ("/workspace/first", &[("src/lib.rs", "formatted")]),
            (
                "/workspace/second",
                &[("src/lib.rs", "edited-concurrently")],
            ),
        ]);
        let plan = plan(None, current);

        assert!(!plan.can_record(
            &updated,
            &BTreeSet::from(["/workspace/first/src/lib.rs"]),
            false,
        ));
    }

    #[test]
    fn concurrently_changed_selected_targets_are_not_cached_after_checking() {
        let current = snapshot(&[("/workspace/first", &[("src/lib.rs", "before-checking")])]);
        let updated = snapshot(&[("/workspace/first", &[("src/lib.rs", "edited-concurrently")])]);
        let plan = plan(None, current);

        assert!(!plan.can_record(
            &updated,
            &BTreeSet::from(["/workspace/first/src/lib.rs"]),
            true,
        ));
    }

    #[test]
    fn concurrently_changed_formatter_configuration_is_not_cached() {
        let current = snapshot(&[("/workspace/first", &[("src/lib.rs", "formatted")])]);
        let mut updated = current.clone();
        updated.configuration.insert(
            String::from("/workspace/rustfmt.toml"),
            String::from("changed-concurrently"),
        );
        let plan = plan(None, current);

        assert!(!plan.can_record(
            &updated,
            &BTreeSet::from(["/workspace/first/src/lib.rs"]),
            false,
        ));
        assert!(!plan.can_record(
            &updated,
            &BTreeSet::from(["/workspace/first/src/lib.rs"]),
            true,
        ));
    }

    #[test]
    fn newly_discovered_module_configuration_can_be_verified_and_cached() {
        let current = snapshot(&[("/workspace/first", &[("src/lib.rs", "formatted")])]);
        let mut updated = current.clone();
        updated.configuration.insert(
            String::from("/workspace/external/rustfmt.toml"),
            String::from("newly-discovered-config"),
        );
        let plan = plan(None, current);

        assert!(plan.can_record(
            &updated,
            &BTreeSet::from(["/workspace/first/src/lib.rs"]),
            false,
        ));
        assert!(plan.can_record(
            &updated,
            &BTreeSet::from(["/workspace/first/src/lib.rs"]),
            true,
        ));
    }

    #[test]
    fn manifest_records_cross_package_and_generated_module_ownership() -> io::Result<()> {
        let directory = tempfile::tempdir()?;
        let package = directory.path().join("package");
        let generated = package.join("target");
        fs::create_dir_all(package.join("src"))?;
        fs::create_dir_all(&generated)?;
        fs::write(package.join("src/lib.rs"), "mod generated;")?;
        fs::write(generated.join("module.rs"), "pub fn generated() {}")?;
        fs::write(directory.path().join("shared.rs"), "pub fn shared() {}")?;

        let root = package.join("src/lib.rs").canonicalize()?;
        let generated = generated.join("module.rs").canonicalize()?;
        let shared = directory.path().join("shared.rs").canonicalize()?;
        let package = package.canonicalize()?;
        let manifest_path = directory.path().join("modules.json");
        write_manifest(
            &manifest_path,
            &ModuleManifest {
                schema: String::from(MODULE_MANIFEST_SCHEMA),
                version: MODULE_MANIFEST_VERSION,
                roots: vec![ModuleRoot {
                    path: path_string(&root)?,
                    files: vec![path_string(&root)?, path_string(&generated)?],
                    dependencies: vec![
                        path_string(&root)?,
                        path_string(&generated)?,
                        path_string(&shared)?,
                    ],
                    probes: vec![probe(&root)?, probe(&generated)?, probe(&shared)?],
                }],
            },
        )?;

        let graph = read_module_manifests(
            &[manifest_path.clone()],
            &BTreeSet::from([target(&root, &package)]),
        )?;
        assert_eq!(
            graph.modules.get(&path_string(&root)?),
            Some(&BTreeSet::from([
                path_string(&root)?,
                path_string(&generated)?,
                path_string(&shared)?,
            ]))
        );
        assert!(!manifest_path.exists());
        Ok(())
    }

    #[test]
    fn missing_and_incomplete_authoritative_manifests_fail_closed() -> io::Result<()> {
        let directory = tempfile::tempdir()?;
        let package = directory.path().canonicalize()?;
        let root = package.join("lib.rs");
        fs::write(&root, "pub fn root() {}")?;
        let targets = BTreeSet::from([target(&root, &package)]);
        assert!(read_module_manifests(&[], &targets).is_err());

        let missing_root = package.join("missing-root.json");
        write_manifest(
            &missing_root,
            &ModuleManifest {
                schema: String::from(MODULE_MANIFEST_SCHEMA),
                version: MODULE_MANIFEST_VERSION,
                roots: vec![],
            },
        )?;
        assert!(read_module_manifests(&[missing_root], &targets).is_err());

        let missing_file = package.join("missing-file.json");
        write_manifest(
            &missing_file,
            &ModuleManifest {
                schema: String::from(MODULE_MANIFEST_SCHEMA),
                version: MODULE_MANIFEST_VERSION,
                roots: vec![ModuleRoot {
                    path: path_string(&root)?,
                    files: vec![],
                    dependencies: vec![],
                    probes: vec![],
                }],
            },
        )?;
        assert!(read_module_manifests(&[missing_file], &targets).is_err());

        let wrong_version = package.join("wrong-version.json");
        write_manifest(
            &wrong_version,
            &ModuleManifest {
                schema: String::from(MODULE_MANIFEST_SCHEMA),
                version: MODULE_MANIFEST_VERSION + 1,
                roots: vec![],
            },
        )?;
        assert!(read_module_manifests(&[wrong_version], &targets).is_err());
        Ok(())
    }

    #[test]
    fn duplicate_manifest_roots_and_files_fail_closed() -> io::Result<()> {
        let directory = tempfile::tempdir()?;
        let package = directory.path().canonicalize()?;
        let root = package.join("lib.rs");
        fs::write(&root, "pub fn root() {}")?;
        let targets = BTreeSet::from([target(&root, &package)]);
        let root_path = path_string(&root)?;

        let duplicate_files = package.join("duplicate-files.json");
        write_manifest(
            &duplicate_files,
            &ModuleManifest {
                schema: String::from(MODULE_MANIFEST_SCHEMA),
                version: MODULE_MANIFEST_VERSION,
                roots: vec![ModuleRoot {
                    path: root_path.clone(),
                    files: vec![root_path.clone(), root_path.clone()],
                    dependencies: vec![root_path.clone()],
                    probes: vec![probe(&root)?],
                }],
            },
        )?;
        assert!(read_module_manifests(&[duplicate_files], &targets).is_err());

        let duplicate_dependencies = package.join("duplicate-dependencies.json");
        write_manifest(
            &duplicate_dependencies,
            &ModuleManifest {
                schema: String::from(MODULE_MANIFEST_SCHEMA),
                version: MODULE_MANIFEST_VERSION,
                roots: vec![ModuleRoot {
                    path: root_path.clone(),
                    files: vec![root_path.clone()],
                    dependencies: vec![root_path.clone(), root_path.clone()],
                    probes: vec![probe(&root)?],
                }],
            },
        )?;
        assert!(read_module_manifests(&[duplicate_dependencies], &targets).is_err());

        let duplicate_roots = package.join("duplicate-roots.json");
        let record = ModuleRoot {
            path: root_path.clone(),
            files: vec![root_path.clone()],
            dependencies: vec![root_path],
            probes: vec![probe(&root)?],
        };
        write_manifest(
            &duplicate_roots,
            &ModuleManifest {
                schema: String::from(MODULE_MANIFEST_SCHEMA),
                version: MODULE_MANIFEST_VERSION,
                roots: vec![record.clone(), record],
            },
        )?;
        assert!(read_module_manifests(&[duplicate_roots], &targets).is_err());

        let duplicate_probes = package.join("duplicate-probes.json");
        write_manifest(
            &duplicate_probes,
            &ModuleManifest {
                schema: String::from(MODULE_MANIFEST_SCHEMA),
                version: MODULE_MANIFEST_VERSION,
                roots: vec![ModuleRoot {
                    path: path_string(&root)?,
                    files: vec![path_string(&root)?],
                    dependencies: vec![path_string(&root)?],
                    probes: vec![probe(&root)?, probe(&root)?],
                }],
            },
        )?;
        assert!(read_module_manifests(&[duplicate_probes], &targets).is_err());
        Ok(())
    }

    #[test]
    fn formatter_manifest_paths_must_be_canonical() -> io::Result<()> {
        let directory = tempfile::tempdir()?;
        let package = directory.path().canonicalize()?;
        let root = package.join("lib.rs");
        fs::write(&root, "pub fn root() {}")?;
        let targets = BTreeSet::from([target(&root, &package)]);
        let manifest = package.join("relative.json");
        write_manifest(
            &manifest,
            &ModuleManifest {
                schema: String::from(MODULE_MANIFEST_SCHEMA),
                version: MODULE_MANIFEST_VERSION,
                roots: vec![ModuleRoot {
                    path: path_string(&root)?,
                    files: vec![String::from("lib.rs")],
                    dependencies: vec![path_string(&root)?],
                    probes: vec![probe(&root)?],
                }],
            },
        )?;
        assert!(read_module_manifests(&[manifest], &targets).is_err());
        Ok(())
    }

    #[test]
    fn formatted_files_must_be_recorded_as_parsed_dependencies() -> io::Result<()> {
        let directory = tempfile::tempdir()?;
        let package = directory.path().canonicalize()?;
        let root = package.join("lib.rs");
        let module = package.join("module.rs");
        fs::write(&root, "mod module;")?;
        fs::write(&module, "pub fn module() {}")?;
        let targets = BTreeSet::from([target(&root, &package)]);
        let manifest = package.join("missing-dependency.json");
        write_manifest(
            &manifest,
            &ModuleManifest {
                schema: String::from(MODULE_MANIFEST_SCHEMA),
                version: MODULE_MANIFEST_VERSION,
                roots: vec![ModuleRoot {
                    path: path_string(&root)?,
                    files: vec![path_string(&root)?, path_string(&module)?],
                    dependencies: vec![path_string(&root)?],
                    probes: vec![probe(&root)?],
                }],
            },
        )?;

        assert!(read_module_manifests(&[manifest], &targets).is_err());
        Ok(())
    }

    #[test]
    fn loaded_dependencies_require_matching_native_resolution_probes() -> io::Result<()> {
        let directory = tempfile::tempdir()?;
        let package = directory.path().canonicalize()?;
        let root = package.join("lib.rs");
        fs::write(&root, "pub fn root() {}")?;
        let targets = BTreeSet::from([target(&root, &package)]);
        let manifest = package.join("missing-probe.json");
        write_manifest(
            &manifest,
            &ModuleManifest {
                schema: String::from(MODULE_MANIFEST_SCHEMA),
                version: MODULE_MANIFEST_VERSION,
                roots: vec![ModuleRoot {
                    path: path_string(&root)?,
                    files: vec![path_string(&root)?],
                    dependencies: vec![path_string(&root)?],
                    probes: vec![],
                }],
            },
        )?;

        assert!(read_module_manifests(&[manifest], &targets).is_err());
        Ok(())
    }

    #[test]
    fn resolution_probes_track_existing_and_missing_directories() -> io::Result<()> {
        let directory = tempfile::tempdir()?;
        let existing = directory.path().canonicalize()?;
        let missing = existing.join("missing");

        assert_eq!(
            observe_module_probe(&path_string(&existing)?)?,
            ProbeObservation {
                canonical: Some(path_string(&existing)?),
                exists: true,
                is_directory: true,
            }
        );
        assert_eq!(
            observe_module_probe(&path_string(&missing)?)?,
            ProbeObservation {
                canonical: None,
                exists: false,
                is_directory: false,
            }
        );
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn native_resolution_probe_observes_symlink_retargeting() -> io::Result<()> {
        let directory = tempfile::tempdir()?;
        let directory = directory.path().canonicalize()?;
        let original = directory.join("original.rs");
        let replacement = directory.join("replacement.rs");
        let logical = directory.join("linked.rs");
        fs::write(&original, "pub fn original() {}")?;
        fs::write(&replacement, "pub fn replacement() {}")?;
        std::os::unix::fs::symlink(&original, &logical)?;

        let first = observe_module_probe(&path_string(&logical)?)?;
        fs::remove_file(&logical)?;
        std::os::unix::fs::symlink(&replacement, &logical)?;
        let second = observe_module_probe(&path_string(&logical)?)?;

        assert_ne!(first, second);
        assert_eq!(first.canonical, Some(path_string(&original)?));
        assert_eq!(second.canonical, Some(path_string(&replacement)?));
        Ok(())
    }

    #[test]
    fn native_resolution_probe_observes_new_module_candidates() -> io::Result<()> {
        let directory = tempfile::tempdir()?;
        let directory = directory.path().canonicalize()?;
        let candidate = directory.join("nested").join("mod.rs");
        let first = observe_module_probe(&path_string(&candidate)?)?;

        fs::create_dir_all(directory.join("nested"))?;
        fs::write(&candidate, "pub fn nested() {}")?;
        let second = observe_module_probe(&path_string(&candidate)?)?;

        assert!(!first.exists);
        assert!(second.exists);
        assert_ne!(first, second);
        Ok(())
    }

    #[test]
    fn native_resolution_probe_observes_file_replaced_by_directory() -> io::Result<()> {
        let directory = tempfile::tempdir()?;
        let directory = directory.path().canonicalize()?;
        let candidate = directory.join("nested");
        fs::write(&candidate, "a file")?;
        let first = observe_module_probe(&path_string(&candidate)?)?;

        fs::remove_file(&candidate)?;
        fs::create_dir(&candidate)?;
        let second = observe_module_probe(&path_string(&candidate)?)?;

        assert!(first.exists);
        assert!(second.exists);
        assert_eq!(first.canonical, second.canonical);
        assert!(!first.is_directory);
        assert!(second.is_directory);
        assert_ne!(first, second);
        Ok(())
    }

    #[test]
    fn stdout_and_json_emit_modes_bypass_the_cache() {
        assert!(has_observable_emit_mode(&[
            String::from("--emit"),
            String::from("stdout"),
        ]));
        assert!(has_observable_emit_mode(&[String::from("--emit=json")]));
        assert!(has_observable_emit_mode(&[String::from("-v")]));
        assert!(has_observable_emit_mode(&[String::from("-lv")]));
        assert!(has_observable_emit_mode(&[String::from("-lV")]));
        assert!(has_observable_emit_mode(&[String::from("-qh")]));
        assert!(has_observable_emit_mode(&[String::from("-l")]));
        assert!(has_observable_emit_mode(&[String::from(
            "--files-with-diff"
        )]));
        assert!(has_observable_emit_mode(&[String::from("--config-help")]));
        assert!(has_observable_emit_mode(&[String::from("--file-lines=[]")]));
        assert!(has_observable_emit_mode(&[
            String::from("--config"),
            String::from("emit_mode=Stdout"),
        ]));
        assert!(has_observable_emit_mode(&[String::from(
            "--config=emit_mode=Stdout"
        )]));
        assert!(has_observable_emit_mode(&[
            String::from("--config"),
            String::from("max_width=100,emit_mode=Stdout"),
        ]));
        assert!(has_observable_emit_mode(&[
            String::from("--config"),
            String::from("verbose=Verbose"),
        ]));
        assert!(has_observable_emit_mode(&[String::from(
            "--config=file_lines=[]"
        )]));
        assert!(!has_observable_emit_mode(&[
            String::from("--emit"),
            String::from("files"),
        ]));
        assert!(has_observable_emit_mode(&[
            String::from("--config"),
            String::from("max_width=100"),
        ]));
        assert!(!has_observable_emit_mode(&[String::from("-q")]));
    }

    #[test]
    fn formatting_only_import_granularity_configuration_can_use_the_cache() {
        for granularity in ["Preserve", "Crate", "Module", "Item", "One"] {
            assert!(!has_observable_emit_mode(&[
                String::from("--config"),
                format!("imports_granularity={granularity}"),
                String::from("--check"),
            ]));
            assert!(!has_observable_emit_mode(&[format!(
                "--config=imports_granularity={granularity}"
            )]));
        }

        for configuration in [
            "imports_granularity=Invalid",
            "imports_granularity=Item,emit_mode=Stdout",
            "imports_granularity=Item,verbose=Verbose",
            "imports_granularity=Item,file_lines=[]",
            " imports_granularity=Item",
            "imports_granularity=Item ",
        ] {
            assert!(has_observable_emit_mode(&[
                String::from("--config"),
                String::from(configuration),
            ]));
            assert!(has_observable_emit_mode(&[format!(
                "--config={configuration}"
            )]));
        }

        assert!(has_observable_emit_mode(&[String::from("--config")]));
    }

    #[test]
    fn verification_removes_explicit_file_emission_before_checking() {
        assert_eq!(
            verification_arguments(&[String::from("--emit"), String::from("files")]),
            vec![String::from("--check")]
        );
        assert_eq!(
            verification_arguments(&[String::from("--emit=files")]),
            vec![String::from("--check")]
        );
        assert_eq!(
            verification_arguments(&[String::from("--check")]),
            vec![String::from("--check")]
        );
    }
}
