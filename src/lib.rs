#![feature(rustc_private)]
#![deny(rust_2018_idioms)]
#![warn(unreachable_pub)]
#![recursion_limit = "256"]
#![allow(clippy::match_like_matches_macro)]
#![allow(unreachable_pub)]

// N.B. these crates are loaded from the sysroot, so they need extern crate.
extern crate rustc_ast;
extern crate rustc_ast_pretty;
extern crate rustc_data_structures;
extern crate rustc_errors;
extern crate rustc_expand;
extern crate rustc_feature;
extern crate rustc_parse;
extern crate rustc_session;
extern crate rustc_span;
extern crate thin_vec;

// Necessary to pull in object code as the rest of the rustc crates are shipped only as rmeta
// files.
#[allow(unused_extern_crates)]
extern crate rustc_driver;

use std::cell::RefCell;
use std::cmp::min;
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::fmt;
use std::fs::{self, OpenOptions};
use std::io::{self, Write};
use std::mem;
use std::panic;
use std::path::{Path, PathBuf};
use std::rc::Rc;

use rustc_ast::ast;
use rustc_span::symbol;
use thiserror::Error;

use crate::comment::LineClasses;
use crate::emitter::Emitter;
use crate::formatting::{FormatErrorMap, FormattingError, ReportedErrors, SourceFile};
use crate::modules::ModuleResolutionError;
use crate::parse::parser::DirectoryOwnership;
use crate::parse::session::{FileProbe, ParseSess};
use crate::shape::Indent;
use crate::utils::indent_next_line;

pub use crate::config::{
    CliOptions, Color, Config, Edition, EmitMode, FileLines, FileName, NewlineStyle, Range,
    StyleEdition, Verbosity, Version, load_config,
};

pub use crate::format_report_formatter::{FormatReportFormatter, FormatReportFormatterBuilder};

pub use crate::rustfmt_diff::{ModifiedChunk, ModifiedLines};

#[macro_use]
mod utils;

macro_rules! static_regex {
    ($re:literal) => {{
        static RE: ::std::sync::OnceLock<::regex::Regex> = ::std::sync::OnceLock::new();
        RE.get_or_init(|| ::regex::Regex::new($re).unwrap())
    }};
}

mod attr;
mod chains;
mod closures;
mod comment;
pub(crate) mod config;
mod coverage;
mod emitter;
mod expr;
mod format_report_formatter;
pub(crate) mod formatting;
pub(crate) mod header;
mod ignore_path;
mod imports;
mod items;
mod lists;
mod macros;
mod matches;
mod missed_spans;
pub(crate) mod modules;
mod overflow;
mod pairs;
mod parse;
mod patterns;
mod range;
mod release_channel;
mod reorder;
mod rewrite;
pub(crate) mod rustfmt_diff;
mod shape;
mod skip;
mod sort;
pub(crate) mod source_file;
pub(crate) mod source_map;
mod spanned;
mod stmt;
mod string;
#[cfg(test)]
mod test;
mod types;
mod vertical;
pub(crate) mod visitor;

/// The various errors that can occur during formatting. Note that not all of
/// these can currently be propagated to clients.
#[derive(Error, Debug)]
pub enum ErrorKind {
    /// Line has exceeded character limit (found, maximum).
    #[error(
        "line formatted, but exceeded maximum width \
         (maximum: {1} (see `max_width` option), found: {0})"
    )]
    LineOverflow(usize, usize),
    /// Line ends in whitespace.
    #[error("left behind trailing whitespace")]
    TrailingWhitespace,
    /// Used deprecated skip attribute.
    #[error("`rustfmt_skip` is deprecated; use `rustfmt::skip`")]
    DeprecatedAttr,
    /// Used a rustfmt:: attribute other than skip or skip::macros.
    #[error("invalid attribute")]
    BadAttr,
    /// An io error during reading or writing.
    #[error("io error: {0}")]
    IoError(io::Error),
    /// Error during module resolution.
    #[error("{0}")]
    ModuleResolutionError(#[from] ModuleResolutionError),
    /// Parse error occurred when parsing the input.
    #[error("parse error")]
    ParseError,
    /// The user mandated a version and the current version of Rustfmt does not
    /// satisfy that requirement.
    #[error("version mismatch")]
    VersionMismatch,
    /// If we had formatted the given node, then we would have lost a comment.
    #[error("not formatted because a comment would be lost")]
    LostComment,
    /// Invalid glob pattern in `ignore` configuration option.
    #[error("Invalid glob pattern found in ignore list: {0}")]
    InvalidGlobPattern(ignore::Error),
}

impl ErrorKind {
    fn is_comment(&self) -> bool {
        matches!(self, ErrorKind::LostComment)
    }
}

impl From<io::Error> for ErrorKind {
    fn from(e: io::Error) -> ErrorKind {
        ErrorKind::IoError(e)
    }
}

/// Result of formatting a snippet of code along with ranges of lines that didn't get formatted,
/// i.e., that got returned as they were originally.
#[derive(Debug)]
struct FormattedSnippet {
    snippet: String,
    non_formatted_ranges: Vec<(usize, usize)>,
}

impl FormattedSnippet {
    /// In case the snippet needed to be wrapped in a function, this shifts down the ranges of
    /// non-formatted code.
    fn unwrap_code_block(&mut self) {
        self.non_formatted_ranges
            .iter_mut()
            .for_each(|(low, high)| {
                *low -= 1;
                *high -= 1;
            });
    }

    /// Returns `true` if the line n did not get formatted.
    fn is_line_non_formatted(&self, n: usize) -> bool {
        self.non_formatted_ranges
            .iter()
            .any(|(low, high)| *low <= n && n <= *high)
    }
}

/// Reports on any issues that occurred during a run of Rustfmt.
///
/// Can be reported to the user using the `Display` impl on [`FormatReportFormatter`].
#[derive(Clone)]
pub struct FormatReport {
    // Maps stringified file paths to their associated formatting errors.
    internal: Rc<RefCell<(FormatErrorMap, ReportedErrors)>>,
    non_formatted_ranges: Vec<(usize, usize)>,
}

impl FormatReport {
    fn new() -> FormatReport {
        FormatReport {
            internal: Rc::new(RefCell::new((HashMap::new(), ReportedErrors::default()))),
            non_formatted_ranges: Vec::new(),
        }
    }

    fn add_non_formatted_ranges(&mut self, mut ranges: Vec<(usize, usize)>) {
        self.non_formatted_ranges.append(&mut ranges);
    }

    fn append(&self, f: FileName, mut v: Vec<FormattingError>) {
        self.track_errors(&v);
        self.internal
            .borrow_mut()
            .0
            .entry(f)
            .and_modify(|fe| fe.append(&mut v))
            .or_insert(v);
    }

    fn track_errors(&self, new_errors: &[FormattingError]) {
        let errs = &mut self.internal.borrow_mut().1;
        if !new_errors.is_empty() {
            errs.has_formatting_errors = true;
        }
        if errs.has_operational_errors && errs.has_check_errors && errs.has_unformatted_code_errors
        {
            return;
        }
        for err in new_errors {
            match err.kind {
                ErrorKind::LineOverflow(..) => {
                    errs.has_operational_errors = true;
                }
                ErrorKind::TrailingWhitespace => {
                    errs.has_operational_errors = true;
                    errs.has_unformatted_code_errors = true;
                }
                ErrorKind::LostComment => {
                    errs.has_unformatted_code_errors = true;
                }
                ErrorKind::DeprecatedAttr | ErrorKind::BadAttr | ErrorKind::VersionMismatch => {
                    errs.has_check_errors = true;
                }
                _ => {}
            }
        }
    }

    fn add_diff(&mut self) {
        self.internal.borrow_mut().1.has_diff = true;
    }

    fn add_macro_format_failure(&mut self) {
        self.internal.borrow_mut().1.has_macro_format_failure = true;
    }

    fn add_parsing_error(&mut self) {
        self.internal.borrow_mut().1.has_parsing_errors = true;
    }

    fn warning_count(&self) -> usize {
        self.internal
            .borrow()
            .0
            .values()
            .map(|errors| errors.len())
            .sum()
    }

    /// Whether any warnings or errors are present in the report.
    pub fn has_warnings(&self) -> bool {
        self.internal.borrow().1.has_formatting_errors
    }

    /// Print the report to a terminal using colours and potentially other
    /// fancy output.
    #[deprecated(note = "Use FormatReportFormatter with colors enabled instead")]
    pub fn fancy_print(
        &self,
        mut t: Box<dyn term::Terminal<Output = io::Stderr>>,
    ) -> Result<(), term::Error> {
        writeln!(
            t,
            "{}",
            FormatReportFormatterBuilder::new(self)
                .enable_colors(true)
                .build()
        )?;
        Ok(())
    }
}

/// Deprecated - Use FormatReportFormatter instead
// https://github.com/rust-lang/rust/issues/78625
// https://github.com/rust-lang/rust/issues/39935
impl fmt::Display for FormatReport {
    // Prints all the formatting errors.
    fn fmt(&self, fmt: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        write!(fmt, "{}", FormatReportFormatterBuilder::new(self).build())?;
        Ok(())
    }
}

/// Format the given snippet. The snippet is expected to be *complete* code.
/// When we cannot parse the given snippet, this function returns `None`.
fn format_snippet(snippet: &str, config: &Config, is_macro_def: bool) -> Option<FormattedSnippet> {
    let mut config = config.clone();
    panic::catch_unwind(|| {
        let mut out: Vec<u8> = Vec::with_capacity(snippet.len() * 2);
        config.set().emit_mode(config::EmitMode::Stdout);
        config.set().verbose(Verbosity::Quiet);
        config.set().show_parse_errors(false);
        if is_macro_def {
            config.set().error_on_unformatted(true);
        }

        let (formatting_error, result) = {
            let input = Input::Text(snippet.into());
            let mut session = Session::new(config, Some(&mut out));
            let result = session.format_input_inner(input, is_macro_def);
            (
                session.errors.has_macro_format_failure
                    || session.out.as_ref().unwrap().is_empty() && !snippet.is_empty()
                    || result.is_err()
                    || (is_macro_def && session.has_unformatted_code_errors()),
                result,
            )
        };
        if formatting_error {
            None
        } else {
            String::from_utf8(out).ok().map(|snippet| FormattedSnippet {
                snippet,
                non_formatted_ranges: result.unwrap().non_formatted_ranges,
            })
        }
    })
    // Discard panics encountered while formatting the snippet
    // The ? operator is needed to remove the extra Option
    .ok()?
}

/// Format the given code block. Mainly targeted for code block in comment.
/// The code block may be incomplete (i.e., parser may be unable to parse it).
/// To avoid panic in parser, we wrap the code block with a dummy function.
/// The returned code block does **not** end with newline.
fn format_code_block(
    code_snippet: &str,
    config: &Config,
    is_macro_def: bool,
) -> Option<FormattedSnippet> {
    const FN_MAIN_PREFIX: &str = "fn main() {\n";

    fn enclose_in_main_block(s: &str, config: &Config) -> String {
        let indent = Indent::from_width(config, config.tab_spaces());
        let mut result = String::with_capacity(s.len() * 2);
        result.push_str(FN_MAIN_PREFIX);
        let mut need_indent = true;
        for (kind, line) in LineClasses::new(s) {
            if need_indent {
                result.push_str(&indent.to_string(config));
            }
            result.push_str(&line);
            result.push('\n');
            need_indent = indent_next_line(kind, &line, config);
        }
        result.push('}');
        result
    }

    // Wrap the given code block with `fn main()` if it does not have one.
    let snippet = enclose_in_main_block(code_snippet, config);
    let mut result = String::with_capacity(snippet.len());
    let mut is_first = true;

    // While formatting the code, ignore the config's newline style setting and always use "\n"
    // instead of "\r\n" for the newline characters. This is ok because the output here is
    // not directly outputted by rustfmt command, but used by the comment formatter's input.
    // We have output-file-wide "\n" ==> "\r\n" conversion process after here if it's necessary.
    let mut config_with_unix_newline = config.clone();
    config_with_unix_newline
        .set()
        .newline_style(NewlineStyle::Unix);
    let mut formatted = format_snippet(&snippet, &config_with_unix_newline, is_macro_def)?;
    // Remove wrapping main block
    formatted.unwrap_code_block();

    // Trim "fn main() {" on the first line and "}" on the last line,
    // then unindent the whole code block.
    let block_len = formatted
        .snippet
        .rfind('}')
        .unwrap_or_else(|| formatted.snippet.len());

    // It's possible that `block_len < FN_MAIN_PREFIX.len()`. This can happen if the code block was
    // formatted into the empty string, leading to the enclosing `fn main() {\n}` being formatted
    // into `fn main() {}`. In this case no unindentation is done.
    let block_start = min(FN_MAIN_PREFIX.len(), block_len);

    let mut is_indented = true;
    let indent_str = Indent::from_width(config, config.tab_spaces()).to_string(config);
    for (kind, ref line) in LineClasses::new(&formatted.snippet[block_start..block_len]) {
        if !is_first {
            result.push('\n');
        } else {
            is_first = false;
        }
        let trimmed_line = if !is_indented {
            line
        } else if line.len() > config.max_width() {
            // If there are lines that are larger than max width, we cannot tell
            // whether we have succeeded but have some comments or strings that
            // are too long, or we have failed to format code block. We will be
            // conservative and just return `None` in this case.
            return None;
        } else if line.len() > indent_str.len() {
            // Make sure that the line has leading whitespaces.
            if line.starts_with(indent_str.as_ref()) {
                let offset = if config.hard_tabs() {
                    1
                } else {
                    config.tab_spaces()
                };
                &line[offset..]
            } else {
                line
            }
        } else {
            line
        };
        result.push_str(trimmed_line);
        is_indented = indent_next_line(kind, line, config);
    }
    Some(FormattedSnippet {
        snippet: result,
        non_formatted_ranges: formatted.non_formatted_ranges,
    })
}

/// A session is a run of rustfmt across a single or multiple inputs.
pub struct Session<'b, T: Write> {
    pub config: Config,
    pub out: Option<&'b mut T>,
    pub(crate) errors: ReportedErrors,
    source_file: SourceFile,
    emitter: Box<dyn Emitter + 'b>,
    module_graph: Option<ResolvedModuleGraph>,
}

/// Files actually selected by rustfmt's native module resolver for each input.
struct ResolvedModuleGraph {
    roots: BTreeMap<PathBuf, ResolvedRootFiles>,
    complete: bool,
}

/// Distinguishes files actually formatted from every source loaded or probed by the parser.
#[derive(Default)]
struct ResolvedRootFiles {
    files: BTreeSet<PathBuf>,
    dependencies: BTreeSet<PathBuf>,
    probes: BTreeMap<PathBuf, FileProbe>,
}

/// Versioned handoff consumed by incremental cargo-fmt after a successful formatter run.
#[derive(serde::Serialize)]
struct ModuleGraphManifest<'a> {
    schema: &'static str,
    version: u32,
    roots: Vec<ModuleGraphRoot<'a>>,
}

#[derive(serde::Serialize)]
struct ModuleGraphRoot<'a> {
    path: &'a Path,
    files: Vec<&'a Path>,
    dependencies: Vec<&'a Path>,
    probes: Vec<&'a FileProbe>,
}

/// Rejects unresolved and non-UTF-8 paths that cannot be represented in a cache manifest.
fn canonical_graph_path(path: &Path) -> Option<PathBuf> {
    let canonical = path.canonicalize().ok()?;
    canonical.to_str().is_some().then_some(canonical)
}

/// Canonicalizes all native sources, failing the entire graph if any source is unavailable.
fn canonical_graph_paths<'a>(
    paths: impl Iterator<Item = Option<&'a Path>>,
) -> Option<BTreeSet<PathBuf>> {
    paths
        .map(|path| path.and_then(canonical_graph_path))
        .collect()
}

impl<'b, T: Write + 'b> Session<'b, T> {
    pub fn new(config: Config, mut out: Option<&'b mut T>) -> Session<'b, T> {
        let emitter = create_emitter(&config);

        if let Some(ref mut out) = out {
            let _ = emitter.emit_header(out);
        }

        Session {
            config,
            out,
            emitter,
            errors: ReportedErrors::default(),
            source_file: SourceFile::new(),
            module_graph: None,
        }
    }

    /// The main entry point for Rustfmt. Formats the given input according to the
    /// given config. `out` is only necessary if required by the configuration.
    pub fn format(&mut self, input: Input) -> Result<FormatReport, ErrorKind> {
        self.format_input_inner(input, false)
    }

    /// Enables opt-in collection of the exact files selected for each input.
    #[doc(hidden)]
    pub fn enable_module_graph(&mut self) {
        self.module_graph = Some(ResolvedModuleGraph {
            roots: BTreeMap::new(),
            complete: true,
        });
    }

    pub(crate) fn module_graph_enabled(&self) -> bool {
        self.module_graph.is_some()
    }

    /// Records formatted files, all parsed dependencies, and native resolution decisions.
    ///
    /// Any incomplete source, missing dependency probe, or conflicting observation disables
    /// manifest publication for the entire formatter invocation.
    pub(crate) fn record_module_graph<'a, 'd>(
        &mut self,
        root: &FileName,
        files: impl Iterator<Item = &'a FileName>,
        dependencies: impl Iterator<Item = Option<&'d Path>>,
        probes: Option<Vec<FileProbe>>,
    ) {
        let Some(graph) = self.module_graph.as_mut() else {
            return;
        };
        let FileName::Real(root) = root else {
            graph.complete = false;
            return;
        };
        let Some(root) = canonical_graph_path(root) else {
            graph.complete = false;
            return;
        };
        let Some(resolved_files) = canonical_graph_paths(files.map(|file| match file {
            FileName::Real(path) => Some(path.as_path()),
            _ => None,
        })) else {
            graph.complete = false;
            return;
        };
        let Some(loaded_dependencies) = canonical_graph_paths(dependencies) else {
            graph.complete = false;
            return;
        };

        let Some(probes) = probes else {
            graph.complete = false;
            return;
        };
        let mut resolved_probes = BTreeMap::new();
        let mut observed_dependencies = BTreeSet::new();
        for probe in probes {
            if !probe.path.is_absolute()
                || probe.path.to_str().is_none()
                || probe.exists != probe.canonical.is_some()
                || (!probe.exists && probe.is_directory)
                || probe
                    .canonical
                    .as_ref()
                    .is_some_and(|path| !path.is_absolute() || path.to_str().is_none())
            {
                graph.complete = false;
                return;
            }
            if let Some(canonical) = &probe.canonical {
                observed_dependencies.insert(canonical.clone());
            }
            if resolved_probes.insert(probe.path.clone(), probe).is_some() {
                graph.complete = false;
                return;
            }
        }

        if !resolved_files.contains(&root)
            || !resolved_files.is_subset(&loaded_dependencies)
            || !loaded_dependencies.is_subset(&observed_dependencies)
        {
            graph.complete = false;
            return;
        }
        let resolved = graph.roots.entry(root).or_default();
        resolved.files.extend(resolved_files);
        resolved.dependencies.extend(loaded_dependencies);
        for (path, probe) in resolved_probes {
            if let Some(previous) = resolved.probes.insert(path, probe.clone()) {
                if previous != probe {
                    graph.complete = false;
                    return;
                }
            }
        }
    }

    /// Atomically publishes only a complete graph containing exactly the requested roots.
    #[doc(hidden)]
    pub fn write_module_manifest(&self, path: &Path, expected_roots: &[PathBuf]) -> io::Result<()> {
        let Some(graph) = self.module_graph.as_ref().filter(|graph| graph.complete) else {
            return Err(io::Error::other("the rustfmt module graph is incomplete"));
        };

        let roots = expected_roots
            .iter()
            .map(fs::canonicalize)
            .collect::<io::Result<BTreeSet<_>>>()?;
        if roots.len() != graph.roots.len()
            || roots.iter().any(|root| !graph.roots.contains_key(root))
        {
            return Err(io::Error::other("the rustfmt module graph is incomplete"));
        }

        let manifest = ModuleGraphManifest {
            schema: "ohm.rustfmt-files",
            version: 1,
            roots: graph
                .roots
                .iter()
                .map(|(root, resolved)| ModuleGraphRoot {
                    path: root,
                    files: resolved.files.iter().map(PathBuf::as_path).collect(),
                    dependencies: resolved.dependencies.iter().map(PathBuf::as_path).collect(),
                    probes: resolved.probes.values().collect(),
                })
                .collect(),
        };
        let temporary = path.with_extension(format!("{}.tmp", std::process::id()));
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temporary)?;
        let result = (|| {
            serde_json::to_writer(&mut file, &manifest).map_err(io::Error::other)?;
            file.flush()?;
            fs::rename(&temporary, path)
        })();
        if result.is_err() {
            let _ = fs::remove_file(&temporary);
        }
        result
    }

    pub fn override_config<F, U>(&mut self, mut config: Config, f: F) -> U
    where
        F: FnOnce(&mut Session<'b, T>) -> U,
    {
        mem::swap(&mut config, &mut self.config);
        let result = f(self);
        mem::swap(&mut config, &mut self.config);
        result
    }

    pub fn add_operational_error(&mut self) {
        self.errors.has_operational_errors = true;
    }

    pub fn has_operational_errors(&self) -> bool {
        self.errors.has_operational_errors
    }

    pub fn has_parsing_errors(&self) -> bool {
        self.errors.has_parsing_errors
    }

    pub fn has_formatting_errors(&self) -> bool {
        self.errors.has_formatting_errors
    }

    pub fn has_check_errors(&self) -> bool {
        self.errors.has_check_errors
    }

    pub fn has_diff(&self) -> bool {
        self.errors.has_diff
    }

    pub fn has_unformatted_code_errors(&self) -> bool {
        self.errors.has_unformatted_code_errors
    }

    pub fn has_no_errors(&self) -> bool {
        !(self.has_operational_errors()
            || self.has_parsing_errors()
            || self.has_formatting_errors()
            || self.has_check_errors()
            || self.has_diff()
            || self.has_unformatted_code_errors()
            || self.errors.has_macro_format_failure)
    }
}

pub(crate) fn create_emitter<'a>(config: &Config) -> Box<dyn Emitter + 'a> {
    match config.emit_mode() {
        EmitMode::Files if config.make_backup() => {
            Box::new(emitter::FilesWithBackupEmitter::default())
        }
        EmitMode::Files => Box::new(emitter::FilesEmitter::new(
            config.print_misformatted_file_names(),
        )),
        EmitMode::Stdout | EmitMode::Coverage => {
            Box::new(emitter::StdoutEmitter::new(config.verbose()))
        }
        EmitMode::Json => Box::new(emitter::JsonEmitter::default()),
        EmitMode::ModifiedLines => Box::new(emitter::ModifiedLinesEmitter::default()),
        EmitMode::Checkstyle => Box::new(emitter::CheckstyleEmitter::default()),
        EmitMode::Diff => Box::new(emitter::DiffEmitter::new(config.clone())),
    }
}

impl<'b, T: Write + 'b> Drop for Session<'b, T> {
    fn drop(&mut self) {
        if let Some(ref mut out) = self.out {
            let _ = self.emitter.emit_footer(out);
        }
    }
}

#[derive(Debug)]
pub enum Input {
    File(PathBuf),
    Text(String),
}

impl Input {
    fn file_name(&self) -> FileName {
        match *self {
            Input::File(ref file) => FileName::Real(file.clone()),
            Input::Text(..) => FileName::Stdin,
        }
    }

    fn to_directory_ownership(&self, parse_session: &ParseSess) -> Option<DirectoryOwnership> {
        match self {
            Input::File(ref file) => {
                // If there exists a directory with the same name as an input,
                // then the input should be parsed as a sub module.
                let file_stem = file.file_stem()?;
                let directory = file.parent()?.to_path_buf().join(file_stem);
                if parse_session.file_exists(&directory) && directory.is_dir() {
                    Some(DirectoryOwnership::Owned {
                        relative: file_stem.to_str().map(symbol::Ident::from_str),
                    })
                } else {
                    None
                }
            }
            _ => None,
        }
    }
}

#[cfg(test)]
mod unit_tests {
    use super::*;

    #[test]
    fn module_manifest_records_canonical_sorted_files_for_each_root() -> io::Result<()> {
        let directory = tempfile::tempdir()?;
        let first_root = directory.path().join("first.rs");
        let second_root = directory.path().join("second.rs");
        let shared_module = directory.path().join("shared.rs");
        for path in [&first_root, &second_root, &shared_module] {
            fs::write(path, "fn formatted() {}\n")?;
        }

        let mut output = Vec::new();
        let mut session = Session::new(Config::default(), Some(&mut output));
        session.enable_module_graph();
        session.record_module_graph(
            &FileName::Real(second_root.clone()),
            [
                FileName::Real(shared_module.clone()),
                FileName::Real(second_root.clone()),
            ]
            .iter(),
            [&second_root, &shared_module]
                .into_iter()
                .map(|path| Some(path.as_path())),
            Some(vec![
                FileProbe {
                    path: second_root.clone(),
                    canonical: Some(second_root.canonicalize()?),
                    exists: true,
                    is_directory: false,
                },
                FileProbe {
                    path: shared_module.clone(),
                    canonical: Some(shared_module.canonicalize()?),
                    exists: true,
                    is_directory: false,
                },
            ]),
        );
        session.record_module_graph(
            &FileName::Real(first_root.clone()),
            [
                FileName::Real(shared_module.clone()),
                FileName::Real(first_root.clone()),
            ]
            .iter(),
            [&first_root, &shared_module]
                .into_iter()
                .map(|path| Some(path.as_path())),
            Some(vec![
                FileProbe {
                    path: first_root.clone(),
                    canonical: Some(first_root.canonicalize()?),
                    exists: true,
                    is_directory: false,
                },
                FileProbe {
                    path: shared_module.clone(),
                    canonical: Some(shared_module.canonicalize()?),
                    exists: true,
                    is_directory: false,
                },
            ]),
        );

        let manifest_path = directory.path().join("modules.json");
        session.write_module_manifest(&manifest_path, &[second_root, first_root.clone()])?;
        let manifest: serde_json::Value =
            serde_json::from_slice(&fs::read(manifest_path)?).map_err(io::Error::other)?;

        assert_eq!(manifest["schema"], "ohm.rustfmt-files");
        assert_eq!(manifest["version"], 1);
        assert_eq!(
            manifest["roots"][0]["path"],
            first_root.canonicalize()?.to_string_lossy().as_ref()
        );
        assert_eq!(
            manifest["roots"][0]["files"].as_array().map(Vec::len),
            Some(2)
        );
        assert_eq!(
            manifest["roots"][0]["dependencies"]
                .as_array()
                .map(Vec::len),
            Some(2)
        );
        assert_eq!(
            manifest["roots"][0]["probes"].as_array().map(Vec::len),
            Some(2)
        );
        assert_eq!(manifest["roots"].as_array().map(Vec::len), Some(2));
        Ok(())
    }

    #[test]
    fn successful_write_mode_publishes_actual_resolved_module_graph() -> io::Result<()> {
        let directory = tempfile::tempdir()?;
        let root = directory.path().join("root.rs");
        let external = directory.path().join("external.rs");
        let parsed = directory.path().join("parsed.rs");
        let skipped = directory.path().join("skipped.rs");
        fs::write(
            &root,
            concat!(
                "#[path = \"external.rs\"]\nmod external;\nmod parsed;\n",
                "#[rustfmt::skip]\nmod skipped;\nfn root( ){ }\n",
            ),
        )?;
        fs::write(&external, "fn external( ){ }\n")?;
        fs::write(&parsed, "#![rustfmt::skip]\nfn parsed( ){ }\n")?;
        fs::write(&skipped, "fn skipped( {{{\n")?;

        let mut configuration = Config::default();
        configuration.set().emit_mode(EmitMode::Files);
        let mut output = Vec::new();
        let mut session = Session::new(configuration, Some(&mut output));
        session.enable_module_graph();
        session
            .format(Input::File(root.clone()))
            .map_err(io::Error::other)?;

        assert!(session.has_no_errors());
        assert_eq!(fs::read_to_string(&external)?, "fn external() {}\n");
        assert_eq!(
            fs::read_to_string(&parsed)?,
            "#![rustfmt::skip]\nfn parsed( ){ }\n"
        );
        assert_eq!(fs::read_to_string(&skipped)?, "fn skipped( {{{\n");
        let manifest_path = directory.path().join("modules.json");
        session.write_module_manifest(&manifest_path, &[root])?;
        let manifest: serde_json::Value =
            serde_json::from_slice(&fs::read(manifest_path)?).map_err(io::Error::other)?;
        let files = manifest["roots"][0]["files"]
            .as_array()
            .ok_or_else(|| io::Error::other("module files missing"))?;
        let dependencies = manifest["roots"][0]["dependencies"]
            .as_array()
            .ok_or_else(|| io::Error::other("module dependencies missing"))?;
        let probes = manifest["roots"][0]["probes"]
            .as_array()
            .ok_or_else(|| io::Error::other("module probes missing"))?;
        let parsed_path = parsed.canonicalize()?;
        let skipped_path = skipped.canonicalize()?;
        let alternate_parsed_path = directory.path().join("parsed/mod.rs");

        assert_eq!(files.len(), 2);
        assert_eq!(dependencies.len(), 3);
        assert!(
            !files
                .iter()
                .any(|file| file.as_str() == parsed_path.to_str())
        );
        assert!(
            dependencies
                .iter()
                .any(|file| file.as_str() == parsed_path.to_str())
        );
        assert!(
            !dependencies
                .iter()
                .any(|file| file.as_str() == skipped_path.to_str())
        );
        assert!(probes.iter().any(|probe| {
            probe["exists"] == true
                && probe["is_directory"] == false
                && probe["canonical"].as_str() == parsed_path.to_str()
        }));
        assert!(probes.iter().any(|probe| {
            probe["exists"] == false
                && probe["is_directory"] == false
                && probe["canonical"].is_null()
                && probe["path"].as_str() == alternate_parsed_path.to_str()
        }));
        assert!(
            probes
                .iter()
                .all(|probe| { probe["canonical"].as_str() != skipped_path.to_str() })
        );
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn module_manifest_preserves_logical_symlink_probes() -> io::Result<()> {
        let directory = tempfile::tempdir()?;
        let root = directory.path().join("root.rs");
        let first = directory.path().join("first.rs");
        let second = directory.path().join("second.rs");
        let linked = directory.path().join("linked.rs");
        fs::write(&root, "#[path = \"linked.rs\"]\nmod linked;\n")?;
        fs::write(&first, "fn first() {}\n")?;
        fs::write(&second, "fn second() {}\n")?;
        std::os::unix::fs::symlink(&first, &linked)?;

        for (index, expected) in [&first, &second].into_iter().enumerate() {
            if index == 1 {
                fs::remove_file(&linked)?;
                std::os::unix::fs::symlink(&second, &linked)?;
            }

            let mut output = Vec::new();
            let mut session = Session::new(Config::default(), Some(&mut output));
            session.enable_module_graph();
            session
                .format(Input::File(root.clone()))
                .map_err(io::Error::other)?;
            let manifest_path = directory.path().join(format!("modules-{index}.json"));
            session.write_module_manifest(&manifest_path, std::slice::from_ref(&root))?;
            let manifest: serde_json::Value =
                serde_json::from_slice(&fs::read(manifest_path)?).map_err(io::Error::other)?;
            let probes = manifest["roots"][0]["probes"]
                .as_array()
                .ok_or_else(|| io::Error::other("module probes missing"))?;
            let canonical = expected.canonicalize()?;

            assert!(probes.iter().any(|probe| {
                probe["path"].as_str() == linked.to_str()
                    && probe["exists"] == true
                    && probe["is_directory"] == false
                    && probe["canonical"].as_str() == canonical.to_str()
            }));
        }

        Ok(())
    }

    #[test]
    fn benign_macro_fallback_does_not_invalidate_complete_module_manifest() -> io::Result<()> {
        let directory = tempfile::tempdir()?;
        let root = directory.path().join("root.rs");
        fs::write(&root, "fn formatted() {}\n")?;

        let mut output = Vec::new();
        let mut session = Session::new(Config::default(), Some(&mut output));
        session.enable_module_graph();
        session
            .format(Input::File(root.clone()))
            .map_err(io::Error::other)?;
        session.errors.has_macro_format_failure = true;
        assert!(!session.has_no_errors());

        let manifest_path = directory.path().join("modules.json");
        session.write_module_manifest(&manifest_path, &[root])?;
        assert!(manifest_path.is_file());
        Ok(())
    }

    #[test]
    fn incomplete_module_manifest_is_never_published() -> io::Result<()> {
        let directory = tempfile::tempdir()?;
        let root = directory.path().join("root.rs");
        let module = directory.path().join("module.rs");
        fs::write(&root, "mod module;\n")?;
        fs::write(&module, "fn formatted() {}\n")?;

        let mut output = Vec::new();
        let mut session = Session::new(Config::default(), Some(&mut output));
        session.enable_module_graph();
        session.record_module_graph(
            &FileName::Real(root.clone()),
            [FileName::Real(module)].iter(),
            [root.as_path()].into_iter().map(Some),
            Some(vec![FileProbe {
                path: root.clone(),
                canonical: Some(root.canonicalize()?),
                exists: true,
                is_directory: false,
            }]),
        );

        let manifest_path = directory.path().join("modules.json");
        assert!(
            session
                .write_module_manifest(&manifest_path, &[root])
                .is_err()
        );
        assert!(!manifest_path.exists());
        Ok(())
    }

    #[test]
    fn test_no_panic_on_format_snippet_and_format_code_block() {
        // `format_snippet()` and `format_code_block()` should not panic
        // even when we cannot parse the given snippet.
        let snippet = "let";
        assert!(format_snippet(snippet, &Config::default(), false).is_none());
        assert!(format_code_block(snippet, &Config::default(), false).is_none());
    }

    fn test_format_inner<F>(formatter: F, input: &str, expected: &str) -> bool
    where
        F: Fn(&str, &Config, bool) -> Option<FormattedSnippet>,
    {
        let output = formatter(input, &Config::default(), false);
        output.is_some() && output.unwrap().snippet == expected
    }

    #[test]
    fn test_format_snippet() {
        let snippet = "fn main() { println!(\"hello, world\"); }";
        #[cfg(not(windows))]
        let expected = "fn main() {\n    \
                        println!(\"hello, world\");\n\
                        }\n";
        #[cfg(windows)]
        let expected = "fn main() {\r\n    \
                        println!(\"hello, world\");\r\n\
                        }\r\n";
        assert!(test_format_inner(format_snippet, snippet, expected));
    }

    #[test]
    fn test_format_code_block_fail() {
        #[rustfmt::skip]
        let code_block = "this_line_is_100_characters_long_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx(x, y, z);";
        assert!(format_code_block(code_block, &Config::default(), false).is_none());
    }

    #[test]
    fn test_format_code_block() {
        // simple code block
        let code_block = "let x=3;";
        let expected = "let x = 3;";
        assert!(test_format_inner(format_code_block, code_block, expected));

        // more complex code block, taken from chains.rs.
        let code_block =
"let (nested_shape, extend) = if !parent_rewrite_contains_newline && is_continuable(&parent) {
(
chain_indent(context, shape.add_offset(parent_rewrite.len())),
context.config.indent_style() == IndentStyle::Visual || is_small_parent,
)
} else if is_block_expr(context, &parent, &parent_rewrite) {
match context.config.indent_style() {
// Try to put the first child on the same line with parent's last line
IndentStyle::Block => (parent_shape.block_indent(context.config.tab_spaces()), true),
// The parent is a block, so align the rest of the chain with the closing
// brace.
IndentStyle::Visual => (parent_shape, false),
}
} else {
(
chain_indent(context, shape.add_offset(parent_rewrite.len())),
false,
)
};
";
        let expected =
"let (nested_shape, extend) = if !parent_rewrite_contains_newline && is_continuable(&parent) {
    (
        chain_indent(context, shape.add_offset(parent_rewrite.len())),
        context.config.indent_style() == IndentStyle::Visual || is_small_parent,
    )
} else if is_block_expr(context, &parent, &parent_rewrite) {
    match context.config.indent_style() {
        // Try to put the first child on the same line with parent's last line
        IndentStyle::Block => (parent_shape.block_indent(context.config.tab_spaces()), true),
        // The parent is a block, so align the rest of the chain with the closing
        // brace.
        IndentStyle::Visual => (parent_shape, false),
    }
} else {
    (
        chain_indent(context, shape.add_offset(parent_rewrite.len())),
        false,
    )
};";
        assert!(test_format_inner(format_code_block, code_block, expected));
    }
}
