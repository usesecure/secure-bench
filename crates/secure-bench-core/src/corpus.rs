//! Phase 1 first-party corpus validation, leakage detection, and fingerprinting.

use crate::adapter::fingerprint;
use crate::model::{BenchmarkSuite, CaseKind, SUITE_SCHEMA_V2};
use crate::pipeline::{ContractError, validate_suite_contract};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io::Read;
use std::path::{Component, Path, PathBuf};
use thiserror::Error;

const MAX_CASE_FILES: usize = 64;
const MAX_CASE_BYTES: u64 = 1024 * 1024;
const MAX_FILE_BYTES: u64 = 256 * 1024;

/// The seven public Phase 1 rule-family categories.
pub const PHASE_1_CATEGORIES: [&str; 7] = [
    "command-execution",
    "raw-sql-construction",
    "filesystem-boundary",
    "outbound-request-boundary",
    "redirect-boundary",
    "dynamic-code-execution",
    "authorization-dominance",
];

/// Corpus validation summary and computed fingerprints.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CorpusValidation {
    /// Total cases.
    pub cases: u64,
    /// Vulnerable cases.
    pub vulnerable_cases: u64,
    /// Safe controls.
    pub safe_controls: u64,
    /// Computed corpus fingerprint.
    pub corpus_fingerprint: String,
    /// Computed content fingerprint by case identifier.
    pub case_fingerprints: BTreeMap<String, String>,
}

/// Corpus contract, filesystem, provenance, or leakage error.
#[derive(Debug, Error)]
pub enum CorpusError {
    /// Typed suite contract failure.
    #[error(transparent)]
    Contract(#[from] ContractError),
    /// Filesystem access failure without source contents.
    #[error("could not inspect corpus path `{path}`: {detail}")]
    Io {
        /// Repository-relative or requested path.
        path: String,
        /// Sanitized filesystem error.
        detail: String,
    },
    /// Phase 1 semantic contract failure.
    #[error("Phase 1 corpus contract is invalid: {0}")]
    Semantic(String),
    /// Scanner-visible answer leakage.
    #[error("scanner-visible answer leakage in `{path}`: {detail}")]
    AnswerLeakage {
        /// Repository-relative fixture path.
        path: String,
        /// Kind of leaked metadata, without source text.
        detail: String,
    },
    /// Committed content does not match its manifest fingerprint.
    #[error(
        "content fingerprint mismatch for case `{case_id}`: expected {expected}, computed {computed}"
    )]
    FingerprintMismatch {
        /// Stable case identifier.
        case_id: String,
        /// Manifest fingerprint.
        expected: String,
        /// Computed fingerprint.
        computed: String,
    },
}

/// Computes fixture fingerprints without accepting them as valid manifest claims.
///
/// # Errors
///
/// Returns [`CorpusError`] for unsafe paths, symlinks, unsupported files, excessive content,
/// answer leakage, or filesystem failures.
pub fn inspect_corpus(
    suite: &BenchmarkSuite,
    repository_root: &Path,
) -> Result<CorpusValidation, CorpusError> {
    validate_suite_contract(suite)?;
    crate::schema::validate_suite(suite).map_err(|error| {
        CorpusError::Semantic(format!("suite schema validation failed: {error}"))
    })?;
    validate_phase_1_metadata(suite)?;

    let forbidden = forbidden_terms(suite);
    let mut case_fingerprints = BTreeMap::new();
    let mut vulnerable_cases = 0_u64;
    let mut safe_controls = 0_u64;
    for case in &suite.cases {
        match case.kind {
            CaseKind::Vulnerable => vulnerable_cases += 1,
            CaseKind::SafeControl => safe_controls += 1,
        }
        let fixture_path = safe_join(repository_root, &case.fixture_path)?;
        validate_scanner_visible_tree(
            repository_root,
            &fixture_path,
            &case.fixture_path,
            &forbidden,
        )?;
        validate_declared_language(&fixture_path, &case.fixture_path, &case.language)?;
        let digest = fingerprint_directory(&fixture_path, &case.fixture_path)?;
        case_fingerprints.insert(case.case_id.clone(), digest);
    }

    let corpus_fingerprint = aggregate_fingerprint(&case_fingerprints);
    Ok(CorpusValidation {
        cases: u64::try_from(suite.cases.len()).unwrap_or(u64::MAX),
        vulnerable_cases,
        safe_controls,
        corpus_fingerprint,
        case_fingerprints,
    })
}

/// Validates the Phase 1 corpus and every committed fingerprint.
///
/// # Errors
///
/// Returns [`CorpusError`] for any typed, semantic, leakage, path, or fingerprint failure.
pub fn validate_corpus(
    suite: &BenchmarkSuite,
    repository_root: &Path,
) -> Result<CorpusValidation, CorpusError> {
    let validation = inspect_corpus(suite, repository_root)?;
    for case in &suite.cases {
        let expected = case.content_fingerprint.as_deref().ok_or_else(|| {
            CorpusError::Semantic(format!(
                "case `{}` has no content fingerprint",
                case.case_id
            ))
        })?;
        let computed = validation
            .case_fingerprints
            .get(&case.case_id)
            .map(String::as_str)
            .ok_or_else(|| {
                CorpusError::Semantic(format!(
                    "case `{}` was not included in fingerprinting",
                    case.case_id
                ))
            })?;
        if expected != computed {
            return Err(CorpusError::FingerprintMismatch {
                case_id: case.case_id.clone(),
                expected: expected.to_owned(),
                computed: computed.to_owned(),
            });
        }
    }
    let expected_corpus = suite
        .corpus_fingerprint
        .as_deref()
        .ok_or_else(|| CorpusError::Semantic("suite has no corpus fingerprint".to_owned()))?;
    if expected_corpus != validation.corpus_fingerprint {
        return Err(CorpusError::FingerprintMismatch {
            case_id: suite.suite_id.clone(),
            expected: expected_corpus.to_owned(),
            computed: validation.corpus_fingerprint.clone(),
        });
    }
    Ok(validation)
}

fn validate_phase_1_metadata(suite: &BenchmarkSuite) -> Result<(), CorpusError> {
    if suite.schema_version != SUITE_SCHEMA_V2 {
        return Err(CorpusError::Semantic(format!(
            "expected schema `{SUITE_SCHEMA_V2}`"
        )));
    }
    if suite
        .corpus_fingerprint
        .as_deref()
        .is_none_or(str::is_empty)
    {
        return Err(CorpusError::Semantic(
            "suite corpus fingerprint is required".to_owned(),
        ));
    }
    if suite.provenance.authors.is_empty() {
        return Err(CorpusError::Semantic(
            "suite authorship is required".to_owned(),
        ));
    }

    if suite.cases.len() != 14 {
        return Err(CorpusError::Semantic(
            "Phase 1 requires exactly 14 cases in seven pairs".to_owned(),
        ));
    }
    let mut category_kinds = BTreeMap::<&str, BTreeSet<CaseKind>>::new();
    let mut category_counts = BTreeMap::<(&str, CaseKind), u64>::new();
    let mut languages = BTreeSet::new();
    let mut frameworks = BTreeSet::new();
    for case in &suite.cases {
        if case
            .content_fingerprint
            .as_deref()
            .is_none_or(str::is_empty)
            || case
                .eligibility
                .rationale
                .as_deref()
                .is_none_or(str::is_empty)
            || case.provenance.authors.is_empty()
        {
            return Err(CorpusError::Semantic(format!(
                "case `{}` is missing fingerprint, eligibility rationale, or authorship",
                case.case_id
            )));
        }
        category_kinds
            .entry(case.category.as_str())
            .or_default()
            .insert(case.kind);
        *category_counts
            .entry((case.category.as_str(), case.kind))
            .or_default() += 1;
        languages.insert(case.language.to_ascii_lowercase());
        if let Some(framework) = &case.framework {
            frameworks.insert(framework.to_ascii_lowercase());
        }
    }
    for category in PHASE_1_CATEGORIES {
        let kinds = category_kinds.get(category).ok_or_else(|| {
            CorpusError::Semantic(format!("missing required category `{category}`"))
        })?;
        if !kinds.contains(&CaseKind::Vulnerable) || !kinds.contains(&CaseKind::SafeControl) {
            return Err(CorpusError::Semantic(format!(
                "category `{category}` must pair vulnerable and safe-control cases"
            )));
        }
        if category_counts.get(&(category, CaseKind::Vulnerable)) != Some(&1)
            || category_counts.get(&(category, CaseKind::SafeControl)) != Some(&1)
        {
            return Err(CorpusError::Semantic(format!(
                "category `{category}` must contain exactly one vulnerable case and one control"
            )));
        }
    }
    let required_languages = ["javascript", "jsx", "typescript", "tsx"];
    if required_languages
        .iter()
        .any(|language| !languages.contains(*language))
    {
        return Err(CorpusError::Semantic(
            "corpus must include JavaScript, JSX, TypeScript, and TSX".to_owned(),
        ));
    }
    let required_frameworks = ["node.js", "express", "next.js"];
    if required_frameworks
        .iter()
        .any(|framework| !frameworks.contains(*framework))
    {
        return Err(CorpusError::Semantic(
            "corpus must include Node.js, Express, and Next.js".to_owned(),
        ));
    }
    Ok(())
}

fn validate_declared_language(
    fixture_root: &Path,
    display_root: &str,
    language: &str,
) -> Result<(), CorpusError> {
    let expected_extension = match language {
        "javascript" => "js",
        "jsx" => "jsx",
        "typescript" => "ts",
        "tsx" => "tsx",
        _ => {
            return Err(CorpusError::Semantic(format!(
                "fixture `{display_root}` declares an unsupported language"
            )));
        }
    };
    if collect_files(fixture_root, display_root)?
        .iter()
        .any(|path| {
            path.extension().and_then(|extension| extension.to_str()) == Some(expected_extension)
        })
    {
        Ok(())
    } else {
        Err(CorpusError::Semantic(format!(
            "fixture `{display_root}` has no source file matching declared language `{language}`"
        )))
    }
}

fn forbidden_terms(suite: &BenchmarkSuite) -> BTreeSet<String> {
    let mut terms = [
        "vulnerable",
        "vulnerability",
        "unsafe",
        "safe",
        "expected",
        "expectation",
        "source",
        "sink",
        "outcome",
        "rule",
        "insecure",
    ]
    .into_iter()
    .map(str::to_owned)
    .collect::<BTreeSet<_>>();
    for case in &suite.cases {
        terms.insert(case.category.to_ascii_lowercase());
        if let Some(invariant) = &case.invariant {
            terms.insert(invariant.to_ascii_lowercase());
        }
        for expected in &case.expected_findings {
            terms.insert(expected.expectation_id.to_ascii_lowercase());
            terms.insert(expected.category.to_ascii_lowercase());
            terms.insert(expected.invariant.to_ascii_lowercase());
        }
    }
    terms
}

fn validate_scanner_visible_tree(
    repository_root: &Path,
    fixture_root: &Path,
    relative_fixture: &str,
    forbidden: &BTreeSet<String>,
) -> Result<(), CorpusError> {
    let root_metadata = fs::symlink_metadata(fixture_root).map_err(|error| CorpusError::Io {
        path: relative_fixture.to_owned(),
        detail: error.to_string(),
    })?;
    if !root_metadata.is_dir() || root_metadata.file_type().is_symlink() {
        return Err(CorpusError::Semantic(format!(
            "fixture `{relative_fixture}` must be a regular directory"
        )));
    }

    let files = collect_files(fixture_root, relative_fixture)?;
    for file in files {
        let relative = file
            .strip_prefix(repository_root)
            .map_err(|_| CorpusError::Semantic("fixture escaped the repository root".to_owned()))?;
        let display = slash_path(relative);
        check_path_terms(relative, &display, forbidden)?;
        let bytes = fs::read(&file).map_err(|error| CorpusError::Io {
            path: display.clone(),
            detail: error.to_string(),
        })?;
        let text = std::str::from_utf8(&bytes).map_err(|_| CorpusError::AnswerLeakage {
            path: display.clone(),
            detail: "fixture text is not UTF-8".to_owned(),
        })?;
        check_content_terms(text, &display, forbidden)?;
        check_package_name(text, &display, forbidden)?;
    }
    Ok(())
}

fn collect_files(root: &Path, display_root: &str) -> Result<Vec<PathBuf>, CorpusError> {
    let mut pending = vec![root.to_path_buf()];
    let mut files = Vec::new();
    let mut total_bytes = 0_u64;
    while let Some(directory) = pending.pop() {
        let entries = fs::read_dir(&directory).map_err(|error| CorpusError::Io {
            path: display_root.to_owned(),
            detail: error.to_string(),
        })?;
        for entry in entries {
            let entry = entry.map_err(|error| CorpusError::Io {
                path: display_root.to_owned(),
                detail: error.to_string(),
            })?;
            let path = entry.path();
            let metadata = fs::symlink_metadata(&path).map_err(|error| CorpusError::Io {
                path: display_root.to_owned(),
                detail: error.to_string(),
            })?;
            if metadata.file_type().is_symlink() {
                return Err(CorpusError::Semantic(format!(
                    "fixture `{display_root}` contains a symlink"
                )));
            }
            if metadata.is_dir() {
                pending.push(path);
            } else if metadata.is_file() {
                if metadata.len() > MAX_FILE_BYTES {
                    return Err(CorpusError::Semantic(format!(
                        "fixture `{display_root}` contains a file larger than {MAX_FILE_BYTES} bytes"
                    )));
                }
                total_bytes = total_bytes.saturating_add(metadata.len());
                files.push(path);
            } else {
                return Err(CorpusError::Semantic(format!(
                    "fixture `{display_root}` contains a non-regular entry"
                )));
            }
        }
    }
    if files.is_empty() || files.len() > MAX_CASE_FILES || total_bytes > MAX_CASE_BYTES {
        return Err(CorpusError::Semantic(format!(
            "fixture `{display_root}` must contain 1..={MAX_CASE_FILES} files and at most {MAX_CASE_BYTES} bytes"
        )));
    }
    files.sort();
    Ok(files)
}

fn check_path_terms(
    path: &Path,
    display: &str,
    forbidden: &BTreeSet<String>,
) -> Result<(), CorpusError> {
    let allowed_extensions = ["js", "jsx", "json", "ts", "tsx"];
    let extension = path
        .extension()
        .and_then(|value| value.to_str())
        .unwrap_or("");
    if !allowed_extensions.contains(&extension) {
        return Err(CorpusError::AnswerLeakage {
            path: display.to_owned(),
            detail: "unsupported scanner-visible file type".to_owned(),
        });
    }
    for component in path.components() {
        if let Component::Normal(value) = component {
            let normalized = normalize_words(&value.to_string_lossy());
            if contains_forbidden_name(&normalized, forbidden) {
                return Err(CorpusError::AnswerLeakage {
                    path: display.to_owned(),
                    detail: "path names a labeled answer or outcome".to_owned(),
                });
            }
        }
    }
    Ok(())
}

fn check_content_terms(
    text: &str,
    display: &str,
    forbidden: &BTreeSet<String>,
) -> Result<(), CorpusError> {
    let lowercase = text.to_ascii_lowercase();
    for term in forbidden.iter().filter(|term| term.contains([' ', '-'])) {
        if lowercase.contains(term) {
            return Err(CorpusError::AnswerLeakage {
                path: display.to_owned(),
                detail: "content embeds matcher-owned category or invariant text".to_owned(),
            });
        }
    }

    for line in text.lines() {
        let trimmed = line.trim_start();
        if (trimmed.starts_with("//") || trimmed.starts_with("/*") || trimmed.starts_with('*'))
            && contains_forbidden_name(trimmed, forbidden)
        {
            return Err(CorpusError::AnswerLeakage {
                path: display.to_owned(),
                detail: "comment names a labeled answer or outcome".to_owned(),
            });
        }
        let words = identifier_words(line);
        for (index, word) in words.iter().enumerate() {
            if matches!(
                word.as_str(),
                "function" | "const" | "let" | "var" | "class"
            ) && let Some(identifier) = words.get(index + 1)
            {
                let normalized = normalize_words(identifier);
                if contains_forbidden_name(&normalized, forbidden) {
                    return Err(CorpusError::AnswerLeakage {
                        path: display.to_owned(),
                        detail: "declared identifier names a labeled answer or outcome".to_owned(),
                    });
                }
            }
        }
    }
    Ok(())
}

fn check_package_name(
    text: &str,
    display: &str,
    forbidden: &BTreeSet<String>,
) -> Result<(), CorpusError> {
    if !display.ends_with("/package.json") {
        return Ok(());
    }
    let value: serde_json::Value = serde_json::from_str(text).map_err(|_| {
        CorpusError::Semantic(format!(
            "fixture package metadata `{display}` is invalid JSON"
        ))
    })?;
    let name = value
        .get("name")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| {
            CorpusError::Semantic(format!("fixture package metadata `{display}` has no name"))
        })?;
    if contains_forbidden_name(name, forbidden) {
        return Err(CorpusError::AnswerLeakage {
            path: display.to_owned(),
            detail: "package name identifies a labeled answer, rule family, or outcome".to_owned(),
        });
    }
    Ok(())
}

fn contains_forbidden_name(value: &str, forbidden: &BTreeSet<String>) -> bool {
    let normalized = normalize_words(value);
    forbidden.iter().any(|term| {
        let normalized_term = normalize_words(term);
        !normalized_term.is_empty() && normalized.contains(&normalized_term)
    })
}

fn identifier_words(line: &str) -> Vec<String> {
    line.split(|character: char| !(character.is_ascii_alphanumeric() || character == '_'))
        .filter(|word| !word.is_empty())
        .map(str::to_ascii_lowercase)
        .collect()
}

fn normalize_words(value: &str) -> String {
    value
        .chars()
        .filter(char::is_ascii_alphanumeric)
        .flat_map(char::to_lowercase)
        .collect()
}

fn fingerprint_directory(root: &Path, display_root: &str) -> Result<String, CorpusError> {
    let files = collect_files(root, display_root)?;
    let mut hasher = Sha256::new();
    for path in files {
        let relative = path.strip_prefix(root).map_err(|_| {
            CorpusError::Semantic(format!("fixture `{display_root}` escaped its case root"))
        })?;
        let relative = slash_path(relative);
        let mut file = fs::File::open(&path).map_err(|error| CorpusError::Io {
            path: format!("{display_root}/{relative}"),
            detail: error.to_string(),
        })?;
        let size = file
            .metadata()
            .map_err(|error| CorpusError::Io {
                path: format!("{display_root}/{relative}"),
                detail: error.to_string(),
            })?
            .len();
        hasher.update(
            u64::try_from(relative.len())
                .unwrap_or(u64::MAX)
                .to_be_bytes(),
        );
        hasher.update(relative.as_bytes());
        hasher.update(size.to_be_bytes());
        let mut buffer = [0_u8; 8192];
        loop {
            let read = file.read(&mut buffer).map_err(|error| CorpusError::Io {
                path: format!("{display_root}/{relative}"),
                detail: error.to_string(),
            })?;
            if read == 0 {
                break;
            }
            hasher.update(&buffer[..read]);
        }
    }
    Ok(hex_digest(&hasher.finalize()))
}

fn aggregate_fingerprint(fingerprints: &BTreeMap<String, String>) -> String {
    let mut bytes = Vec::new();
    for (case_id, digest) in fingerprints {
        bytes.extend_from_slice(case_id.as_bytes());
        bytes.push(0);
        bytes.extend_from_slice(digest.as_bytes());
        bytes.push(0);
    }
    fingerprint(&bytes)
}

fn safe_join(root: &Path, relative: &str) -> Result<PathBuf, CorpusError> {
    let path = Path::new(relative);
    if path.is_absolute()
        || path.components().any(|component| {
            matches!(
                component,
                Component::ParentDir | Component::RootDir | Component::Prefix(_)
            )
        })
    {
        return Err(CorpusError::Semantic(
            "fixture paths must remain repository-relative".to_owned(),
        ));
    }
    Ok(root.join(path))
}

fn slash_path(path: &Path) -> String {
    path.components()
        .filter_map(|component| match component {
            Component::Normal(value) => Some(value.to_string_lossy()),
            _ => None,
        })
        .collect::<Vec<_>>()
        .join("/")
}

fn hex_digest(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        encoded.push(char::from(HEX[usize::from(byte >> 4)]));
        encoded.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    encoded
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pipeline::load_suite;
    use std::fs::OpenOptions;
    use std::io::Write;
    use tempfile::TempDir;

    const PHASE_1_SUITE: &[u8] = include_bytes!("../../../fixtures/corpus-v1.toml");

    fn repository_root() -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
    }

    fn copy_tree(source: &Path, destination: &Path) -> std::io::Result<()> {
        fs::create_dir_all(destination)?;
        let mut pending = vec![(source.to_path_buf(), destination.to_path_buf())];
        while let Some((source_directory, destination_directory)) = pending.pop() {
            for entry in fs::read_dir(source_directory)? {
                let entry = entry?;
                let metadata = entry.metadata()?;
                let target = destination_directory.join(entry.file_name());
                if metadata.is_dir() {
                    fs::create_dir(&target)?;
                    pending.push((entry.path(), target));
                } else {
                    fs::copy(entry.path(), target)?;
                }
            }
        }
        Ok(())
    }

    #[test]
    fn word_normalization_is_case_and_punctuation_independent() {
        assert_eq!(normalize_words("Raw-SQL_value"), "rawsqlvalue");
    }

    #[test]
    fn aggregate_fingerprint_is_ordered() {
        let fingerprints = BTreeMap::from([
            ("case-b".to_owned(), "b".repeat(64)),
            ("case-a".to_owned(), "a".repeat(64)),
        ]);
        assert_eq!(aggregate_fingerprint(&fingerprints).len(), 64);
    }

    #[test]
    fn committed_phase_1_corpus_satisfies_schema_semantics_and_fingerprints()
    -> Result<(), Box<dyn std::error::Error>> {
        let suite = load_suite(PHASE_1_SUITE)?;
        crate::schema::validate_suite(&suite)?;
        let validation = validate_corpus(&suite, &repository_root())?;
        assert_eq!(validation.cases, 14);
        assert_eq!(validation.vulnerable_cases, 7);
        assert_eq!(validation.safe_controls, 7);
        assert_eq!(validation.case_fingerprints.len(), 14);
        Ok(())
    }

    #[test]
    fn fingerprint_drift_is_rejected() -> Result<(), Box<dyn std::error::Error>> {
        let mut suite = load_suite(PHASE_1_SUITE)?;
        if let Some(case) = suite.cases.first_mut() {
            case.content_fingerprint = Some("0".repeat(64));
        }
        assert!(matches!(
            validate_corpus(&suite, &repository_root()),
            Err(CorpusError::FingerprintMismatch { .. })
        ));
        Ok(())
    }

    #[test]
    fn scanner_visible_answer_labels_are_rejected() -> Result<(), Box<dyn std::error::Error>> {
        let suite = load_suite(PHASE_1_SUITE)?;
        let temporary = TempDir::new()?;
        let source = repository_root().join("fixtures/corpus");
        let destination = temporary.path().join("fixtures/corpus");
        copy_tree(&source, &destination)?;
        let entry = destination.join("case-001/src/entry.js");
        let mut file = OpenOptions::new().append(true).open(entry)?;
        file.write_all(b"\n// vulnerable outcome label\n")?;

        assert!(matches!(
            inspect_corpus(&suite, temporary.path()),
            Err(CorpusError::AnswerLeakage { .. })
        ));
        Ok(())
    }

    #[test]
    fn normalized_category_names_are_rejected_from_declarations()
    -> Result<(), Box<dyn std::error::Error>> {
        let suite = load_suite(PHASE_1_SUITE)?;
        let temporary = TempDir::new()?;
        let source = repository_root().join("fixtures/corpus");
        let destination = temporary.path().join("fixtures/corpus");
        copy_tree(&source, &destination)?;
        let entry = destination.join("case-001/src/entry.js");
        let mut file = OpenOptions::new().append(true).open(entry)?;
        file.write_all(b"\nconst commandExecution = 1;\n")?;

        assert!(matches!(
            inspect_corpus(&suite, temporary.path()),
            Err(CorpusError::AnswerLeakage { .. })
        ));
        Ok(())
    }

    #[test]
    fn normalized_category_names_are_rejected_from_package_metadata()
    -> Result<(), Box<dyn std::error::Error>> {
        let suite = load_suite(PHASE_1_SUITE)?;
        let temporary = TempDir::new()?;
        let source = repository_root().join("fixtures/corpus");
        let destination = temporary.path().join("fixtures/corpus");
        copy_tree(&source, &destination)?;
        fs::write(
            destination.join("case-001/package.json"),
            br#"{"name":"commandExecutionProject","private":true,"type":"module"}"#,
        )?;

        assert!(matches!(
            inspect_corpus(&suite, temporary.path()),
            Err(CorpusError::AnswerLeakage { .. })
        ));
        Ok(())
    }

    #[test]
    fn every_required_category_must_remain_paired() -> Result<(), Box<dyn std::error::Error>> {
        let mut suite = load_suite(PHASE_1_SUITE)?;
        if let Some(case) = suite
            .cases
            .iter_mut()
            .find(|case| case.case_id == "phase1-002")
        {
            case.category = "unpaired-control".to_owned();
        }
        assert!(matches!(
            inspect_corpus(&suite, &repository_root()),
            Err(CorpusError::Semantic(_))
        ));
        Ok(())
    }
}
