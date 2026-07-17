//! Disclosed development regression corpus generation and semantic validation.

use crate::{Phase12Error, canonical_json, sha256};
use secure_bench_core::phase5::{
    EvidenceEffectV2, EvidenceRoleV2, SinkSemanticKind, SourceSemanticKind,
};
use secure_bench_core::taxonomy::{FrozenTaxonomy, TaxonomyCategory};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

/// Public regression manifest schema identity.
pub const REGRESSION_SCHEMA: &str = "secure-bench-phase12-public-regression-v1";
/// Public regression corpus identity.
pub const REGRESSION_ID: &str = "phase-12-public-regression-v1";

/// Supported framework stratum.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Framework {
    /// Node.js request handler.
    NodeJs,
    /// Express request handler.
    Express,
    /// Next.js App Router route handler.
    NextAppRouter,
    /// Next.js Server Action.
    ServerActions,
}

/// Supported public fixture source format.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Language {
    /// JavaScript source.
    JavaScript,
    /// JSX source.
    Jsx,
    /// TypeScript source.
    TypeScript,
    /// TSX source.
    Tsx,
}

/// Supported value-flow topology.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Topology {
    /// Source reaches the sink in the same handler without an intermediate call.
    Direct,
    /// Source reaches the sink through a same-file helper.
    HelperMediated,
    /// Source reaches an aliased sink wrapper in another file.
    InterFileAliased,
    /// Source reaches the sink through an explicit control-flow join.
    ControlFlowSensitive,
}

/// Public case classification.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CaseKind {
    /// Connected source-to-sensitive-sink flow without an effective barrier.
    ContractVulnerable,
    /// Paired flow protected by an effective terminating barrier.
    ContractSafeControl,
}

/// Exact frozen taxonomy coordinate copied from the canonical taxonomy.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TaxonomyCoordinate {
    /// Frozen taxonomy version.
    pub taxonomy_version: String,
    /// Canonical category identifier.
    pub category_id: String,
    /// Canonical invariant identifier.
    pub invariant_id: String,
    /// Canonical primary CWE.
    pub primary_cwe: String,
}

/// Portable one-based source span.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SourceSpan {
    /// Corpus-root-relative source file.
    pub file: String,
    /// First line.
    pub start_line: u32,
    /// First column.
    pub start_column: u32,
    /// Last line.
    pub end_line: u32,
    /// Last column.
    pub end_column: u32,
}

/// One value-identity-aware path node.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RegressionPathNode {
    /// Evidence role.
    pub role: EvidenceRoleV2,
    /// Security-relevant effect.
    pub effect: EvidenceEffectV2,
    /// Stable concrete value identity shared across the path.
    pub value_id: String,
    /// Source semantic kind for a source node.
    pub source_kind: Option<SourceSemanticKind>,
    /// Sink semantic kind for a sink node.
    pub sink_kind: Option<SinkSemanticKind>,
    /// Exact committed source span.
    pub span: SourceSpan,
}

/// Effective barrier contract for a paired control.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct BarrierContract {
    /// Barrier effect.
    pub effect: EvidenceEffectV2,
    /// Concrete value protected by the barrier.
    pub value_id: String,
    /// Whether rejection terminates before the sink.
    pub terminating: bool,
    /// Whether the barrier dominates the sink.
    pub dominates_sink: bool,
    /// Exact barrier span.
    pub span: SourceSpan,
}

/// One committed public source file.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct FixtureFile {
    /// Corpus-root-relative path.
    pub path: String,
    /// Exact file SHA-256.
    pub sha256: String,
}

/// One public regression case.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RegressionCase {
    /// Stable case identifier.
    pub case_id: String,
    /// Public case kind.
    pub kind: CaseKind,
    /// Exact canonical taxonomy coordinates.
    pub taxonomy: TaxonomyCoordinate,
    /// Complete connected semantic path.
    pub path: Vec<RegressionPathNode>,
    /// Connectivity for each adjacent node.
    pub connected_edges: Vec<bool>,
    /// Effective barriers; empty for the vulnerable member.
    pub effective_barriers: Vec<BarrierContract>,
    /// Committed fixture files.
    pub files: Vec<FixtureFile>,
    /// Aggregate case fingerprint.
    pub case_sha256: String,
}

/// Reversible paired mutation commitment.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct MutationContract {
    /// Human-auditable forward mutation.
    pub forward: String,
    /// Human-auditable inverse mutation.
    pub inverse: String,
    /// Vulnerable case fingerprint restored by the inverse.
    pub inverse_restores_sha256: String,
    /// Safe-control case fingerprint produced by the forward mutation.
    pub forward_produces_sha256: String,
}

/// One paired public regression contract.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RegressionPair {
    /// Stable pair identifier.
    pub pair_id: String,
    /// Public rule-family stratum.
    pub family_id: String,
    /// Framework stratum.
    pub framework: Framework,
    /// Language stratum.
    pub language: Language,
    /// Topology stratum.
    pub topology: Topology,
    /// Connected vulnerable case.
    pub vulnerable: RegressionCase,
    /// Paired same-value safe control.
    pub control: RegressionCase,
    /// Forward and inverse mutation commitment.
    pub mutation: MutationContract,
}

/// Exact coverage counts for the disclosed corpus.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CoverageSummary {
    /// Pair counts by SE family.
    pub families: BTreeMap<String, u64>,
    /// Pair counts by framework.
    pub frameworks: BTreeMap<String, u64>,
    /// Pair counts by language.
    pub languages: BTreeMap<String, u64>,
    /// Pair counts by topology.
    pub topologies: BTreeMap<String, u64>,
}

/// Public, disclosed development regression manifest.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RegressionManifest {
    /// Schema identity.
    pub schema_version: String,
    /// Secure Bench prospective version.
    pub benchmark_version: String,
    /// Corpus identity.
    pub corpus_id: String,
    /// Explicit disclosure status.
    pub disclosed_development_material: bool,
    /// Explicit statement that this is not an unseen holdout.
    pub unseen_holdout: bool,
    /// Frozen taxonomy artifact hash.
    pub taxonomy_sha256: String,
    /// Evidence Contract v2 artifact hash.
    pub evidence_contract_sha256: String,
    /// Complete public pairs.
    pub pairs: Vec<RegressionPair>,
    /// Exact factor balance.
    pub coverage: CoverageSummary,
    /// Fixture licensing and authorship statement.
    pub provenance: String,
}

#[derive(Clone, Copy)]
struct FamilySpec {
    family_id: &'static str,
    category_id: &'static str,
    sink_kind: SinkSemanticKind,
    barrier_effect: EvidenceEffectV2,
}

#[derive(Clone, Copy)]
struct PairSpec {
    ordinal: usize,
    family: FamilySpec,
    framework: Framework,
    language: Language,
    topology: Topology,
}

struct RenderedCase {
    files: BTreeMap<String, Vec<u8>>,
    source_file: String,
    source_needle: String,
    sink_file: String,
    sink_needle: String,
    propagation: Vec<(String, String)>,
    barrier: Option<(String, String)>,
}

const FAMILIES: [FamilySpec; 7] = [
    FamilySpec {
        family_id: "SE1001",
        category_id: "secure-bench.category.authorization-dominance",
        sink_kind: SinkSemanticKind::ProtectedRecordMutation,
        barrier_effect: EvidenceEffectV2::AuthorizesOperation,
    },
    FamilySpec {
        family_id: "SE1002",
        category_id: "secure-bench.category.command-execution",
        sink_kind: SinkSemanticKind::OsCommandExecution,
        barrier_effect: EvidenceEffectV2::RejectsAndTerminates,
    },
    FamilySpec {
        family_id: "SE1003",
        category_id: "secure-bench.category.dynamic-code-execution",
        sink_kind: SinkSemanticKind::DynamicCodeEvaluation,
        barrier_effect: EvidenceEffectV2::RejectsAndTerminates,
    },
    FamilySpec {
        family_id: "SE1004",
        category_id: "secure-bench.category.filesystem-boundary",
        sink_kind: SinkSemanticKind::FilesystemRead,
        barrier_effect: EvidenceEffectV2::ConstrainsToPolicy,
    },
    FamilySpec {
        family_id: "SE1005",
        category_id: "secure-bench.category.outbound-request-boundary",
        sink_kind: SinkSemanticKind::OutboundRequest,
        barrier_effect: EvidenceEffectV2::ConstrainsToPolicy,
    },
    FamilySpec {
        family_id: "SE1006",
        category_id: "secure-bench.category.redirect-boundary",
        sink_kind: SinkSemanticKind::RedirectResponse,
        barrier_effect: EvidenceEffectV2::ConstrainsToPolicy,
    },
    FamilySpec {
        family_id: "SE1007",
        category_id: "secure-bench.category.sql-construction",
        sink_kind: SinkSemanticKind::SqlQueryExecution,
        barrier_effect: EvidenceEffectV2::RejectsAndTerminates,
    },
];

fn enum_name<T: Serialize>(value: T) -> Result<String, Phase12Error> {
    serde_json::to_value(value)
        .map_err(|error| Phase12Error::Serialization(error.to_string()))?
        .as_str()
        .map(str::to_owned)
        .ok_or_else(|| {
            Phase12Error::InvalidRegression("factor did not serialize as text".to_owned())
        })
}

fn assignments() -> Vec<PairSpec> {
    let frameworks = [
        Framework::NodeJs,
        Framework::Express,
        Framework::NextAppRouter,
        Framework::ServerActions,
    ];
    let languages = [
        Language::JavaScript,
        Language::Jsx,
        Language::TypeScript,
        Language::Tsx,
    ];
    let topologies = [
        Topology::Direct,
        Topology::HelperMediated,
        Topology::InterFileAliased,
        Topology::ControlFlowSensitive,
    ];
    let mut pairs = Vec::new();
    for (family_index, family) in FAMILIES.iter().copied().enumerate() {
        for (topology_index, topology) in topologies.iter().copied().enumerate() {
            pairs.push(PairSpec {
                ordinal: pairs.len() + 1,
                family,
                framework: frameworks[(family_index + topology_index) % frameworks.len()],
                language: languages[(family_index * 2 + topology_index) % languages.len()],
                topology,
            });
        }
    }
    pairs
}

fn extension(language: Language) -> &'static str {
    match language {
        Language::JavaScript => "js",
        Language::Jsx => "jsx",
        Language::TypeScript => "ts",
        Language::Tsx => "tsx",
    }
}

fn source_expression(
    framework: Framework,
    family: FamilySpec,
) -> (&'static str, SourceSemanticKind, &'static str) {
    if family.family_id == "SE1001" {
        return match framework {
            Framework::NodeJs => (
                "request.query.resourceId",
                SourceSemanticKind::ProtectedResourceId,
                "request",
            ),
            Framework::Express => (
                "request.body.resourceId",
                SourceSemanticKind::ProtectedResourceId,
                "request",
            ),
            Framework::NextAppRouter => (
                "(await request.json()).resourceId",
                SourceSemanticKind::ProtectedResourceId,
                "request",
            ),
            Framework::ServerActions => (
                "formData.get(\"resourceId\")",
                SourceSemanticKind::ProtectedResourceId,
                "formData",
            ),
        };
    }
    match framework {
        Framework::NodeJs => (
            "request.query.value",
            SourceSemanticKind::HttpQueryValue,
            "request",
        ),
        Framework::Express => (
            "request.body.value",
            SourceSemanticKind::HttpBodyField,
            "request",
        ),
        Framework::NextAppRouter => (
            "(await request.json()).value",
            SourceSemanticKind::HttpBodyField,
            "request",
        ),
        Framework::ServerActions => (
            "formData.get(\"value\")",
            SourceSemanticKind::FormDataValue,
            "formData",
        ),
    }
}

fn prelude(family: FamilySpec) -> &'static str {
    match family.family_id {
        "SE1001" => "import { authorize, principal, records } from \"fixture-runtime\";\n",
        "SE1002" => {
            "import { exec } from \"node:child_process\";\nconst ALLOWED_COMMANDS = new Set([\"status\"]);\n"
        }
        "SE1003" => "const ALLOWED_EXPRESSIONS = new Set([\"1 + 1\"]);\n",
        "SE1004" => {
            "import { readFile } from \"node:fs/promises\";\nimport { resolve, sep } from \"node:path\";\nconst ROOT = \"/srv/public-data\";\n"
        }
        "SE1005" => "const TRUSTED_HOSTS = new Set([\"api.example.test\"]);\n",
        "SE1006" => "import { redirect } from \"next/navigation\";\n",
        "SE1007" => {
            "import { db } from \"fixture-runtime\";\nconst ALLOWED_QUERIES = new Set([\"SELECT status FROM jobs\"]);\n"
        }
        _ => "",
    }
}

fn sink_statement(family: FamilySpec, value: &str) -> String {
    match family.family_id {
        "SE1001" => format!("return records.update({value});"),
        "SE1002" => format!("return exec({value});"),
        "SE1003" => format!("return eval({value});"),
        "SE1004" => format!("return readFile(resolve(ROOT, {value}));"),
        "SE1005" => format!("return fetch({value});"),
        "SE1006" => format!("return redirect({value});"),
        "SE1007" => format!("return db.query({value});"),
        _ => String::new(),
    }
}

fn barrier_statement(family: FamilySpec, value: &str) -> String {
    match family.family_id {
        "SE1001" => format!("if (!await authorize(principal, \"update\", {value})) {{ return; }}"),
        "SE1002" => format!("if (!ALLOWED_COMMANDS.has({value})) {{ return; }}"),
        "SE1003" => format!("if (!ALLOWED_EXPRESSIONS.has({value})) {{ return; }}"),
        "SE1004" => {
            format!("if (!resolve(ROOT, {value}).startsWith(`${{ROOT}}${{sep}}`)) {{ return; }}")
        }
        "SE1005" => format!("if (!TRUSTED_HOSTS.has(new URL({value}).hostname)) {{ return; }}"),
        "SE1006" => format!("if (!{value}.startsWith(\"/\")) {{ return; }}"),
        "SE1007" => format!("if (!ALLOWED_QUERIES.has({value})) {{ return; }}"),
        _ => String::new(),
    }
}

fn jsx_line(language: Language, ordinal: usize) -> Option<String> {
    matches!(language, Language::Jsx | Language::Tsx).then(|| {
        format!(
            "  const view = <span data-case=\"pair-{ordinal:03}\">{{String(candidate)}}</span>; void view;"
        )
    })
}

fn render_case(spec: PairSpec, label: &str, control: bool) -> RenderedCase {
    let extension = extension(spec.language);
    let (source, _, parameter) = source_expression(spec.framework, spec.family);
    let source_line = format!("  const candidate = {source};");
    let view = jsx_line(spec.language, spec.ordinal)
        .map(|line| format!("{line}\n"))
        .unwrap_or_default();
    let function = format!("handle{label}{:03}", spec.ordinal);
    let consume = format!("consume{label}{:03}", spec.ordinal);
    let pair_root = format!("cases/pair-{:03}", spec.ordinal);
    let entry_path = format!("{pair_root}/case-{label}.{extension}");
    let boundary_path = format!("{pair_root}/case-{label}-boundary.{extension}");
    let sink_value = if spec.topology == Topology::ControlFlowSensitive {
        "forwarded"
    } else {
        "candidate"
    };
    let sink = sink_statement(spec.family, sink_value);
    let barrier = control.then(|| barrier_statement(spec.family, sink_value));
    let signature = if spec.framework == Framework::ServerActions {
        format!("export async function {function}(formData) {{")
    } else {
        format!("export async function {function}({parameter}) {{")
    };

    let mut files = BTreeMap::new();
    let mut propagation = Vec::new();
    match spec.topology {
        Topology::Direct => {
            let barrier_line = barrier
                .as_ref()
                .map(|line| format!("  {line}\n"))
                .unwrap_or_default();
            let text = format!(
                "{}\n{signature}\n{source_line}\n{view}{barrier_line}  {sink}\n}}\n",
                prelude(spec.family).trim_end()
            );
            files.insert(entry_path.clone(), text.into_bytes());
        }
        Topology::HelperMediated => {
            let call = format!("return {consume}(candidate);");
            let barrier_line = barrier
                .as_ref()
                .map(|line| format!("  {line}\n"))
                .unwrap_or_default();
            let text = format!(
                "{}\n{signature}\n{source_line}\n{view}  {call}\n}}\n\nasync function {consume}(candidate) {{\n{barrier_line}  {sink}\n}}\n",
                prelude(spec.family).trim_end()
            );
            propagation.push((entry_path.clone(), call));
            files.insert(entry_path.clone(), text.into_bytes());
        }
        Topology::InterFileAliased => {
            let entry = format!(
                "import {{ {consume} as dispatch }} from \"./case-{label}-boundary.{extension}\";\n\n{signature}\n{source_line}\n{view}  return dispatch(candidate);\n}}\n"
            );
            let barrier_line = barrier
                .as_ref()
                .map(|line| format!("  {line}\n"))
                .unwrap_or_default();
            let boundary = format!(
                "{}\nexport async function {consume}(candidate) {{\n{barrier_line}  {sink}\n}}\n",
                prelude(spec.family).trim_end()
            );
            propagation.push((entry_path.clone(), "return dispatch(candidate);".to_owned()));
            files.insert(entry_path.clone(), entry.into_bytes());
            files.insert(boundary_path.clone(), boundary.into_bytes());
        }
        Topology::ControlFlowSensitive => {
            let forward = "const forwarded = candidate;".to_owned();
            let barrier_line = barrier
                .as_ref()
                .map(|line| format!("  {line}\n"))
                .unwrap_or_default();
            let text = format!(
                "{}\n{signature}\n{source_line}\n{view}  if (candidate === null) {{ return; }}\n  {forward}\n{barrier_line}  {sink}\n}}\n",
                prelude(spec.family).trim_end()
            );
            propagation.push((entry_path.clone(), forward));
            files.insert(entry_path.clone(), text.into_bytes());
        }
    }

    RenderedCase {
        files,
        source_file: entry_path,
        source_needle: source.to_owned(),
        sink_file: if spec.topology == Topology::InterFileAliased {
            boundary_path
        } else {
            format!("{pair_root}/case-{label}.{extension}")
        },
        sink_needle: sink,
        propagation,
        barrier: barrier.map(|line| {
            let file = if spec.topology == Topology::InterFileAliased {
                format!("{pair_root}/case-{label}-boundary.{extension}")
            } else {
                format!("{pair_root}/case-{label}.{extension}")
            };
            (file, line)
        }),
    }
}

fn locate(
    files: &BTreeMap<String, Vec<u8>>,
    file: &str,
    needle: &str,
) -> Result<SourceSpan, Phase12Error> {
    let bytes = files.get(file).ok_or_else(|| {
        Phase12Error::InvalidRegression(format!("missing rendered file `{file}`"))
    })?;
    let text = std::str::from_utf8(bytes)
        .map_err(|_| Phase12Error::InvalidRegression(format!("fixture `{file}` is not UTF-8")))?;
    let offset = text.find(needle).ok_or_else(|| {
        Phase12Error::InvalidRegression(format!("`{needle}` is absent from `{file}`"))
    })?;
    if text[offset + needle.len()..].contains(needle) {
        return Err(Phase12Error::InvalidRegression(format!(
            "`{needle}` is not unique in `{file}`"
        )));
    }
    let prefix = &text[..offset];
    let start_line = u32::try_from(prefix.bytes().filter(|byte| *byte == b'\n').count() + 1)
        .map_err(|_| Phase12Error::InvalidRegression("line number overflow".to_owned()))?;
    let line_start = prefix.rfind('\n').map_or(0, |position| position + 1);
    let start_column = u32::try_from(offset - line_start + 1)
        .map_err(|_| Phase12Error::InvalidRegression("column number overflow".to_owned()))?;
    let end_column = start_column
        .checked_add(
            u32::try_from(needle.len())
                .map_err(|_| Phase12Error::InvalidRegression("span length overflow".to_owned()))?,
        )
        .ok_or_else(|| Phase12Error::InvalidRegression("column number overflow".to_owned()))?;
    Ok(SourceSpan {
        file: file.to_owned(),
        start_line,
        start_column,
        end_line: start_line,
        end_column,
    })
}

fn aggregate_files(files: &[FixtureFile]) -> String {
    let mut bytes = Vec::new();
    for file in files {
        bytes.extend_from_slice(file.path.as_bytes());
        bytes.push(0);
        bytes.extend_from_slice(file.sha256.as_bytes());
        bytes.push(b'\n');
    }
    sha256(&bytes)
}

fn taxonomy_coordinate(
    taxonomy: &FrozenTaxonomy,
    spec: PairSpec,
) -> Result<TaxonomyCoordinate, Phase12Error> {
    let category = taxonomy
        .categories
        .iter()
        .find(|category| category.category_id == spec.family.category_id)
        .ok_or_else(|| {
            Phase12Error::InvalidRegression(format!(
                "{} is absent from the frozen taxonomy",
                spec.family.category_id
            ))
        })?;
    Ok(TaxonomyCoordinate {
        taxonomy_version: taxonomy.taxonomy_version.clone(),
        category_id: category.category_id.clone(),
        invariant_id: category.invariant_id.clone(),
        primary_cwe: category.primary_cwe.id.clone(),
    })
}

fn role_for_barrier(family: FamilySpec) -> EvidenceRoleV2 {
    if family.family_id == "SE1001" {
        EvidenceRoleV2::Authorization
    } else if matches!(family.family_id, "SE1002" | "SE1003" | "SE1007") {
        EvidenceRoleV2::Sanitizer
    } else {
        EvidenceRoleV2::Guard
    }
}

fn case_contract(
    spec: PairSpec,
    label: &str,
    control: bool,
    rendered: &RenderedCase,
    taxonomy: &FrozenTaxonomy,
) -> Result<RegressionCase, Phase12Error> {
    let value_id = format!("pair-{:03}-value", spec.ordinal);
    let (_, source_kind, _) = source_expression(spec.framework, spec.family);
    let mut path = vec![RegressionPathNode {
        role: EvidenceRoleV2::Source,
        effect: EvidenceEffectV2::PreservesInfluence,
        value_id: value_id.clone(),
        source_kind: Some(source_kind),
        sink_kind: None,
        span: locate(
            &rendered.files,
            &rendered.source_file,
            &rendered.source_needle,
        )?,
    }];
    for (file, needle) in &rendered.propagation {
        path.push(RegressionPathNode {
            role: EvidenceRoleV2::Propagation,
            effect: EvidenceEffectV2::PreservesInfluence,
            value_id: value_id.clone(),
            source_kind: None,
            sink_kind: None,
            span: locate(&rendered.files, file, needle)?,
        });
    }
    let barriers = if let Some((file, needle)) = &rendered.barrier {
        let span = locate(&rendered.files, file, needle)?;
        path.push(RegressionPathNode {
            role: role_for_barrier(spec.family),
            effect: spec.family.barrier_effect,
            value_id: value_id.clone(),
            source_kind: None,
            sink_kind: None,
            span: span.clone(),
        });
        vec![BarrierContract {
            effect: spec.family.barrier_effect,
            value_id: value_id.clone(),
            terminating: true,
            dominates_sink: true,
            span,
        }]
    } else {
        Vec::new()
    };
    path.push(RegressionPathNode {
        role: EvidenceRoleV2::Sink,
        effect: EvidenceEffectV2::PreservesInfluence,
        value_id,
        source_kind: None,
        sink_kind: Some(spec.family.sink_kind),
        span: locate(&rendered.files, &rendered.sink_file, &rendered.sink_needle)?,
    });
    let files = rendered
        .files
        .iter()
        .map(|(path, bytes)| FixtureFile {
            path: path.clone(),
            sha256: sha256(bytes),
        })
        .collect::<Vec<_>>();
    Ok(RegressionCase {
        case_id: format!("phase12-case-{:03}-{label}", spec.ordinal),
        kind: if control {
            CaseKind::ContractSafeControl
        } else {
            CaseKind::ContractVulnerable
        },
        taxonomy: taxonomy_coordinate(taxonomy, spec)?,
        connected_edges: vec![true; path.len().saturating_sub(1)],
        effective_barriers: barriers,
        case_sha256: aggregate_files(&files),
        files,
        path,
    })
}

fn increment<T: Serialize + Copy>(
    map: &mut BTreeMap<String, u64>,
    value: T,
) -> Result<(), Phase12Error> {
    *map.entry(enum_name(value)?).or_default() += 1;
    Ok(())
}

/// Builds the deterministic public regression manifest and source file set in memory.
///
/// # Errors
///
/// Returns an error if the frozen taxonomy is incomplete or a generated semantic span cannot be
/// established exactly.
pub fn build_regression(
    taxonomy: &FrozenTaxonomy,
    taxonomy_sha256: String,
    evidence_contract_sha256: String,
) -> Result<(RegressionManifest, BTreeMap<String, Vec<u8>>), Phase12Error> {
    let mut pairs = Vec::new();
    let mut all_files = BTreeMap::new();
    let mut coverage = CoverageSummary {
        families: BTreeMap::new(),
        frameworks: BTreeMap::new(),
        languages: BTreeMap::new(),
        topologies: BTreeMap::new(),
    };
    for spec in assignments() {
        let vulnerable_render = render_case(spec, "a", false);
        let control_render = render_case(spec, "b", true);
        let vulnerable = case_contract(spec, "a", false, &vulnerable_render, taxonomy)?;
        let control = case_contract(spec, "b", true, &control_render, taxonomy)?;
        for (path, bytes) in vulnerable_render
            .files
            .into_iter()
            .chain(control_render.files)
        {
            if all_files.insert(path.clone(), bytes).is_some() {
                return Err(Phase12Error::InvalidRegression(format!(
                    "duplicate generated fixture path `{path}`"
                )));
            }
        }
        *coverage
            .families
            .entry(spec.family.family_id.to_owned())
            .or_default() += 1;
        increment(&mut coverage.frameworks, spec.framework)?;
        increment(&mut coverage.languages, spec.language)?;
        increment(&mut coverage.topologies, spec.topology)?;
        pairs.push(RegressionPair {
            pair_id: format!("phase12-pair-{:03}", spec.ordinal),
            family_id: spec.family.family_id.to_owned(),
            framework: spec.framework,
            language: spec.language,
            topology: spec.topology,
            mutation: MutationContract {
                forward: "Insert the family-specific terminating barrier over the same concrete value before the sensitive sink.".to_owned(),
                inverse: "Remove only that barrier and restore the original connected vulnerable flow.".to_owned(),
                inverse_restores_sha256: vulnerable.case_sha256.clone(),
                forward_produces_sha256: control.case_sha256.clone(),
            },
            vulnerable,
            control,
        });
    }
    let manifest = RegressionManifest {
        schema_version: REGRESSION_SCHEMA.to_owned(),
        benchmark_version: "0.2.0".to_owned(),
        corpus_id: REGRESSION_ID.to_owned(),
        disclosed_development_material: true,
        unseen_holdout: false,
        taxonomy_sha256,
        evidence_contract_sha256,
        pairs,
        coverage,
        provenance: "Original synthetic Secure Bench material, generated deterministically under Apache-2.0 for disclosed development regression and contract conformance only.".to_owned(),
    };
    validate_regression(&manifest, &all_files, taxonomy)?;
    Ok((manifest, all_files))
}

fn category<'a>(taxonomy: &'a FrozenTaxonomy, id: &str) -> Option<&'a TaxonomyCategory> {
    taxonomy
        .categories
        .iter()
        .find(|category| category.category_id == id)
}

fn span_text<'a>(
    span: &SourceSpan,
    files: &'a BTreeMap<String, Vec<u8>>,
) -> Result<&'a str, Phase12Error> {
    let text = std::str::from_utf8(
        files
            .get(&span.file)
            .ok_or_else(|| Phase12Error::InvalidRegression(format!("missing `{}`", span.file)))?,
    )
    .map_err(|_| Phase12Error::InvalidRegression(format!("`{}` is not UTF-8", span.file)))?;
    if span.start_line != span.end_line || span.start_line == 0 || span.start_column == 0 {
        return Err(Phase12Error::InvalidRegression(
            "regression spans must be one-line spans".to_owned(),
        ));
    }
    let line_index = usize::try_from(span.start_line - 1)
        .map_err(|_| Phase12Error::InvalidRegression("line index overflow".to_owned()))?;
    let line = text.lines().nth(line_index).ok_or_else(|| {
        Phase12Error::InvalidRegression(format!("span is outside `{}`", span.file))
    })?;
    let start = usize::try_from(span.start_column - 1)
        .map_err(|_| Phase12Error::InvalidRegression("column index overflow".to_owned()))?;
    let end = usize::try_from(span.end_column - 1)
        .map_err(|_| Phase12Error::InvalidRegression("column index overflow".to_owned()))?;
    line.get(start..end).ok_or_else(|| {
        Phase12Error::InvalidRegression(format!("span columns are outside `{}`", span.file))
    })
}

#[allow(clippy::too_many_lines)]
fn validate_case(
    case: &RegressionCase,
    expected_kind: CaseKind,
    pair: &RegressionPair,
    files: &BTreeMap<String, Vec<u8>>,
    taxonomy: &FrozenTaxonomy,
) -> Result<(), Phase12Error> {
    if case.kind != expected_kind
        || case.path.len() < 2
        || case.connected_edges.len() != case.path.len() - 1
        || case.connected_edges.iter().any(|connected| !connected)
        || case.path.first().map(|node| node.role) != Some(EvidenceRoleV2::Source)
        || case.path.last().map(|node| node.role) != Some(EvidenceRoleV2::Sink)
    {
        return Err(Phase12Error::InvalidRegression(format!(
            "{} is not a complete connected source-to-sink contract",
            case.case_id
        )));
    }
    let values = case
        .path
        .iter()
        .map(|node| &node.value_id)
        .collect::<BTreeSet<_>>();
    if values.len() != 1 || values.iter().any(|value| value.is_empty()) {
        return Err(Phase12Error::InvalidRegression(format!(
            "{} does not preserve one concrete value identity",
            case.case_id
        )));
    }
    let taxonomy_category = category(taxonomy, &case.taxonomy.category_id).ok_or_else(|| {
        Phase12Error::InvalidRegression(format!(
            "{} has an unknown taxonomy category",
            case.case_id
        ))
    })?;
    if case.taxonomy.taxonomy_version != taxonomy.taxonomy_version
        || case.taxonomy.category_id != pair.vulnerable.taxonomy.category_id
        || case.taxonomy.invariant_id != taxonomy_category.invariant_id
        || case.taxonomy.primary_cwe != taxonomy_category.primary_cwe.id
    {
        return Err(Phase12Error::InvalidRegression(format!(
            "{} drifted from the frozen canonical taxonomy",
            case.case_id
        )));
    }
    for file in &case.files {
        let bytes = files.get(&file.path).ok_or_else(|| {
            Phase12Error::InvalidRegression(format!("{} references a missing file", case.case_id))
        })?;
        if sha256(bytes) != file.sha256 {
            return Err(Phase12Error::InvalidRegression(format!(
                "{} fixture hash differs",
                case.case_id
            )));
        }
    }
    if aggregate_files(&case.files) != case.case_sha256 {
        return Err(Phase12Error::InvalidRegression(format!(
            "{} aggregate fingerprint differs",
            case.case_id
        )));
    }
    let source = span_text(&case.path[0].span, files)?;
    let sink = span_text(&case.path[case.path.len() - 1].span, files)?;
    if !source.contains("candidate") && !source.contains("request") && !source.contains("formData")
    {
        return Err(Phase12Error::InvalidRegression(format!(
            "{} source span is disconnected",
            case.case_id
        )));
    }
    if !sink.contains("candidate") && !sink.contains("forwarded") {
        return Err(Phase12Error::InvalidRegression(format!(
            "{} sink does not consume the connected value",
            case.case_id
        )));
    }
    if pair.topology == Topology::Direct && (source == "value" || sink.contains("(value)")) {
        return Err(Phase12Error::InvalidRegression(format!(
            "{} repeats the historical disconnected direct-flow defect",
            case.case_id
        )));
    }
    match expected_kind {
        CaseKind::ContractVulnerable if !case.effective_barriers.is_empty() => {
            return Err(Phase12Error::InvalidRegression(format!(
                "{} unexpectedly contains an effective barrier",
                case.case_id
            )));
        }
        CaseKind::ContractSafeControl => {
            if case.effective_barriers.len() != 1 {
                return Err(Phase12Error::InvalidRegression(format!(
                    "{} must contain exactly one effective barrier",
                    case.case_id
                )));
            }
            let barrier = &case.effective_barriers[0];
            if !barrier.terminating
                || !barrier.dominates_sink
                || barrier.value_id != case.path[0].value_id
                || barrier.effect != pair.control.path[pair.control.path.len() - 2].effect
            {
                return Err(Phase12Error::InvalidRegression(format!(
                    "{} barrier does not protect the same value and dominate the sink",
                    case.case_id
                )));
            }
            let barrier_text = span_text(&barrier.span, files)?;
            let protected_name = if sink.contains("forwarded") {
                "forwarded"
            } else {
                "candidate"
            };
            if !barrier_text.contains(protected_name) || !barrier_text.contains("return;") {
                return Err(Phase12Error::InvalidRegression(format!(
                    "{} barrier protects another value or does not terminate",
                    case.case_id
                )));
            }
        }
        CaseKind::ContractVulnerable => {}
    }
    Ok(())
}

/// Validates taxonomy binding, connected paths, value identity, barriers, duplicates, balance,
/// mutation inverses, source spans, and answer leakage for the public regression corpus.
///
/// # Errors
///
/// Returns an error when any prospective corpus contract differs.
pub fn validate_regression(
    manifest: &RegressionManifest,
    files: &BTreeMap<String, Vec<u8>>,
    taxonomy: &FrozenTaxonomy,
) -> Result<(), Phase12Error> {
    if manifest.schema_version != REGRESSION_SCHEMA
        || manifest.benchmark_version != "0.2.0"
        || manifest.corpus_id != REGRESSION_ID
        || !manifest.disclosed_development_material
        || manifest.unseen_holdout
        || manifest.pairs.len() != 28
    {
        return Err(Phase12Error::InvalidRegression(
            "public regression identity, disclosure, or population differs".to_owned(),
        ));
    }
    let mut pair_ids = BTreeSet::new();
    let mut case_ids = BTreeSet::new();
    let mut case_hashes = BTreeSet::new();
    for pair in &manifest.pairs {
        if !pair_ids.insert(&pair.pair_id)
            || !case_ids.insert(&pair.vulnerable.case_id)
            || !case_ids.insert(&pair.control.case_id)
            || !case_hashes.insert(&pair.vulnerable.case_sha256)
            || !case_hashes.insert(&pair.control.case_sha256)
            || pair.mutation.inverse_restores_sha256 != pair.vulnerable.case_sha256
            || pair.mutation.forward_produces_sha256 != pair.control.case_sha256
            || pair.vulnerable.taxonomy != pair.control.taxonomy
        {
            return Err(Phase12Error::InvalidRegression(format!(
                "{} has duplicate identities, taxonomy drift, or a broken inverse",
                pair.pair_id
            )));
        }
        validate_case(
            &pair.vulnerable,
            CaseKind::ContractVulnerable,
            pair,
            files,
            taxonomy,
        )?;
        validate_case(
            &pair.control,
            CaseKind::ContractSafeControl,
            pair,
            files,
            taxonomy,
        )?;
    }
    if manifest.coverage.families.len() != 7
        || manifest.coverage.families.values().any(|count| *count != 4)
        || manifest.coverage.frameworks.len() != 4
        || manifest
            .coverage
            .frameworks
            .values()
            .any(|count| *count != 7)
        || manifest.coverage.languages.len() != 4
        || manifest
            .coverage
            .languages
            .values()
            .any(|count| *count != 7)
        || manifest.coverage.topologies.len() != 4
        || manifest
            .coverage
            .topologies
            .values()
            .any(|count| *count != 7)
    {
        return Err(Phase12Error::InvalidRegression(
            "public regression factor balance differs".to_owned(),
        ));
    }
    let forbidden = [
        "secure-bench",
        "se100",
        "cwe-",
        "expectation",
        "vulnerable",
        "safe_control",
        "contract_safe",
    ];
    for (path, bytes) in files {
        if path.starts_with('/') || path.contains("..") || path.contains('\\') {
            return Err(Phase12Error::InvalidRegression(format!(
                "fixture path `{path}` is not portable"
            )));
        }
        let lower = String::from_utf8_lossy(bytes).to_ascii_lowercase();
        if forbidden
            .iter()
            .any(|term| path.to_ascii_lowercase().contains(term) || lower.contains(term))
        {
            return Err(Phase12Error::InvalidRegression(format!(
                "fixture `{path}` leaks matcher-owned terminology"
            )));
        }
        if lower.contains("undefined") || lower.contains("othercandidate") {
            return Err(Phase12Error::InvalidRegression(format!(
                "fixture `{path}` contains an undefined or unrelated value"
            )));
        }
    }
    Ok(())
}

/// Serializes the public manifest in canonical pretty JSON form.
///
/// # Errors
///
/// Returns an error when serialization fails.
pub fn manifest_bytes(manifest: &RegressionManifest) -> Result<Vec<u8>, Phase12Error> {
    canonical_json(manifest)
}

#[cfg(test)]
pub(crate) fn mutate_control_barrier_value(manifest: &mut RegressionManifest) {
    if let Some(pair) = manifest.pairs.first_mut()
        && let Some(barrier) = pair.control.effective_barriers.first_mut()
    {
        barrier.value_id = "different-value".to_owned();
    }
}

#[cfg(test)]
pub(crate) fn mutate_taxonomy(manifest: &mut RegressionManifest) {
    if let Some(pair) = manifest.pairs.first_mut() {
        pair.vulnerable.taxonomy.invariant_id = "drifted-invariant".to_owned();
    }
}
