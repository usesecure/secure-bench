use crate::model::{Experiment, LedgerEntry, Observation, ResourceUsage};
use crate::{Phase23Error, canonical_json, collect_files, sha256, sha256_file, write_atomic};
use secure_bench_phase21::sandbox::{
    SEMGREP_SOURCE, Scanner, base_arguments, fixed_environment, scanner_command, scanner_sandbox,
};
use serde_json::{Value, json};
use std::fs::{self, File, OpenOptions};
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

const PHASE22: &str = "b8ef30bfcd9761644001b63ed9b9f717ebd09d93";
const RULESET: &str = "phase19/rules/capability-normalized-v1.yml";
const RULESET_SHA256: &str = "06af4cf6d10da30ad585d57b781cf6aef734add03b90ea36c78e920c4c10a07c";
const SEMGREP: &str = "/tmp/secure-bench-tools/semgrep/1.170.0/venv/bin/semgrep";
const SEMGREP_SHA256: &str = "0280e5c6cca8d8e4cb2c41858b06697b957daf23d718cac411999c4c515507e1";
const ZERO_HASH: &str = "0000000000000000000000000000000000000000000000000000000000000000";

fn experiment(
    sequence: u64,
    id: &str,
    control: Option<&str>,
    changed_variable: &str,
    target_count: u64,
    jobs: Option<u64>,
    address_space_bytes: Option<u64>,
    process_limit: Option<u64>,
    open_files_limit: Option<u64>,
    stack_bytes: Option<u64>,
) -> Experiment {
    Experiment {
        sequence,
        id: id.to_owned(),
        control: control.map(str::to_owned),
        changed_variable: changed_variable.to_owned(),
        target_count,
        jobs,
        address_space_bytes,
        process_limit,
        open_files_limit,
        stack_bytes,
        pid_namespace: true,
        full_profile: true,
    }
}

fn diagnostic_plan() -> Vec<Experiment> {
    let as4 = Some(4_294_967_296);
    let nproc64 = Some(64);
    vec![
        experiment(
            1,
            "baseline-16-auto",
            None,
            "control",
            16,
            None,
            as4,
            nproc64,
            None,
            None,
        ),
        experiment(
            2,
            "targets-8-auto",
            Some("baseline-16-auto"),
            "target-count=8",
            8,
            None,
            as4,
            nproc64,
            None,
            None,
        ),
        experiment(
            3,
            "targets-4-auto",
            Some("baseline-16-auto"),
            "target-count=4",
            4,
            None,
            as4,
            nproc64,
            None,
            None,
        ),
        experiment(
            4,
            "targets-2-auto",
            Some("baseline-16-auto"),
            "target-count=2",
            2,
            None,
            as4,
            nproc64,
            None,
            None,
        ),
        experiment(
            5,
            "targets-1-auto",
            Some("baseline-16-auto"),
            "target-count=1",
            1,
            None,
            as4,
            nproc64,
            None,
            None,
        ),
        experiment(
            6,
            "jobs-1",
            Some("baseline-16-auto"),
            "jobs=1",
            16,
            Some(1),
            as4,
            nproc64,
            None,
            None,
        ),
        experiment(
            7,
            "jobs-2",
            Some("baseline-16-auto"),
            "jobs=2",
            16,
            Some(2),
            as4,
            nproc64,
            None,
            None,
        ),
        experiment(
            8,
            "jobs-4",
            Some("baseline-16-auto"),
            "jobs=4",
            16,
            Some(4),
            as4,
            nproc64,
            None,
            None,
        ),
        experiment(
            9,
            "jobs-8",
            Some("baseline-16-auto"),
            "jobs=8",
            16,
            Some(8),
            as4,
            nproc64,
            None,
            None,
        ),
        experiment(
            10,
            "jobs-16",
            Some("baseline-16-auto"),
            "jobs=16",
            16,
            Some(16),
            as4,
            nproc64,
            None,
            None,
        ),
        experiment(
            11,
            "no-process-limit",
            Some("baseline-16-auto"),
            "process-limit=unlimited",
            16,
            None,
            as4,
            None,
            None,
            None,
        ),
        experiment(
            12,
            "process-limit-128",
            Some("baseline-16-auto"),
            "process-limit=128",
            16,
            None,
            as4,
            Some(128),
            None,
            None,
        ),
        experiment(
            13,
            "no-address-space-limit",
            Some("baseline-16-auto"),
            "address-space=unlimited",
            16,
            None,
            None,
            nproc64,
            None,
            None,
        ),
        experiment(
            14,
            "address-space-8g",
            Some("baseline-16-auto"),
            "address-space=8GiB",
            16,
            None,
            Some(8_589_934_592),
            nproc64,
            None,
            None,
        ),
        experiment(
            15,
            "open-files-64",
            Some("baseline-16-auto"),
            "open-files=64",
            16,
            None,
            as4,
            nproc64,
            Some(64),
            None,
        ),
        experiment(
            16,
            "stack-64m",
            Some("baseline-16-auto"),
            "stack=64MiB",
            16,
            None,
            as4,
            nproc64,
            None,
            Some(67_108_864),
        ),
    ]
}

fn threshold_plan() -> Vec<Experiment> {
    let as4 = Some(4_294_967_296);
    let nproc64 = Some(64);
    let control = Some("diagnostic/baseline-16-auto");
    vec![
        experiment(
            1,
            "stack-8m",
            control,
            "stack=8MiB",
            16,
            None,
            as4,
            nproc64,
            None,
            Some(8_388_608),
        ),
        experiment(
            2,
            "stack-16m",
            control,
            "stack=16MiB",
            16,
            None,
            as4,
            nproc64,
            None,
            Some(16_777_216),
        ),
        experiment(
            3,
            "stack-32m",
            control,
            "stack=32MiB",
            16,
            None,
            as4,
            nproc64,
            None,
            Some(33_554_432),
        ),
        experiment(
            4,
            "stack-64m-confirm",
            control,
            "stack=64MiB",
            16,
            None,
            as4,
            nproc64,
            None,
            Some(67_108_864),
        ),
        experiment(
            5,
            "stack-128m",
            control,
            "stack=128MiB",
            16,
            None,
            as4,
            nproc64,
            None,
            Some(134_217_728),
        ),
        experiment(
            6,
            "stack-256m",
            control,
            "stack=256MiB",
            16,
            None,
            as4,
            nproc64,
            None,
            Some(268_435_456),
        ),
        experiment(
            7,
            "stack-512m",
            control,
            "stack=512MiB",
            16,
            None,
            as4,
            nproc64,
            None,
            Some(536_870_912),
        ),
        experiment(
            8,
            "stack-1g",
            control,
            "stack=1GiB",
            16,
            None,
            as4,
            nproc64,
            None,
            Some(1_073_741_824),
        ),
        experiment(
            9,
            "address-space-16g",
            control,
            "address-space=16GiB",
            16,
            None,
            Some(17_179_869_184),
            nproc64,
            None,
            None,
        ),
        experiment(
            10,
            "address-space-32g",
            control,
            "address-space=32GiB",
            16,
            None,
            Some(34_359_738_368),
            nproc64,
            None,
            None,
        ),
        experiment(
            11,
            "jobs-3",
            control,
            "jobs=3",
            16,
            Some(3),
            as4,
            nproc64,
            None,
            None,
        ),
        experiment(
            12,
            "jobs-2-confirm",
            control,
            "jobs=2",
            16,
            Some(2),
            as4,
            nproc64,
            None,
            None,
        ),
    ]
}

fn prepare_input(directory: &Path, targets: u64) -> Result<PathBuf, Phase23Error> {
    let input = directory.join("input");
    fs::create_dir_all(&input)?;
    for index in 1..=targets {
        let body = if index % 2 == 0 {
            "// Phase 23 original synthetic fixture; never sourced from a holdout.\nexport function execute(command, exec) {\n  return exec(command);\n}\n"
        } else {
            "// Phase 23 original synthetic fixture; never sourced from a holdout.\nexport function evaluate(input) {\n  return (0, eval)(input);\n}\n"
        };
        write_atomic(&input.join(format!("app-{index:02}.js")), body.as_bytes())?;
    }
    Ok(input)
}

fn command_for(experiment: &Experiment) -> Vec<String> {
    let mut command = scanner_command(Scanner::Semgrep);
    if let Some(jobs) = experiment.jobs {
        command.insert(8, format!("--jobs={jobs}"));
    }
    command
}

fn append_limit(arguments: &mut Vec<String>, name: &str, value: Option<u64>) {
    if let Some(value) = value {
        arguments.push(format!("--{name}={value}"));
    }
}

fn sandbox_arguments(
    root: &Path,
    experiment: &Experiment,
    input: &Path,
    directory: &Path,
) -> Vec<String> {
    let mut arguments = scanner_sandbox(
        Scanner::Semgrep,
        true,
        input,
        &root.join(RULESET),
        directory,
    );
    arguments.extend([
        "--".to_owned(),
        "/usr/bin/time".to_owned(),
        "--verbose".to_owned(),
        "--output=/tmp/run/resource.txt".to_owned(),
        "--".to_owned(),
        "/usr/bin/prlimit".to_owned(),
    ]);
    append_limit(&mut arguments, "as", experiment.address_space_bytes);
    append_limit(&mut arguments, "nproc", experiment.process_limit);
    append_limit(&mut arguments, "nofile", experiment.open_files_limit);
    append_limit(&mut arguments, "stack", experiment.stack_bytes);
    arguments.push("--".to_owned());
    arguments.extend(command_for(experiment));
    arguments
}

struct ProcessEvidence {
    exit_code: Option<i32>,
    timed_out: bool,
    duration_ms: u64,
    stdout: Vec<u8>,
    stderr: Vec<u8>,
    raw: Option<Vec<u8>>,
    resource: Vec<u8>,
}

fn run_process(arguments: &[String], directory: &Path) -> Result<ProcessEvidence, Phase23Error> {
    run_process_with_timeout(arguments, directory, Duration::from_secs(60))
}

fn run_process_with_timeout(
    arguments: &[String],
    directory: &Path,
    timeout: Duration,
) -> Result<ProcessEvidence, Phase23Error> {
    let stdout_path = directory.join("stdout.bin");
    let stderr_path = directory.join("stderr.bin");
    let stdout = File::create(&stdout_path)?;
    let stderr = File::create(&stderr_path)?;
    let started = Instant::now();
    let mut child = Command::new("/usr/bin/bwrap")
        .args(arguments)
        .env_clear()
        .env("LANG", "C.UTF-8")
        .env("LC_ALL", "C.UTF-8")
        .env("PATH", "/usr/bin:/bin")
        .env("TZ", "UTC")
        .stdin(Stdio::null())
        .stdout(Stdio::from(stdout))
        .stderr(Stdio::from(stderr))
        .spawn()?;
    let mut timed_out = false;
    let status = loop {
        if let Some(status) = child.try_wait()? {
            break status;
        }
        if started.elapsed() >= timeout {
            child.kill()?;
            timed_out = true;
            break child.wait()?;
        }
        thread::sleep(Duration::from_millis(10));
    };
    let raw_path = directory.join("raw.json");
    let resource_path = directory.join("resource.txt");
    Ok(ProcessEvidence {
        exit_code: status.code(),
        timed_out,
        duration_ms: u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX),
        stdout: fs::read(stdout_path)?,
        stderr: fs::read(stderr_path)?,
        raw: raw_path.exists().then(|| fs::read(raw_path)).transpose()?,
        resource: if resource_path.exists() {
            fs::read(resource_path)?
        } else {
            Vec::new()
        },
    })
}

fn resource_value(text: &str, label: &str) -> Option<u64> {
    text.lines().find_map(|line| {
        let (key, value) = line.trim().split_once(':')?;
        (key == label).then(|| value.trim().parse().ok()).flatten()
    })
}

fn resources(bytes: &[u8]) -> ResourceUsage {
    let text = String::from_utf8_lossy(bytes);
    ResourceUsage {
        maximum_resident_kib: resource_value(&text, "Maximum resident set size (kbytes)"),
        minor_page_faults: resource_value(&text, "Minor (reclaiming a frame) page faults"),
        major_page_faults: resource_value(&text, "Major (requiring I/O) page faults"),
        voluntary_context_switches: resource_value(&text, "Voluntary context switches"),
        involuntary_context_switches: resource_value(&text, "Involuntary context switches"),
    }
}

fn raw_has_segmentation_fault(raw: Option<&[u8]>, stderr: &[u8]) -> bool {
    let raw_text = raw.map_or_else(String::new, |bytes| {
        String::from_utf8_lossy(bytes).into_owned()
    });
    let stderr_text = String::from_utf8_lossy(stderr);
    [raw_text.as_str(), stderr_text.as_ref()]
        .iter()
        .any(|text| {
            text.contains("Segmentation fault")
                || text.contains("received signal")
                || text.contains("signal 11")
        })
}

fn terminal_stage(raw: Option<&[u8]>, timed_out: bool, segmentation_fault: bool) -> String {
    if timed_out {
        return "external-watchdog".to_owned();
    }
    if segmentation_fault {
        return "semgrep-core".to_owned();
    }
    let Some(raw) = raw else {
        return "python-startup-or-core-launch".to_owned();
    };
    let Ok(value) = serde_json::from_slice::<Value>(raw) else {
        return "json-write".to_owned();
    };
    if value
        .get("errors")
        .and_then(Value::as_array)
        .is_some_and(Vec::is_empty)
    {
        "completed-json-and-cleanup".to_owned()
    } else {
        "scanner-error-json".to_owned()
    }
}

fn relative_attempt(experiment: &Experiment) -> String {
    format!(
        "phase23/output/diagnostic/attempts/{:02}-{}",
        experiment.sequence, experiment.id
    )
}

fn observe(root: &Path, experiment: &Experiment) -> Result<Observation, Phase23Error> {
    let relative = relative_attempt(experiment);
    let directory = root.join(&relative);
    fs::create_dir_all(&directory)?;
    let input = prepare_input(&directory, experiment.target_count)?;
    let arguments = sandbox_arguments(root, experiment, &input, &directory);
    if arguments
        .iter()
        .any(|argument| argument.contains("holdout"))
    {
        return Err(Phase23Error::Contract(
            "diagnostic command references a holdout path".to_owned(),
        ));
    }
    let command = std::iter::once("/usr/bin/bwrap".to_owned())
        .chain(arguments.iter().cloned())
        .collect::<Vec<_>>();
    let evidence = run_process(&arguments, &directory)?;
    let segmentation_fault = raw_has_segmentation_fault(evidence.raw.as_deref(), &evidence.stderr);
    let stage = terminal_stage(
        evidence.raw.as_deref(),
        evidence.timed_out,
        segmentation_fault,
    );
    let raw_output_path = evidence
        .raw
        .as_ref()
        .map(|_| format!("{relative}/raw.json"));
    let raw_output_sha256 = evidence.raw.as_deref().map(sha256);
    let observation = Observation {
        experiment: experiment.clone(),
        command_sha256: sha256(&canonical_json(&command)?),
        command,
        environment: fixed_environment(),
        exit_code: evidence.exit_code,
        timed_out: evidence.timed_out,
        duration_ms: evidence.duration_ms,
        segmentation_fault,
        terminal_stage: stage,
        stdout_path: format!("{relative}/stdout.bin"),
        stdout_sha256: sha256(&evidence.stdout),
        stderr_path: format!("{relative}/stderr.bin"),
        stderr_sha256: sha256(&evidence.stderr),
        raw_output_path,
        raw_output_sha256,
        resource_path: format!("{relative}/resource.txt"),
        resource_sha256: sha256(&evidence.resource),
        resources: resources(&evidence.resource),
    };
    write_atomic(
        &directory.join("observation.json"),
        &canonical_json(&observation)?,
    )?;
    Ok(observation)
}

fn append_ledger<T: serde::Serialize>(
    ledger: &Path,
    sequence: u64,
    previous: &str,
    observation: &T,
    event: &str,
) -> Result<String, Phase23Error> {
    let payload_sha256 = sha256(&canonical_json(observation)?);
    let projection = json!({
        "schema_version": "secure-bench-phase23-diagnostic-ledger-v1",
        "sequence": sequence,
        "event": event,
        "payload_sha256": payload_sha256,
        "previous_entry_hash": previous,
    });
    let entry_hash = sha256(&canonical_json(&projection)?);
    let entry = LedgerEntry {
        schema_version: "secure-bench-phase23-diagnostic-ledger-v1".to_owned(),
        sequence,
        event: event.to_owned(),
        payload_sha256,
        previous_entry_hash: previous.to_owned(),
        entry_hash: entry_hash.clone(),
    };
    let mut file = OpenOptions::new().create(true).append(true).open(ledger)?;
    file.write_all(&canonical_json(&entry)?)?;
    file.sync_all()?;
    Ok(entry_hash)
}

fn write_sha256s(output: &Path) -> Result<(), Phase23Error> {
    let mut files = Vec::new();
    collect_files(output, &mut files)?;
    files.retain(|path| path.file_name().and_then(|name| name.to_str()) != Some("SHA256SUMS"));
    files.sort();
    let mut sums = String::new();
    for file in files {
        let relative = file.strip_prefix(output).map_err(|_| {
            Phase23Error::Contract(format!("output escaped SHA root: {}", file.display()))
        })?;
        sums.push_str(&format!(
            "{}  {}\n",
            sha256_file(&file)?,
            relative.display()
        ));
    }
    write_atomic(&output.join("SHA256SUMS"), sums.as_bytes())
}

fn validate_frozen_inputs(root: &Path) -> Result<(), Phase23Error> {
    let head = Command::new("git")
        .args(["rev-parse", "HEAD"])
        .current_dir(root)
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .output()?;
    if !head.status.success() || String::from_utf8_lossy(&head.stdout).trim() != PHASE22 {
        return Err(Phase23Error::Contract(
            "diagnosis must start from the exact Phase 22 commit".to_owned(),
        ));
    }
    if sha256_file(&root.join(RULESET))? != RULESET_SHA256 {
        return Err(Phase23Error::Contract("frozen ruleset drift".to_owned()));
    }
    let actual_semgrep = sha256_file(Path::new(SEMGREP))?;
    if actual_semgrep != SEMGREP_SHA256 {
        return Err(Phase23Error::Contract(format!(
            "Semgrep entrypoint drift: expected {SEMGREP_SHA256}, got {actual_semgrep}"
        )));
    }
    Ok(())
}

fn execute_diagnostic_plan(
    root: &Path,
    output_name: &str,
    state: &str,
    plan: &[Experiment],
) -> Result<String, Phase23Error> {
    validate_frozen_inputs(root)?;
    let output = root.join("phase23/output").join(output_name);
    if output.exists() {
        return Err(Phase23Error::Execution(format!(
            "{output_name} evidence already exists; reruns are forbidden"
        )));
    }
    fs::create_dir_all(&output)?;
    write_atomic(&output.join("experiment-plan.json"), &canonical_json(plan)?)?;
    let ledger = output.join("ledger.jsonl");
    let mut previous = ZERO_HASH.to_owned();
    let mut observations = Vec::new();
    for experiment in plan {
        let observation = observe(root, experiment)?;
        previous = append_ledger(
            &ledger,
            experiment.sequence,
            &previous,
            &observation,
            "synthetic-semgrep-diagnostic-completed",
        )?;
        observations.push(observation);
    }
    let summary = json!({
        "schema_version": "secure-bench-phase23-diagnosis-v1",
        "state": state,
        "scope": "new Phase 23 synthetic fixtures only",
        "phase22_commit": PHASE22,
        "semgrep_version": "1.170.0",
        "ruleset_sha256": RULESET_SHA256,
        "synthetic_semgrep_executions": observations.len(),
        "holdout_accesses": 0,
        "network": false,
        "retries": 0,
        "ledger_head": previous,
        "segmentation_faults": observations.iter().filter(|value| value.segmentation_fault).count(),
        "observations": observations,
    });
    write_atomic(&output.join("diagnosis.json"), &canonical_json(&summary)?)?;
    write_sha256s(&output)?;
    Ok(serde_json::to_string(&json!({
        "state": state,
        "synthetic_semgrep_executions": plan.len(),
        "ledger_head": previous,
    }))?)
}

/// Executes the sealed synthetic diagnostic matrix exactly once.
pub fn diagnose(root: &Path) -> Result<String, Phase23Error> {
    execute_diagnostic_plan(
        root,
        "diagnostic",
        "diagnostic-matrix-completed",
        &diagnostic_plan(),
    )
}

/// Executes the sealed resource-threshold matrix exactly once.
pub fn diagnose_thresholds(root: &Path) -> Result<String, Phase23Error> {
    execute_diagnostic_plan(
        root,
        "thresholds",
        "resource-threshold-matrix-completed",
        &threshold_plan(),
    )
}

fn stack_probe_arguments(
    root: &Path,
    output: &Path,
    corrected: bool,
    venv_python: bool,
) -> Vec<String> {
    let mut arguments = base_arguments(true);
    arguments.extend([
        "--dir".to_owned(),
        "/tmp/secure-bench-tools/semgrep".to_owned(),
        "--dir".to_owned(),
        "/tmp/secure-bench-tools/semgrep/1.170.0".to_owned(),
        "--ro-bind".to_owned(),
        SEMGREP_SOURCE.to_owned(),
        "/tmp/secure-bench-tools/semgrep/1.170.0".to_owned(),
        "--ro-bind".to_owned(),
        root.join("phase23/reproducer/stack_limit_probe.py")
            .to_string_lossy()
            .into_owned(),
        "/tmp/probe.py".to_owned(),
        "--bind".to_owned(),
        output.to_string_lossy().into_owned(),
        "/tmp/run".to_owned(),
        "--clearenv".to_owned(),
    ]);
    for entry in fixed_environment() {
        let (name, value) = entry.split_once('=').unwrap_or((entry.as_str(), ""));
        arguments.extend(["--setenv".to_owned(), name.to_owned(), value.to_owned()]);
    }
    arguments.extend([
        "--".to_owned(),
        "/usr/bin/time".to_owned(),
        "--verbose".to_owned(),
        "--output=/tmp/run/resource.txt".to_owned(),
        "--".to_owned(),
        "/usr/bin/prlimit".to_owned(),
        "--as=4294967296".to_owned(),
        "--nproc=64".to_owned(),
    ]);
    if corrected {
        arguments.push("--stack=8388608".to_owned());
    }
    arguments.extend([
        "--".to_owned(),
        if venv_python {
            "/tmp/secure-bench-tools/semgrep/1.170.0/venv/bin/python".to_owned()
        } else {
            "/usr/bin/python3.14".to_owned()
        },
        "/tmp/probe.py".to_owned(),
    ]);
    arguments
}

fn limit_pair(value: &Value, pointer: &str) -> Option<(i64, i64)> {
    let values = value.pointer(pointer)?.as_array()?;
    Some((values.first()?.as_i64()?, values.get(1)?.as_i64()?))
}

/// Proves the frozen Semgrep pre-exec stack mutation with and without the correction.
pub fn probe_stack_limits(root: &Path) -> Result<String, Phase23Error> {
    validate_frozen_inputs(root)?;
    let output = root.join("phase23/output/stack-probes");
    if output.exists() {
        return Err(Phase23Error::Execution(
            "stack probe evidence already exists; reruns are forbidden".to_owned(),
        ));
    }
    fs::create_dir_all(&output)?;
    let ledger = output.join("ledger.jsonl");
    let mut previous = ZERO_HASH.to_owned();
    let mut observations = Vec::new();
    for (sequence, id, corrected) in [
        (1_u64, "baseline-unbounded-hard-stack", false),
        (2_u64, "corrected-bounded-hard-stack", true),
    ] {
        let directory = output.join(format!("attempts/{sequence:02}-{id}"));
        fs::create_dir_all(&directory)?;
        let arguments = stack_probe_arguments(root, &directory, corrected, true);
        let command = std::iter::once("/usr/bin/bwrap".to_owned())
            .chain(arguments.iter().cloned())
            .collect::<Vec<_>>();
        let evidence = run_process(&arguments, &directory)?;
        let limits: Value = serde_json::from_slice(&evidence.stdout)?;
        let before = limit_pair(&limits, "/before/stack").ok_or_else(|| {
            Phase23Error::Execution(format!("probe {id} omitted before stack limits"))
        })?;
        let after = limit_pair(&limits, "/after/stack").ok_or_else(|| {
            Phase23Error::Execution(format!("probe {id} omitted after stack limits"))
        })?;
        let passed = evidence.exit_code == Some(0)
            && !evidence.timed_out
            && if corrected {
                before == (8_388_608, 8_388_608) && after == before
            } else {
                before == (8_388_608, -1) && after.0 == 1_000_000_000 && after.1 == -1
            };
        let relative = format!("phase23/output/stack-probes/attempts/{sequence:02}-{id}");
        let observation = json!({
            "schema_version": "secure-bench-phase23-stack-probe-observation-v1",
            "sequence": sequence,
            "id": id,
            "scanner_process": false,
            "changed_variable": if corrected {"hard-stack=8MiB"} else {"control"},
            "command": command,
            "command_sha256": sha256(&canonical_json(&command)?),
            "environment": fixed_environment(),
            "exit_code": evidence.exit_code,
            "timed_out": evidence.timed_out,
            "duration_ms": evidence.duration_ms,
            "stdout_path": format!("{relative}/stdout.bin"),
            "stdout_sha256": sha256(&evidence.stdout),
            "stderr_path": format!("{relative}/stderr.bin"),
            "stderr_sha256": sha256(&evidence.stderr),
            "resource_path": format!("{relative}/resource.txt"),
            "resource_sha256": sha256(&evidence.resource),
            "limits": limits,
            "passed": passed,
        });
        if !passed {
            return Err(Phase23Error::Execution(format!(
                "stack limit probe {id} contradicted the causal model"
            )));
        }
        write_atomic(
            &directory.join("observation.json"),
            &canonical_json(&observation)?,
        )?;
        previous = append_ledger(
            &ledger,
            sequence,
            &previous,
            &observation,
            "synthetic-stack-limit-probe-completed",
        )?;
        observations.push(observation);
    }
    let report = json!({
        "schema_version": "secure-bench-phase23-stack-probe-v1",
        "state": "verified",
        "synthetic_probe_processes": 2,
        "synthetic_scanner_processes": 0,
        "holdout_accesses": 0,
        "network": false,
        "ledger_head": previous,
        "observations": observations,
    });
    write_atomic(&output.join("stack-probe.json"), &canonical_json(&report)?)?;
    write_sha256s(&output)?;
    Ok(serde_json::to_string(&json!({
        "state": "verified",
        "synthetic_probe_processes": 2,
        "ledger_head": previous,
    }))?)
}

/// Seals the retained non-scanner setup failure without repeating its process.
pub fn finalize_probe_setup_failure(root: &Path) -> Result<String, Phase23Error> {
    validate_frozen_inputs(root)?;
    let output = root.join("phase23/output/probes");
    let directory = output.join("attempts/01-baseline-unbounded-hard-stack");
    let observation_path = directory.join("observation.json");
    let ledger = output.join("ledger.jsonl");
    if observation_path.exists() || ledger.exists() || output.join("SHA256SUMS").exists() {
        return Err(Phase23Error::Execution(
            "probe setup failure is already sealed".to_owned(),
        ));
    }
    let stdout = fs::read(directory.join("stdout.bin"))?;
    let stderr = fs::read(directory.join("stderr.bin"))?;
    let resource = fs::read(directory.join("resource.txt"))?;
    if !stdout.is_empty()
        || !String::from_utf8_lossy(&stderr)
            .contains("ModuleNotFoundError: No module named 'semgrep'")
    {
        return Err(Phase23Error::Execution(
            "retained setup failure does not match the observed import error".to_owned(),
        ));
    }
    let arguments = stack_probe_arguments(root, &directory, false, false);
    let command = std::iter::once("/usr/bin/bwrap".to_owned())
        .chain(arguments.iter().cloned())
        .collect::<Vec<_>>();
    let relative = "phase23/output/probes/attempts/01-baseline-unbounded-hard-stack";
    let observation = json!({
        "schema_version": "secure-bench-phase23-stack-probe-setup-failure-v1",
        "sequence": 1,
        "id": "baseline-unbounded-hard-stack",
        "scanner_process": false,
        "setup_failure": "system Python did not activate the frozen Semgrep venv",
        "command": command,
        "command_sha256": sha256(&canonical_json(&command)?),
        "environment": fixed_environment(),
        "exit_code": 1,
        "timed_out": false,
        "stdout_path": format!("{relative}/stdout.bin"),
        "stdout_sha256": sha256(&stdout),
        "stderr_path": format!("{relative}/stderr.bin"),
        "stderr_sha256": sha256(&stderr),
        "resource_path": format!("{relative}/resource.txt"),
        "resource_sha256": sha256(&resource),
        "passed": false,
        "repeated": false,
    });
    write_atomic(&observation_path, &canonical_json(&observation)?)?;
    let head = append_ledger(
        &ledger,
        1,
        ZERO_HASH,
        &observation,
        "synthetic-stack-probe-setup-failed",
    )?;
    let report = json!({
        "schema_version": "secure-bench-phase23-stack-probe-setup-failure-report-v1",
        "state": "setup-failed-before-semgrep-import",
        "synthetic_probe_processes": 1,
        "synthetic_scanner_processes": 0,
        "retries": 0,
        "holdout_accesses": 0,
        "network": false,
        "ledger_head": head,
        "observation": observation,
    });
    write_atomic(
        &output.join("setup-failure.json"),
        &canonical_json(&report)?,
    )?;
    write_sha256s(&output)?;
    Ok(serde_json::to_string(&json!({
        "state": "setup-failed-before-semgrep-import",
        "synthetic_probe_processes": 1,
        "retries": 0,
        "ledger_head": head,
    }))?)
}

/// Writes the exhaustive Phase 23 checksum ledger without starting a scanner.
pub fn seal_phase23(root: &Path) -> Result<String, Phase23Error> {
    validate_frozen_inputs(root)?;
    let phase = root.join("phase23");
    let mut files = Vec::new();
    collect_files(&phase, &mut files)?;
    files.retain(|path| {
        let Ok(relative) = path.strip_prefix(&phase) else {
            return false;
        };
        relative != Path::new("SHA256SUMS")
            && relative
                .components()
                .next()
                .is_none_or(|component| component.as_os_str() != "target")
    });
    files.sort();
    let mut sums = String::new();
    for file in files {
        let relative = file.strip_prefix(&phase).map_err(|_| {
            Phase23Error::Contract(format!("Phase 23 hash path escaped: {}", file.display()))
        })?;
        sums.push_str(&format!(
            "{}  {}\n",
            sha256_file(&file)?,
            relative.display()
        ));
    }
    write_atomic(&phase.join("SHA256SUMS"), sums.as_bytes())?;
    Ok(serde_json::to_string(&json!({
        "state": "sealed",
        "files": sums.lines().count(),
        "sha256s_sha256": sha256(sums.as_bytes()),
        "scanner_processes_started": 0,
    }))?)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plan_changes_one_declared_variable_per_control() {
        let plan = diagnostic_plan();
        assert_eq!(plan.len(), 16);
        assert_eq!(plan[0].id, "baseline-16-auto");
        assert!(
            plan.iter()
                .all(|item| item.pid_namespace && item.full_profile)
        );
        assert!(plan.iter().all(|item| item.target_count > 0));
        assert_eq!(threshold_plan().len(), 12);
    }

    #[test]
    fn segmentation_fault_detection_is_explicit() {
        assert!(raw_has_segmentation_fault(
            Some(br#"{"errors":[{"message":"Segmentation fault"}]}"#),
            b""
        ));
        assert!(!raw_has_segmentation_fault(
            Some(br#"{"errors":[],"results":[]}"#),
            b""
        ));
    }
}
