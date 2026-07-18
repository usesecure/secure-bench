use crate::{Phase21Error, sha256_file};
use serde_json::Value;
use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

/// Corrected profile name frozen for Phase 22.
pub const CORRECTED_PROFILE: &str = "phase21-null-device-v1";
/// Diagnostic profile that intentionally retains the Phase 20 `nodev` defect.
pub const LEGACY_PROFILE: &str = "phase20-nodev-reproduction";
/// Frozen OpenGrep version.
pub const OPENGREP_VERSION: &str = "1.22.0";
/// Frozen Semgrep CE version.
pub const SEMGREP_VERSION: &str = "1.170.0";
/// Frozen OpenGrep host cache path.
pub const OPENGREP_SOURCE: &str = "/tmp/secure-bench-tools/opengrep/1.22.0/opengrep_manylinux_x86";
/// OpenGrep path visible to the scanner.
pub const OPENGREP_TARGET: &str = "/tmp/secure-bench-tools/opengrep/1.22.0/opengrep_manylinux_x86";
/// Frozen Semgrep host cache root.
pub const SEMGREP_SOURCE: &str = "/tmp/secure-bench-tools/semgrep/1.170.0";
/// Semgrep path visible to the scanner.
pub const SEMGREP_TARGET: &str = "/tmp/secure-bench-tools/semgrep/1.170.0/venv/bin/semgrep";
const SEMGREP_WHEELHOUSE: &str = "/tmp/secure-bench-tools/semgrep/1.170.0/wheelhouse";
const SEMGREP_INSTALLED: &str =
    "/tmp/secure-bench-tools/semgrep/1.170.0/installed-distributions.json";
const SEMGREP_REQUIREMENTS: &str = "/tmp/secure-bench-tools/semgrep/1.170.0/requirements.lock";
const SEMGREP_CLOSURE_SHA256: &str =
    "5371b438dc6e3c5529794b21c668057164f52fa1375e0e91ee6c8f241fb74181";

/// Qualified scanner identity.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Scanner {
    /// OpenGrep native executable.
    OpenGrep,
    /// Semgrep Community Edition OSS engine.
    Semgrep,
}

impl Scanner {
    /// Stable output identity.
    pub const fn id(self) -> &'static str {
        match self {
            Self::OpenGrep => "opengrep",
            Self::Semgrep => "semgrep-ce",
        }
    }

    /// Frozen version.
    pub const fn version(self) -> &'static str {
        match self {
            Self::OpenGrep => OPENGREP_VERSION,
            Self::Semgrep => SEMGREP_VERSION,
        }
    }

    /// Host cache source and in-sandbox executable.
    pub const fn mount(self) -> (&'static str, &'static str) {
        match self {
            Self::OpenGrep => (OPENGREP_SOURCE, OPENGREP_TARGET),
            Self::Semgrep => (SEMGREP_SOURCE, SEMGREP_TARGET),
        }
    }
}

/// Fixed non-credential process environment.
pub fn fixed_environment() -> Vec<String> {
    vec![
        "HOME=/tmp/home".to_owned(),
        "LANG=C.UTF-8".to_owned(),
        "LC_ALL=C.UTF-8".to_owned(),
        "PATH=/usr/bin:/bin".to_owned(),
        "SEMGREP_ENABLE_VERSION_CHECK=0".to_owned(),
        "SEMGREP_SEND_METRICS=off".to_owned(),
        "TZ=UTC".to_owned(),
        "XDG_CACHE_HOME=/tmp/cache".to_owned(),
    ]
}

fn push_dirs(arguments: &mut Vec<String>, paths: &[&str]) {
    for path in paths {
        arguments.extend(["--dir".to_owned(), (*path).to_owned()]);
    }
}

/// Common profile construction. The legacy profile differs only at `/dev` and
/// exists solely to reproduce the defect on synthetic inputs.
pub fn base_arguments(corrected: bool) -> Vec<String> {
    let mut arguments = vec![
        "--unshare-net".to_owned(),
        "--unshare-pid".to_owned(),
        "--die-with-parent".to_owned(),
        "--new-session".to_owned(),
        "--as-pid-1".to_owned(),
        "--ro-bind".to_owned(),
        "/".to_owned(),
        "/".to_owned(),
    ];
    if corrected {
        arguments.extend([
            "--tmpfs".to_owned(),
            "/dev".to_owned(),
            "--dev-bind".to_owned(),
            "/dev/null".to_owned(),
            "/dev/null".to_owned(),
        ]);
    }
    arguments.extend([
        "--proc".to_owned(),
        "/proc".to_owned(),
        "--tmpfs".to_owned(),
        "/tmp".to_owned(),
        "--tmpfs".to_owned(),
        "/home".to_owned(),
        "--tmpfs".to_owned(),
        "/root".to_owned(),
        "--tmpfs".to_owned(),
        "/run/user".to_owned(),
        "--tmpfs".to_owned(),
        "/var/tmp".to_owned(),
    ]);
    push_dirs(
        &mut arguments,
        &[
            "/tmp/fixture",
            "/tmp/rules",
            "/tmp/run",
            "/tmp/home",
            "/tmp/cache",
            "/tmp/secure-bench-tools",
        ],
    );
    arguments
}

fn scanner_mount_dirs(scanner: Scanner) -> &'static [&'static str] {
    match scanner {
        Scanner::OpenGrep => &[
            "/tmp/secure-bench-tools/opengrep",
            "/tmp/secure-bench-tools/opengrep/1.22.0",
        ],
        Scanner::Semgrep => &[
            "/tmp/secure-bench-tools/semgrep",
            "/tmp/secure-bench-tools/semgrep/1.170.0",
        ],
    }
}

/// Complete scanner sandbox arguments before the scanner-specific command.
pub fn scanner_sandbox(
    scanner: Scanner,
    corrected: bool,
    fixture: &Path,
    rule: &Path,
    output: &Path,
) -> Vec<String> {
    let mut arguments = base_arguments(corrected);
    push_dirs(&mut arguments, scanner_mount_dirs(scanner));
    let (source, _) = scanner.mount();
    let target = match scanner {
        Scanner::OpenGrep => OPENGREP_TARGET,
        Scanner::Semgrep => "/tmp/secure-bench-tools/semgrep/1.170.0",
    };
    arguments.extend([
        "--ro-bind".to_owned(),
        source.to_owned(),
        target.to_owned(),
        "--ro-bind".to_owned(),
        fixture.to_string_lossy().into_owned(),
        "/tmp/fixture".to_owned(),
        "--ro-bind".to_owned(),
        rule.to_string_lossy().into_owned(),
        "/tmp/rules/rule.yml".to_owned(),
        "--bind".to_owned(),
        output.to_string_lossy().into_owned(),
        "/tmp/run".to_owned(),
        "--chdir".to_owned(),
        "/tmp/fixture".to_owned(),
        "--clearenv".to_owned(),
    ]);
    for entry in fixed_environment() {
        let (name, value) = entry.split_once('=').unwrap_or((entry.as_str(), ""));
        arguments.extend(["--setenv".to_owned(), name.to_owned(), value.to_owned()]);
    }
    arguments
}

/// Exact scanner arguments for a synthetic scan.
pub fn scanner_command(scanner: Scanner) -> Vec<String> {
    let executable = scanner.mount().1;
    match scanner {
        Scanner::OpenGrep => vec![
            executable.to_owned(),
            "scan".to_owned(),
            "--json".to_owned(),
            "--json-output=/tmp/run/raw.json".to_owned(),
            "--error".to_owned(),
            "--disable-version-check".to_owned(),
            "--no-rewrite-rule-ids".to_owned(),
            "--config=/tmp/rules/rule.yml".to_owned(),
            ".".to_owned(),
        ],
        Scanner::Semgrep => vec![
            executable.to_owned(),
            "scan".to_owned(),
            "--json".to_owned(),
            "--json-output=/tmp/run/raw.json".to_owned(),
            "--error".to_owned(),
            "--metrics=off".to_owned(),
            "--disable-version-check".to_owned(),
            "--no-rewrite-rule-ids".to_owned(),
            "--no-git-ignore".to_owned(),
            "--config=/tmp/rules/rule.yml".to_owned(),
            ".".to_owned(),
        ],
    }
}

/// Validate frozen executables before any scanner starts.
pub fn validate_tools(root: &Path) -> Result<serde_json::Value, Phase21Error> {
    let expected = [
        (
            "/usr/bin/bwrap",
            "139bf12775025adf5c8523d119c5ad2950281335573708fd839c60181a3886dc",
        ),
        (
            OPENGREP_SOURCE,
            "45bcd58440e397ed52c50e953ccf5948909ea77087c9186fc7d277216f62e319",
        ),
        (
            "/usr/bin/python3.14",
            "7af874aca05879e1823cd820913b42fb8d8b994738a05ec39ce4256d85b03861",
        ),
        (
            SEMGREP_INSTALLED,
            "703922233fb0e415b50e4b88ba9622dc6ea3d207a5f4fcb64b6b980da35056df",
        ),
        (
            SEMGREP_REQUIREMENTS,
            "bae00f126f98e84b32b92269d42f6567abab789307383094009030d7f13caf50",
        ),
    ];
    let mut verified = serde_json::Map::new();
    for (path, digest) in expected {
        let actual = sha256_file(Path::new(path))?;
        if actual != digest {
            return Err(Phase21Error::Contract(format!(
                "frozen executable drift at {path}: {actual}"
            )));
        }
        verified.insert(path.to_owned(), serde_json::Value::String(actual));
    }
    let semgrep = PathBuf::from(SEMGREP_TARGET);
    if !semgrep.is_file() {
        return Err(Phase21Error::Contract(format!(
            "frozen Semgrep executable absent: {}",
            semgrep.display()
        )));
    }
    verified.insert(
        SEMGREP_TARGET.to_owned(),
        serde_json::Value::String(sha256_file(&semgrep)?),
    );
    let lock: Value = serde_json::from_slice(&fs::read(
        root.join("phase18/provenance/semgrep-python314-linux-x86_64-lock.json"),
    )?)?;
    let packages = lock
        .get("packages")
        .and_then(Value::as_array)
        .ok_or_else(|| Phase21Error::Contract("Semgrep wheel lock has no packages".to_owned()))?;
    if packages.len() != 66
        || lock.get("closure_sha256").and_then(Value::as_str) != Some(SEMGREP_CLOSURE_SHA256)
    {
        return Err(Phase21Error::Contract(
            "Semgrep wheel closure identity drift".to_owned(),
        ));
    }
    let installed: BTreeMap<String, String> =
        serde_json::from_slice(&fs::read(SEMGREP_INSTALLED)?)?;
    if installed.len() != packages.len() {
        return Err(Phase21Error::Contract(
            "installed Semgrep distribution count drift".to_owned(),
        ));
    }
    for package in packages {
        let text = |field: &str| {
            package
                .get(field)
                .and_then(Value::as_str)
                .ok_or_else(|| Phase21Error::Contract(format!("Semgrep wheel lock omits {field}")))
        };
        let name = text("name")?;
        let version = text("version")?;
        let filename = text("filename")?;
        let expected_hash = text("sha256")?;
        let wheel = Path::new(SEMGREP_WHEELHOUSE).join(filename);
        if sha256_file(&wheel)? != expected_hash
            || installed
                .get(&name.to_ascii_lowercase().replace('_', "-"))
                .map(String::as_str)
                != Some(version)
        {
            return Err(Phase21Error::Contract(format!(
                "Semgrep dependency drift: {name} {version}"
            )));
        }
    }
    verified.insert(
        "semgrep-wheel-closure".to_owned(),
        serde_json::Value::String(SEMGREP_CLOSURE_SHA256.to_owned()),
    );
    verified.insert(
        "semgrep-wheel".to_owned(),
        serde_json::Value::String(
            "09a7e8eeff5e2549161124957184f3566f484370aa6127e425897cef725eb99b".to_owned(),
        ),
    );
    Ok(serde_json::Value::Object(verified))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn corrected_profile_exposes_only_null() {
        let arguments = base_arguments(true);
        assert_eq!(
            arguments
                .windows(3)
                .filter(|window| window[0] == "--dev-bind")
                .count(),
            1
        );
        assert!(
            arguments
                .windows(3)
                .any(|window| { window == ["--dev-bind", "/dev/null", "/dev/null"] })
        );
        for masked in ["/home", "/root", "/run/user", "/var/tmp"] {
            assert!(
                arguments
                    .windows(2)
                    .any(|window| window == ["--tmpfs", masked])
            );
        }
    }

    #[test]
    fn legacy_profile_has_no_device_bind() {
        let arguments = base_arguments(false);
        assert!(!arguments.iter().any(|argument| argument == "--dev-bind"));
        assert!(!arguments.iter().any(|argument| argument == "/dev/null"));
    }
}
