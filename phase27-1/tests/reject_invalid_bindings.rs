//! Negative tests for fail-closed scanner identity bindings.

use std::error::Error;
use std::fs;
use std::io;
use std::path::PathBuf;
use std::process::Command;

#[test]
fn rejects_hash_path_version_lane_and_precedence_drift() -> Result<(), Box<dyn Error>> {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let overlay = root.join("binding-overlay.json");
    let verifier = root.join("scripts/verify-bindings.py");
    let original = fs::read_to_string(&overlay)?;
    let mutations = [
        (
            "hash",
            "5feca58fda54e4f9af0bf3846d04a98825d7315e64cbf80268a2395cf07ff2e6",
            "0feca58fda54e4f9af0bf3846d04a98825d7315e64cbf80268a2395cf07ff2e6",
        ),
        (
            "path",
            "/tmp/secure-bench-tools/opengrep/1.22.0/opengrep_manylinux_x86",
            "/tmp/secure-bench-tools/opengrep/1.22.0/wrong",
        ),
        (
            "version",
            "\"version\": \"1.170.0\"",
            "\"version\": \"1.170.1\"",
        ),
        (
            "lane",
            "\"lane\": \"native\"",
            "\"lane\": \"capability_normalized\"",
        ),
        (
            "precedence",
            "\"mode\": \"conditional-identity-overlay\"",
            "\"mode\": \"unconditional-replacement\"",
        ),
    ];

    for (index, (name, needle, replacement)) in mutations.iter().enumerate() {
        let mutated = original.replacen(needle, replacement, 1);
        if mutated == original {
            return Err(io::Error::other(format!("mutation {name} did not apply")).into());
        }
        let path = std::env::temp_dir().join(format!(
            "secure-bench-phase27-1-{name}-{}-{index}.json",
            std::process::id()
        ));
        fs::write(&path, mutated)?;
        let status = Command::new("python3")
            .arg(&verifier)
            .arg("--overlay-only")
            .arg("--overlay")
            .arg(&path)
            .status()?;
        fs::remove_file(&path)?;
        if status.success() {
            return Err(
                io::Error::other(format!("verifier accepted invalid {name} binding")).into(),
            );
        }
    }
    Ok(())
}
