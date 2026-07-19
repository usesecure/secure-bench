//! Fail-closed negative tests for the atomic Phase 17 Cargo closure.

use std::error::Error;
use std::fs;
use std::io;
use std::path::PathBuf;
use std::process::Command;

#[test]
fn rejects_version_workspace_identity_and_precedence_drift() -> Result<(), Box<dyn Error>> {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let overlay = root.join("binding-overlay.json");
    let verifier = root.join("scripts/verify-compatibility.py");
    let original = fs::read_to_string(&overlay)?;
    let mutations = [
        (
            "different-versions",
            "\"cargo_version\": \"0.3.0\"",
            "\"cargo_version\": \"0.1.0\"",
        ),
        (
            "different-workspaces",
            "\"same_workspace\": true",
            "\"same_workspace\": false",
        ),
        (
            "commit",
            "241600628315db6d8a77e62bbaf6e61ba5c628f1",
            "041600628315db6d8a77e62bbaf6e61ba5c628f1",
        ),
        (
            "tree",
            "e2512d180118e6487a979ba03d1961c41d17825d",
            "02512d180118e6487a979ba03d1961c41d17825d",
        ),
        (
            "lock-hash",
            "4c826bbc6f77a3db0084257b383cb6892bc23a265234b08bc738e03bcb77ef36",
            "0c826bbc6f77a3db0084257b383cb6892bc23a265234b08bc738e03bcb77ef36",
        ),
        (
            "mixed-context",
            "\"mixed_workspace_or_version_forbidden\": true",
            "\"mixed_workspace_or_version_forbidden\": false",
        ),
        (
            "precedence",
            "after-phase27-1-for-opengrep-cargo-pair-only",
            "before-phase27-1-unconditionally",
        ),
    ];
    for (index, (name, needle, replacement)) in mutations.iter().enumerate() {
        let mutated = original.replacen(needle, replacement, 1);
        if mutated == original {
            return Err(io::Error::other(format!("mutation {name} did not apply")).into());
        }
        let path = std::env::temp_dir().join(format!(
            "secure-bench-phase27-2-{name}-{}-{index}.json",
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
