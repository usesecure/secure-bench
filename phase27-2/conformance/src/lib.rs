#![forbid(unsafe_code)]
//! Synthetic scanner-free conformance for the original Phase 17 Cargo closure.

#[cfg(test)]
mod tests {
    use secure_bench_opengrep_adapter::{ADAPTER_VERSION, adapt_report, report_assessment};
    use secure_bench_scanner_protocol::{
        AdapterIdentity, ArtifactIdentity, DeclaredCapabilities, ExitSemantics, PROTOCOL_VERSION,
        ReportAssessment, ResourcePolicy, RulesetIdentity, SCANNER_MANIFEST_SCHEMA,
        ScannerIdentity, ScannerManifest, SignatureVerification,
    };
    use std::collections::BTreeSet;
    use std::error::Error;
    use std::fs;

    fn manifest() -> ScannerManifest {
        ScannerManifest {
            schema_version: SCANNER_MANIFEST_SCHEMA.to_owned(),
            protocol_version: PROTOCOL_VERSION.to_owned(),
            scanner: ScannerIdentity {
                id: "opengrep".to_owned(),
                version: "1.22.0".to_owned(),
                upstream_repository: "https://github.com/opengrep/opengrep".to_owned(),
                license: "LGPL-2.1-only".to_owned(),
            },
            artifact: ArtifactIdentity {
                url: "https://github.com/opengrep/opengrep/releases/download/test/opengrep"
                    .to_owned(),
                name: "opengrep".to_owned(),
                operating_system: "linux".to_owned(),
                architecture: "x86_64".to_owned(),
                size_bytes: 1,
                sha256: "0".repeat(64),
                verification: SignatureVerification {
                    scheme: "sigstore".to_owned(),
                    signature_url: "https://example.invalid/signature".to_owned(),
                    signature_sha256: "1".repeat(64),
                    certificate_url: "https://example.invalid/certificate".to_owned(),
                    certificate_sha256: "2".repeat(64),
                    certificate_issuer: "https://token.actions.githubusercontent.com".to_owned(),
                    certificate_identity: "synthetic".to_owned(),
                    source_revision: "3".repeat(40),
                    verification_command: vec!["synthetic".to_owned()],
                },
            },
            ruleset: RulesetIdentity {
                id: "synthetic".to_owned(),
                version: "1".to_owned(),
                origin: "synthetic".to_owned(),
                license: "Apache-2.0".to_owned(),
                sha256: "4".repeat(64),
                rule_ids: BTreeSet::from(["synthetic.eval-call".to_owned()]),
            },
            capabilities: DeclaredCapabilities {
                languages: BTreeSet::from(["javascript".to_owned()]),
                frameworks: BTreeSet::new(),
                inter_file: false,
                interprocedural: false,
                taint: false,
                qualification: "synthetic conformance only".to_owned(),
            },
            command_template: vec![
                "{binary}".to_owned(),
                "--config".to_owned(),
                "{ruleset}".to_owned(),
                "--json-output".to_owned(),
                "{raw_output}".to_owned(),
                "{fixture_root}".to_owned(),
            ],
            resources: ResourcePolicy {
                timeout_ms: 1_000,
                max_output_bytes: 1_000_000,
                memory_limit_mib: 256,
                process_limit: 4,
                network_allowed: false,
                isolated_fixture_copy: true,
            },
            exit_semantics: ExitSemantics {
                clean: BTreeSet::from([0]),
                findings: BTreeSet::from([1]),
                all_other: "failure".to_owned(),
            },
            adapter: AdapterIdentity {
                raw_output_format: "opengrep-json-v1".to_owned(),
                adapter_id: "secure-bench-opengrep-json".to_owned(),
                adapter_version: ADAPTER_VERSION.to_owned(),
            },
        }
    }

    #[test]
    fn original_closure_adapts_synthetic_bytes_and_rejects_traversal() -> Result<(), Box<dyn Error>>
    {
        assert_eq!(ADAPTER_VERSION, "1.0.0");
        assert_eq!(PROTOCOL_VERSION, "1.0.0");
        let root = std::env::temp_dir().join(format!(
            "secure-bench-phase27-2-synthetic-{}",
            std::process::id()
        ));
        if root.exists() {
            fs::remove_dir_all(&root)?;
        }
        fs::create_dir_all(root.join("src"))?;
        fs::write(root.join("src/app.js"), b"eval(input);\n")?;
        let raw = br#"{"version":"1.22.0","results":[{"check_id":"synthetic.eval-call","path":"src/app.js","start":{"line":1,"col":1,"offset":0},"end":{"line":1,"col":12,"offset":11},"extra":{"message":"synthetic","severity":"ERROR","metadata":{},"fingerprint":"synthetic"}}],"errors":[]}"#;
        let report = adapt_report("synthetic", raw, &root, &manifest())?;
        assert_eq!(report.findings.len(), 1);
        assert_eq!(
            report_assessment(&Ok(report)),
            ReportAssessment::Valid { findings: 1 }
        );
        let traversal = raw
            .windows(b"src/app.js".len())
            .position(|window| window == b"src/app.js")
            .ok_or("synthetic path missing")?;
        let mut bad = raw.to_vec();
        bad.splice(
            traversal..traversal + b"src/app.js".len(),
            b"../app.js".iter().copied(),
        );
        assert!(adapt_report("synthetic", &bad, &root, &manifest()).is_err());
        fs::remove_dir_all(root)?;
        Ok(())
    }
}
