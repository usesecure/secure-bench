# Secure Bench Phase 0–1 Methodology

## Neutrality statement

Secure Bench is designed to remain useful when any particular analyzer performs poorly. Phase 0 deliberately uses synthetic, committed mock reports so the harness can be audited before real tools or corpora introduce product and environment effects.

Phase 0 results are contract demonstrations only. They are not measurements of Secure Engine, the tools commonly producing SARIF, or any other scanner. They must not be published as rankings, used as marketing comparisons, or cited as evidence that one analyzer is superior.

## Labels and eligibility

Every case declares its stable identifier, vulnerable or safe-control label, language, framework, neutral category, fixture path, required capabilities, compatible evidence formats, resource budget, network policy, license, origin, and modification history before report evaluation.

Vulnerable cases declare at least one expected invariant violation. Safe controls cannot declare an expected finding. This prevents a safe case from being silently treated as an unlabeled vulnerable case.

Expected findings are matcher-only data. They are not present in fixture file names beyond neutral case identity, report adapter inputs, recorded command arguments, environment variables, or scanner configuration. Phase 0 does not have a scanner process to receive them.

## Matching contract

An observed finding receives detection credit only when it satisfies every declared constraint:

1. neutral category equality;
2. violated invariant equality;
3. source location or a predeclared equivalent location;
4. sink location or a predeclared equivalent location; and
5. minimum evidence-path length and ordered required hop kinds.

Location constraints use repository-relative paths and one-based coordinates. Equivalent variants must be declared in the suite rather than inferred by an adapter. A severity label, rule identifier, large rule inventory, or raw alert count cannot compensate for incorrect evidence.

Assignment is one-to-one. Multiple semantically identical alerts are duplicates, not additional detections. Multiple distinct valid candidates create an explicit ambiguity record. These rules reduce credit inflation from splitting one issue into many alerts or emitting broad keyword matches.

## Separate metrics

Phase 0 intentionally has no aggregate quality number.

- Vulnerable recall uses all eligible expectations as its denominator, so crashes, timeouts, missing scans, parse failures, and unsupported cases receive no detection credit.
- Attempted vulnerable recall exposes performance only among successfully completed cases without hiding the eligible population.
- Safe-control false-positive rate uses successfully attempted safe controls as its denominator.
- Safe-control clean coverage divides successfully completed clean controls by all eligible controls. A failed safe control therefore cannot appear clean.
- Evidence-path, source, and sink accuracy are reported over detected expectations.
- Severity and confidence calibration are reported over detected expectations and never affect detection credit.
- Duplicate rate is reported over normalized findings from successful cases.
- Crash, timeout, missing, parse-failure, and unsupported counts remain separate.
- Cold duration, warm duration, peak memory, and output size remain separate from quality.

Every rate contains raw integer counts and an explicit denominator. Basis points are a display projection, not a second source of truth.

## Provenance and auditability

Results fingerprint the exact suite manifest, recorded-run manifest, and native report with SHA-256. They retain the public tool name, version, recorded argument array, configuration fingerprint, native report schema, sanitized host metadata, and all participating schema identifiers.

Every aggregate is reproducible from normalized findings, expectation decisions, finding dispositions, case executions, and committed inputs. Exported results omit report messages and source text and accept only relative source coordinates.

## Phase 0 limitations

The corpus has one minimal vulnerable case and one paired safe control. It is intentionally too small and synthetic for statistical claims, confidence intervals, language coverage claims, severity calibration conclusions, performance comparisons, or production readiness conclusions. No external projects, scanner binaries, scanner packages, or live outputs are included.

## Phase 1 corpus methodology

Phase 1 adds seven original vulnerable/control pairs covering public command execution, raw SQL construction, filesystem, outbound request, redirect, dynamic code execution, and authorization-dominance invariants. The projects span JavaScript, JSX, TypeScript, and TSX across Node.js, Express-style handlers, and Next.js App Router or Server Action forms.

Cases are designed from public security invariants and ordinary framework behavior. They are not derived from Secure Engine source, private rule implementations, or private fixtures. Neutral scanner-visible names are mandatory, and automated leakage checks reject answer labels, matcher categories, and invariant text in fixture paths, declarations, and comments. SHA-256 content fingerprints make fixture drift visible before execution.

Eligibility, labels, constraints, evidence requirements, and resource budgets are declared before execution. Successful reports pass through the public scoring-blind adapter. The adapter receives no expectation or score data; matching remains one-to-one and exact. Live operational failures extend, rather than replace, the Phase 0 failure model.

## Phase 1 limitations

Fourteen synthetic cases cannot support public rankings, confidence intervals, broad framework coverage, production quality claims, or cross-tool conclusions. A single Secure Engine baseline is sensitive to the exact binary, configuration, host, and public CLI behavior. Timing and observed memory are descriptive measurements, not comparative performance claims.

Phase 1 does not claim kernel-enforced network isolation, a read-only mount sandbox, descendant-inclusive memory accounting, or hard filesystem quotas. The child environment is cleared, cases are copied to temporary workspaces, direct-process memory is sampled, time and accepted report sizes are bounded, and process groups are cleaned. Stronger execution isolation remains later roadmap work.
