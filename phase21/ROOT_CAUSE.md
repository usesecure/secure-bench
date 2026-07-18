# Phase 21 root-cause report

## Incident boundary

Phase 20 commit `6c27c9bb26b96855228d1a8e6483483ff4174907`
contains exactly 336 immutable attempts. The OpenGrep and Semgrep lanes failed
because each Python startup path received `EACCES` while opening `/dev/null`.
Phase 21 does not correct, rerun, or reinterpret those attempts.

All Phase 21 runtime diagnosis and qualification used the new files under
`phase21/fixtures`, `phase21/rules`, and `phase21/canaries`. No Phase 19
holdout fixture was opened, read, copied, parsed, mounted into a scanner
sandbox, or used to construct a canary.

## Exact cause

Phase 20 starts bubblewrap with `--ro-bind / /`. On this host, the cloned `/dev`
mount is visible inside the sandbox as:

```text
devtmpfs /dev ro,nosuid,nodev
```

`/dev/null` still appears to be a mode `0666` character device with major 1,
minor 3. Its apparent owner changes to the unmapped UID/GID 65534, but its mode
permits every identity. The access check nevertheless returns `EACCES` because
the containing mount has `MS_NODEV`.

The isolated diagnostic matrix was:

| Sandbox variant | `/dev` or `/dev/null` mount | Open read/write |
|---|---|---|
| host | devtmpfs without `nodev` | succeeds |
| `--ro-bind / /` | devtmpfs `ro,nodev` | `EACCES` |
| plus network/PID/temp namespaces | devtmpfs `ro,nodev` | `EACCES` |
| ordinary `--bind /dev/null` | bind retains `nodev` | `EACCES` |
| `--dev-bind /dev/null` | device bind without `nodev` | succeeds |

Namespace changes did not affect the result. The process remained
`NoNewPrivs=1`, with no effective capabilities and no installed seccomp filter.
The SELinux context was unchanged from the working host access. Ownership,
seccomp, SELinux, network isolation, PID isolation, and temporary-directory
construction are therefore excluded as the cause. The decisive variable is
`nodev`, and bubblewrap's documented device-bind operation is the narrow
mechanism that clears it for the selected device.

The committed legacy probe independently reproduces the critical observation:
`/dev/null` is character device 1:3, mode `0666`, yet `open(O_RDWR)` returns
errno 13. Its complete mount and process-control record is
`output/attempts/sandbox-probe-legacy/stdout.bin`. Both scanners independently
emit `/dev/null` `PermissionError` under that diagnostic profile.

## Correction

The corrected profile applies this device policy after the read-only root bind:

```text
--tmpfs /dev
--dev-bind /dev/null /dev/null
```

This is deliberately not a bind of the host `/dev` tree. The fresh device
directory contains exactly one entry, `null`. The probe proves that entry is a
character device 1:3, mode `0666`; reads return immediate EOF and writes report
the discarded byte count. No other device is available.

The same profile reduces unrelated host visibility:

- fresh empty mounts mask `/home`, `/root`, `/run/user`, and `/var/tmp`;
- a fresh `/proc` corresponds to the new PID namespace;
- the root remains read-only and an attempted `/etc` write returns `EROFS`;
- the new network namespace has no default route and an external test-net
  connect returns `ENETUNREACH`;
- the child environment is cleared and repopulated with fixed non-credential
  values;
- only fixture, rule, frozen tool, and per-attempt output paths are explicitly
  mounted.

The complete corrected mount, permission, device, route, capability, and
process-control log is
`output/attempts/sandbox-probe-corrected/stdout.bin`. The exact reusable
contract and tool hashes are in
`output/corrected-environment-contract.json`.

## Qualification result

OpenGrep 1.22.0 and Semgrep CE 1.170.0 both:

- start and report the expected version;
- read the clean fixture and emit valid JSON with zero findings and exit 0;
- read the finding fixture and emit the exact synthetic rule finding with the
  frozen policy exit 1;
- reject the malformed rule with exit 7;
- terminate under the external namespace watchdog without a retry;
- have their adapters reject a scanner-free malformed JSON mock.

Semgrep's successful reports identify the OSS engine. Standard output,
standard error, raw output, exit status, duration, command, environment, and
hashes are retained per attempt. `output/ledger.jsonl` chains all 16
observations. `output/SHA256SUMS` seals every output artifact, and the
scanner-free independent verifier re-adapts the raw successful reports and
recomputes the chain.

Synthetic operability is not accuracy evidence. Phase 20 remains an unavailable
multi-scanner comparison, and Phase 22 must be described as a post-open recovery
study if the same 112 cases are used.

