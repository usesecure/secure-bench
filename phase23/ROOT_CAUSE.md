# Phase 23 Semgrep CE root cause

## Finding

Semgrep CE 1.170.0 raises the child `semgrep-core` soft `RLIMIT_STACK` before
`exec`. Under the Phase 22 outer `RLIMIT_AS=4 GiB`, automatic parallelism then
reserves enough virtual stack address space to make thread creation fail.
`semgrep-core` mishandles that allocation failure and terminates with signal 11.
This is virtual-address reservation pressure, not resident-memory exhaustion.

The frozen Python file
`semgrep/core_runner.py` (SHA-256
`76f298b49667228a6157504ab8b7b56f87033693ed0aab279faa465bb895058a`)
implements `setrlimits_preexec_fn` at lines 135–199. It reads `RLIMIT_STACK`,
sorts candidates including `old_soft_limit * 100` and `1_000_000_000`, and sets
the greatest permitted soft value before launching `semgrep-core`.

The equivalent causal probe records:

- Phase 22 control: stack `[8_388_608, unlimited]` before pre-exec and
  `[1_000_000_000, unlimited]` afterward;
- Phase 23 correction: stack `[8_388_608, 8_388_608]` before and after;
- both profiles retain address space `[4_294_967_296, 4_294_967_296]` and
  process limit `[64, 64]`.

The minimum one-file reproducer crashes with automatic jobs. Jobs 1 and 2
complete; jobs 3 and above crash. With otherwise identical limits, stack caps
from 8 through 128 MiB complete while 256 MiB through 1 GiB crash. The baseline
crash reaches only 101,624 KiB maximum RSS and records `semgrep-core exited with
-11`, fault address `0xfffffffffffffff9`, and an empty signal-handler stack
trace in thread 27. Removing the address-space limit or raising it to 16 GiB
also completes, but widens resources and does not correct the causal mutation.

## Minimal correction

Phase 23 adds exactly this outer limit before Semgrep starts:

```text
/usr/bin/prlimit --as=4294967296 --nproc=64 --stack=8388608 -- semgrep ...
```

Setting both soft and hard stack to the already-effective 8 MiB soft value
prevents the frozen pre-exec hook from raising it. It narrows, rather than
widens, the process resource contract and changes no scanner, wheel, dependency,
ruleset, adapter, mount, namespace, permission, device, network, or host path.

## Scope boundary

All 39 scanner executions in Phase 23 used newly authored synthetic fixtures:
28 diagnosis/threshold executions and 11 qualification executions. The four
non-scanner probe processes comprise one retained setup failure, two causal
stack probes, and one qualification confinement probe. There were zero retries,
zero holdout accesses, and no Phase 22 or Phase 24 execution.

