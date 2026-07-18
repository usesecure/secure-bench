# Phase 23 minimal patch

The corrected execution profile adds one argument to the existing outer
`prlimit` invocation:

```diff
 /usr/bin/prlimit \
   --as=4294967296 \
   --nproc=64 \
+  --stack=8388608 \
   -- semgrep ...
```

This fixes the demonstrated stack-limit mutation without changing the frozen
Semgrep CE 1.170.0 artifact, Python environment, dependency lock, ruleset,
adapter, command semantics, filesystem view, devices, network namespace, PID
namespace, credential masking, or host permissions.

