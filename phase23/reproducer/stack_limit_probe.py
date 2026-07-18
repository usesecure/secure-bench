#!/usr/bin/python3.14
"""Observe Semgrep's frozen pre-exec stack-limit transformation."""

import json
import resource

from semgrep.core_runner import setrlimits_preexec_fn


def limits() -> dict[str, list[int]]:
    return {
        "address_space": list(resource.getrlimit(resource.RLIMIT_AS)),
        "processes": list(resource.getrlimit(resource.RLIMIT_NPROC)),
        "stack": list(resource.getrlimit(resource.RLIMIT_STACK)),
    }


before = limits()
setrlimits_preexec_fn()
after = limits()
print(json.dumps({"after": after, "before": before}, sort_keys=True))

