#!/usr/bin/env python3
"""Record effective Phase 25 limits and environment, then exec frozen Semgrep."""

import json
import os
import resource
import sys


def limits(kind):
    return list(resource.getrlimit(kind))


record = {
    "address_space": limits(resource.RLIMIT_AS),
    "processes": limits(resource.RLIMIT_NPROC),
    "stack": limits(resource.RLIMIT_STACK),
    "open_files": limits(resource.RLIMIT_NOFILE),
    "environment": [f"{name}={value}" for name, value in sorted(os.environ.items())],
    "mountinfo": open("/proc/self/mountinfo", "rb").read().decode("utf-8"),
}
with open("/tmp/run/effective-environment.json", "w", encoding="utf-8") as output:
    json.dump(record, output, sort_keys=True, separators=(",", ":"))
    output.write("\n")

os.execv(sys.argv[1], sys.argv[1:])
