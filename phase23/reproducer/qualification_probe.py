#!/usr/bin/env python3
"""Phase 23 non-scanner sandbox confinement probe."""

import json
import os
import resource
import socket


def attempt(label, operation):
    try:
        operation()
    except OSError as error:
        return {"label": label, "blocked": True, "errno": error.errno}
    return {"label": label, "blocked": False, "errno": None}


with open("/dev/null", "wb", buffering=0) as device:
    null_write = device.write(b"phase23")

observations = {
    "network": attempt("network", lambda: socket.create_connection(("198.51.100.1", 9), 0.1)),
    "outside_write": attempt("outside_write", lambda: open("/phase23-forbidden", "wb")),
    "proc_pid": os.readlink("/proc/self"),
    "stack": list(resource.getrlimit(resource.RLIMIT_STACK)),
    "address_space": list(resource.getrlimit(resource.RLIMIT_AS)),
    "processes": list(resource.getrlimit(resource.RLIMIT_NPROC)),
    "null_write": null_write,
    "credentials_visible": any(name in os.environ for name in ("AWS_SECRET_ACCESS_KEY", "GITHUB_TOKEN", "OPENAI_API_KEY")),
}
print(json.dumps(observations, sort_keys=True, separators=(",", ":")))
