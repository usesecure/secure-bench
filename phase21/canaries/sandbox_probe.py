import errno
import json
import os
import socket
import stat


def read_text(path):
    try:
        with open(path, "r", encoding="utf-8") as handle:
            return handle.read()
    except OSError as error:
        return f"ERROR:{error.errno}:{error.strerror}"


def directory(path):
    try:
        return sorted(os.listdir(path))
    except OSError as error:
        return [f"ERROR:{error.errno}:{error.strerror}"]


result = {
    "schema_version": "secure-bench-phase21-sandbox-probe-v1",
    "uid": os.getuid(),
    "gid": os.getgid(),
    "dev_entries": directory("/dev"),
    "home_entries": directory("/home"),
    "root_entries": directory("/root"),
    "run_user_entries": directory("/run/user"),
    "var_tmp_entries": directory("/var/tmp"),
    "proc_1_comm": read_text("/proc/1/comm").strip(),
    "proc_status": read_text("/proc/self/status"),
    "mountinfo": read_text("/proc/self/mountinfo"),
    "network_route": read_text("/proc/net/route"),
}

try:
    metadata = os.stat("/dev/null")
    result["null"] = {
        "type": "character" if stat.S_ISCHR(metadata.st_mode) else "other",
        "mode": oct(stat.S_IMODE(metadata.st_mode)),
        "uid": metadata.st_uid,
        "gid": metadata.st_gid,
        "major": os.major(metadata.st_rdev),
        "minor": os.minor(metadata.st_rdev),
    }
    descriptor = os.open("/dev/null", os.O_RDWR)
    result["null"]["read_bytes"] = len(os.read(descriptor, 1))
    result["null"]["write_bytes"] = os.write(descriptor, b"x")
    os.close(descriptor)
    result["null"]["open_errno"] = None
except OSError as error:
    result.setdefault("null", {})["open_errno"] = error.errno
    result["null"]["open_error"] = error.strerror

try:
    with open("/etc/secure-bench-phase21-write-canary", "wb") as handle:
        handle.write(b"forbidden")
    result["outside_write_errno"] = None
except OSError as error:
    result["outside_write_errno"] = error.errno

network = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
network.settimeout(0.2)
try:
    network.connect(("192.0.2.1", 9))
    result["network_connect_errno"] = None
except OSError as error:
    result["network_connect_errno"] = error.errno
finally:
    network.close()

print(json.dumps(result, sort_keys=True, separators=(",", ":")))
