#!/usr/bin/env python3
"""Build and preserve the sealed Phase 28 native adapter without modifying Phase 28."""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
import tempfile


REPO = Path(__file__).resolve().parents[2]
COMMIT = "be54f5cea9221da67eebdb9c71dca70b7ad9674d"
PHASE28_TREE = "4c1c45ee433b70ff85eb4327be3612975e556a18"
DURABLE = Path("/home/danielcastrillon/Proyectos/secure-bench-tool-cache/native-adapters/phase28") / COMMIT
ACTIVE = Path("/tmp/secure-bench-tools/native-adapters/phase28") / COMMIT
TOOLCHAIN = Path("/tmp/secure-bench-tools/rust/1.96.1/bin")
EXPECTED = {
    "phase28/Cargo.toml": "977abb07b4c749283a5c0f6e628c2d27f354e2174cf5c831d824efe8ddb20854",
    "phase28/Cargo.lock": "8c5ebaba39e867c869a37b96d839ca37cfdc9d6b4736b5376697c009d565a2a3",
    "phase28/src/main.rs": "211b440e798f891bb73acb439ec7696cdefbc705de38cb91237b4dc80b044d0d",
}


def sha(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def canonical(value: object) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()


def write(path: Path, value: str | bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(value.encode() if isinstance(value, str) else value)


def sums(root: Path) -> None:
    paths = sorted(path for path in root.rglob("*") if path.is_file() and path.name != "SHA256SUMS")
    write(root / "SHA256SUMS", "".join(f"{sha(path)}  {path.relative_to(root)}\n" for path in paths))


def verify_sums(root: Path) -> None:
    entries = set()
    for line in (root / "SHA256SUMS").read_text().splitlines():
        digest, relative = line.split("  ", 1)
        path = root / relative
        if relative in entries or not path.is_file() or sha(path) != digest:
            raise RuntimeError(f"checksum mismatch: {relative}")
        entries.add(relative)
    actual = {str(path.relative_to(root)) for path in root.rglob("*") if path.is_file() and path.name != "SHA256SUMS"}
    if entries != actual:
        raise RuntimeError("durable inventory differs")


def main() -> None:
    if DURABLE.exists() or ACTIVE.exists():
        raise RuntimeError("native adapter destination already exists")
    for relative, expected in EXPECTED.items():
        if sha(REPO / relative) != expected:
            raise RuntimeError(f"sealed source differs: {relative}")
    identities = subprocess.run(
        ["git", "rev-parse", "HEAD", "main", f"{COMMIT}:phase28"],
        cwd=REPO,
        check=True,
        capture_output=True,
        text=True,
    ).stdout.splitlines()
    if identities != [COMMIT, COMMIT, PHASE28_TREE]:
        raise RuntimeError(f"Git source identity differs: {identities}")
    environment = os.environ.copy()
    environment.update(
        {
            "PATH": f"{TOOLCHAIN}:/home/danielcastrillon/.cargo/bin:/usr/bin:/bin",
            "CARGO_NET_OFFLINE": "true",
            "SOURCE_DATE_EPOCH": subprocess.run(
                ["git", "show", "-s", "--format=%ct", COMMIT], cwd=REPO, check=True, capture_output=True, text=True
            ).stdout.strip(),
            "RUSTFLAGS": f"--remap-path-prefix={REPO}=/workspace/secure-bench",
        }
    )
    with tempfile.TemporaryDirectory(
        prefix="secure-bench-phase29-native-build-", dir="/home/danielcastrillon/Proyectos"
    ) as temporary:
        target = Path(temporary) / "target"
        command = [
            str(TOOLCHAIN / "cargo"),
            "build",
            "--release",
            "--locked",
            "--offline",
            "--manifest-path",
            str(REPO / "phase28/Cargo.toml"),
            "--target-dir",
            str(target),
        ]
        subprocess.run(command, cwd=REPO, env=environment, check=True)
        binary = target / "release/secure-bench-phase28-native-adapter"
        if not binary.is_file():
            raise RuntimeError("release helper was not materialized")
        DURABLE.mkdir(parents=True)
        (DURABLE / "bin").mkdir()
        shutil.copyfile(binary, DURABLE / "bin/secure-bench-phase28-native-adapter")
        shutil.copyfile(REPO / "phase28/Cargo.lock", DURABLE / "Cargo.lock")
        binary_sha = sha(DURABLE / "bin/secure-bench-phase28-native-adapter")
        source_manifest = {
            "schema_version": "secure-bench-phase29-native-helper-source-v1",
            "source_commit": COMMIT,
            "source_tree": PHASE28_TREE,
            "files": [{"path": path, "sha256": digest} for path, digest in EXPECTED.items()],
        }
        write(DURABLE / "source-manifest.json", canonical(source_manifest))
        provenance = {
            "schema_version": "secure-bench-phase29-native-helper-provenance-v1",
            "source_commit": COMMIT,
            "source_tree": PHASE28_TREE,
            "cargo_lock_sha256": EXPECTED["phase28/Cargo.lock"],
            "toolchain": "rustc 1.96.1 (31fca3adb 2026-06-26)",
            "toolchain_path": str(TOOLCHAIN),
            "build_mode": "release locked offline",
            "build_command": [item.replace(str(target), "{isolated_target_dir}") for item in command],
            "rustflags": environment["RUSTFLAGS"],
            "binary_sha256": binary_sha,
            "durable_path": str(DURABLE / "bin/secure-bench-phase28-native-adapter"),
            "active_path": str(ACTIVE / "bin/secure-bench-phase28-native-adapter"),
            "network_requests": 0,
            "phase28_modified": False,
        }
        write(DURABLE / "provenance.json", canonical(provenance))
        write(
            DURABLE / "restore.sh",
            "#!/usr/bin/env bash\nset -euo pipefail\n"
            f"root={json.dumps(str(DURABLE))}\nactive={json.dumps(str(ACTIVE))}\n"
            "install -d -m 0755 \"$active/bin\"\n"
            "install -m 0555 \"$root/bin/secure-bench-phase28-native-adapter\" \"$active/bin/secure-bench-phase28-native-adapter\"\n"
            f"echo {binary_sha}  \"$active/bin/secure-bench-phase28-native-adapter\" | sha256sum -c -\n",
        )
        write(
            DURABLE / "README.md",
            "# Phase 28 native adapter cache\n\nOffline release build of the exact helper source sealed in Phase 28. Run `restore.sh` to materialize the active copy. Scanner execution is not part of restoration.\n",
        )
        sums(DURABLE)
        verify_sums(DURABLE)
        os.chmod(DURABLE / "restore.sh", 0o555)
        for path in sorted(DURABLE.rglob("*"), reverse=True):
            os.chmod(path, 0o555 if path.is_dir() or path.stat().st_mode & stat.S_IXUSR else 0o444)
        os.chmod(DURABLE, 0o555)
        subprocess.run([str(DURABLE / "restore.sh")], check=True)
        if sha(ACTIVE / "bin/secure-bench-phase28-native-adapter") != binary_sha:
            raise RuntimeError("active restoration is not byte-identical")
        print(f"native_helper_build=PASS binary_sha256={binary_sha} durable={DURABLE} active={ACTIVE}")


if __name__ == "__main__":
    main()
