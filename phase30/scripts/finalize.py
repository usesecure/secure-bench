#!/usr/bin/env python3
"""Create the exhaustive Phase 30 inventory and checksum manifest."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path


def sha256_file(path: Path) -> str:
    """Return a streaming SHA-256 digest."""
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def files(phase30: Path, include_inventory: bool) -> list[Path]:
    """Return all contractual Phase 30 files in deterministic order."""
    selected = []
    for path in phase30.rglob("*"):
        if not path.is_file() or "target" in path.parts or "__pycache__" in path.parts:
            continue
        if path.name == "SHA256SUMS" or (path.name == "inventory.json" and not include_inventory):
            continue
        selected.append(path)
    return sorted(selected)


def main() -> None:
    """Write inventory.json, then SHA256SUMS including the inventory itself."""
    phase30 = Path(__file__).resolve().parents[1]
    root = phase30.parent
    inventory_entries = [
        {
            "path": path.relative_to(root).as_posix(),
            "sha256": sha256_file(path),
            "size_bytes": path.stat().st_size,
        }
        for path in files(phase30, include_inventory=False)
    ]
    inventory = {
        "entries": inventory_entries,
        "entry_count": len(inventory_entries),
        "schema_version": "secure-bench-phase30-inventory-v1",
    }
    (phase30 / "inventory.json").write_text(
        json.dumps(inventory, sort_keys=True, separators=(",", ":")) + "\n",
        encoding="utf-8",
    )
    lines = [
        f"{sha256_file(path)}  {path.relative_to(root).as_posix()}\n"
        for path in files(phase30, include_inventory=True)
    ]
    (phase30 / "SHA256SUMS").write_text("".join(lines), encoding="utf-8")


if __name__ == "__main__":
    main()

