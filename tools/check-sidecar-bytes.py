#!/usr/bin/env python3
"""Fail when a scenario sidecar's bytes differ from the checked-in manifest.

The ML pipeline binds each trained model's record to the sha256 of the exact
sidecar bytes it was evaluated against (scenario_yaml_sha256): one edited byte,
or a CRLF checkout, silently invalidates every record bound to that sidecar.
scenarios/sidecars.sha256 lists the hash of every tracked scenarios/*.yaml, so
a sidecar can only change together with a deliberate manifest update, which CI
gates behind the `retrain` label.

Run from the repository root: `python3 tools/check-sidecar-bytes.py`
Exits non-zero listing every sidecar that is changed, missing or unlisted.
After a retrain, regenerate the manifest with:
    git ls-files 'scenarios/*.yaml' | xargs sha256sum > scenarios/sidecars.sha256
"""

import hashlib
import subprocess
import sys

MANIFEST = "scenarios/sidecars.sha256"


def tracked_sidecars() -> list[str]:
    return subprocess.run(
        ["git", "ls-files", "scenarios/*.yaml"],
        check=True, capture_output=True, text=True,
    ).stdout.split()


def manifest_hashes() -> dict[str, str]:
    hashes = {}
    with open(MANIFEST, encoding="ascii") as f:
        for line in f:
            digest, path = line.rstrip("\n").split("  ", 1)
            hashes[path] = digest
    return hashes


def sha256_of(path: str) -> str:
    with open(path, "rb") as f:
        return hashlib.sha256(f.read()).hexdigest()


def main() -> int:
    expected = manifest_hashes()
    sidecars = tracked_sidecars()
    problems = []
    for path in sidecars:
        if path not in expected:
            problems.append(f"{path}: not in {MANIFEST}")
        elif sha256_of(path) != expected[path]:
            problems.append(f"{path}: bytes differ from {MANIFEST}")
    for path in sorted(set(expected) - set(sidecars)):
        problems.append(f"{path}: listed in {MANIFEST} but not tracked")
    for problem in problems:
        print(problem)
    if problems:
        print(f"\n{len(problems)} sidecar problem(s): an existing sidecar changes only "
              f"with a retrain; a new one only needs its line in {MANIFEST}")
        return 1
    print(f"{len(sidecars)} sidecar(s), all match {MANIFEST}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
