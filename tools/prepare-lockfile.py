#!/usr/bin/env python3
"""Resolve the release lockfile using only crates.io, without local development patches."""
from pathlib import Path
import os
import shutil
import subprocess
import tempfile
import tomllib

root = Path(__file__).resolve().parents[1]
with tempfile.TemporaryDirectory(prefix="aegis-release-") as directory:
    stage = Path(directory) / "source"
    shutil.copytree(root, stage, ignore=shutil.ignore_patterns(".git", ".cargo", "target", "__pycache__"))
    environment = dict(os.environ, CARGO_HOME=str(Path(directory) / "cargo"))
    (stage / "Cargo.lock").unlink(missing_ok=True)
    subprocess.run(["cargo", "generate-lockfile"], cwd=stage, env=environment, check=True, timeout=180)
    lock = tomllib.loads((stage / "Cargo.lock").read_text())
    required = {"arche-web", "arche-firestore", "phylax-core", "phylax-gcp", "phylax-oidc", "capulus"}
    for package in lock["package"]:
        if package["name"] in required:
            if package.get("source") != "registry+https://github.com/rust-lang/crates.io-index" or not package.get("checksum"):
                raise ValueError(f"non-public release dependency: {package['name']}")
            if package["name"] == "capulus" and tuple(map(int, package["version"].split("."))) < (0, 6, 12):
                raise ValueError("publish Capulus 0.6.12 before preparing the Aegis release")
            required.remove(package["name"])
    if required:
        raise ValueError(f"missing shared release dependencies: {required}")
    shutil.copyfile(stage / "Cargo.lock", root / "Cargo.lock")
print("Resolved Cargo.lock from crates.io. Review and commit it before tagging the release.")
