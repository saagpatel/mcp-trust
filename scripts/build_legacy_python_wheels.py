#!/usr/bin/env python3
"""Build the two reviewed legacy wheels inside a network-off container.

This helper is intentionally narrow.  It imports the pinned setuptools tree
before running each exact ``setup.py`` because Python 3.12 no longer ships the
stdlib ``distutils`` module used by these old projects.
"""

from __future__ import annotations

import os
import runpy
import shutil
import sys
import tarfile
from pathlib import Path


def _safe_extract(archive_path: Path, destination: Path) -> Path:
    destination.mkdir(parents=True, exist_ok=False)
    with tarfile.open(archive_path, "r:gz") as archive:
        archive.extractall(destination, filter="data")
    roots = [path for path in destination.iterdir() if path.is_dir()]
    if len(roots) != 1 or any(path.is_symlink() for path in destination.rglob("*")):
        raise RuntimeError(f"unsafe or ambiguous source archive: {archive_path.name}")
    return roots[0]


def _build(source: Path, output: Path) -> None:
    setup = source / "setup.py"
    if not setup.is_file():
        raise RuntimeError(f"setup.py is absent: {source.name}")
    previous = Path.cwd()
    argv = list(sys.argv)
    try:
        os.chdir(source)
        sys.argv = [str(setup), "bdist_wheel", "--dist-dir", str(output)]
        import setuptools  # noqa: F401, PLC0415

        runpy.run_path(str(setup), run_name="__main__")
    finally:
        sys.argv = argv
        os.chdir(previous)


def main() -> int:
    work = Path("/work")
    build = work / "build"
    output = work / "out"
    if build.exists() or output.exists():
        raise RuntimeError("build output already exists")
    output.mkdir(parents=True)
    pymeta = _safe_extract(work / "inputs/PyMeta3-0.5.1.tar.gz", build / "pymeta")
    pybars = _safe_extract(work / "inputs/pybars3-0.9.7.tar.gz", build / "pybars")
    _build(pymeta, output)
    _build(pybars, output)
    expected = {
        "pybars3-0.9.7-py3-none-any.whl",
        "pymeta3-0.5.1-py3-none-any.whl",
    }
    actual = {path.name for path in output.glob("*.whl")}
    if actual != expected:
        raise RuntimeError(f"unexpected wheel outputs: {sorted(actual)}")
    shutil.rmtree(build)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
