"""Read-only binding checks for the optional real scan engine runtime."""

from __future__ import annotations

import base64
import hashlib
import hmac
import importlib.machinery
import importlib.metadata
import importlib.util
from pathlib import Path

MCP_AUDIT_RUNTIME_MODULES = (
    "mcp_audit",
    "mcp_audit.analyzer",
    "mcp_audit.connector",
    "mcp_audit.models",
    "mcp_audit.scorer",
)


def _has_symlink_component(path: Path) -> bool:
    if not path.is_absolute():
        return True
    current = Path(path.anchor)
    for component in path.parts[1:]:
        current /= component
        if current.is_symlink():
            return True
    return False


def _regular_unsymlinked_path(path: Path, root: Path) -> bool:
    try:
        relative = path.relative_to(root)
    except ValueError:
        return False
    if _has_symlink_component(root):
        return False
    current = root
    for component in relative.parts:
        current /= component
        if current.is_symlink():
            return False
    return path.is_file()


def _recorded_file_intact(item: object, candidate: Path) -> bool:
    recorded_hash = getattr(item, "hash", None)
    recorded_size = getattr(item, "size", None)
    if (
        getattr(recorded_hash, "mode", None) != "sha256"
        or not isinstance(getattr(recorded_hash, "value", None), str)
        or not isinstance(recorded_size, int)
        or recorded_size != candidate.stat().st_size
    ):
        return False
    actual_hash = base64.urlsafe_b64encode(hashlib.sha256(candidate.read_bytes()).digest())
    actual_value = actual_hash.rstrip(b"=").decode("ascii")
    return hmac.compare_digest(actual_value, recorded_hash.value)


def modules_belong_to_distribution(
    distribution: str, modules: tuple[str, ...]
) -> bool:
    """Return whether required modules are intact files owned by a distribution.

    The check does not import optional scanner code on the host. A stale or
    forged ``dist-info`` directory is not enough: every lazily imported module
    must resolve to a regular path with no symlinked component and match the
    size and SHA-256 recorded by that same installed distribution.
    """
    try:
        if not modules or any(not module or module.startswith(".") for module in modules):
            return False
        root_module = modules[0].split(".", maxsplit=1)[0]
        if any(
            module != root_module and not module.startswith(f"{root_module}.")
            for module in modules
        ):
            return False
        installed = importlib.metadata.distribution(distribution)
        root_spec = importlib.util.find_spec(root_module)
        files = installed.files
        if root_spec is None or not isinstance(root_spec.origin, str) or files is None:
            return False
        install_root = Path(installed.locate_file(""))
        if not install_root.is_dir() or install_root.is_symlink():
            return False
        entry_paths = [str(item).replace("\\", "/") for item in files]
        if len(entry_paths) != len(set(entry_paths)):
            return False
        entries = dict(zip(entry_paths, files, strict=True))
        selected: dict[str, Path] = {}
        for module in modules:
            stem = module.replace(".", "/")
            options = (f"{stem}.py", f"{stem}/__init__.py")
            matches = [(path, entries[path]) for path in options if path in entries]
            if len(matches) != 1:
                return False
            relative, item = matches[0]
            candidate = Path(installed.locate_file(item))
            if (
                not _regular_unsymlinked_path(candidate, install_root)
                or not _recorded_file_intact(item, candidate)
            ):
                return False
            selected[module] = candidate
        for module in modules:
            if module == root_module:
                spec = root_spec
            else:
                parent_module = module.rsplit(".", maxsplit=1)[0]
                parent_file = selected.get(parent_module)
                if parent_file is None or parent_file.name != "__init__.py":
                    return False
                spec = importlib.machinery.PathFinder.find_spec(
                    module, [str(parent_file.parent)]
                )
            if spec is None or not isinstance(spec.origin, str):
                return False
            spec_origin = Path(spec.origin)
            if (
                not _regular_unsymlinked_path(spec_origin, install_root)
                or spec_origin != selected[module]
            ):
                return False
        return True
    except (AttributeError, ImportError, OSError, RuntimeError, TypeError, ValueError):
        return False
