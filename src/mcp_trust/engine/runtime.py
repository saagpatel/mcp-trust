"""Read-only binding checks for the optional real scan engine runtime."""

from __future__ import annotations

import base64
import hashlib
import hmac
import importlib.machinery
import importlib.metadata
import importlib.util
import re
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


def _normalized_distribution_name(value: str) -> str:
    return re.sub(r"[-_.]+", "-", value).lower()


def _recorded_file_binding(item: object, candidate: Path) -> dict[str, object] | None:
    recorded_hash = getattr(item, "hash", None)
    recorded_size = getattr(item, "size", None)
    if (
        getattr(recorded_hash, "mode", None) != "sha256"
        or not isinstance(getattr(recorded_hash, "value", None), str)
        or type(recorded_size) is not int
        or recorded_size < 0
    ):
        return None
    content = candidate.read_bytes()
    if recorded_size != len(content):
        return None
    digest = hashlib.sha256(content).digest()
    actual_hash = base64.urlsafe_b64encode(digest)
    actual_value = actual_hash.rstrip(b"=").decode("ascii")
    if not hmac.compare_digest(actual_value, recorded_hash.value):
        return None
    return {
        "record_hash": f"sha256={recorded_hash.value}",
        "sha256": "sha256:" + digest.hex(),
        "size": recorded_size,
    }


def distribution_runtime_binding(
    distribution: str, modules: tuple[str, ...]
) -> dict[str, object] | None:
    """Return privacy-safe distribution and module integrity bindings.

    The check does not import optional scanner code on the host. A stale or
    forged ``dist-info`` directory is not enough: every lazily imported module
    must resolve to a regular path with no symlinked component and match the
    size and SHA-256 recorded by that same installed distribution.
    """
    try:
        if not modules or any(not module or module.startswith(".") for module in modules):
            return None
        root_module = modules[0].split(".", maxsplit=1)[0]
        if any(
            module != root_module and not module.startswith(f"{root_module}.") for module in modules
        ):
            return None
        installed = importlib.metadata.distribution(distribution)
        metadata_name = installed.metadata.get("Name")
        metadata_version = installed.metadata.get("Metadata-Version")
        installer = installed.read_text("INSTALLER")
        if (
            not isinstance(metadata_name, str)
            or _normalized_distribution_name(metadata_name)
            != _normalized_distribution_name(distribution)
            or not isinstance(installed.version, str)
            or not installed.version
            or not isinstance(metadata_version, str)
            or not metadata_version
            or installer is None
            or installer.strip() != "uv"
        ):
            return None
        root_spec = importlib.util.find_spec(root_module)
        files = installed.files
        if root_spec is None or not isinstance(root_spec.origin, str) or files is None:
            return None
        install_root = Path(installed.locate_file(""))
        if not install_root.is_dir() or install_root.is_symlink():
            return None
        entry_paths = [str(item).replace("\\", "/") for item in files]
        if len(entry_paths) != len(set(entry_paths)):
            return None
        entries = dict(zip(entry_paths, files, strict=True))
        record_matches = [
            (path, item)
            for path, item in entries.items()
            if path.endswith(".dist-info/RECORD")
        ]
        expected_record = (
            _normalized_distribution_name(metadata_name).replace("-", "_")
            + f"-{installed.version}.dist-info/RECORD"
        )
        if len(record_matches) != 1 or record_matches[0][0] != expected_record:
            return None
        record_relative, record_item = record_matches[0]
        record_path = Path(installed.locate_file(record_item))
        if not _regular_unsymlinked_path(record_path, install_root):
            return None
        record_content = record_path.read_bytes()
        if not record_content:
            return None
        selected: dict[str, Path] = {}
        bindings: dict[str, dict[str, object]] = {}
        origins: dict[str, str] = {}
        for module in modules:
            stem = module.replace(".", "/")
            options = (f"{stem}.py", f"{stem}/__init__.py")
            matches = [(path, entries[path]) for path in options if path in entries]
            if len(matches) != 1:
                return None
            relative, item = matches[0]
            candidate = Path(installed.locate_file(item))
            if not _regular_unsymlinked_path(candidate, install_root):
                return None
            binding = _recorded_file_binding(item, candidate)
            if binding is None:
                return None
            selected[module] = candidate
            bindings[module] = binding
        for module in modules:
            if module == root_module:
                spec = root_spec
            else:
                parent_module = module.rsplit(".", maxsplit=1)[0]
                parent_file = selected.get(parent_module)
                if parent_file is None or parent_file.name != "__init__.py":
                    return None
                spec = importlib.machinery.PathFinder.find_spec(module, [str(parent_file.parent)])
            if spec is None or not isinstance(spec.origin, str):
                return None
            spec_origin = Path(spec.origin)
            if (
                not _regular_unsymlinked_path(spec_origin, install_root)
                or spec_origin != selected[module]
            ):
                return None
            origins[module] = spec_origin.relative_to(install_root).as_posix()
        return {
            "distribution": {
                "name": metadata_name,
                "version": installed.version,
                "metadata_version": metadata_version,
                "installer": "uv",
                "record_path": record_relative,
                "record_sha256": "sha256:" + hashlib.sha256(record_content).hexdigest(),
                "record_size": len(record_content),
            },
            "modules": [
                {
                    "module": module,
                    "path": selected[module].relative_to(install_root).as_posix(),
                    "origin": origins[module],
                    **bindings[module],
                }
                for module in modules
            ],
        }
    except (AttributeError, ImportError, OSError, RuntimeError, TypeError, ValueError):
        return None


def modules_belong_to_distribution(distribution: str, modules: tuple[str, ...]) -> bool:
    """Return whether required modules are intact files owned by a distribution."""
    return distribution_runtime_binding(distribution, modules) is not None


def distribution_module_bindings(
    distribution: str, modules: tuple[str, ...]
) -> list[dict[str, object]] | None:
    """Return only the module projection of a complete runtime binding."""
    binding = distribution_runtime_binding(distribution, modules)
    if binding is None:
        return None
    projected = binding.get("modules")
    return projected if isinstance(projected, list) else None
