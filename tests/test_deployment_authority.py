from __future__ import annotations

import hashlib
import importlib.util
import json
import os
import plistlib
import pty
import re
import select
import shutil
import stat
import subprocess
import sys
import time
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
REFRESH = ROOT / "scripts/refresh_and_publish.sh"
DEPLOY = ROOT / "scripts/deploy_production.sh"
VALIDATOR = ROOT / "scripts/validate_deploy_authorization.py"
DEPLOY_DOC = ROOT / "DEPLOY-VERCEL.md"
PLIST = ROOT / "deploy/launchd/com.d.mcp-trust-refresh.plist"
INSTALLER = ROOT / "deploy/launchd/install.sh"
PROJECT_ID = "prj_ugC28dxX9xAGYnYjIkQXigxZB672"
ORG_ID = "team_nZORCFEbaw3I8iSUrA2cWMJB"
ORIGIN_URL = "https://github.com/saagpatel/mcp-trust.git"
NODE_BIN = Path("/bin/sh")
PYTHON_BIN = Path(sys.executable)

_PUBLICATION_TEST_SPEC = importlib.util.spec_from_file_location(
    "publication_test_helpers",
    ROOT / "tests/test_publication_admission.py",
)
assert _PUBLICATION_TEST_SPEC is not None and _PUBLICATION_TEST_SPEC.loader is not None
PUBLICATION_TEST_HELPERS = importlib.util.module_from_spec(_PUBLICATION_TEST_SPEC)
_PUBLICATION_TEST_SPEC.loader.exec_module(PUBLICATION_TEST_HELPERS)


def _run(
    args: list[str],
    *,
    cwd: Path | None = None,
    env: dict[str, str] | None = None,
    check: bool = True,
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        args,
        cwd=cwd,
        env=env,
        check=check,
        text=True,
        capture_output=True,
    )


def _write_executable(path: Path, body: str) -> None:
    path.write_text(body, encoding="utf-8")
    path.chmod(path.stat().st_mode | stat.S_IXUSR)


TTY_TIMEOUT_ENV = "MCP_TRUST_TEST_TTY_TIMEOUT"
TTY_TIMEOUT_DEFAULT = 60.0


def _tty_timeout_seconds() -> float:
    """Wall-clock budget for a deploy script driven through a pty.

    These tests spawn the real script and wait for it to exit. The happy path
    measures ~14s on an idle machine, so the original hardcoded 10s budget sat
    *below* the cost of a passing run and failed under suite load rather than on
    behavior. That matters more here than in a normal flaky test: a timeout
    aborts before the security assertion is ever reached, so the run proves
    nothing in either direction while still going red. The budget must be
    generous enough that only a genuine hang trips it.

    Overridable for slow or heavily loaded machines. A malformed or
    non-positive override falls back to the default rather than failing the
    suite on a bad env var.
    """
    raw = os.environ.get(TTY_TIMEOUT_ENV)
    if not raw:
        return TTY_TIMEOUT_DEFAULT
    try:
        value = float(raw)
    except ValueError:
        return TTY_TIMEOUT_DEFAULT
    return value if value > 0 else TTY_TIMEOUT_DEFAULT


def _run_with_tty(
    args: list[str],
    *,
    cwd: Path,
    env: dict[str, str],
    confirmation: str,
    before_confirmation: Callable[[], None] | None = None,
) -> subprocess.CompletedProcess[str]:
    master, slave = pty.openpty()
    process = subprocess.Popen(
        args,
        cwd=cwd,
        env=env,
        stdin=slave,
        stdout=slave,
        stderr=slave,
        close_fds=True,
    )
    os.close(slave)
    os.set_blocking(master, False)
    output = bytearray()
    timeout = _tty_timeout_seconds()
    deadline = time.monotonic() + timeout
    confirmation_sent = False
    while process.poll() is None:
        if time.monotonic() > deadline:
            process.kill()
            raise AssertionError(
                f"deployment test process did not exit within {timeout:g} seconds "
                f"(raise {TTY_TIMEOUT_ENV} if this machine is slower)"
            )
        readable, _, _ = select.select([master], [], [], 0.2)
        if readable:
            try:
                chunk = os.read(master, 65536)
                if not chunk:
                    break
                output.extend(chunk)
                if not confirmation_sent and b"Type DEPLOY_MCP_TRUST_PRODUCTION" in output:
                    if before_confirmation is not None:
                        before_confirmation()
                    os.write(master, f"{confirmation}\r".encode())
                    confirmation_sent = True
            except (BlockingIOError, OSError):
                break
    try:
        while True:
            chunk = os.read(master, 65536)
            if not chunk:
                break
            output.extend(chunk)
    except (BlockingIOError, OSError):
        pass
    os.close(master)
    return subprocess.CompletedProcess(
        args=args,
        returncode=process.wait(timeout=5),
        stdout=output.decode(errors="replace"),
        stderr="",
    )


def _git(repo: Path, *args: str) -> str:
    return _run(["git", *args], cwd=repo).stdout.strip()


def _tree_sha256(root: Path) -> str:
    digest = hashlib.sha256()
    for path in sorted(root.rglob("*"), key=lambda item: item.relative_to(root).as_posix()):
        if not path.is_file():
            continue
        digest.update(path.relative_to(root).as_posix().encode())
        digest.update(b"\0")
        digest.update(hashlib.sha256(path.read_bytes()).hexdigest().encode())
        digest.update(b"\0")
    return digest.hexdigest()


def _canonical_bytes(value: object) -> bytes:
    return (
        json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode() + b"\n"
    )


def _public_readback_manifest(files: list[dict[str, object]]) -> dict[str, object]:
    public_files = [item for item in files if item["path"] != "vercel.json"]
    routes = []
    largest_body = 1
    for index, item in enumerate(public_files):
        relative = item["path"]
        if relative == "index.html":
            route, expected_status = "/", 200
        elif relative == "404.html":
            route, expected_status = "/__mcp_trust_candidate_missing__", 404
        elif (
            isinstance(relative, str)
            and relative.startswith("ui/")
            and relative.endswith("/index.html")
        ):
            route, expected_status = "/" + relative[: -len("/index.html")], 200
        elif (
            isinstance(relative, str)
            and relative.startswith("servers/")
            and relative.endswith("/badge.json")
        ):
            route, expected_status = "/" + relative, 200
        else:
            raise AssertionError(f"unmapped fixture route: {relative}")
        body_bytes = item["bytes"]
        body_digest = item["sha256"]
        assert isinstance(body_bytes, int)
        assert isinstance(body_digest, str)
        largest_body = max(largest_body, body_bytes)
        routes.append(
            {
                "id": f"route-{index:03d}",
                "method": "GET",
                "route": route,
                "expected_status": expected_status,
                "body_sha256": body_digest[len("sha256:") :],
            }
        )
    return {
        "schema": "WebReleaseSentinelManifestV1",
        "contract_version": "1.0.0",
        "name": "mcp-trust-site-candidate-exact",
        "defaults": {
            "timeout_seconds": 10,
            "max_body_bytes": largest_body,
            "follow_same_origin_redirects": False,
        },
        "denied_methods": ["POST", "PUT", "PATCH", "DELETE", "CONNECT", "TRACE"],
        "routes": routes,
    }


def _write_deployable_site_candidate(
    site: Path,
    *,
    rollback_identity: dict[str, object] | None = None,
    implementation_revision: str = "d" * 40,
    implementation_tree_digest: str = "sha256:" + "e" * 64,
) -> dict[str, object]:
    files = []
    for path in sorted(site.rglob("*"), key=lambda item: item.relative_to(site).as_posix()):
        relative = path.relative_to(site).as_posix()
        if not path.is_file() or relative in {"SITE_CANDIDATE.json", ".vercel/project.json"}:
            continue
        files.append(
            {
                "path": relative,
                "bytes": path.stat().st_size,
                "sha256": "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest(),
            }
        )
    content_digest = "sha256:" + hashlib.sha256(_canonical_bytes(files)).hexdigest()
    digest = lambda value: "sha256:" + hashlib.sha256(value.encode()).hexdigest()  # noqa: E731
    bindings = {
        "candidate_manifest_digest": digest("candidate"),
        "review_artifact_sha256": digest("review-artifact"),
        "review_receipt_digest": digest("review-receipt"),
        "disposition_policy_sha256": digest("disposition"),
        "seed_digest": digest("seed"),
        "masking_digest": digest("masking"),
        "policy_digest": digest("policy"),
        "source_revision": "8" * 40,
        "source_tree_digest": digest("source-tree"),
        "state": "REVIEW_ONLY_ACCEPTED_FOR_SOURCE_REVIEW",
        "publication_allowed": False,
        "deployment_allowed": False,
        "rollback_state": "PROVIDER_NATIVE_FIRST_PUBLICATION_REVIEW_BOUND",
    }
    observed = datetime.now(tz=UTC) - timedelta(seconds=5)
    rollback: dict[str, object] = {
        "schema": "McpTrustProviderNativeRollbackBindingV1",
        "state": "PROVIDER_NATIVE_FIRST_PUBLICATION_REVIEW_BOUND",
        "provider": "vercel",
        "observed_at": observed.isoformat(),
        "freshness_seconds": 3600,
        "production_target": {
            "alias": "mcp-trust.vercel.app",
            "deployment_id": "dpl_previous",
            "immutable_deployment_url": "previous.vercel.app",
            "project_id": PROJECT_ID,
            "team_id": ORG_ID,
            "target": "production",
            "deployment_state": "READY_PROMOTED",
            "source_revision": "1" * 40,
            "source_tree": "2" * 40,
            "public_tree_digest": digest("public-tree"),
        },
        "provenance": {
            "provider_metadata_receipt": digest("provider-metadata"),
            "provider_binding_decision_receipt": digest("provider-decision"),
        },
        "conditions": {
            "first_following_same_project_publication": True,
            "no_intervening_production_deployment": True,
            "target_must_remain_retained": True,
            "prepublication_provider_readback_required": True,
            "immediate_previous_rollback_only": True,
        },
        "authority": {
            "publication_allowed": False,
            "deployment_allowed": False,
            "rollback_execution_allowed": False,
            "scheduler_activation_allowed": False,
        },
        "unknown": [
            "provider_artifact_digest",
            "exercised_rollback_routing",
            "future_prepublication_binding",
        ],
        "claim_ceiling": (
            "Review-only target binding; not publication authority, not deployment "
            "authority, and not exercised rollback proof."
        ),
    }
    rollback["receipt_digest"] = "sha256:" + hashlib.sha256(
        _canonical_bytes(rollback)
    ).hexdigest()
    manifest: dict[str, object] = {
        "schema": "McpTrustSiteCandidateV2",
        "state": "REVIEW_ONLY_ACCEPTED_FOR_SOURCE_REVIEW",
        "created_at": observed.isoformat(),
        "base_url": "https://mcp-trust.vercel.app",
        "publication_allowed": False,
        "deployment_allowed": False,
        "claim_ceiling": "Review-only historical artifact; not publication or deployment.",
        "implementation_binding": {
            "state": "CLEAN_COMMITTED",
            "revision": implementation_revision,
            "source_tree_digest": implementation_tree_digest,
        },
        "bindings": bindings,
        "corrections_digest": digest("corrections"),
        "site_counts": {
            "servers": 1,
            "scanned": 1,
            "masked": 1,
            "stale": 0,
            "demo": 0,
        },
        "freshness": {
            "mode": "STATIC_HISTORICAL_ONLY",
            "horizon_days": 90,
            "evaluated_at": observed.isoformat(),
            "earliest_stale_after": (observed + timedelta(days=90)).isoformat(),
            "publication_not_after": (observed + timedelta(hours=1)).isoformat(),
            "state_counts": {
                "FRESH": 1,
                "STALE": 0,
                "UNKNOWN": 0,
                "NOT_APPLICABLE": 0,
            },
        },
        "projection_digests": {
            "refresh_scan_results": digest("scan-results"),
            "refresh_static_snapshot": digest("snapshot"),
            "masking": digest("mask-projection"),
            "site_content": content_digest,
        },
        "content": {"digest": content_digest, "files": files},
        "public_readback": _public_readback_manifest(files),
        "rollback": rollback,
        "blocking_gates": [
            "explicit_publication_authority_required",
            "provider_native_rollback_revalidation_and_publication_approval_required",
        ],
    }
    manifest["receipt_digest"] = "sha256:" + hashlib.sha256(_canonical_bytes(manifest)).hexdigest()
    (site / "SITE_CANDIDATE.json").write_bytes(_canonical_bytes(manifest))
    return manifest


def _make_deploy_repo(tmp_path: Path) -> tuple[Path, Path, Path]:
    upstream = tmp_path / "upstream.git"
    repo = tmp_path / "repo"
    _run(["git", "init", "--bare", str(upstream)])
    _run(["git", "init", "-b", "main", str(repo)])
    _git(repo, "config", "user.email", "security-test@example.invalid")
    _git(repo, "config", "user.name", "Security Test")
    (repo / "scripts").mkdir()
    shutil.copy2(DEPLOY, repo / "scripts/deploy_production.sh")
    shutil.copy2(VALIDATOR, repo / "scripts/validate_deploy_authorization.py")
    shutil.copy2(
        ROOT / "scripts/build_publication_package.py",
        repo / "scripts/build_publication_package.py",
    )
    shutil.copytree(
        ROOT / "src",
        repo / "src",
        ignore=shutil.ignore_patterns("__pycache__", "*.pyc"),
    )
    (repo / "site").mkdir()
    (repo / "site/index.html").write_text("current deployment\n", encoding="utf-8")
    (repo / "site/vercel.json").write_text("{}\n", encoding="utf-8")
    (repo / ".gitignore").write_text(
        "site/\n.vercel/\n__pycache__/\n*.pyc\n",
        encoding="utf-8",
    )
    (repo / ".vercel").mkdir()
    (repo / "site/.vercel").mkdir()
    link = json.dumps({"projectId": PROJECT_ID, "orgId": ORG_ID, "projectName": "mcp-trust"})
    (repo / ".vercel/project.json").write_text(link, encoding="utf-8")
    (repo / "site/.vercel/project.json").write_text(link, encoding="utf-8")
    rollback_site = repo.parent / "prior-site"
    rollback_site.mkdir()
    (rollback_site / "index.html").write_text("prior deployment\n", encoding="utf-8")
    rollback_manifest = _write_deployable_site_candidate(rollback_site)
    rollback_identity = {
        "receipt_digest": rollback_manifest["receipt_digest"],
        "content_digest": rollback_manifest["content"]["digest"],
    }
    _write_deployable_site_candidate(repo / "site", rollback_identity=rollback_identity)
    _git(repo, "add", ".")
    _git(repo, "commit", "-m", "fixture")
    commit = _git(repo, "rev-parse", "HEAD")
    tree_output = _run(["git", "ls-tree", "-r", "--full-tree", commit], cwd=repo).stdout.encode()
    _write_deployable_site_candidate(
        repo / "site",
        rollback_identity=rollback_identity,
        implementation_revision=commit,
        implementation_tree_digest="sha256:" + hashlib.sha256(tree_output).hexdigest(),
    )
    _git(repo, "remote", "add", "origin", str(upstream))
    _git(repo, "push", "-u", "origin", "main")
    _git(repo, "remote", "set-url", "origin", ORIGIN_URL)

    fake_vercel = tmp_path / "fake-vercel"
    record = tmp_path / "vercel-invocation.txt"
    _write_executable(
        fake_vercel,
        "#!/bin/sh\n"
        "{\n"
        "  printf 'cwd=%s\\n' \"$PWD\"\n"
        "  printf 'home=%s\\n' \"$HOME\"\n"
        "  printf 'path=%s\\n' \"$PATH\"\n"
        "  printf 'xdg_config=%s\\n' \"$XDG_CONFIG_HOME\"\n"
        "  printf 'xdg_data=%s\\n' \"$XDG_DATA_HOME\"\n"
        "  printf 'xdg_cache=%s\\n' \"$XDG_CACHE_HOME\"\n"
        "  printf 'tmpdir=%s\\n' \"$TMPDIR\"\n"
        "  printf 'node_options=%s\\n' \"${NODE_OPTIONS:-}\"\n"
        "  printf 'project=%s\\n' \"$VERCEL_PROJECT_ID\"\n"
        "  printf 'org=%s\\n' \"$VERCEL_ORG_ID\"\n"
        "  printf 'arg=%s\\n' \"$@\"\n"
        f"}} > {record!s}\n",
    )
    return repo, fake_vercel, record


def _write_approval(
    path: Path,
    *,
    repo: Path,
    commit: str,
    vercel_bin: Path,
    issued_at: datetime | None = None,
    expires_at: datetime | None = None,
    approval_path: Path | None = None,
    target_url: str = "https://mcp-trust.vercel.app",
    branch: str = "main",
    node_bin: Path = NODE_BIN,
) -> None:
    now = datetime.now(tz=UTC)
    issued_at = issued_at or now - timedelta(seconds=5)
    expires_at = expires_at or now + timedelta(minutes=5)
    candidate_copy = path.parent / f"{path.stem}-candidate"
    package_path = path.parent / f"{path.stem}-package"
    for old in (candidate_copy, package_path):
        if old.exists():
            for item in old.rglob("*"):
                item.chmod(0o700 if item.is_dir() else 0o600)
            old.chmod(0o700)
            shutil.rmtree(old)
    shutil.copytree(
        repo / "site",
        candidate_copy,
        ignore=shutil.ignore_patterns(".vercel"),
    )
    publication_payload = PUBLICATION_TEST_HELPERS._approval_payload(candidate_copy)
    publication_issued = now - timedelta(seconds=10)
    provider = publication_payload["provider_prepublication"]
    rollback = json.loads((candidate_copy / "SITE_CANDIDATE.json").read_text())["rollback"]
    target = rollback["production_target"]
    provider.update(
        {
            "observed_at": (now - timedelta(seconds=15)).isoformat(),
            "alias": target["alias"],
            "deployment_id": target["deployment_id"],
            "immutable_deployment_url": target["immutable_deployment_url"],
            "project_id": target["project_id"],
            "team_id": target["team_id"],
            "source_revision": target["source_revision"],
            "source_tree": target["source_tree"],
            "public_tree_digest": target["public_tree_digest"],
        }
    )
    provider.pop("receipt_digest", None)
    provider["receipt_digest"] = "sha256:" + hashlib.sha256(
        _canonical_bytes(provider)
    ).hexdigest()
    publication_payload["issued_at"] = publication_issued.isoformat()
    publication_payload["expires_at"] = (publication_issued + timedelta(minutes=45)).isoformat()
    publication_payload["operator_acceptance"]["accepted_at"] = (
        publication_issued - timedelta(seconds=1)
    ).isoformat()
    publication_payload["rollback"].update(
        {
            "embedded_candidate_rollback_receipt": rollback["receipt_digest"],
            "prepublication_revalidation_receipt": provider["receipt_digest"],
            "immediate_previous_deployment_id": target["deployment_id"],
        }
    )
    publication_approval = path.parent / f"{path.stem}-content.json"
    PUBLICATION_TEST_HELPERS._resign(publication_payload, publication_approval)
    PUBLICATION_TEST_HELPERS.build_publication_package(
        candidate_path=candidate_copy,
        approval_path=publication_approval,
        output_path=package_path,
        now=now,
    )
    # Production output is deliberately read-only. Restore fixture ownership
    # permissions so pytest can remove its task-owned temporary directory.
    for item in package_path.rglob("*"):
        item.chmod(0o700 if item.is_dir() else 0o600)
    package_path.chmod(0o700)
    package_manifest_path = package_path / "PUBLICATION_PACKAGE.json"
    package_manifest = json.loads(package_manifest_path.read_text())
    payload = {
        "schema": "McpTrustProductionDeployAuthorizationV4",
        "receipt_id": "security-test-receipt",
        "repository": str(repo.resolve()),
        "branch": branch,
        "commit": commit,
        "target_url": target_url,
        "vercel_project_id": PROJECT_ID,
        "vercel_org_id": ORG_ID,
        "vercel_invocation_path": str(vercel_bin.absolute()),
        "vercel_bin": str(vercel_bin.resolve()),
        "vercel_sha256": hashlib.sha256(vercel_bin.read_bytes()).hexdigest(),
        "node_invocation_path": str(node_bin.absolute()),
        "node_bin": str(node_bin.resolve()),
        "node_sha256": hashlib.sha256(node_bin.read_bytes()).hexdigest(),
        "python_invocation_path": str(PYTHON_BIN.absolute()),
        "python_bin": str(PYTHON_BIN.resolve()),
        "python_sha256": hashlib.sha256(PYTHON_BIN.read_bytes()).hexdigest(),
        "publication_verifier_path": str(
            (repo / "scripts/build_publication_package.py").resolve()
        ),
        "publication_verifier_sha256": hashlib.sha256(
            (repo / "scripts/build_publication_package.py").read_bytes()
        ).hexdigest(),
        "approval_path": str((approval_path or path).resolve()),
        "output_path": str((repo / "site").resolve()),
        "output_sha256": _tree_sha256(repo / "site"),
        "issued_at": issued_at.isoformat().replace("+00:00", "Z"),
        "expires_at": expires_at.isoformat().replace("+00:00", "Z"),
        "publication_package_path": str(package_path.resolve()),
        "publication_package_manifest_sha256": "sha256:"
        + hashlib.sha256(package_manifest_path.read_bytes()).hexdigest(),
        "publication_package_receipt_digest": package_manifest["receipt_digest"],
        "publication_approval_path": str(publication_approval.resolve()),
        "publication_approval_sha256": "sha256:"
        + hashlib.sha256(publication_approval.read_bytes()).hexdigest(),
        "publication_approval_receipt_digest": publication_payload["receipt_digest"],
        "provider_prepublication_receipt_digest": provider["receipt_digest"],
        "operator_acceptance_statement_sha256": publication_payload[
            "operator_acceptance"
        ]["statement_sha256"],
    }
    site_manifest = json.loads((repo / "site/SITE_CANDIDATE.json").read_text())
    rollback_path = repo.parent / "prior-site"
    rollback_manifest = json.loads((rollback_path / "SITE_CANDIDATE.json").read_text())
    payload["site_candidate_receipt_digest"] = site_manifest["receipt_digest"]
    payload["site_candidate_content_digest"] = site_manifest["content"]["digest"]
    payload["implementation_revision"] = site_manifest["implementation_binding"]["revision"]
    payload["implementation_source_tree_digest"] = site_manifest["implementation_binding"][
        "source_tree_digest"
    ]
    payload["rollback_artifact_path"] = str(rollback_path.resolve())
    payload["rollback_site_candidate_receipt_digest"] = rollback_manifest["receipt_digest"]
    payload["rollback_site_candidate_content_digest"] = rollback_manifest["content"]["digest"]
    payload["approval_receipt_digest"] = "sha256:" + hashlib.sha256(
        _canonical_bytes(payload)
    ).hexdigest()
    path.write_bytes(_canonical_bytes(payload))
    path.chmod(0o600)


def _deploy_command(
    repo: Path,
    approval: Path,
    vercel_bin: Path,
    *,
    commit: str | None = None,
    target_url: str = "https://mcp-trust.vercel.app",
    node_bin: Path = NODE_BIN,
) -> list[str]:
    return [
        "/bin/bash",
        str(repo / "scripts/deploy_production.sh"),
        "--expected-repo",
        str(repo.resolve()),
        "--expected-commit",
        commit or _git(repo, "rev-parse", "HEAD"),
        "--target-url",
        target_url,
        "--project-id",
        PROJECT_ID,
        "--org-id",
        ORG_ID,
        "--approval",
        str(approval),
        "--vercel-bin",
        str(vercel_bin),
        "--node-bin",
        str(node_bin),
        "--python-bin",
        str(PYTHON_BIN),
        "--expected-output-sha256",
        _tree_sha256(repo / "site"),
        "--rollback-artifact",
        str((repo.parent / "prior-site").resolve()),
        "--publication-package",
        str((approval.parent / f"{approval.stem}-package").resolve()),
        "--publication-approval",
        str((approval.parent / f"{approval.stem}-content.json").resolve()),
    ]


def _deploy_env(tmp_path: Path, record: Path) -> dict[str, str]:
    env = os.environ.copy()
    for key in ("XPC_SERVICE_NAME", "LAUNCH_JOBKEY_LABEL", "MCP_TRUST_AUTO_DEPLOY"):
        env.pop(key, None)
    # deploy_production.sh rejects every VERCEL_*/NOW_* except VERCEL_TOKEN, and
    # reports whichever it meets FIRST. Any such variable inherited from the
    # developer's shell therefore shadows the one a test injects, and the case
    # fails on the reported name while the guard is working correctly. Observed
    # 2026-07-18: a Claude Code Vercel plugin exports VERCEL_PLUGIN_BOOTSTRAP_HINTS
    # and turned 36 cases red. Strip the whole surface so the harness owns it.
    for key in [k for k in env if k.startswith(("VERCEL_", "NOW_"))]:
        env.pop(key, None)
    env.update(
        {
            "HOME": str(tmp_path / "home"),
            "XDG_CACHE_HOME": str(tmp_path / "cache"),
            "UV_CACHE_DIR": str(tmp_path / "uv-cache"),
            "VERCEL_TOKEN": "fake-test-token",
        }
    )
    return env


def _record_values(record: Path) -> dict[str, list[str]]:
    values: dict[str, list[str]] = {}
    for line in record.read_text(encoding="utf-8").splitlines():
        key, value = line.split("=", 1)
        values.setdefault(key, []).append(value)
    return values


def test_refresh_and_scheduler_have_no_deployment_authority() -> None:
    refresh = REFRESH.read_text(encoding="utf-8")
    plist = PLIST.read_text(encoding="utf-8")
    installer = INSTALLER.read_text(encoding="utf-8")
    assert "vercel deploy" not in refresh
    assert "MCP_TRUST_AUTO_DEPLOY" not in plist
    assert '--engine-materialization "${ENGINE_MATERIALIZATION_RECEIPT}"' in refresh
    assert '--host-capacity "${HOST_CAPACITY_RECEIPT}"' in refresh
    assert "launchctl load" not in installer
    assert "launchctl bootstrap" not in installer
    assert '"${LAUNCHCTL_BIN}" disable' in installer
    assert DEPLOY.exists()


def test_refresh_schedule_is_monday_at_0900_local() -> None:
    schedule = plistlib.loads(PLIST.read_bytes())["StartCalendarInterval"]
    assert schedule == {"Weekday": 1, "Hour": 9, "Minute": 0}


def test_deploy_doc_names_current_authorization_schema_and_bound_tools() -> None:
    validator = VALIDATOR.read_text(encoding="utf-8")
    schema_match = re.search(r'^SCHEMA = "([^"]+)"$', validator, flags=re.MULTILINE)
    assert schema_match is not None

    documentation = DEPLOY_DOC.read_text(encoding="utf-8")
    assert f"`{schema_match.group(1)}`" in documentation
    assert "Vercel, Node, Python, and publication-verifier" in documentation


def test_refresh_rejects_legacy_auto_deploy_before_prerequisites(tmp_path: Path) -> None:
    fake_bin = tmp_path / "bin"
    fake_bin.mkdir()
    for name in ("docker", "uv", "vercel"):
        _write_executable(fake_bin / name, f'#!/bin/sh\necho {name} >> "$CALLS"\nexit 99\n')
    calls = tmp_path / "calls"
    env = os.environ.copy()
    env.update(
        {
            "PATH": f"{fake_bin}:/usr/bin:/bin",
            "CALLS": str(calls),
            "MCP_TRUST_AUTO_DEPLOY": "1",
            "HOME": str(tmp_path / "home"),
            "UV_CACHE_DIR": str(tmp_path / "uv-cache"),
        }
    )
    result = _run(["bash", str(REFRESH)], cwd=ROOT, env=env, check=False)
    assert result.returncode != 0
    assert "no longer authorizes deployment" in result.stdout + result.stderr
    assert not calls.exists()


def test_installer_writes_disabled_refresh_only_plist(tmp_path: Path) -> None:
    home = tmp_path / "home"
    launchctl = tmp_path / "fake-launchctl"
    record = tmp_path / "launchctl.txt"
    test_launchd = tmp_path / "launchd"
    test_launchd.mkdir()
    shutil.copy2(PLIST, test_launchd / PLIST.name)
    test_installer = test_launchd / INSTALLER.name
    installer_text = INSTALLER.read_text(encoding="utf-8").replace(
        'LAUNCHCTL_BIN="/bin/launchctl"',
        f'LAUNCHCTL_BIN="{launchctl}"',
    )
    assert installer_text != INSTALLER.read_text(encoding="utf-8")
    test_installer.write_text(installer_text, encoding="utf-8")
    test_installer.chmod(INSTALLER.stat().st_mode)
    hostile_bin = tmp_path / "hostile-bin"
    hostile_bin.mkdir()
    hostile_calls = tmp_path / "hostile-calls.txt"
    for command in ("dirname", "id", "mkdir", "sed", "plutil", "launchctl"):
        _write_executable(
            hostile_bin / command,
            f'#!/bin/sh\nprintf "%s\\n" "{command}" >> "$HOSTILE_CALLS"\nexit 99\n',
        )
    _write_executable(
        launchctl,
        "#!/bin/sh\n"
        'printf \'%s\\n\' "$*" >> "$FAKE_LAUNCHCTL_RECORD"\n'
        'if [ "$1" = print ]; then exit 1; fi\n'
        'if [ "$1" = print-disabled ]; then '
        "printf '\"com.d.mcp-trust-refresh\" => disabled\\n'; fi\n",
    )
    env = os.environ.copy()
    env.update(
        {
            "HOME": str(home),
            "MCP_TRUST_LAUNCHCTL_BIN": str(hostile_bin / "launchctl"),
            "FAKE_LAUNCHCTL_RECORD": str(record),
            "MCP_TRUST_AUTO_DEPLOY": "1",
            "HOSTILE_CALLS": str(hostile_calls),
            "PATH": str(hostile_bin),
        }
    )
    result = _run(["/bin/bash", str(test_installer)], cwd=ROOT, env=env)
    installed = home / "Library/LaunchAgents/com.d.mcp-trust-refresh.plist"
    text = installed.read_text(encoding="utf-8")
    installed_path = plistlib.loads(installed.read_bytes())["EnvironmentVariables"]["PATH"]
    actions = record.read_text(encoding="utf-8")
    assert "MCP_TRUST_AUTO_DEPLOY" not in text
    assert "deploy_production" not in text
    assert "refresh_and_publish.sh" in text
    assert installed_path == ("/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin")
    assert str(hostile_bin) not in installed_path
    assert not hostile_calls.exists()
    assert "disable gui/" in actions
    assert "bootout gui/" in actions
    assert "load" not in actions
    assert "bootstrap" not in actions
    assert "Defined schedule: weekly, Monday 09:00 (local)." in result.stdout


@pytest.mark.parametrize(
    ("mutation", "expected"),
    [
        ("missing", "exact publication package"),
        ("pending", "exact publication package"),
        ("rollback_unknown", "exact publication package"),
        ("rollback_mismatch", "exact publication package"),
        ("retained_tamper", "rollback artifact content digest mismatch"),
        ("duplicate_key", "exact publication package"),
        ("implementation_missing", "exact publication package"),
        ("implementation_revision", "exact publication package"),
        ("implementation_tree", "exact publication package"),
        ("readback_missing", "exact publication package"),
        ("readback_invalid_route", "exact publication package"),
    ],
)
def test_deploy_rejects_unqualified_site_candidate(
    tmp_path: Path, mutation: str, expected: str
) -> None:
    repo, vercel_bin, record = _make_deploy_repo(tmp_path)
    commit = _git(repo, "rev-parse", "HEAD")
    approval = tmp_path / "approval.json"
    _write_approval(approval, repo=repo, commit=commit, vercel_bin=vercel_bin)
    manifest_path = repo / "site/SITE_CANDIDATE.json"
    if mutation == "missing":
        manifest_path.unlink()
    elif mutation == "retained_tamper":
        (repo.parent / "prior-site/index.html").write_text("tampered\n", encoding="utf-8")
    elif mutation == "duplicate_key":
        manifest_path.write_text(
            manifest_path.read_text().replace(
                '"schema":"McpTrustSiteCandidateV2"',
                '"schema":"McpTrustSiteCandidateV2","schema":"McpTrustSiteCandidateV2"',
                1,
            ),
            encoding="utf-8",
        )
    elif mutation == "readback_invalid_route":
        invalid_page = repo / "site/ui/bad slug/index.html"
        invalid_page.parent.mkdir(parents=True)
        invalid_page.write_text("invalid route\n", encoding="utf-8")
        _write_deployable_site_candidate(
            repo / "site",
            implementation_revision=json.loads(manifest_path.read_text())["implementation_binding"][
                "revision"
            ],
            implementation_tree_digest=json.loads(manifest_path.read_text())[
                "implementation_binding"
            ]["source_tree_digest"],
        )
    else:
        manifest = json.loads(manifest_path.read_text())
        if mutation == "pending":
            manifest["state"] = "REVIEW_ONLY_PENDING_SANITIZED_REACCEPTANCE"
            manifest["publication_allowed"] = False
            manifest["deployment_allowed"] = False
        elif mutation == "rollback_unknown":
            manifest["rollback"] = {
                "state": "UNKNOWN",
                "reason": "no-prior-immutable-site-candidate-bound",
            }
        elif mutation == "implementation_missing":
            manifest.pop("implementation_binding")
        elif mutation == "implementation_revision":
            manifest["implementation_binding"]["revision"] = "f" * 40
        elif mutation == "implementation_tree":
            manifest["implementation_binding"]["source_tree_digest"] = "sha256:" + "f" * 64
        elif mutation == "readback_missing":
            manifest.pop("public_readback")
        else:
            manifest["rollback"]["production_target"]["deployment_id"] = "dpl_substituted"
        manifest.pop("receipt_digest")
        manifest["receipt_digest"] = (
            "sha256:" + hashlib.sha256(_canonical_bytes(manifest)).hexdigest()
        )
        manifest_path.write_bytes(_canonical_bytes(manifest))
    result = _run(
        _deploy_command(repo, approval, vercel_bin),
        cwd=repo,
        env=_deploy_env(tmp_path, record),
        check=False,
    )
    assert result.returncode != 0
    assert expected in result.stdout + result.stderr
    assert not record.exists()


@pytest.mark.parametrize(
    ("mutation", "expected"),
    [
        ("scheduler", "scheduler context"),
        ("detached", "detached HEAD"),
        ("feature_branch", "approved branch"),
        ("dirty", "worktree is not clean"),
        ("untracked", "worktree is not clean"),
        ("sha_mismatch", "HEAD does not match"),
        ("target_substitution", "production target"),
        ("project_substitution", "approved production project"),
        ("org_substitution", "approved production organization"),
        ("remote_substitution", "origin fetch URL"),
        ("expected_repo_substitution", "repository root"),
        ("output_substitution", "exact publication package"),
        ("output_symlink", "publication candidate contains a symlink"),
        ("output_root_symlink", "output root must not be a symlink"),
        ("rollback_same_as_output", "distinct from and outside current output"),
        ("rollback_contains_output", "distinct from and outside current output"),
        ("rollback_symlink", "rollback artifact path must not contain a symlink"),
        ("project_link_substitution", "project link does not match"),
        ("tool_digest_substitution", "vercel_sha256 mismatch"),
        ("stale_approval", "expired"),
        ("missing_approval", "approval file is missing"),
        ("copied_approval", "publication_package_path"),
        ("mismatched_approval", "approval branch mismatch"),
        ("missing_upstream", "upstream"),
        ("ahead", "ahead/behind"),
        ("behind", "ahead/behind"),
    ],
)
def test_manual_deploy_fails_closed(tmp_path: Path, mutation: str, expected: str) -> None:
    repo, vercel_bin, record = _make_deploy_repo(tmp_path)
    commit = _git(repo, "rev-parse", "HEAD")
    approval = tmp_path / "approval.json"
    _write_approval(approval, repo=repo, commit=commit, vercel_bin=vercel_bin)
    env = _deploy_env(tmp_path, record)
    command = _deploy_command(repo, approval, vercel_bin)

    if mutation == "scheduler":
        env["XPC_SERVICE_NAME"] = "com.d.mcp-trust-refresh"
    elif mutation == "detached":
        _git(repo, "checkout", "--detach", commit)
    elif mutation == "feature_branch":
        _git(repo, "checkout", "-b", "feature")
    elif mutation == "dirty":
        (repo / ".gitignore").write_text("site/\n.vercel/\n# dirty\n", encoding="utf-8")
    elif mutation == "untracked":
        (repo / "untracked.txt").write_text("dirty\n", encoding="utf-8")
    elif mutation == "sha_mismatch":
        command = _deploy_command(repo, approval, vercel_bin, commit="0" * 40)
    elif mutation == "target_substitution":
        command = _deploy_command(repo, approval, vercel_bin, target_url="https://attacker.invalid")
    elif mutation == "project_substitution":
        command[command.index("--project-id") + 1] = "prj_attacker"
    elif mutation == "org_substitution":
        command[command.index("--org-id") + 1] = "team_attacker"
    elif mutation == "remote_substitution":
        _git(repo, "remote", "set-url", "origin", str(tmp_path / "upstream.git"))
    elif mutation == "expected_repo_substitution":
        command[command.index("--expected-repo") + 1] = str(tmp_path)
    elif mutation == "output_substitution":
        (repo / "site/vercel.json").write_text('{"rewritten": true}\n', encoding="utf-8")
    elif mutation == "output_symlink":
        (repo / "site/leak").symlink_to(repo / ".git/config")
    elif mutation == "output_root_symlink":
        real_site = tmp_path / "real-site"
        (repo / "site").rename(real_site)
        with (repo / ".git/info/exclude").open("a", encoding="utf-8") as handle:
            handle.write("site\n")
        (repo / "site").symlink_to(real_site)
    elif mutation == "rollback_same_as_output":
        command[command.index("--rollback-artifact") + 1] = str((repo / "site").resolve())
    elif mutation == "rollback_contains_output":
        command[command.index("--rollback-artifact") + 1] = str(repo.resolve())
    elif mutation == "rollback_symlink":
        rollback_link = tmp_path / "prior-site-link"
        rollback_link.symlink_to(repo.parent / "prior-site", target_is_directory=True)
        command[command.index("--rollback-artifact") + 1] = str(rollback_link)
    elif mutation == "project_link_substitution":
        (repo / ".vercel/project.json").write_text(
            json.dumps(
                {
                    "projectId": "prj_attacker",
                    "orgId": ORG_ID,
                    "projectName": "mcp-trust",
                }
            ),
            encoding="utf-8",
        )
    elif mutation == "tool_digest_substitution":
        vercel_bin.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
        vercel_bin.chmod(0o700)
    elif mutation == "stale_approval":
        old = datetime.now(tz=UTC) - timedelta(hours=1)
        _write_approval(
            approval,
            repo=repo,
            commit=commit,
            vercel_bin=vercel_bin,
            issued_at=old,
            expires_at=old + timedelta(minutes=5),
        )
    elif mutation == "missing_approval":
        approval.unlink()
    elif mutation == "copied_approval":
        original = tmp_path / "original.json"
        _write_approval(original, repo=repo, commit=commit, vercel_bin=vercel_bin)
        shutil.copy2(original, approval)
    elif mutation == "mismatched_approval":
        _write_approval(
            approval,
            repo=repo,
            commit=commit,
            vercel_bin=vercel_bin,
            branch="feature",
        )
    elif mutation == "missing_upstream":
        _git(repo, "branch", "--unset-upstream")
    elif mutation == "ahead":
        (repo / "ahead.txt").write_text("ahead\n", encoding="utf-8")
        _git(repo, "add", "ahead.txt")
        _git(repo, "commit", "-m", "ahead")
        new_commit = _git(repo, "rev-parse", "HEAD")
        _write_approval(approval, repo=repo, commit=new_commit, vercel_bin=vercel_bin)
        command = _deploy_command(repo, approval, vercel_bin, commit=new_commit)
    elif mutation == "behind":
        _git(repo, "commit", "--allow-empty", "-m", "remote-ahead")
        remote_commit = _git(repo, "rev-parse", "HEAD")
        _git(repo, "update-ref", "refs/remotes/origin/main", remote_commit)
        _git(repo, "reset", "--hard", commit)

    result = _run(command, cwd=repo, env=env, check=False)
    assert result.returncode != 0
    assert expected in result.stdout + result.stderr
    assert not record.exists()


def test_path_injection_cannot_replace_approved_deployment_tool(tmp_path: Path) -> None:
    repo, vercel_bin, record = _make_deploy_repo(tmp_path)
    commit = _git(repo, "rev-parse", "HEAD")
    approval = tmp_path / "approval.json"
    _write_approval(approval, repo=repo, commit=commit, vercel_bin=vercel_bin)
    rogue_dir = tmp_path / "rogue-bin"
    rogue_dir.mkdir()
    rogue_record = tmp_path / "rogue.txt"
    _write_executable(
        rogue_dir / "vercel",
        '#!/bin/sh\nprintf called > "$ROGUE_RECORD"\n',
    )
    env = _deploy_env(tmp_path, record)
    env["PATH"] = f"{rogue_dir}:{env['PATH']}"
    env["ROGUE_RECORD"] = str(rogue_record)
    result = _run_with_tty(
        _deploy_command(repo, approval, vercel_bin),
        cwd=repo,
        env=env,
        confirmation="DEPLOY_MCP_TRUST_PRODUCTION",
    )
    assert result.returncode == 0, result.stdout + result.stderr
    assert record.exists()
    assert not rogue_record.exists()


def test_direct_invocation_cannot_select_ambient_bash(tmp_path: Path) -> None:
    repo, vercel_bin, record = _make_deploy_repo(tmp_path)
    commit = _git(repo, "rev-parse", "HEAD")
    approval = tmp_path / "approval.json"
    _write_approval(approval, repo=repo, commit=commit, vercel_bin=vercel_bin)
    rogue_dir = tmp_path / "rogue-bin"
    rogue_dir.mkdir()
    rogue_record = tmp_path / "rogue-bash.txt"
    _write_executable(
        rogue_dir / "bash",
        f"#!/bin/sh\nprintf called > {rogue_record!s}\nexit 99\n",
    )
    env = _deploy_env(tmp_path, record)
    env["PATH"] = f"{rogue_dir}:{env.get('PATH', '')}"
    result = _run(
        _deploy_command(repo, approval, vercel_bin)[1:],
        cwd=repo,
        env=env,
        check=False,
    )
    assert result.returncode != 0
    assert "interactive TTY" in result.stderr
    assert not rogue_record.exists()
    assert not record.exists()


def test_fully_authorized_manual_deploy_reaches_only_fake_sink(tmp_path: Path) -> None:
    repo, vercel_bin, record = _make_deploy_repo(tmp_path)
    commit = _git(repo, "rev-parse", "HEAD")
    approval = tmp_path / "approval.json"
    _write_approval(approval, repo=repo, commit=commit, vercel_bin=vercel_bin)
    env = _deploy_env(tmp_path, record)
    env["NODE_OPTIONS"] = "--require=/private/tmp/hostile-node-option.js"
    result = _run_with_tty(
        _deploy_command(repo, approval, vercel_bin),
        cwd=repo,
        env=env,
        confirmation="DEPLOY_MCP_TRUST_PRODUCTION",
    )
    assert result.returncode == 0, result.stdout + result.stderr
    values = _record_values(record)
    assert values["cwd"] == [str((repo / "site").resolve())]
    assert values["project"] == [PROJECT_ID]
    assert values["org"] == [ORG_ID]
    assert values["home"][0].startswith("/tmp/mcp-trust-vercel.")
    runtime_root = str(Path(values["home"][0]).parent)
    assert values["path"] == ["/usr/bin:/bin"]
    assert values["xdg_config"] == [f"{runtime_root}/config"]
    assert values["xdg_data"] == [f"{runtime_root}/data"]
    assert values["xdg_cache"] == [f"{runtime_root}/cache"]
    assert values["tmpdir"] == [f"{runtime_root}/tmp"]
    assert values["node_options"] == [""]
    assert values["arg"] == [
        "deploy",
        ".",
        "--yes",
        "--cwd",
        str((repo / "site").resolve()),
        "--project",
        PROJECT_ID,
        "--scope",
        ORG_ID,
        "--target",
        "production",
    ]


def test_fully_authorized_non_tty_execution_is_rejected(tmp_path: Path) -> None:
    repo, vercel_bin, record = _make_deploy_repo(tmp_path)
    commit = _git(repo, "rev-parse", "HEAD")
    approval = tmp_path / "approval.json"
    _write_approval(approval, repo=repo, commit=commit, vercel_bin=vercel_bin)
    result = _run(
        _deploy_command(repo, approval, vercel_bin),
        cwd=repo,
        env=_deploy_env(tmp_path, record),
        check=False,
    )
    assert result.returncode != 0
    assert "interactive TTY" in result.stderr
    assert not record.exists()


def test_post_confirmation_revalidation_catches_output_change(tmp_path: Path) -> None:
    repo, vercel_bin, record = _make_deploy_repo(tmp_path)
    commit = _git(repo, "rev-parse", "HEAD")
    approval = tmp_path / "approval.json"
    _write_approval(approval, repo=repo, commit=commit, vercel_bin=vercel_bin)

    def mutate_output() -> None:
        (repo / "site/vercel.json").write_text('{"changed": true}\n', encoding="utf-8")

    result = _run_with_tty(
        _deploy_command(repo, approval, vercel_bin),
        cwd=repo,
        env=_deploy_env(tmp_path, record),
        confirmation="DEPLOY_MCP_TRUST_PRODUCTION",
        before_confirmation=mutate_output,
    )
    assert result.returncode != 0
    assert "exact publication package" in result.stdout
    assert not record.exists()


@pytest.mark.parametrize(
    ("mutation", "expected"),
    [
        ("missing_output_link", "approval output_sha256 mismatch"),
        ("wrong_output_link", "approval output_sha256 mismatch"),
        ("symlinked_output_link", "publication candidate contains a symlink"),
        ("legacy_output_link", "exact publication package"),
        ("ancestor_link", "unexpected ambient Vercel binding source"),
    ],
)
def test_deployment_binding_sources_fail_closed(
    tmp_path: Path, mutation: str, expected: str
) -> None:
    repo, vercel_bin, record = _make_deploy_repo(tmp_path)
    commit = _git(repo, "rev-parse", "HEAD")
    approval = tmp_path / "approval.json"
    _write_approval(approval, repo=repo, commit=commit, vercel_bin=vercel_bin)
    output_link = repo / "site/.vercel/project.json"
    if mutation == "missing_output_link":
        output_link.unlink()
    elif mutation == "wrong_output_link":
        output_link.write_text(
            json.dumps({"projectId": "prj_attacker", "orgId": ORG_ID}),
            encoding="utf-8",
        )
    elif mutation == "symlinked_output_link":
        output_link.unlink()
        output_link.symlink_to(repo / ".vercel/project.json")
    elif mutation == "legacy_output_link":
        legacy = repo / "site/.now"
        legacy.mkdir()
        (legacy / "project.json").write_text("{}\n", encoding="utf-8")
    elif mutation == "ancestor_link":
        ancestor = tmp_path / ".vercel"
        ancestor.mkdir(exist_ok=True)
        (ancestor / "project.json").write_text("{}\n", encoding="utf-8")
    result = _run(
        _deploy_command(repo, approval, vercel_bin),
        cwd=repo,
        env=_deploy_env(tmp_path, record),
        check=False,
    )
    assert result.returncode != 0
    assert expected in result.stdout + result.stderr
    assert not record.exists()


@pytest.mark.parametrize(
    "name",
    [
        "VERCEL_PROJECT_ID",
        "VERCEL_ORG_ID",
        "VERCEL_SCOPE",
        "VERCEL_TARGET",
        "NOW_PROJECT_ID",
        "NOW_ORG_ID",
    ],
)
def test_inherited_provider_binding_variables_are_rejected(tmp_path: Path, name: str) -> None:
    repo, vercel_bin, record = _make_deploy_repo(tmp_path)
    commit = _git(repo, "rev-parse", "HEAD")
    approval = tmp_path / "approval.json"
    _write_approval(approval, repo=repo, commit=commit, vercel_bin=vercel_bin)
    env = _deploy_env(tmp_path, record)
    env[name] = "attacker"
    result = _run(
        _deploy_command(repo, approval, vercel_bin),
        cwd=repo,
        env=env,
        check=False,
    )
    assert result.returncode != 0
    assert f"ambient Vercel binding variable is forbidden: {name}" in result.stderr
    assert not record.exists()


def test_post_confirmation_revalidation_catches_link_and_tool_changes(
    tmp_path: Path,
) -> None:
    for kind in ("link", "tool"):
        case = tmp_path / kind
        case.mkdir()
        repo, vercel_bin, record = _make_deploy_repo(case)
        commit = _git(repo, "rev-parse", "HEAD")
        approval = case / "approval.json"
        _write_approval(approval, repo=repo, commit=commit, vercel_bin=vercel_bin)

        def mutate(
            kind: str = kind,
            repo: Path = repo,
            vercel_bin: Path = vercel_bin,
        ) -> None:
            if kind == "link":
                (repo / "site/.vercel/project.json").write_text(
                    json.dumps({"projectId": "prj_attacker", "orgId": ORG_ID}),
                    encoding="utf-8",
                )
            else:
                vercel_bin.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
                vercel_bin.chmod(0o700)

        result = _run_with_tty(
            _deploy_command(repo, approval, vercel_bin),
            cwd=repo,
            env=_deploy_env(case, record),
            confirmation="DEPLOY_MCP_TRUST_PRODUCTION",
            before_confirmation=mutate,
        )
        assert result.returncode != 0
        assert not record.exists()


@pytest.mark.parametrize("kind", ["approval", "node"])
def test_post_confirmation_revalidation_catches_approval_and_node_changes(
    tmp_path: Path, kind: str
) -> None:
    repo, vercel_bin, record = _make_deploy_repo(tmp_path)
    commit = _git(repo, "rev-parse", "HEAD")
    node_bin = tmp_path / "fake-node"
    _write_executable(node_bin, '#!/bin/sh\nexec "$@"\n')
    approval = tmp_path / "approval.json"
    _write_approval(
        approval,
        repo=repo,
        commit=commit,
        vercel_bin=vercel_bin,
        node_bin=node_bin,
    )

    def mutate() -> None:
        if kind == "approval":
            data = json.loads(approval.read_text(encoding="utf-8"))
            data["target_url"] = "https://attacker.invalid"
            approval.write_text(json.dumps(data), encoding="utf-8")
        else:
            node_bin.write_text("#!/bin/sh\nexit 99\n", encoding="utf-8")
            node_bin.chmod(0o700)

    result = _run_with_tty(
        _deploy_command(repo, approval, vercel_bin, node_bin=node_bin),
        cwd=repo,
        env=_deploy_env(tmp_path, record),
        confirmation="DEPLOY_MCP_TRUST_PRODUCTION",
        before_confirmation=mutate,
    )
    assert result.returncode != 0
    assert not record.exists()


def test_tty_timeout_default_exceeds_the_happy_path_cost(monkeypatch):
    """Regression: the budget was 10s while a passing run measures ~14s, so the
    suite went red on load without ever reaching a security assertion."""
    monkeypatch.delenv(TTY_TIMEOUT_ENV, raising=False)
    assert _tty_timeout_seconds() == TTY_TIMEOUT_DEFAULT
    assert _tty_timeout_seconds() > 14


def test_tty_timeout_honours_an_override(monkeypatch):
    monkeypatch.setenv(TTY_TIMEOUT_ENV, "180")
    assert _tty_timeout_seconds() == 180.0


@pytest.mark.parametrize("bad", ["", "   ", "abc", "0", "-5"])
def test_tty_timeout_falls_back_on_an_unusable_override(monkeypatch, bad):
    """A malformed or non-positive override must not silently turn every
    deployment test into an immediate failure."""
    monkeypatch.setenv(TTY_TIMEOUT_ENV, bad)
    assert _tty_timeout_seconds() == TTY_TIMEOUT_DEFAULT
