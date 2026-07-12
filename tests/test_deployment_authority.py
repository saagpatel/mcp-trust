from __future__ import annotations

import hashlib
import json
import os
import pty
import select
import shutil
import stat
import subprocess
import time
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
REFRESH = ROOT / "scripts/refresh_and_publish.sh"
DEPLOY = ROOT / "scripts/deploy_production.sh"
VALIDATOR = ROOT / "scripts/validate_deploy_authorization.py"
PLIST = ROOT / "deploy/launchd/com.d.mcp-trust-refresh.plist"
INSTALLER = ROOT / "deploy/launchd/install.sh"
PROJECT_ID = "prj_ugC28dxX9xAGYnYjIkQXigxZB672"
ORG_ID = "team_nZORCFEbaw3I8iSUrA2cWMJB"
ORIGIN_URL = "https://github.com/saagpatel/mcp-trust.git"
NODE_BIN = Path("/bin/sh")


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
    deadline = time.monotonic() + 10
    confirmation_sent = False
    while process.poll() is None:
        if time.monotonic() > deadline:
            process.kill()
            raise AssertionError("deployment test process did not exit within 10 seconds")
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
    (repo / "site").mkdir()
    (repo / "site/vercel.json").write_text("{}\n", encoding="utf-8")
    (repo / ".gitignore").write_text("site/\n.vercel/\n", encoding="utf-8")
    (repo / ".vercel").mkdir()
    (repo / "site/.vercel").mkdir()
    link = json.dumps(
        {"projectId": PROJECT_ID, "orgId": ORG_ID, "projectName": "mcp-trust"}
    )
    (repo / ".vercel/project.json").write_text(link, encoding="utf-8")
    (repo / "site/.vercel/project.json").write_text(link, encoding="utf-8")
    _git(repo, "add", ".")
    _git(repo, "commit", "-m", "fixture")
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
    payload = {
        "schema": "McpTrustProductionDeployAuthorizationV2",
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
        "approval_path": str((approval_path or path).resolve()),
        "output_path": str((repo / "site").resolve()),
        "output_sha256": _tree_sha256(repo / "site"),
        "issued_at": issued_at.isoformat().replace("+00:00", "Z"),
        "expires_at": expires_at.isoformat().replace("+00:00", "Z"),
    }
    path.write_text(json.dumps(payload), encoding="utf-8")
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
        "--expected-output-sha256",
        _tree_sha256(repo / "site"),
    ]


def _deploy_env(tmp_path: Path, record: Path) -> dict[str, str]:
    env = os.environ.copy()
    for key in ("XPC_SERVICE_NAME", "LAUNCH_JOBKEY_LABEL", "MCP_TRUST_AUTO_DEPLOY"):
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
    assert "launchctl load" not in installer
    assert "launchctl bootstrap" not in installer
    assert '"${LAUNCHCTL_BIN}" disable' in installer
    assert DEPLOY.exists()


def test_refresh_rejects_legacy_auto_deploy_before_prerequisites(tmp_path: Path) -> None:
    fake_bin = tmp_path / "bin"
    fake_bin.mkdir()
    for name in ("docker", "uv", "vercel"):
        _write_executable(fake_bin / name, f"#!/bin/sh\necho {name} >> \"$CALLS\"\nexit 99\n")
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
    _write_executable(
        launchctl,
        "#!/bin/sh\n"
        "printf '%s\\n' \"$*\" >> \"$FAKE_LAUNCHCTL_RECORD\"\n"
        "if [ \"$1\" = print ]; then exit 1; fi\n"
        "if [ \"$1\" = print-disabled ]; then "
        "printf '\"com.d.mcp-trust-refresh\" => disabled\\n'; fi\n",
    )
    env = os.environ.copy()
    env.update(
        {
            "HOME": str(home),
            "MCP_TRUST_LAUNCHCTL_BIN": str(launchctl),
            "FAKE_LAUNCHCTL_RECORD": str(record),
            "MCP_TRUST_AUTO_DEPLOY": "1",
        }
    )
    _run(["bash", str(INSTALLER)], cwd=ROOT, env=env)
    installed = home / "Library/LaunchAgents/com.d.mcp-trust-refresh.plist"
    text = installed.read_text(encoding="utf-8")
    actions = record.read_text(encoding="utf-8")
    assert "MCP_TRUST_AUTO_DEPLOY" not in text
    assert "deploy_production" not in text
    assert "refresh_and_publish.sh" in text
    assert "disable gui/" in actions
    assert "bootout gui/" in actions
    assert "load" not in actions
    assert "bootstrap" not in actions


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
        ("output_substitution", "output tree SHA-256 mismatch"),
        ("output_symlink", "deployment output contains a symlink"),
        ("output_root_symlink", "output root must not be a symlink"),
        ("project_link_substitution", "project link does not match"),
        ("tool_digest_substitution", "vercel_sha256 mismatch"),
        ("stale_approval", "expired"),
        ("missing_approval", "approval file is missing"),
        ("copied_approval", "approval_path"),
        ("mismatched_approval", "approval branch mismatch"),
        ("missing_upstream", "upstream"),
        ("ahead", "ahead/behind"),
        ("behind", "ahead/behind"),
    ],
)
def test_manual_deploy_fails_closed(
    tmp_path: Path, mutation: str, expected: str
) -> None:
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
        command = _deploy_command(
            repo, approval, vercel_bin, target_url="https://attacker.invalid"
        )
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
        "#!/bin/sh\nprintf called > \"$ROGUE_RECORD\"\n",
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
    assert values["home"][0].startswith("/private/tmp/mcp-trust-vercel.")
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
    assert "output tree SHA-256 mismatch" in result.stdout
    assert not record.exists()


@pytest.mark.parametrize(
    ("mutation", "expected"),
    [
        ("missing_output_link", "output Vercel project link is missing"),
        ("wrong_output_link", "output Vercel project link does not match"),
        ("symlinked_output_link", "deployment output contains a symlink"),
        ("legacy_output_link", "unexpected ambient Vercel binding source"),
        ("ancestor_link", "unexpected ambient Vercel binding source"),
    ],
)
def test_deployment_binding_sources_fail_closed(
    tmp_path: Path, mutation: str, expected: str
) -> None:
    repo, vercel_bin, record = _make_deploy_repo(tmp_path)
    commit = _git(repo, "rev-parse", "HEAD")
    approval = tmp_path / "approval.json"
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
    _write_approval(approval, repo=repo, commit=commit, vercel_bin=vercel_bin)
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
def test_inherited_provider_binding_variables_are_rejected(
    tmp_path: Path, name: str
) -> None:
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
    _write_executable(node_bin, "#!/bin/sh\nexec \"$@\"\n")
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
