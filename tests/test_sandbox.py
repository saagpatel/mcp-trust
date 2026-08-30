"""Tests for execution sandboxing. The wrap/select logic is pure and always
runs; actual container execution is integration-gated (needs a Docker daemon)."""

from __future__ import annotations

import json
import os
import re
import subprocess
import sys
from pathlib import Path

import pytest

from mcp_trust.core.models import ServerSource, SourceKind
from mcp_trust.engine.base import ScanError
from mcp_trust.engine.mcpaudit import MCPAuditEngine
from mcp_trust.engine.sandbox import (
    SANDBOX_RUNTIME_READBACK_CLAIM_CEILING,
    DockerSandbox,
    DockerSandboxCleanupError,
    DockerSandboxRuntimeReadbackError,
    NoSandbox,
    Sandbox,
    sandbox_server_process_digest,
    select_sandbox,
)

_IMAGE_ID = "sha256:" + "1" * 64
_CONTAINER_ID = "c" * 64


def _owned_container_inspect(
    sandbox: DockerSandbox,
    container_id: str,
    **overrides: object,
) -> str:
    container: dict[str, object] = {
        "Id": container_id,
        "Name": f"/{sandbox.container_name}",
        "Config": {"Labels": {"com.mcp-trust.scan-owner": sandbox._owner_token}},
    }
    container.update(overrides)
    return json.dumps([container])


def _runtime_runner(
    sandbox: DockerSandbox,
    *,
    container_override: dict[str, object] | None = None,
    process_override: dict[str, object] | None = None,
):  # noqa: ANN202
    present = False
    server_process_digest = ""
    image_env = ["PATH=/usr/local/bin"]
    container = {
        "Id": _CONTAINER_ID,
        "Name": f"/{sandbox.container_name}",
        "Image": _IMAGE_ID,
        "State": {"Running": True},
        "Config": {
            "Env": [
                *image_env,
                f"HOME={sandbox.workdir}",
                f"TMPDIR={sandbox.workdir}",
                *[f"{key}={value}" for key, value in sandbox.env.items()],
            ],
            "User": sandbox.user,
            "WorkingDir": sandbox.workdir,
            "Labels": {"com.mcp-trust.scan-owner": sandbox._owner_token},
        },
        "HostConfig": {
            "NetworkMode": "none",
            "ReadonlyRootfs": True,
            "CapDrop": ["ALL"],
            "SecurityOpt": ["no-new-privileges"],
            "Memory": 512 * 1024 * 1024,
            "MemorySwap": 512 * 1024 * 1024,
            "NanoCpus": 1_000_000_000,
            "PidsLimit": 256,
            "Privileged": False,
            "Binds": None,
            "Tmpfs": {sandbox.workdir: "rw,size=67108864,mode=1777"},
        },
        "Mounts": [],
    }
    if container_override:
        container.update(container_override)
    process = {
        "uid": 1000,
        "gid": 1000,
        "environment_names": sorted({"PATH", "HOME", "TMPDIR", *sandbox.env}),
        "network_interfaces": ["lo"],
        "cap_eff": "0000000000000000",
        "no_new_privs": "1",
        "root_mount_options": ["ro"],
        "workdir_mount_options": ["rw"],
        "workdir_filesystem": "tmpfs",
        "root_write_denied": True,
        "workdir_write_verified": True,
        "memory_max": str(512 * 1024 * 1024),
        "pids_max": "256",
        "cpu_quota": "100000",
        "cpu_period": "100000",
        "server_process_cmdline_digest": "pending",
        "server_process_state": "S (sleeping)",
        "same_network_namespace": True,
        "same_mount_namespace": True,
        "same_cgroup": True,
    }
    if process_override:
        process.update(process_override)

    def runner(command: list[str], **_kwargs: object) -> subprocess.CompletedProcess[str]:
        nonlocal present, server_process_digest
        if "create" in command:
            present = True
            image_index = command.index(sandbox.image)
            server_process_digest = sandbox_server_process_digest(
                command[image_index + 1], command[image_index + 2 :]
            )
            process["server_process_cmdline_digest"] = server_process_digest
            return subprocess.CompletedProcess(command, 0, _CONTAINER_ID + "\n", "")
        if "inspect" in command and "container" in command:
            return subprocess.CompletedProcess(command, 0, json.dumps([container]), "")
        if "inspect" in command and "image" in command:
            return subprocess.CompletedProcess(
                command,
                0,
                json.dumps([{"Id": _IMAGE_ID, "Config": {"Env": image_env}}]),
                "",
            )
        if "exec" in command:
            return subprocess.CompletedProcess(command, 0, json.dumps(process), "")
        if "ls" in command:
            return subprocess.CompletedProcess(
                command, 0, _CONTAINER_ID + "\n" if present else "", ""
            )
        if "rm" in command:
            present = False
            return subprocess.CompletedProcess(command, 0, _CONTAINER_ID + "\n", "")
        return subprocess.CompletedProcess(command, 0, "", "")

    return runner


def test_no_sandbox_is_passthrough() -> None:
    sb = NoSandbox()
    assert isinstance(sb, Sandbox)
    assert sb.available() is True
    assert sb.wrap("npx", ["-y", "@acme/server"]) == ("npx", ["-y", "@acme/server"])


def test_docker_wrap_runs_original_command_inside_container() -> None:
    sb = DockerSandbox(image="node:22-slim")
    cmd, args = sb.wrap("npx", ["-y", "@acme/server", "--flag"])
    assert cmd == "docker"
    # The image then the original command + args come last, in order.
    assert args[-5:] == ["node:22-slim", "npx", "-y", "@acme/server", "--flag"]


def test_docker_wrap_applies_isolation_flags() -> None:
    sandbox = DockerSandbox()
    cmd, args = sandbox.wrap("uvx", ["acme-mcp"])
    assert cmd == "docker"
    joined = " ".join(args)
    # No egress, no privileges, no caps, read-only fs, resource ceilings.
    assert "--network none" in joined
    assert "--security-opt no-new-privileges" in joined
    assert "--cap-drop ALL" in joined
    assert "--read-only" in args
    assert "--pids-limit" in args
    assert "--memory" in args
    assert "/scan:rw,size=64m,mode=1777" in args
    assert "-i" in args  # stdio transport stays open
    assert args[args.index("--name") + 1] == sandbox.container_name
    assert "com.mcp-trust.scan-owner=" in args[args.index("--label") + 1]
    # original command lands after the image
    assert args[-2:] == ["uvx", "acme-mcp"]


def test_docker_scan_identity_is_unique() -> None:
    assert DockerSandbox().container_name != DockerSandbox().container_name


def test_docker_runtime_readback_is_live_bound_and_privacy_minimized() -> None:
    secret = "must-not-appear-in-receipt-56e65a"
    sandbox = DockerSandbox(env={"API_TOKEN": secret})
    runner = _runtime_runner(sandbox)
    sandbox.prepare_owned_container("python", ["server.py"], runner=runner)

    readback = sandbox.capture_runtime_readback(runner=runner)

    assert readback["state"] == "VERIFIED"
    assert readback["image_id"] == _IMAGE_ID
    assert readback["controls"] == {key: True for key in readback["controls"]}
    assert readback["observed"]["injected_dummy_env_names"] == ["API_TOKEN"]
    assert readback["observed"]["secret_values_emitted_in_readback"] is False
    assert readback["claim_ceiling"] == SANDBOX_RUNTIME_READBACK_CLAIM_CEILING
    assert secret not in json.dumps(readback)


def test_docker_runtime_attestor_uses_same_uid_readonly_workdir_and_isolated_python() -> None:
    sandbox = DockerSandbox()
    base_runner = _runtime_runner(sandbox)
    commands: list[list[str]] = []

    def runner(command: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
        commands.append(command)
        return base_runner(command, **kwargs)

    sandbox.prepare_owned_container("python", ["server.py"], runner=runner)
    sandbox.capture_runtime_readback(runner=runner)

    attestor = next(command for command in commands if "exec" in command)
    assert attestor[:3] == ["docker", "container", "exec"]
    assert attestor[3:9] == [
        "--user",
        "1000:1000",
        "--workdir",
        "/",
        _CONTAINER_ID,
        "/opt/venv/bin/python",
    ]
    assert attestor[9:11] == ["-I", "-c"]


def test_python_isolated_mode_ignores_target_controlled_imports(tmp_path: Path) -> None:
    (tmp_path / "json.py").write_text("raise RuntimeError('target module imported')\n")
    completed = subprocess.run(
        [sys.executable, "-I", "-c", "import json; print(json.dumps({'verified': True}))"],
        cwd=tmp_path,
        text=True,
        capture_output=True,
        check=False,
    )

    assert completed.returncode == 0
    assert completed.stdout.strip() == '{"verified": true}'


def test_docker_runtime_attestor_does_not_resolve_through_container_path() -> None:
    assert DockerSandbox.attestor_executable == "/opt/venv/bin/python"
    assert DockerSandbox.attestor_command == "python"


def test_docker_runtime_attestor_requires_configured_target_user() -> None:
    sandbox = DockerSandbox(user=None)
    runner = _runtime_runner(sandbox)
    sandbox.prepare_owned_container("python", ["server.py"], runner=runner)

    with pytest.raises(DockerSandboxRuntimeReadbackError, match="configured target user"):
        sandbox.capture_runtime_readback(runner=runner)


@pytest.mark.parametrize(
    ("process_override", "failed_control"),
    [
        ({"network_interfaces": ["eth0", "lo"]}, "network_none"),
        ({"cap_eff": "0000000000000001"}, "capabilities_dropped"),
        ({"no_new_privs": "0"}, "no_new_privileges"),
        ({"root_write_denied": False}, "read_only_root"),
        ({"memory_max": str(512 * 1024 * 1024 + 1)}, "memory_limit"),
        ({"pids_max": "512"}, "pids_limit"),
        ({"uid": 65534}, "non_root_user"),
        ({"server_process_state": "Z (zombie)"}, "live_process_observed"),
        ({"same_network_namespace": False}, "shared_namespaces_and_cgroup"),
    ],
)
def test_docker_runtime_readback_rejects_false_green_process_observations(
    process_override: dict[str, object],
    failed_control: str,
) -> None:
    sandbox = DockerSandbox()
    runner = _runtime_runner(sandbox, process_override=process_override)
    sandbox.prepare_owned_container("python", ["server.py"], runner=runner)

    with pytest.raises(DockerSandboxRuntimeReadbackError) as caught:
        sandbox.capture_runtime_readback(runner=runner)

    assert caught.value.failed_controls == (failed_control,)
    assert str(caught.value).endswith(f"failed controls: {failed_control}")


def test_docker_runtime_readback_rejects_daemon_control_tampering() -> None:
    private_runtime_value = "private-runtime-network-value-7264c0"
    sandbox = DockerSandbox()
    runner = _runtime_runner(
        sandbox,
        container_override={
            "HostConfig": {
                "NetworkMode": private_runtime_value,
                "ReadonlyRootfs": True,
                "CapDrop": ["ALL"],
                "SecurityOpt": ["no-new-privileges"],
                "Memory": 512 * 1024 * 1024,
                "MemorySwap": 512 * 1024 * 1024,
                "NanoCpus": 1_000_000_000,
                "PidsLimit": 256,
                "Privileged": False,
                "Binds": None,
                "Tmpfs": {"/scan": "rw,size=67108864,mode=1777"},
            }
        },
    )
    sandbox.prepare_owned_container("python", ["server.py"], runner=runner)

    with pytest.raises(DockerSandboxRuntimeReadbackError, match="did not match") as caught:
        sandbox.capture_runtime_readback(runner=runner)

    assert caught.value.failed_controls == ("network_none",)
    assert str(caught.value).endswith("failed controls: network_none")
    assert private_runtime_value not in str(caught.value)


def test_runtime_control_diagnostics_are_sorted_allowlisted_and_deduplicated() -> None:
    private_path = "/Users/operator/private/runtime-observation"
    error = DockerSandboxRuntimeReadbackError.from_failed_controls(
        ["pids_limit", private_path, "network_none", "pids_limit", 7]
    )

    assert error.failed_controls == ("network_none", "pids_limit")
    assert str(error).endswith("failed controls: network_none, pids_limit")
    assert private_path not in str(error)


def test_malformed_runtime_value_has_no_raw_parser_exception_chain() -> None:
    private_runtime_value = "/Users/operator/private/runtime-numeric-value"
    sandbox = DockerSandbox()
    runner = _runtime_runner(
        sandbox,
        process_override={"uid": private_runtime_value},
    )
    sandbox.prepare_owned_container("python", ["server.py"], runner=runner)

    with pytest.raises(
        DockerSandboxRuntimeReadbackError, match="numeric readback is invalid"
    ) as caught:
        sandbox.capture_runtime_readback(runner=runner)

    assert caught.value.failed_controls == ()
    assert caught.value.__cause__ is None
    assert caught.value.__context__ is None
    assert private_runtime_value not in str(caught.value)


def test_invalid_attestor_json_has_no_raw_parser_exception_chain() -> None:
    private_runtime_value = "/Users/operator/private/invalid-attestor-json"
    sandbox = DockerSandbox()
    base_runner = _runtime_runner(sandbox)

    def runner(command: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
        if "exec" in command:
            return subprocess.CompletedProcess(command, 0, private_runtime_value, "")
        return base_runner(command, **kwargs)

    sandbox.prepare_owned_container("python", ["server.py"], runner=runner)
    with pytest.raises(
        DockerSandboxRuntimeReadbackError, match="attestor returned invalid JSON"
    ) as caught:
        sandbox.capture_runtime_readback(runner=runner)

    assert caught.value.failed_controls == ()
    assert caught.value.__cause__ is None
    assert caught.value.__context__ is None
    assert private_runtime_value not in str(caught.value)


def test_docker_runtime_readback_fails_closed_without_bound_attestor() -> None:
    sandbox = DockerSandbox()
    base_runner = _runtime_runner(sandbox)

    def runner(command: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
        if "exec" in command:
            assert DockerSandbox.attestor_executable in command
            return subprocess.CompletedProcess(command, 127, "", "not found")
        return base_runner(command, **kwargs)

    sandbox.prepare_owned_container("python", ["server.py"], runner=runner)
    with pytest.raises(DockerSandboxRuntimeReadbackError, match="attestor failed"):
        sandbox.capture_runtime_readback(runner=runner)


def test_docker_prepares_immutable_container_before_connector_launch() -> None:
    sandbox = DockerSandbox(host="unix:///tmp/controlled-docker.sock")
    container_id = "c" * 64

    def runner(command: list[str], **_kwargs: object) -> subprocess.CompletedProcess[str]:
        return subprocess.CompletedProcess(command, 0, container_id + "\n", "")

    command, args = sandbox.prepare_owned_container("npx", ["server"], runner=runner)

    assert command == "docker"
    assert args == [
        "--host",
        "unix:///tmp/controlled-docker.sock",
        "container",
        "start",
        "--attach",
        "--interactive",
        container_id,
    ]


def test_docker_prepare_rejects_a_short_container_id() -> None:
    sandbox = DockerSandbox()
    calls: list[list[str]] = []

    def runner(command: list[str], **_kwargs: object) -> subprocess.CompletedProcess[str]:
        calls.append(command)
        if "create" in command:
            return subprocess.CompletedProcess(command, 0, "c" * 12 + "\n", "")
        if "ls" in command:
            return subprocess.CompletedProcess(command, 0, "", "")
        raise AssertionError(command)

    with pytest.raises(DockerSandboxCleanupError, match="immutable scan container ID"):
        sandbox.prepare_owned_container("npx", ["server"], runner=runner)

    assert all("--no-trunc" in command for command in calls if "ls" in command)
    assert not any("rm" in command for command in calls)


def test_docker_create_timeout_cleans_delayed_daemon_materialization(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    sandbox = DockerSandbox()
    container_id = "e" * 64
    calls: list[list[str]] = []
    list_queries = 0
    removed = False
    monkeypatch.setattr("mcp_trust.engine.sandbox.time.sleep", lambda _seconds: None)

    def runner(command: list[str], **_kwargs: object) -> subprocess.CompletedProcess[str]:
        nonlocal list_queries, removed
        calls.append(command)
        if "create" in command:
            raise subprocess.TimeoutExpired(command, 10.0)
        if "ls" in command:
            list_queries += 1
            stdout = container_id + "\n" if list_queries == 7 and not removed else ""
            return subprocess.CompletedProcess(command, 0, stdout, "")
        if "inspect" in command:
            return subprocess.CompletedProcess(
                command, 0, _owned_container_inspect(sandbox, container_id), ""
            )
        if "rm" in command:
            removed = True
            return subprocess.CompletedProcess(command, 0, container_id + "\n", "")
        raise AssertionError(command)

    with pytest.raises(DockerSandboxCleanupError, match="could not create"):
        sandbox.prepare_owned_container("npx", ["server"], runner=runner)

    assert any("rm" in command and container_id in command for command in calls)
    assert "ls" in calls[-1]
    assert all("--no-trunc" in command for command in calls if "ls" in command)


@pytest.mark.parametrize("delayed_id", ["e" * 12, "E" * 64, "not-an-id"])
def test_docker_create_timeout_rejects_non_full_delayed_identity(
    delayed_id: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    sandbox = DockerSandbox()
    calls: list[list[str]] = []
    monkeypatch.setattr("mcp_trust.engine.sandbox.time.sleep", lambda _seconds: None)

    def runner(command: list[str], **_kwargs: object) -> subprocess.CompletedProcess[str]:
        calls.append(command)
        if "create" in command:
            raise subprocess.TimeoutExpired(command, 10.0)
        if "ls" in command:
            return subprocess.CompletedProcess(command, 0, delayed_id + "\n", "")
        if "rm" in command:
            raise AssertionError("non-full delayed identities must never be removed")
        raise AssertionError(command)

    with pytest.raises(DockerSandboxCleanupError, match="cleanup could not prove"):
        sandbox.prepare_owned_container("npx", ["server"], runner=runner)

    assert all("--no-trunc" in command for command in calls if "ls" in command)
    assert not any("rm" in command for command in calls)


def test_docker_cleanup_requires_untruncated_identity() -> None:
    sandbox = DockerSandbox(host="unix:///tmp/controlled-docker.sock")
    container_id = "f" * 64
    present = False
    calls: list[list[str]] = []

    def runner(command: list[str], **_kwargs: object) -> subprocess.CompletedProcess[str]:
        nonlocal present
        calls.append(command)
        if "create" in command:
            present = True
            return subprocess.CompletedProcess(command, 0, container_id + "\n", "")
        if "ls" in command:
            listed_id = container_id if "--no-trunc" in command else container_id[:12]
            return subprocess.CompletedProcess(
                command, 0, listed_id + "\n" if present else "", ""
            )
        if "inspect" in command:
            return subprocess.CompletedProcess(
                command, 0, _owned_container_inspect(sandbox, container_id), ""
            )
        if "rm" in command:
            assert command[-1] == container_id
            present = False
            return subprocess.CompletedProcess(command, 0, container_id + "\n", "")
        raise AssertionError(command)

    sandbox.prepare_owned_container("npx", ["server"], runner=runner)

    assert (
        sandbox.cleanup_owned_container(runner=runner)
        == "CONTAINER_ABSENCE_VERIFIED"
    )
    list_queries = [command for command in calls if "ls" in command]
    assert len(list_queries) == 2
    assert all("--no-trunc" in command for command in list_queries)
    assert any("rm" in command and command[-1] == container_id for command in calls)


def test_docker_cleanup_rejects_short_prefix_without_removal() -> None:
    sandbox = DockerSandbox()
    container_id = "f" * 64
    calls: list[list[str]] = []

    def runner(command: list[str], **_kwargs: object) -> subprocess.CompletedProcess[str]:
        calls.append(command)
        if "create" in command:
            return subprocess.CompletedProcess(command, 0, container_id + "\n", "")
        if "ls" in command:
            assert "--no-trunc" in command
            return subprocess.CompletedProcess(command, 0, container_id[:12] + "\n", "")
        if "rm" in command:
            raise AssertionError("a short prefix must never be removed")
        raise AssertionError(command)

    sandbox.prepare_owned_container("npx", ["server"], runner=runner)

    with pytest.raises(DockerSandboxCleanupError, match="ambiguous"):
        sandbox.cleanup_owned_container(runner=runner)

    assert not any("rm" in command for command in calls)


def test_docker_cleanup_removes_only_owned_container_id_and_proves_absence() -> None:
    sandbox = DockerSandbox(host="unix:///tmp/controlled-docker.sock")
    container_id = "a" * 64
    calls: list[list[str]] = []
    list_results = iter([container_id + "\n", ""])

    def runner(command: list[str], **_kwargs: object) -> subprocess.CompletedProcess[str]:
        calls.append(command)
        if "ls" in command:
            return subprocess.CompletedProcess(command, 0, next(list_results), "")
        if "inspect" in command:
            return subprocess.CompletedProcess(
                command, 0, _owned_container_inspect(sandbox, container_id), ""
            )
        return subprocess.CompletedProcess(command, 0, container_id + "\n", "")

    assert (
        sandbox.cleanup_owned_container(runner=runner)
        == "CONTAINER_ABSENCE_VERIFIED"
    )
    assert calls[1][-3:] == ["container", "inspect", container_id]
    assert calls[2][-4:] == ["container", "rm", "--force", container_id]
    for query in (calls[0], calls[3]):
        assert query[:3] == ["docker", "--host", "unix:///tmp/controlled-docker.sock"]
        assert "--no-trunc" in query
        assert f"name=^/{sandbox.container_name}$" in query
        assert any(
            value.startswith("label=com.mcp-trust.scan-owner=") for value in query
        )


@pytest.mark.parametrize(
    "inspect_overrides",
    [
        {"Id": "b" * 64},
        {"Name": "/another-container"},
        {"Config": {"Labels": {"com.mcp-trust.scan-owner": "another-owner"}}},
    ],
)
def test_docker_cleanup_rejects_inspected_identity_tampering(
    inspect_overrides: dict[str, object],
) -> None:
    sandbox = DockerSandbox()
    container_id = "a" * 64
    calls: list[list[str]] = []

    def runner(command: list[str], **_kwargs: object) -> subprocess.CompletedProcess[str]:
        calls.append(command)
        if "ls" in command:
            return subprocess.CompletedProcess(command, 0, container_id + "\n", "")
        if "inspect" in command:
            return subprocess.CompletedProcess(
                command,
                0,
                _owned_container_inspect(sandbox, container_id, **inspect_overrides),
                "",
            )
        if "rm" in command:
            raise AssertionError("a mismatched inspected identity must never be removed")
        raise AssertionError(command)

    with pytest.raises(DockerSandboxCleanupError, match="owned container identity"):
        sandbox.cleanup_owned_container(runner=runner)

    assert not any("rm" in command for command in calls)


def test_docker_cleanup_empty_readback_is_verified_without_removal() -> None:
    calls: list[list[str]] = []

    def runner(command: list[str], **_kwargs: object) -> subprocess.CompletedProcess[str]:
        calls.append(command)
        return subprocess.CompletedProcess(command, 0, "", "")

    assert DockerSandbox().cleanup_owned_container(runner=runner) == (
        "CONTAINER_ABSENCE_VERIFIED"
    )
    assert len(calls) == 2
    assert all("ls" in command for command in calls)
    assert all("--no-trunc" in command for command in calls)


@pytest.mark.parametrize("stdout", ["not-an-id\n", "a" * 12 + "\n" + "b" * 12 + "\n"])
def test_docker_cleanup_rejects_ambiguous_identity(stdout: str) -> None:
    def runner(command: list[str], **_kwargs: object) -> subprocess.CompletedProcess[str]:
        return subprocess.CompletedProcess(command, 0, stdout, "")

    with pytest.raises(DockerSandboxCleanupError, match="ambiguous"):
        DockerSandbox().cleanup_owned_container(runner=runner)


def test_docker_cleanup_fails_closed_when_daemon_query_fails() -> None:
    def runner(command: list[str], **_kwargs: object) -> subprocess.CompletedProcess[str]:
        return subprocess.CompletedProcess(command, 1, "", "daemon unavailable")

    with pytest.raises(DockerSandboxCleanupError, match="could not query"):
        DockerSandbox().cleanup_owned_container(runner=runner)


def test_docker_wrap_binds_the_preflighted_local_daemon() -> None:
    host = "unix:///Users/operator/.colima/default/docker.sock"

    command, args = DockerSandbox(host=host).wrap("npx", ["x"])

    assert command == "docker"
    assert args[:3] == ["--host", host, "run"]


def test_docker_network_is_configurable() -> None:
    _, args = DockerSandbox(network="bridge").wrap("npx", ["x"])
    assert "bridge" in args


def test_docker_runs_non_root_by_default() -> None:
    _, default_args = DockerSandbox().wrap("npx", ["x"])
    assert "--user" in default_args and "1000:1000" in default_args
    # HOME/TMPDIR point at the writable tmpfs so the unprivileged user can run.
    assert "HOME=/scan" in default_args and "TMPDIR=/scan" in default_args
    # Explicit override is honored.
    _, custom = DockerSandbox(user="65534:65534").wrap("npx", ["x"])
    assert "65534:65534" in custom
    # Opt out to root (for an image that requires it) with user=None.
    _, rooted = DockerSandbox(user=None).wrap("npx", ["x"])
    assert "--user" not in rooted


def test_select_sandbox_by_name_and_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("MCP_TRUST_SANDBOX", raising=False)
    assert isinstance(select_sandbox("none"), NoSandbox)
    assert isinstance(select_sandbox("docker"), DockerSandbox)
    assert isinstance(select_sandbox(), NoSandbox)  # default
    monkeypatch.setenv("MCP_TRUST_SANDBOX", "docker")
    assert isinstance(select_sandbox(), DockerSandbox)


def test_select_sandbox_uses_only_the_dedicated_preflighted_host(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    expected = "unix:///Users/operator/.colima/default/docker.sock"
    monkeypatch.setenv("DOCKER_HOST", "tcp://remote.example:2375")
    monkeypatch.setenv("MCP_TRUST_DOCKER_HOST", expected)

    sandbox = select_sandbox("docker")

    assert isinstance(sandbox, DockerSandbox)
    assert sandbox.host == expected


def test_select_sandbox_unknown_raises() -> None:
    with pytest.raises(ValueError, match="Unknown sandbox"):
        select_sandbox("vm")


def test_select_sandbox_per_server_image_overrides_env(monkeypatch: pytest.MonkeyPatch) -> None:
    # A server baked into a purpose-built image must scan against THAT image
    # even when the corpus-wide default is set — otherwise a whole-corpus
    # refresh silently keeps stale grades for it.
    monkeypatch.setenv("MCP_TRUST_SANDBOX_IMAGE", "corpus-default:1")
    sandbox = select_sandbox("docker", image="live-batch:2")
    assert isinstance(sandbox, DockerSandbox)
    assert sandbox.image == "live-batch:2"

    fallback = select_sandbox("docker", image=None)
    assert isinstance(fallback, DockerSandbox)
    assert fallback.image == "corpus-default:1"


def test_select_sandbox_image_ignored_for_none(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("MCP_TRUST_SANDBOX", raising=False)
    assert isinstance(select_sandbox("none", image="live-batch:2"), NoSandbox)


def test_engine_resolves_per_server_sandbox_image(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("MCP_TRUST_SANDBOX", "docker")
    monkeypatch.setenv("MCP_TRUST_SANDBOX_IMAGE", "corpus-default:1")

    pinned = ServerSource(
        kind=SourceKind.NPM, reference="@acme/baked", sandbox_image="live-batch:2"
    )
    unpinned = ServerSource(kind=SourceKind.NPM, reference="@acme/plain")

    engine = MCPAuditEngine()
    resolved = engine._resolve_sandbox(pinned)
    assert isinstance(resolved, DockerSandbox)
    assert resolved.image == "live-batch:2"

    default = engine._resolve_sandbox(unpinned)
    assert isinstance(default, DockerSandbox)
    assert default.image == "corpus-default:1"

    # An explicitly injected sandbox wins the SANDBOX CHOICE (test/CLI injection
    # seam) — but trust enforcement still applies, so use a trusted source.
    injected = NoSandbox()
    trusted = ServerSource(kind=SourceKind.NPM, reference="@acme/ref", trusted=True)
    assert MCPAuditEngine(sandbox=injected)._resolve_sandbox(trusted) is injected


def test_engine_wraps_launch_through_sandbox() -> None:
    # Verify the engine's launch spec composes with the sandbox without needing
    # mcp-audits installed: launch_spec -> sandbox.wrap.
    src = ServerSource(kind=SourceKind.NPM, reference="@acme/server", args=["--x"])
    base_cmd, base_args = MCPAuditEngine._launch_spec(src)
    assert (base_cmd, base_args) == ("npx", ["-y", "@acme/server", "--x"])

    wrapped_cmd, wrapped_args = DockerSandbox().wrap(base_cmd, base_args)
    assert wrapped_cmd == "docker"
    assert wrapped_args[-4:] == ["npx", "-y", "@acme/server", "--x"]


def test_engine_refuses_untrusted_without_sandbox(monkeypatch: pytest.MonkeyPatch) -> None:
    # Fail-closed: an untrusted stdio source with no sandbox (default NoSandbox)
    # must raise rather than launch third-party code on the host.
    monkeypatch.delenv("MCP_TRUST_SANDBOX", raising=False)
    engine = MCPAuditEngine()

    untrusted = ServerSource(kind=SourceKind.NPM, reference="@acme/untrusted")
    with pytest.raises(ScanError, match="Refusing to scan untrusted"):
        engine._resolve_sandbox(untrusted)

    # An injected NoSandbox cannot bypass the trust gate for an untrusted source.
    with pytest.raises(ScanError, match="Refusing to scan untrusted"):
        MCPAuditEngine(sandbox=NoSandbox())._resolve_sandbox(untrusted)

    # Capability-based, not class-based: a custom passthrough of a DIFFERENT
    # class that does not isolate (no truthy ``isolates``) is also refused.
    class _FakePassthrough:
        name = "fake"

        def available(self) -> bool:
            return True

        def wrap(self, command: str, args: list[str]) -> tuple[str, list[str]]:
            return command, list(args)

    with pytest.raises(ScanError, match="Refusing to scan untrusted"):
        MCPAuditEngine(sandbox=_FakePassthrough())._resolve_sandbox(untrusted)

    class _UnmanagedIsolatingSandbox(_FakePassthrough):
        isolates = True

    with pytest.raises(ScanError, match="lifecycle contract"):
        MCPAuditEngine(sandbox=_UnmanagedIsolatingSandbox())._resolve_sandbox(untrusted)

    # A trusted source may use NoSandbox — the vetted reference-server flow.
    trusted = ServerSource(kind=SourceKind.NPM, reference="@acme/ref", trusted=True)
    assert isinstance(engine._resolve_sandbox(trusted), NoSandbox)

    # A remote (no-launch) source is exempt — no local process is spawned.
    remote = ServerSource(kind=SourceKind.REMOTE, reference="https://example.com/mcp")
    assert isinstance(engine._resolve_sandbox(remote), NoSandbox)


@pytest.mark.skipif(
    os.environ.get("MCP_TRUST_RUN_DOCKER_RUNTIME_READBACK") != "1",
    reason=(
        "opt-in: requires explicit approval, a pre-existing digest-pinned controlled "
        "Python image, and a bound local Docker daemon"
    ),
)
def test_integration_live_docker_runtime_readback() -> None:
    image = os.environ.get("MCP_TRUST_RUNTIME_READBACK_IMAGE", "")
    host = os.environ.get("MCP_TRUST_DOCKER_HOST")
    if not re.fullmatch(r"sha256:[0-9a-f]{64}", image):
        pytest.fail("MCP_TRUST_RUNTIME_READBACK_IMAGE must be one immutable sha256 ID")
    sandbox = DockerSandbox(image=image, host=host)
    command, args = sandbox.prepare_owned_container(
        "python",
        ["-c", "import time; time.sleep(30)"],
    )
    process = subprocess.Popen(  # noqa: S603 - opt-in exact Docker lifecycle test
        [command, *args],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    try:
        readback = sandbox.capture_runtime_readback()
        assert readback["state"] == "VERIFIED"
        assert readback["image_id"] == image
    finally:
        assert sandbox.cleanup_owned_container() == "CONTAINER_ABSENCE_VERIFIED"
        process.wait(timeout=10)
