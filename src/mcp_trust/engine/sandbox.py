"""Execution sandboxing for the real-engine scan path.

Scanning an untrusted MCP server requires *launching its process* (e.g.
``npx -y <pkg>``) so the engine can connect and enumerate its tools. That runs
third-party code on the host. A ``Sandbox`` isolates that execution by
transforming the launch ``(command, args)`` into a sandboxed equivalent.

Strategies
----------
- ``NoSandbox`` — passthrough. Runs the server directly on the host. ONLY safe
  for servers you already trust. This is the default to preserve the validated
  trusted-reference-server workflow, but it is NOT safe for untrusted servers.
- ``DockerSandbox`` — runs the server inside a locked-down ``docker run``
  container: non-root user, no network, read-only root fs, all capabilities
  dropped, no-new-privileges, memory/PID/CPU limits, no host mounts. The MCP
  stdio transport passes through ``docker run -i``.

Operational note (honest): ``--network none`` blocks a server that fetches its
own package at launch (``npx -y`` / ``uvx`` pull from a registry). For untrusted
scanning, bake the server into a purpose-built image and run it network-off, or
set ``MCP_TRUST_SANDBOX_NETWORK`` deliberately. Stronger isolation (gVisor,
Firecracker microVMs, E2B) is a roadmap option beyond this Docker baseline.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import re
import secrets
import shutil
import subprocess
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from decimal import Decimal, InvalidOperation
from typing import ClassVar, Protocol, runtime_checkable

logger = logging.getLogger(__name__)
_DOCKER_HOST_ENV = "MCP_TRUST_DOCKER_HOST"
_SCAN_OWNER_LABEL = "com.mcp-trust.scan-owner"
_CONTAINER_ID = re.compile(r"^[0-9a-f]{12,64}$")
_DOCKER_CLEANUP_TIMEOUT_SECONDS = 10.0
_DOCKER_CREATE_SETTLE_POLLS = 20
_DOCKER_CREATE_SETTLE_INTERVAL_SECONDS = 0.1
SANDBOX_RUNTIME_READBACK_TIMEOUT_SECONDS = 5.0
_DOCKER_RUNTIME_READBACK_POLLS = 50
_DOCKER_RUNTIME_READBACK_INTERVAL_SECONDS = 0.05
SANDBOX_RUNTIME_READBACK_SCHEMA = "McpTrustSandboxRuntimeReadbackV1"
SANDBOX_RUNTIME_READBACK_CLAIM_CEILING = (
    "Live MCP server PID 1 identity, its container namespaces/cgroup, and Docker "
    "daemon configuration; filesystem write probes run in a same-namespace "
    "same-UID attestor with isolated Python imports and a read-only working directory. "
    "Not proof against artifact replay, Docker, VM, or kernel compromise, server-side "
    "value retention, or an actual egress attempt."
)

_RUNTIME_CONTROL_KEYS = frozenset(
    {
        "network_none",
        "read_only_root",
        "capabilities_dropped",
        "no_new_privileges",
        "memory_limit",
        "memory_swap_disabled",
        "cpu_limit",
        "pids_limit",
        "non_root_user",
        "bounded_writable_tmpfs",
        "no_host_mount",
        "not_privileged",
        "environment_policy",
        "live_process_observed",
        "server_process_identity",
        "shared_namespaces_and_cgroup",
    }
)
_RUNTIME_OBSERVED_KEYS = frozenset(
    {
        "uid",
        "gid",
        "network_interfaces",
        "memory_max_bytes",
        "pids_max",
        "cpu_quota",
        "cpu_period",
        "environment_names",
        "image_environment_names",
        "injected_dummy_env_names",
        "secret_values_emitted_in_readback",
        "server_process_cmdline_digest",
        "workdir",
        "root_write_denied",
        "workdir_write_verified",
    }
)
_RUNTIME_READBACK_KEYS = frozenset(
    {
        "schema",
        "state",
        "proof_boundary",
        "image_id",
        "container_identity_digest",
        "controls",
        "observed",
        "claim_ceiling",
    }
)

_IN_CONTAINER_ATTESTOR = r"""
import hashlib
import json
import os
import pathlib
import sys
import uuid

workdir = sys.argv[1]
status = {}
for line in pathlib.Path('/proc/1/status').read_text().splitlines():
    if ':' in line:
        key, value = line.split(':', 1)
        status[key] = value.strip()

mounts = {}
for line in pathlib.Path('/proc/1/mountinfo').read_text().splitlines():
    before, after = line.split(' - ', 1)
    fields = before.split()
    mounts[fields[4]] = {
        'options': fields[5].split(','),
        'filesystem': after.split()[0],
    }

root_write_denied = False
try:
    pathlib.Path('/.mcp-trust-runtime-probe').write_text('probe')
except OSError:
    root_write_denied = True
else:
    pathlib.Path('/.mcp-trust-runtime-probe').unlink(missing_ok=True)

probe = pathlib.Path(workdir) / ('.mcp-trust-runtime-probe-' + uuid.uuid4().hex)
workdir_write_verified = False
try:
    probe.write_text('probe')
    workdir_write_verified = probe.read_text() == 'probe'
finally:
    probe.unlink(missing_ok=True)

def cgroup(name):
    return pathlib.Path('/sys/fs/cgroup', name).read_text().strip()

cpu_quota, cpu_period = cgroup('cpu.max').split()
server_env = pathlib.Path('/proc/1/environ').read_bytes().split(b'\0')
server_env_names = sorted(
    item.split(b'=', 1)[0].decode('utf-8', 'strict')
    for item in server_env
    if item and b'=' in item
)
uid = int(status['Uid'].split()[0])
gid = int(status['Gid'].split()[0])
payload = {
    'uid': uid,
    'gid': gid,
    'environment_names': server_env_names,
    'network_interfaces': sorted(path.name for path in pathlib.Path('/sys/class/net').iterdir()),
    'cap_eff': status.get('CapEff'),
    'no_new_privs': status.get('NoNewPrivs'),
    'root_mount_options': mounts.get('/', {}).get('options', []),
    'workdir_mount_options': mounts.get(workdir, {}).get('options', []),
    'workdir_filesystem': mounts.get(workdir, {}).get('filesystem'),
    'root_write_denied': root_write_denied,
    'workdir_write_verified': workdir_write_verified,
    'memory_max': cgroup('memory.max'),
    'pids_max': cgroup('pids.max'),
    'cpu_quota': cpu_quota,
    'cpu_period': cpu_period,
    'server_process_cmdline_digest': 'sha256:' + hashlib.sha256(
        pathlib.Path('/proc/1/cmdline').read_bytes()
    ).hexdigest(),
    'server_process_state': status.get('State'),
    'same_network_namespace': (
        os.readlink('/proc/1/ns/net') == os.readlink('/proc/self/ns/net')
    ),
    'same_mount_namespace': (
        os.readlink('/proc/1/ns/mnt') == os.readlink('/proc/self/ns/mnt')
    ),
    'same_cgroup': (
        pathlib.Path('/proc/1/cgroup').read_text()
        == pathlib.Path('/proc/self/cgroup').read_text()
    ),
}
print(json.dumps(payload, sort_keys=True, separators=(',', ':')))
""".strip()


class DockerSandboxCleanupError(RuntimeError):
    """Raised when post-scan Docker container absence cannot be proven."""


class DockerSandboxRuntimeReadbackError(RuntimeError):
    """Raised when live Docker sandbox controls cannot be proven."""


def _memory_bytes(value: str) -> int:
    match = re.fullmatch(r"([1-9][0-9]*)([kmgt]?)", value.lower())
    if match is None:
        raise DockerSandboxRuntimeReadbackError("Docker memory limit is unsupported")
    factors = {"": 1, "k": 1024, "m": 1024**2, "g": 1024**3, "t": 1024**4}
    return int(match.group(1)) * factors[match.group(2)]


def _env_map(values: object) -> dict[str, str]:
    if values is None:
        return {}
    if not isinstance(values, list) or not all(isinstance(item, str) for item in values):
        raise DockerSandboxRuntimeReadbackError("Docker environment readback is invalid")
    result: dict[str, str] = {}
    for item in values:
        if "=" not in item:
            raise DockerSandboxRuntimeReadbackError("Docker environment readback is invalid")
        key, value = item.split("=", 1)
        if not key or key in result:
            raise DockerSandboxRuntimeReadbackError("Docker environment readback is ambiguous")
        result[key] = value
    return result


def sandbox_server_process_digest(command: str, args: list[str]) -> str:
    encoded = b"\0".join(item.encode("utf-8") for item in (command, *args)) + b"\0"
    return "sha256:" + hashlib.sha256(encoded).hexdigest()


def valid_sandbox_runtime_readback(
    value: object,
    *,
    expected_image_id: str,
    expected_profile: dict[str, object],
    expected_dummy_env_names: list[str],
    expected_server_process_digest: str,
) -> bool:
    """Validate the stable, privacy-minimized receipt projection."""
    if not isinstance(value, dict) or set(value) != _RUNTIME_READBACK_KEYS:
        return False
    controls = value.get("controls")
    observed = value.get("observed")
    try:
        expected_memory = _memory_bytes(str(expected_profile["memory"]))
        expected_pids = int(expected_profile["pids_limit"])
        expected_cpus = Decimal(str(expected_profile["cpus"]))
        expected_user = str(expected_profile["user"])
        expected_uid_text, expected_gid_text = expected_user.split(":", 1)
        expected_uid = int(expected_uid_text)
        expected_gid = int(expected_gid_text)
        expected_workdir = str(expected_profile["tmpfs"])
        expected_attestor = str(expected_profile["runtime_attestor"])
    except (DockerSandboxRuntimeReadbackError, InvalidOperation, KeyError, ValueError):
        return False
    image_environment_names = (
        observed.get("image_environment_names") if isinstance(observed, dict) else None
    )
    expected_dummy_names = sorted(set(expected_dummy_env_names))
    expected_environment_names = (
        sorted(set(image_environment_names) | {"HOME", "TMPDIR"} | set(expected_dummy_names))
        if isinstance(image_environment_names, list)
        and all(isinstance(name, str) and name for name in image_environment_names)
        else None
    )
    return bool(
        expected_profile.get("network") == "none"
        and expected_profile.get("read_only_root") is True
        and expected_profile.get("capabilities") == "dropped-all"
        and expected_profile.get("no_new_privileges") is True
        and expected_attestor == "python"
        and value.get("schema") == SANDBOX_RUNTIME_READBACK_SCHEMA
        and value.get("state") == "VERIFIED"
        and value.get("proof_boundary")
        == "live-mcp-server-process-and-docker-daemon-config"
        and value.get("image_id") == expected_image_id
        and isinstance(value.get("container_identity_digest"), str)
        and re.fullmatch(r"sha256:[0-9a-f]{64}", value["container_identity_digest"])
        and isinstance(controls, dict)
        and set(controls) == _RUNTIME_CONTROL_KEYS
        and all(control is True for control in controls.values())
        and isinstance(observed, dict)
        and set(observed) == _RUNTIME_OBSERVED_KEYS
        and type(observed.get("uid")) is int
        and observed["uid"] == expected_uid
        and type(observed.get("gid")) is int
        and observed["gid"] == expected_gid
        and observed.get("network_interfaces") == ["lo"]
        and type(observed.get("memory_max_bytes")) is int
        and observed["memory_max_bytes"] == expected_memory
        and type(observed.get("pids_max")) is int
        and observed["pids_max"] == expected_pids
        and type(observed.get("cpu_quota")) is int
        and observed["cpu_quota"] > 0
        and type(observed.get("cpu_period")) is int
        and observed["cpu_period"] > 0
        and Decimal(observed["cpu_quota"]) / Decimal(observed["cpu_period"])
        == expected_cpus
        and isinstance(observed.get("environment_names"), list)
        and observed["environment_names"] == expected_environment_names
        and all(isinstance(name, str) and name for name in observed["environment_names"])
        and image_environment_names == sorted(set(image_environment_names))
        and isinstance(observed.get("injected_dummy_env_names"), list)
        and observed["injected_dummy_env_names"] == expected_dummy_names
        and set(observed["injected_dummy_env_names"]).issubset(
            observed["environment_names"]
        )
        and observed.get("secret_values_emitted_in_readback") is False
        and observed.get("server_process_cmdline_digest")
        == expected_server_process_digest
        and re.fullmatch(
            r"sha256:[0-9a-f]{64}", str(observed["server_process_cmdline_digest"])
        )
        and observed.get("workdir") == expected_workdir
        and observed.get("root_write_denied") is True
        and observed.get("workdir_write_verified") is True
        and value.get("claim_ceiling") == SANDBOX_RUNTIME_READBACK_CLAIM_CEILING
    )


def normalize_local_docker_host(value: str) -> str:
    """Return one explicit local Docker Unix-socket endpoint.

    Refresh scans launch untrusted code, so a remote Docker daemon would move
    that execution outside the reviewed local isolation boundary. The endpoint
    is passed as a Docker CLI argument because the MCP SDK intentionally drops
    ambient variables such as ``DOCKER_HOST`` from child-process environments.
    """
    if (
        not isinstance(value, str)
        or not value.startswith("unix:///")
        or value != value.strip()
        or any(character in value for character in ("\x00", "\n", "\r", "?", "#"))
    ):
        raise ValueError("Docker daemon authority must be one absolute local Unix socket")
    socket_path = value.removeprefix("unix://")
    if not socket_path.startswith("/") or socket_path in {"", "/"}:
        raise ValueError("Docker daemon authority must be one absolute local Unix socket")
    return f"unix://{socket_path}"


@runtime_checkable
class Sandbox(Protocol):
    """Transforms a launch command into a sandboxed equivalent."""

    name: str
    # Whether this strategy actually isolates untrusted execution. The engine's
    # fail-closed gate keys off this capability (not class identity), so any
    # passthrough that does not isolate must declare ``isolates = False``.
    isolates: bool

    def available(self) -> bool:
        """Whether this sandbox can run on the current host."""
        ...

    def wrap(self, command: str, args: list[str]) -> tuple[str, list[str]]:
        """Return the sandboxed ``(command, args)`` to launch instead."""
        ...


class NoSandbox:
    """Passthrough — runs the server directly on the host. Trusted servers only."""

    name: ClassVar[str] = "none"
    isolates: ClassVar[bool] = False

    def available(self) -> bool:
        return True

    def wrap(self, command: str, args: list[str]) -> tuple[str, list[str]]:
        return command, list(args)


@dataclass
class DockerSandbox:
    """Run the server inside a locked-down Docker container.

    The default profile is restrictive: a non-root user, no network, read-only
    root filesystem, all Linux capabilities dropped, no privilege escalation, and
    memory / PID / CPU ceilings. A small writable tmpfs is mounted at ``workdir``
    for scratch, and HOME/TMPDIR point at it so the unprivileged user can run.
    """

    image: str = "node:22-slim"
    network: str = "none"
    memory: str = "512m"
    pids_limit: int = 256
    cpus: str = "1"
    workdir: str = "/scan"
    tmpfs_size: str = "64m"
    tmpfs_mode: str = "1777"
    # Exact local daemon endpoint proven during refresh preflight. It is
    # expressed as a Docker CLI global option so the MCP SDK's intentionally
    # reduced child environment cannot silently drop the execution authority.
    host: str | None = None
    # Non-root by default: run untrusted code as an unprivileged uid so a
    # container/kernel escape does not start from root. Numeric so it needs no
    # passwd entry in the image. Set None to opt out (an image that needs root).
    user: str | None = "1000:1000"
    # Non-functional dummy credentials for the credentialed-sandboxed scan mode,
    # injected as ``-e KEY=VALUE`` so they live only inside the container, never
    # the host env. Only ever set with network off (the engine enforces this).
    env: dict[str, str] = field(default_factory=dict)
    # A per-sandbox unguessable identity lets cleanup target only the container
    # created by this exact scan lifecycle. Neither value is caller-controlled.
    _owner_token: str = field(
        default_factory=lambda: secrets.token_hex(16), init=False, repr=False
    )
    _container_id: str | None = field(default=None, init=False, repr=False)
    _server_process_digest: str | None = field(default=None, init=False, repr=False)

    name: ClassVar[str] = "docker"
    isolates: ClassVar[bool] = True
    # Purpose-built refresh images bind this fixed, non-shell attestor profile.
    # Execution uses the image contract's absolute interpreter path so a
    # target-influenced PATH cannot select a writable shim.
    attestor_command: ClassVar[str] = "python"
    attestor_executable: ClassVar[str] = "/opt/venv/bin/python"

    def __post_init__(self) -> None:
        if self.host is not None:
            self.host = normalize_local_docker_host(self.host)

    @property
    def container_name(self) -> str:
        return f"mcp-trust-scan-{self._owner_token}"

    def available(self) -> bool:
        return shutil.which("docker") is not None

    def wrap(self, command: str, args: list[str]) -> tuple[str, list[str]]:
        docker_args: list[str] = []
        if self.host is not None:
            docker_args += ["--host", self.host]
        docker_args += [
            "run",
            "--rm",
            "-i",  # keep stdin open for the MCP stdio transport
            "--name",
            self.container_name,
            "--label",
            f"{_SCAN_OWNER_LABEL}={self._owner_token}",
            "--network",
            self.network,
            "--memory",
            self.memory,
            "--memory-swap",
            self.memory,  # == memory disables swap (no swap-escape)
            "--pids-limit",
            str(self.pids_limit),
            "--cpus",
            self.cpus,
            "--security-opt",
            "no-new-privileges",
            "--cap-drop",
            "ALL",
            "--read-only",
            "--tmpfs",
            f"{self.workdir}:rw,size={self.tmpfs_size},mode={self.tmpfs_mode}",
            "--workdir",
            self.workdir,
            # Route HOME/TMPDIR to the writable tmpfs so the non-root user can
            # write caches/scratch under a read-only root filesystem.
            "--env",
            f"HOME={self.workdir}",
            "--env",
            f"TMPDIR={self.workdir}",
        ]
        if self.user:
            docker_args += ["--user", self.user]
        # Container-scoped dummy credentials (credentialed-sandboxed mode). Safe
        # only because the network is off; the engine refuses to populate this
        # otherwise.
        for key, value in self.env.items():
            docker_args += ["--env", f"{key}={value}"]
        docker_args += [self.image, command, *args]
        return "docker", docker_args

    def _docker_command(self, *args: str) -> list[str]:
        command = ["docker"]
        if self.host is not None:
            command += ["--host", self.host]
        return [*command, *args]

    @staticmethod
    def _docker_cli_env() -> dict[str, str]:
        # Do not let ambient DOCKER_HOST/DOCKER_CONTEXT redirect cleanup. HOME
        # remains so an unpinned non-refresh caller can use its selected context;
        # the controlled refresh always supplies an exact local Unix host.
        return {
            key: value
            for key in ("HOME", "PATH", "TMPDIR")
            if (value := os.environ.get(key)) is not None
        }

    def _owned_container_ids(
        self,
        *,
        runner: Callable[..., subprocess.CompletedProcess[str]],
    ) -> list[str]:
        try:
            completed = runner(
                self._docker_command(
                    "container",
                    "ls",
                    "--all",
                    "--filter",
                    f"label={_SCAN_OWNER_LABEL}={self._owner_token}",
                    "--filter",
                    f"name=^/{self.container_name}$",
                    "--format",
                    "{{.ID}}",
                ),
                text=True,
                capture_output=True,
                check=False,
                timeout=_DOCKER_CLEANUP_TIMEOUT_SECONDS,
                env=self._docker_cli_env(),
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise DockerSandboxCleanupError(
                "Docker cleanup readback could not query the bound daemon"
            ) from exc
        if completed.returncode != 0:
            raise DockerSandboxCleanupError(
                "Docker cleanup readback could not query the bound daemon"
            )
        container_ids = [line.strip() for line in completed.stdout.splitlines() if line.strip()]
        if len(container_ids) > 1 or any(
            _CONTAINER_ID.fullmatch(container_id) is None for container_id in container_ids
        ):
            raise DockerSandboxCleanupError(
                "Docker cleanup readback returned an ambiguous owned-container identity"
            )
        return container_ids

    def prepare_owned_container(
        self,
        command: str,
        args: list[str],
        *,
        runner: Callable[..., subprocess.CompletedProcess[str]] = subprocess.run,
    ) -> tuple[str, list[str]]:
        """Create the exact scan container before the connector worker starts.

        The connector receives only ``docker start`` for the immutable created
        ID. Therefore a worker that outlives the outer deadline cannot create a
        new container after cleanup has proved that ID absent.
        """
        if self._container_id is not None:
            raise DockerSandboxCleanupError("Docker scan container is already prepared")
        docker_command, run_args = self.wrap(command, args)
        run_index = run_args.index("run")
        create_args = [*run_args[:run_index], "container", "create", *run_args[run_index + 1 :]]
        create_args.remove("--rm")
        try:
            completed = runner(
                [docker_command, *create_args],
                text=True,
                capture_output=True,
                check=False,
                timeout=_DOCKER_CLEANUP_TIMEOUT_SECONDS,
                env=self._docker_cli_env(),
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            # subprocess.run kills and waits for a timed-out CLI child, but the
            # daemon may already have accepted the create request. Observe a
            # bounded quiescence window for delayed materialization, removing
            # only the exact unique identity whenever it appears, then require
            # a final absence readback before failing closed.
            try:
                for _ in range(_DOCKER_CREATE_SETTLE_POLLS):
                    self.cleanup_owned_container(runner=runner)
                    time.sleep(_DOCKER_CREATE_SETTLE_INTERVAL_SECONDS)
                self.cleanup_owned_container(runner=runner)
            except DockerSandboxCleanupError as cleanup_exc:
                raise DockerSandboxCleanupError(
                    "Docker create failed and cleanup could not prove the uniquely "
                    "owned scan container absent"
                ) from cleanup_exc
            raise DockerSandboxCleanupError(
                "Docker could not create the uniquely owned scan container"
            ) from exc
        created_ids = [line.strip() for line in completed.stdout.splitlines() if line.strip()]
        if (
            completed.returncode != 0
            or len(created_ids) != 1
            or _CONTAINER_ID.fullmatch(created_ids[0]) is None
        ):
            # A failed CLI can still have created a daemon object. Query by the
            # unique identity and remove it before returning the preparation error.
            self.cleanup_owned_container(runner=runner)
            raise DockerSandboxCleanupError(
                "Docker did not return one immutable scan container ID"
            )
        self._container_id = created_ids[0]
        self._server_process_digest = sandbox_server_process_digest(command, args)
        return docker_command, self._docker_command(
            "container", "start", "--attach", "--interactive", self._container_id
        )[1:]

    def _runtime_command(
        self,
        runner: Callable[..., subprocess.CompletedProcess[str]],
        deadline: float,
        *args: str,
    ) -> subprocess.CompletedProcess[str]:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise DockerSandboxRuntimeReadbackError(
                "Docker runtime readback exceeded its bounded deadline"
            )
        try:
            return runner(
                self._docker_command(*args),
                text=True,
                capture_output=True,
                check=False,
                timeout=min(SANDBOX_RUNTIME_READBACK_TIMEOUT_SECONDS, remaining),
                env=self._docker_cli_env(),
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise DockerSandboxRuntimeReadbackError(
                "Docker runtime readback command did not complete"
            ) from exc

    @staticmethod
    def _one_json_object(completed: subprocess.CompletedProcess[str]) -> dict[str, object]:
        if completed.returncode != 0:
            raise DockerSandboxRuntimeReadbackError("Docker runtime readback failed")
        try:
            payload = json.loads(completed.stdout)
        except (json.JSONDecodeError, TypeError) as exc:
            raise DockerSandboxRuntimeReadbackError(
                "Docker runtime readback returned invalid JSON"
            ) from exc
        if not isinstance(payload, list) or len(payload) != 1 or not isinstance(payload[0], dict):
            raise DockerSandboxRuntimeReadbackError(
                "Docker runtime readback returned an ambiguous object"
            )
        return payload[0]

    def capture_runtime_readback(
        self,
        *,
        runner: Callable[..., subprocess.CompletedProcess[str]] = subprocess.run,
    ) -> dict[str, object]:
        """Attest the exact live scan process without retaining secret values.

        Docker's daemon configuration and a fixed in-container probe are both
        required. HostConfig alone is not promoted to kernel enforcement proof.
        The raw inspect payloads and environment values never leave this method.
        """
        container_id = self._container_id
        if container_id is None or _CONTAINER_ID.fullmatch(container_id) is None:
            raise DockerSandboxRuntimeReadbackError(
                "Docker runtime readback has no prepared immutable container"
            )

        deadline = time.monotonic() + SANDBOX_RUNTIME_READBACK_TIMEOUT_SECONDS
        container: dict[str, object] | None = None
        for _ in range(_DOCKER_RUNTIME_READBACK_POLLS):
            inspected = self._runtime_command(
                runner, deadline, "container", "inspect", container_id
            )
            if inspected.returncode == 0:
                candidate = self._one_json_object(inspected)
                state = candidate.get("State")
                if isinstance(state, dict) and state.get("Running") is True:
                    container = candidate
                    break
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                break
            time.sleep(min(_DOCKER_RUNTIME_READBACK_INTERVAL_SECONDS, remaining))
        if container is None:
            raise DockerSandboxRuntimeReadbackError(
                "Docker runtime readback never observed the exact container running"
            )

        image = self._one_json_object(
            self._runtime_command(runner, deadline, "image", "inspect", self.image)
        )
        if self.user is None:
            raise DockerSandboxRuntimeReadbackError(
                "Docker in-container runtime attestor requires the configured target user"
            )
        attested = self._runtime_command(
            runner,
            deadline,
            "container",
            "exec",
            "--user",
            self.user,
            "--workdir",
            "/",
            container_id,
            self.attestor_executable,
            "-I",
            "-c",
            _IN_CONTAINER_ATTESTOR,
            self.workdir,
        )
        if attested.returncode != 0:
            raise DockerSandboxRuntimeReadbackError(
                "Docker in-container runtime attestor failed"
            )
        try:
            process = json.loads(attested.stdout)
        except (json.JSONDecodeError, TypeError) as exc:
            raise DockerSandboxRuntimeReadbackError(
                "Docker in-container runtime attestor returned invalid JSON"
            ) from exc
        if not isinstance(process, dict):
            raise DockerSandboxRuntimeReadbackError(
                "Docker in-container runtime attestor returned an invalid object"
            )

        config = container.get("Config")
        host_config = container.get("HostConfig")
        state = container.get("State")
        mounts = container.get("Mounts")
        image_config = image.get("Config")
        if not all(
            isinstance(value, dict) for value in (config, host_config, state, image_config)
        ) or not isinstance(mounts, list):
            raise DockerSandboxRuntimeReadbackError(
                "Docker runtime readback object shape is invalid"
            )
        assert isinstance(config, dict)
        assert isinstance(host_config, dict)
        assert isinstance(state, dict)
        assert isinstance(image_config, dict)

        image_id = container.get("Image")
        expected_memory = _memory_bytes(self.memory)
        try:
            expected_nano_cpus = int(Decimal(self.cpus) * Decimal(1_000_000_000))
        except (InvalidOperation, ValueError) as exc:
            raise DockerSandboxRuntimeReadbackError("Docker CPU limit is unsupported") from exc
        if expected_nano_cpus <= 0:
            raise DockerSandboxRuntimeReadbackError("Docker CPU limit is unsupported")

        expected_env = _env_map(image_config.get("Env", []))
        image_environment_names = sorted(expected_env)
        expected_env.update({"HOME": self.workdir, "TMPDIR": self.workdir, **self.env})
        actual_env = _env_map(config.get("Env", []))
        environment_names = sorted(actual_env)
        dummy_names = sorted(self.env)

        tmpfs = host_config.get("Tmpfs")
        tmpfs_value = tmpfs.get(self.workdir) if isinstance(tmpfs, dict) else None
        expected_tmpfs_size = _memory_bytes(self.tmpfs_size)
        tmpfs_tokens = set(tmpfs_value.split(",")) if isinstance(tmpfs_value, str) else set()
        tmpfs_size_valid = (
            f"size={expected_tmpfs_size}" in tmpfs_tokens
            or f"size={self.tmpfs_size}" in tmpfs_tokens
        )
        tmpfs_valid = {
            "rw",
            f"mode={self.tmpfs_mode}",
        }.issubset(tmpfs_tokens) and tmpfs_size_valid

        cap_drop = host_config.get("CapDrop")
        security_opt = host_config.get("SecurityOpt")
        labels = config.get("Labels")
        exact_identity = bool(
            container.get("Id") == container_id
            and container.get("Name") == f"/{self.container_name}"
            and isinstance(labels, dict)
            and labels.get(_SCAN_OWNER_LABEL) == self._owner_token
            and state.get("Running") is True
        )
        no_host_mount = bool(
            host_config.get("Binds") in (None, [])
            and all(
                isinstance(mount, dict) and mount.get("Type") != "bind" for mount in mounts
            )
        )

        def _process_int(key: str) -> int:
            value = process.get(key)
            if isinstance(value, bool):
                raise DockerSandboxRuntimeReadbackError(
                    "Docker in-container numeric readback is invalid"
                )
            try:
                return int(value)
            except (TypeError, ValueError) as exc:
                raise DockerSandboxRuntimeReadbackError(
                    "Docker in-container numeric readback is invalid"
                ) from exc

        uid = _process_int("uid")
        gid = _process_int("gid")
        memory_max = _process_int("memory_max")
        pids_max = _process_int("pids_max")
        cpu_quota = _process_int("cpu_quota")
        cpu_period = _process_int("cpu_period")
        process_env_names = process.get("environment_names")
        interfaces = process.get("network_interfaces")
        server_process_digest = process.get("server_process_cmdline_digest")
        expected_server_process_digest = self._server_process_digest
        cpu_valid = (
            cpu_period > 0
            and Decimal(cpu_quota) / Decimal(cpu_period) == Decimal(self.cpus)
        )
        controls = {
            "network_none": (
                host_config.get("NetworkMode") == "none" and interfaces == ["lo"]
            ),
            "read_only_root": (
                host_config.get("ReadonlyRootfs") is True
                and "ro" in process.get("root_mount_options", [])
                and process.get("root_write_denied") is True
            ),
            "capabilities_dropped": (
                isinstance(cap_drop, list)
                and {str(value).upper() for value in cap_drop} == {"ALL"}
                and process.get("cap_eff") == "0000000000000000"
            ),
            "no_new_privileges": (
                isinstance(security_opt, list)
                and "no-new-privileges" in security_opt
                and process.get("no_new_privs") == "1"
            ),
            "memory_limit": (
                host_config.get("Memory") == expected_memory
                and memory_max == expected_memory
            ),
            "memory_swap_disabled": host_config.get("MemorySwap") == expected_memory,
            "cpu_limit": host_config.get("NanoCpus") == expected_nano_cpus and cpu_valid,
            "pids_limit": (
                host_config.get("PidsLimit") == self.pids_limit
                and pids_max == self.pids_limit
            ),
            "non_root_user": (
                self.user is not None
                and config.get("User") == self.user
                and uid > 0
                and f"{uid}:{gid}" == self.user
            ),
            "bounded_writable_tmpfs": (
                tmpfs_valid
                and config.get("WorkingDir") == self.workdir
                and process.get("workdir_filesystem") == "tmpfs"
                and "rw" in process.get("workdir_mount_options", [])
                and process.get("workdir_write_verified") is True
            ),
            "no_host_mount": no_host_mount,
            "not_privileged": host_config.get("Privileged") is False,
            "environment_policy": (
                actual_env == expected_env
                and process_env_names == environment_names
                and set(dummy_names).issubset(environment_names)
            ),
            "live_process_observed": (
                exact_identity
                and isinstance(process.get("server_process_state"), str)
                and not process["server_process_state"].startswith("Z")
            ),
            "server_process_identity": (
                isinstance(expected_server_process_digest, str)
                and server_process_digest == expected_server_process_digest
            ),
            "shared_namespaces_and_cgroup": (
                process.get("same_network_namespace") is True
                and process.get("same_mount_namespace") is True
                and process.get("same_cgroup") is True
            ),
        }
        if not all(value is True for value in controls.values()):
            raise DockerSandboxRuntimeReadbackError(
                "Docker live runtime controls did not match the locked scan profile"
            )
        if (
            not isinstance(image_id, str)
            or image_id != image.get("Id")
            or re.fullmatch(r"sha256:[0-9a-f]{64}", image_id) is None
        ):
            raise DockerSandboxRuntimeReadbackError(
                "Docker live runtime image did not match one immutable image ID"
            )

        readback: dict[str, object] = {
            "schema": SANDBOX_RUNTIME_READBACK_SCHEMA,
            "state": "VERIFIED",
            "proof_boundary": "live-mcp-server-process-and-docker-daemon-config",
            "image_id": image_id,
            "container_identity_digest": "sha256:"
            + hashlib.sha256(container_id.encode("ascii")).hexdigest(),
            "controls": controls,
            "observed": {
                "uid": uid,
                "gid": gid,
                "network_interfaces": interfaces,
                "memory_max_bytes": memory_max,
                "pids_max": pids_max,
                "cpu_quota": cpu_quota,
                "cpu_period": cpu_period,
                "environment_names": environment_names,
                "image_environment_names": image_environment_names,
                "injected_dummy_env_names": dummy_names,
                "secret_values_emitted_in_readback": False,
                "server_process_cmdline_digest": server_process_digest,
                "workdir": self.workdir,
                "root_write_denied": True,
                "workdir_write_verified": True,
            },
            "claim_ceiling": SANDBOX_RUNTIME_READBACK_CLAIM_CEILING,
        }
        if not isinstance(expected_server_process_digest, str) or not (
            valid_sandbox_runtime_readback(
                readback,
                expected_image_id=image_id,
                expected_profile={
                    "network": self.network,
                    "read_only_root": True,
                    "capabilities": "dropped-all",
                    "no_new_privileges": True,
                    "memory": self.memory,
                    "pids_limit": self.pids_limit,
                    "cpus": self.cpus,
                    "user": self.user,
                    "tmpfs": self.workdir,
                    "runtime_attestor": self.attestor_command,
                },
                expected_dummy_env_names=dummy_names,
                expected_server_process_digest=expected_server_process_digest,
            )
        ):
            raise DockerSandboxRuntimeReadbackError(
                "Docker runtime readback could not be normalized"
            )
        return readback

    def cleanup_owned_container(
        self,
        *,
        runner: Callable[..., subprocess.CompletedProcess[str]] = subprocess.run,
    ) -> str:
        """Force-remove this scan's owned container and prove it is absent.

        Cleanup selects by both an unguessable owner label and exact generated
        name, then removes by the returned immutable container ID. It never
        removes a name-only or caller-supplied target.
        """
        container_ids = self._owned_container_ids(runner=runner)
        if (
            self._container_id is not None
            and container_ids
            and container_ids[0] != self._container_id
        ):
            raise DockerSandboxCleanupError(
                "Docker cleanup readback did not match the prepared container ID"
            )
        if container_ids:
            try:
                removed = runner(
                    self._docker_command("container", "rm", "--force", container_ids[0]),
                    text=True,
                    capture_output=True,
                    check=False,
                    timeout=_DOCKER_CLEANUP_TIMEOUT_SECONDS,
                    env=self._docker_cli_env(),
                )
            except (OSError, subprocess.TimeoutExpired) as exc:
                raise DockerSandboxCleanupError(
                    "Docker could not force-remove the owned scan container"
                ) from exc
            if removed.returncode != 0:
                raise DockerSandboxCleanupError(
                    "Docker could not force-remove the owned scan container"
                )
        if self._owned_container_ids(runner=runner):
            raise DockerSandboxCleanupError(
                "Docker owned scan container remained after forced cleanup"
            )
        return "CONTAINER_ABSENCE_VERIFIED"


def effective_docker_image(source_image: str | None = None) -> str:
    """The Docker image a scan actually runs in.

    Per-server pin first, then the ``MCP_TRUST_SANDBOX_IMAGE`` corpus default.
    Shared with receipt provenance (``mcp_trust.receipts``) so the recorded
    image can never drift from the image the engine resolves.
    """
    return source_image or os.environ.get("MCP_TRUST_SANDBOX_IMAGE", "node:22-slim")


def select_sandbox(name: str | None = None, image: str | None = None) -> Sandbox:
    """Select a sandbox by name (or ``MCP_TRUST_SANDBOX`` env; default ``none``).

    ``image`` is a per-server override (a server baked into a purpose-built
    image must scan against it); when unset, the ``MCP_TRUST_SANDBOX_IMAGE``
    corpus default applies. Raises ``ValueError`` for an unknown name.
    Availability is the caller's to check via ``sandbox.available()`` so the
    engine can surface a clean error.
    """
    resolved = (name or os.environ.get("MCP_TRUST_SANDBOX", "none")).lower()
    if resolved == "none":
        logger.warning(
            "MCPAuditEngine is running WITHOUT a sandbox — only scan servers you "
            "trust. Set MCP_TRUST_SANDBOX=docker to isolate untrusted servers."
        )
        return NoSandbox()
    if resolved == "docker":
        return DockerSandbox(
            image=effective_docker_image(image),
            network=os.environ.get("MCP_TRUST_SANDBOX_NETWORK", "none"),
            host=(os.environ.get(_DOCKER_HOST_ENV) if os.environ.get(_DOCKER_HOST_ENV) else None),
        )
    raise ValueError(f"Unknown sandbox {resolved!r} (expected 'none' or 'docker').")
