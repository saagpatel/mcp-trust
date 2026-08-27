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

import logging
import os
import re
import secrets
import shutil
import subprocess
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import ClassVar, Protocol, runtime_checkable

logger = logging.getLogger(__name__)
_DOCKER_HOST_ENV = "MCP_TRUST_DOCKER_HOST"
_SCAN_OWNER_LABEL = "com.mcp-trust.scan-owner"
_CONTAINER_ID = re.compile(r"^[0-9a-f]{12,64}$")
_DOCKER_CLEANUP_TIMEOUT_SECONDS = 10.0
_DOCKER_CREATE_SETTLE_POLLS = 20
_DOCKER_CREATE_SETTLE_INTERVAL_SECONDS = 0.1


class DockerSandboxCleanupError(RuntimeError):
    """Raised when post-scan Docker container absence cannot be proven."""


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

    name: ClassVar[str] = "docker"
    isolates: ClassVar[bool] = True

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
        return docker_command, self._docker_command(
            "container", "start", "--attach", "--interactive", self._container_id
        )[1:]

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
