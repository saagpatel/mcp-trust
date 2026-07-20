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
import shutil
from dataclasses import dataclass, field
from typing import ClassVar, Protocol, runtime_checkable

logger = logging.getLogger(__name__)
_DOCKER_HOST_ENV = "MCP_TRUST_DOCKER_HOST"


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

    name: ClassVar[str] = "docker"
    isolates: ClassVar[bool] = True

    def __post_init__(self) -> None:
        if self.host is not None:
            self.host = normalize_local_docker_host(self.host)

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
