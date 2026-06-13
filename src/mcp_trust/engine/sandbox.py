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
  container: no network, read-only root fs, all capabilities dropped,
  no-new-privileges, memory/PID/CPU limits, no host mounts. The MCP stdio
  transport passes through ``docker run -i``.

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
from dataclasses import dataclass
from typing import ClassVar, Protocol, runtime_checkable

logger = logging.getLogger(__name__)


@runtime_checkable
class Sandbox(Protocol):
    """Transforms a launch command into a sandboxed equivalent."""

    name: str

    def available(self) -> bool:
        """Whether this sandbox can run on the current host."""
        ...

    def wrap(self, command: str, args: list[str]) -> tuple[str, list[str]]:
        """Return the sandboxed ``(command, args)`` to launch instead."""
        ...


class NoSandbox:
    """Passthrough — runs the server directly on the host. Trusted servers only."""

    name: ClassVar[str] = "none"

    def available(self) -> bool:
        return True

    def wrap(self, command: str, args: list[str]) -> tuple[str, list[str]]:
        return command, list(args)


@dataclass
class DockerSandbox:
    """Run the server inside a locked-down Docker container.

    The default profile is restrictive: no network, read-only root filesystem,
    all Linux capabilities dropped, no privilege escalation, and memory / PID /
    CPU ceilings. A small writable tmpfs is mounted at ``workdir`` for scratch.
    """

    image: str = "node:22-slim"
    network: str = "none"
    memory: str = "512m"
    pids_limit: int = 256
    cpus: str = "1"
    workdir: str = "/scan"
    tmpfs_size: str = "64m"
    user: str | None = None

    name: ClassVar[str] = "docker"

    def available(self) -> bool:
        return shutil.which("docker") is not None

    def wrap(self, command: str, args: list[str]) -> tuple[str, list[str]]:
        docker_args: list[str] = [
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
            f"{self.workdir}:rw,size={self.tmpfs_size}",
            "--workdir",
            self.workdir,
        ]
        if self.user:
            docker_args += ["--user", self.user]
        docker_args += [self.image, command, *args]
        return "docker", docker_args


def select_sandbox(name: str | None = None) -> Sandbox:
    """Select a sandbox by name (or ``MCP_TRUST_SANDBOX`` env; default ``none``).

    Raises ``ValueError`` for an unknown name. Availability is the caller's to
    check via ``sandbox.available()`` so the engine can surface a clean error.
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
            image=os.environ.get("MCP_TRUST_SANDBOX_IMAGE", "node:22-slim"),
            network=os.environ.get("MCP_TRUST_SANDBOX_NETWORK", "none"),
        )
    raise ValueError(f"Unknown sandbox {resolved!r} (expected 'none' or 'docker').")
