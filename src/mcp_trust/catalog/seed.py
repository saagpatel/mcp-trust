"""Catalog seed — load the bundled server list into the registry."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

from mcp_trust.core.models import Server, ServerSource

_SEED_FILE = Path(__file__).parent / "seed_servers.json"


def load_seed() -> list[Server]:
    """Parse ``seed_servers.json`` and return ``Server`` objects.

    ``added_at`` is set to the current UTC time for each entry so that
    re-seeding an existing database updates the timestamp without losing data.
    """
    raw = json.loads(_SEED_FILE.read_text(encoding="utf-8"))
    now = datetime.now(tz=UTC)
    servers: list[Server] = []
    for entry in raw:
        source_data = entry["source"]
        source = ServerSource(
            kind=source_data["kind"],
            reference=source_data["reference"],
            command=source_data.get("command"),
            args=source_data.get("args", []),
            env_keys=source_data.get("env_keys", []),
        )
        servers.append(
            Server(
                slug=entry["slug"],
                name=entry["name"],
                description=entry.get("description", ""),
                source=source,
                homepage=entry.get("homepage"),
                added_at=now,
            )
        )
    return servers


def seed_into(server_repo: object) -> int:
    """Upsert all seed servers into *server_repo* and return the count.

    *server_repo* must expose a ``upsert(server: Server) -> None`` method
    (i.e. a ``ServerRepository`` instance).
    """
    servers = load_seed()
    for server in servers:
        server_repo.upsert(server)  # type: ignore[union-attr]
    return len(servers)
