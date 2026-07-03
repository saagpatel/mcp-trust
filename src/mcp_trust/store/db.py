"""SQLite connection factory and schema initialisation."""

from __future__ import annotations

import os
import sqlite3


def connect(path: str | os.PathLike) -> sqlite3.Connection:
    """Open (or create) the SQLite database at *path*.

    Accepts ``":memory:"`` for in-process ephemeral databases.
    Sets ``row_factory = sqlite3.Row`` so columns are accessible by name,
    and enables foreign-key enforcement.
    """
    conn = sqlite3.connect(str(path), check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def init_schema(conn: sqlite3.Connection) -> None:
    """Create tables and indexes if they do not already exist."""
    conn.executescript(
        """
        CREATE TABLE IF NOT EXISTS servers (
            slug        TEXT PRIMARY KEY,
            name        TEXT NOT NULL,
            description TEXT NOT NULL DEFAULT '',
            source_json TEXT NOT NULL,
            homepage    TEXT,
            added_at    TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS scans (
            id             TEXT PRIMARY KEY,
            server_slug    TEXT NOT NULL REFERENCES servers(slug),
            engine_name    TEXT NOT NULL,
            engine_version TEXT NOT NULL,
            grade          TEXT NOT NULL,
            transparency   TEXT NOT NULL DEFAULT 'high',
            risk_json      TEXT NOT NULL,
            findings_json  TEXT NOT NULL,
            evidence_json  TEXT,
            scanned_at     TEXT NOT NULL,
            report_ref     TEXT
        );

        CREATE INDEX IF NOT EXISTS idx_scans_slug_time
            ON scans (server_slug, scanned_at);
        """
    )
    columns = {row["name"] for row in conn.execute("PRAGMA table_info(scans)").fetchall()}
    if "evidence_json" not in columns:
        conn.execute("ALTER TABLE scans ADD COLUMN evidence_json TEXT")
    conn.commit()
