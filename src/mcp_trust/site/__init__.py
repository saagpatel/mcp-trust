"""Static-site generation for the MCP Trust catalog.

Renders the registry's stored scans into a low-ops static site (catalog page,
per-server detail pages, shields.io badge endpoints) using the same pure
``mcp_trust.api.web`` renderers the live API uses — one source of truth for
markup. Generation is read-only with respect to untrusted input: it reads
SQLite and writes files, never connecting to a server or spawning a process.
"""
