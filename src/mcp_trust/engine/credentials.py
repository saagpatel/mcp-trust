"""Dummy-credential policy for the ``credentialed-sandboxed`` scan mode.

Some MCP servers refuse to start, or refuse to enumerate their tools, unless
required secret env vars are present — they check the credential's *presence*,
and sometimes its *format*, at startup. A server that only USES the credential
when it makes an outbound API call will still enumerate its full tool surface
with a syntactically-plausible but NON-FUNCTIONAL placeholder, as long as the
sandbox is network-off so the placeholder can never authenticate anywhere.

This module builds those placeholders. The values are obviously fake, exist
solely to satisfy LOCAL startup checks, and are NEVER persisted: the registry
stores env var NAMES only (``ServerSource.env_keys``); receipts record the names
plus a credentialed-scan caveat, never the values.

Safety invariant (enforced by the engine, not here): this mode is opt-in
(``MCP_TRUST_SCAN_CREDENTIALS=dummy``) and runs ONLY inside the docker sandbox
with network off. Injecting credentials while running untrusted code on the host,
or with a reachable network, is exactly the unsafe case the engine refuses.
"""

from __future__ import annotations

# An obviously-fake fixed payload. Long enough to clear common minimum-length
# checks; all-zeros so it reads as a placeholder, never a real secret.
_FAKE_PAYLOAD = "0" * 40

# Format-plausible prefixes keyed by a substring of the UPPERCASED env var name.
# Network-off means no value can authenticate; a prefix only helps a server that
# format-validates its token locally before reaching tool enumeration. First match
# wins, so order most-specific first.
_TYPED_PREFIXES: tuple[tuple[str, str], ...] = (
    ("GITHUB", "ghp_"),
    ("GITLAB", "glpat-"),
    ("SLACK", "xoxb-"),
    ("ANTHROPIC", "sk-ant-"),
    ("OPENAI", "sk-"),
    ("STRIPE", "sk_test_"),
)


def _dummy_value(env_key: str) -> str:
    """A non-functional, format-plausible placeholder for one env var name."""
    upper = env_key.upper()
    for needle, prefix in _TYPED_PREFIXES:
        if needle in upper:
            return f"{prefix}{_FAKE_PAYLOAD}"
    # Generic fallback: presence is enough for servers that don't format-check.
    return f"mcp-trust-dummy-{_FAKE_PAYLOAD}"


def build_dummy_env(env_keys: list[str]) -> dict[str, str]:
    """Map each required env var NAME to a non-functional dummy value.

    Returns an empty dict for an empty input. Values are placeholders only and
    must never be persisted to the catalog or a receipt.
    """
    return {key: _dummy_value(key) for key in env_keys if key}
