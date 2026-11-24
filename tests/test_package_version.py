from importlib.metadata import version

import mcp_trust


def test_runtime_version_matches_distribution() -> None:
    assert mcp_trust.__version__ == version("mcp-trust")
