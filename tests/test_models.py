"""Tests for core/models.py invariants.

Focused on the security-relevant ``Server.slug`` validator: a slug is both a URL
path component and a filesystem path component, so anything that is not strict
kebab-case must be refused at the trust boundary, before it can reach a path-join
in the static-site generator or a route in the API.
"""

from __future__ import annotations

from datetime import UTC, datetime

import pytest
from pydantic import ValidationError

from mcp_trust.core.models import Server, ServerSource, SourceKind


def _server(slug: str) -> Server:
    return Server(
        slug=slug,
        name="X",
        source=ServerSource(kind=SourceKind.NPM, reference="@x/y"),
        added_at=datetime.now(tz=UTC),
    )


@pytest.mark.parametrize("slug", ["mcp-reference-time", "alpha", "a", "x9", "no-such-slug"])
def test_valid_slugs_accepted(slug: str) -> None:
    assert _server(slug).slug == slug


@pytest.mark.parametrize(
    "slug",
    [
        "../etc/passwd",  # path traversal
        "..",  # parent ref
        "a/b",  # path separator
        "a\\b",  # windows separator
        "UPPER",  # not url-safe lowercase
        "with space",  # whitespace
        "trailing-",  # must end alphanumeric
        "-leading",  # must start alphanumeric
        "",  # empty
        "dot.in.slug",  # dots disallowed (could enable '..')
        "a--b",  # empty group between dashes
    ],
)
def test_unsafe_slugs_rejected(slug: str) -> None:
    with pytest.raises(ValidationError):
        _server(slug)
