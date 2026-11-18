# Releasing mcp-trust to PyPI

Releases publish only through `.github/workflows/publish.yml` on a `v*` tag,
using PyPI trusted publishing. The PyPI trusted publisher is bound to
repository `saagpatel/mcp-trust`, workflow `publish.yml` and environment `pypi`;
renaming the file or the environment breaks publishing. There is no token or
manual upload path.

## What the workflow does

1. `build` (read-only): checks the tag against `pyproject.toml`, runs
   `make setup && make check`, builds the wheel and sdist, rebuilds both from a
   fresh clone of the tagged commit and fails unless the SHA-256 digests match
   (`scripts/check_reproducible_build.py`), and writes a CycloneDX SBOM of the
   locked runtime dependencies plus the `engine` extra with
   `uv export --format cyclonedx1.5`.
2. `attest`: signs a SLSA build provenance attestation and an SBOM attestation
   for both files with `actions/attest` (Sigstore, stored on this repository).
3. `publish` (`pypi` environment): uploads the exact bytes from `build`;
   `gh-action-pypi-publish` adds PEP 740 publish attestations.

`.github/workflows/supply-chain.yml` runs the same reproducibility and SBOM
steps on every pull request without any publishing permission.

## Verifying a release

```bash
# PEP 740 publish attestation on PyPI
uvx pypi-attestations verify pypi --repository https://github.com/saagpatel/mcp-trust \
  pypi:mcp_trust-X.Y.Z-py3-none-any.whl

# GitHub build provenance and SBOM attestations (releases after this workflow)
gh attestation verify mcp_trust-X.Y.Z-py3-none-any.whl --repo saagpatel/mcp-trust
gh attestation verify mcp_trust-X.Y.Z-py3-none-any.whl --repo saagpatel/mcp-trust \
  --predicate-type https://cyclonedx.org/bom

# Local reproducibility check of the committed source
make repro-check
```

## Reproducing an older release

Build its tag with the hatchling version recorded in the wheel's `WHEEL` file
(`Generator:` line). For 0.1.1 that is hatchling 1.30.1:

```bash
echo "hatchling==1.30.1" > /tmp/hatchling.txt
uv build --build-constraints /tmp/hatchling.txt
```

The wheel then matches PyPI byte for byte. The sdist's uncompressed tar matches,
but the gzip stream depends on the zlib build of the machine that compressed
it, so compare a macOS rebuild with `gzip -dc` rather than by file digest.
Two builds on the same runner image match exactly.
