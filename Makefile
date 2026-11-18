.PHONY: setup check repro-check sbom

UV_CHECK = @command -v uv >/dev/null 2>&1 || { echo "uv is required; install it from https://docs.astral.sh/uv/" >&2; exit 127; }

setup:
	$(UV_CHECK)
	uv sync --frozen --extra dev

check:
	$(UV_CHECK)
	uv lock --check
	uv run --no-sync ruff check src scripts tests
	uv run --no-sync ruff format --check src scripts tests
	uv run --no-sync pyright
	uv run --no-sync pytest -q
	@set -e; \
	mkdir -p tmp; \
	build_dir=$$(mktemp -d 2>/dev/null || mktemp -d "$$(pwd)/tmp/mcp-trust-build.XXXXXX"); \
	trap 'python3 -c "import shutil, sys; shutil.rmtree(sys.argv[1])" "$$build_dir"' EXIT; \
	uv build --out-dir "$$build_dir"

# Build the committed source twice in fresh clones and compare SHA-256 of every artifact.
repro-check:
	$(UV_CHECK)
	python3 scripts/check_reproducible_build.py --build 'uv build --no-create-gitignore --out-dir {out}'

# CycloneDX SBOM of the locked runtime dependencies plus the engine extra.
sbom:
	$(UV_CHECK)
	uv export --preview-features sbom-export --format cyclonedx1.5 --locked --no-dev --extra engine --output-file mcp-trust.cdx.json
