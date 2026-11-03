.PHONY: setup check

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
