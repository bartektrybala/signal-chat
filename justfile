pre-commit hook="":
    pre-commit run {{hook}} --all-files --show-diff-on-failure

mypy:
	uv run mypy .

test:
    uv run pytest -v --tb=short
