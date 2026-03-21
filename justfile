pre-commit hook="":
    pre-commit run {{hook}} --all-files --show-diff-on-failure

ty:
	uv run ty check

test:
    uv run pytest -v --tb=short

check: pre-commit ty test
	echo "Check finished successfully!"
