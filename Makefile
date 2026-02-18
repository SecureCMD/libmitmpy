.PHONY: env install install-dev test

install:
	pip install -e .

install-dev:
	pip install -e ".[dev]"

test:
	pytest

mitm:
	python examples/mitm/main.py