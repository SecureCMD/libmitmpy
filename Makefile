.PHONY: env install install-dev test

install:
	pip install -e .

install-dev:
	pip install -e ".[dev]"

test:
	pytest

mitm:
	sudo python examples/mitm/main.py

viewer:
	python examples/viewer/main.py