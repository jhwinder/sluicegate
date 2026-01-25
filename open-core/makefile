SHELL := /bin/bash
.ONESHELL:
.SHELLFLAGS := -eu -o pipefail -c

PYTHON ?= python3.11
PKG ?= sg-core
VERSION ?= 0.1.3

.PHONY: help venv tools clean build check-dist test-upload test-verify prod-upload

help:
	@echo "Targets:"
	@echo "  make venv         - create .venv with uv"
	@echo "  make tools        - install build + twine into venv"
	@echo "  make clean        - remove dist/"
	@echo "  make build        - build sdist + wheel into dist/"
	@echo "  make test-upload  - upload dist/* to TestPyPI (prompts for token)"
	@echo "  make test-verify  - install pinned version from TestPyPI (uses extra-index-url)"
	@echo "  make prod-upload  - upload dist/* to PyPI (prompts for token)"
	@echo ""
	@echo "Vars: PYTHON=$(PYTHON) PKG=$(PKG) VERSION=$(VERSION)"

venv:
	uv venv --python $(PYTHON)
	@echo "Run: source .venv/bin/activate"

tools:
	uv pip install -U build twine

clean:
	rm -rf dist

build: clean
	uv run python -m build
	@echo "Built artifacts:"
	@ls -lh dist

check-dist:
	@test -d dist && ls dist/* >/dev/null

test-upload: build
	@echo "Uploading to TestPyPI..."
	@export TWINE_USERNAME="__token__"; \
	read -s -p "TestPyPI token: " TWINE_PASSWORD; echo; \
	export TWINE_PASSWORD="$$TWINE_PASSWORD"; \
	uv run python -m twine upload --repository testpypi dist/*

test-verify:
	@echo "Verifying install from TestPyPI..."
	uv pip install --index-url https://test.pypi.org/simple/ --extra-index-url https://pypi.org/simple $(PKG)==$(VERSION) -v
	@echo "Installed $(PKG)==$(VERSION)"

prod-upload: build
	@echo "Uploading to PyPI..."
	@export TWINE_USERNAME="__token__"; \
	read -s -p "PyPI token: " TWINE_PASSWORD; echo; \
	export TWINE_PASSWORD="$$TWINE_PASSWORD"; \
	uv run python -m twine upload dist/*

