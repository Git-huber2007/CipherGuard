.PHONY: install test lint serve demo lock

install:
	pip install -r requirements.txt
	pip install -e ".[dev]"

test:
	python -m pytest tests/ -q

lint:
	ruff check .

serve:
	python -m cipherguard serve

# Regenerate the static dashboard in docs/
demo:
	python -m cipherguard lab
	python -m cipherguard train
	python -m cipherguard export-demo --out docs

# Re-pin requirements.lock from pyproject.toml
lock:
	uv pip compile pyproject.toml --extra api --universal --python-version 3.10 \
		--custom-compile-command "make lock" -o requirements.lock
