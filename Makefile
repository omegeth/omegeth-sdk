# Checks. Run from the repository root.
#   make check    Python always; JavaScript where Node 20+ is installed (always in CI)

PYTHON ?= python3

.PHONY: check check-python check-js

check: check-python check-js

check-python:
	$(PYTHON) -m unittest discover -s tests -v

check-js:
	@if command -v node >/dev/null; then node tests/test_sdk.js; \
	elif [ -n "$$CI" ]; then echo "FAIL: node is required in CI"; exit 1; \
	else echo "SKIP check-js: node not installed"; fi
