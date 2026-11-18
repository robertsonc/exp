#!/usr/bin/env bash
# Create the dev/test virtualenv (.venv) for CI with a chosen Python (default 3.10). Mirrors `make venv`
# (which pins 3.10) plus dnspython 2.9.2 so the probe tests can import the vendored dependency's twin.
# Dev tooling only: nothing installed here is shipped in a tarball.
set -euo pipefail
py="${1:-3.10}"
cd "$(dirname "${BASH_SOURCE[0]}")/.."
uv venv --python "$py" .venv
uv pip install --python .venv/bin/python pytest hypothesis ruff jsonschema referencing pyyaml openapi-spec-validator
# dnspython 2.9.x declares requires_python>=3.11; exp vendors it on 3.10 deliberately (see vendor.lock note), so
# resolve it as for 3.11 — test_dnspython_compat.py then proves every module imports on the real interpreter.
uv pip install --python .venv/bin/python --python-version 3.11 --no-deps "dnspython==2.9.2"
