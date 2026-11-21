# agent/ developer targets. Run from the repo root as `make -C agent <target>`.
PY ?= ../.venv/bin/python
RUFF ?= ../.venv/bin/ruff

.PHONY: test lint container-test
test:
	$(PY) -m pytest tests -q

lint:
	$(RUFF) check .

# Acceptance tests in systemd containers (needs Docker with privileged containers; ~10-15 minutes).
# EXP_CONTAINER_UBUNTU=24.04 limits the OS matrix (default 24.04,22.04,debian12); EXP_DIST_DIR=<dist with built release> also runs the
# "all shapes converge" test (06-agent.md section 9 item 2); without it that test is skipped.
container-test:
	EXP_CONTAINER_TESTS=1 $(PY) -m pytest tests/container -q -ra -m "harness and not internet" -p no:cacheprovider
