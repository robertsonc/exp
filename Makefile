# exp root Makefile. Every target succeeds on a partially-built repo:
# absent components are skipped with a note.
PY ?= .venv/bin/python
RUFF ?= .venv/bin/ruff
VERSION ?= $(shell cat VERSION)
COMPONENTS := probe collector dashboard agent runner
# Product directories that exist (linted when present).
LINT_DIRS := $(wildcard shared/python probe collector dashboard agent runner test packaging)

.PHONY: venv lint test test-shared $(addprefix test-,$(COMPONENTS)) manager-test build release dev help

help:
	@echo "targets: venv lint test test-shared test-{$(COMPONENTS)} manager-test build release dev"

venv:
	uv venv --python 3.10 .venv
	uv pip install --python .venv/bin/python pytest hypothesis ruff jsonschema pyyaml openapi-spec-validator

lint:
	@if [ -z "$(LINT_DIRS)" ]; then echo "lint: nothing to lint"; else \
	  echo "ruff check $(LINT_DIRS)"; $(RUFF) check $(LINT_DIRS); fi

# pytest exit 5 = no tests collected: not a failure on a partial repo.
define RUN_PYTEST
@set -u; dirs=""; for d in $(1); do [ -d "$$d" ] && dirs="$$dirs $$d"; done; \
if [ -z "$$dirs" ]; then echo "$(2): no test directories yet, skipped"; else \
  $(PY) -m pytest $$dirs -q; rc=$$?; \
  if [ $$rc -eq 5 ]; then echo "$(2): no tests collected, skipped"; rc=0; fi; exit $$rc; fi
endef

test-shared:
	$(call RUN_PYTEST,shared/python/tests shared/openapi test/fixtures test/fakes,shared)

$(addprefix test-,$(COMPONENTS)): test-%:
	$(call RUN_PYTEST,$*/tests,$*)

test: test-shared $(addprefix test-,$(COMPONENTS))

manager-test:
	@if [ -f manager/package.json ]; then cd manager && npm test; \
	else echo "manager-test: manager/package.json absent, skipped"; fi

build:
	@if [ -x packaging/build.sh ]; then packaging/build.sh; \
	else echo "build: packaging/build.sh not present yet (WP-7); nothing to build"; fi

# usage: make release VERSION=x.y.z
release:
	@if [ -x packaging/release.sh ]; then packaging/release.sh "$(VERSION)"; \
	elif [ -x packaging/build.sh ]; then packaging/build.sh --release "$(VERSION)"; \
	else echo "release: packaging scripts not present yet (WP-7); VERSION=$(VERSION)"; fi

dev:
	@echo "exp dev stack (real wiring lands with the components):"
	@echo "  collector : $(PY) -m collector      (see collector/README.md)"
	@echo "  dashboard : $(PY) -m dashboard      (see dashboard/README.md)"
	@echo "  manager   : cd manager && npm run dev"
	@echo "  tests     : make test"
