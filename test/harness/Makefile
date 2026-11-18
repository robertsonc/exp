# Container LAN harness (WP-8). Needs Docker with privileged containers (systemd as PID 1, cgroupns=host).
#   make up [LAYOUT=all|split]   start the simulated event LAN + exp hosts       (see README.md)
#   make down                    remove every harness container and network
#   make shell [HOST=h1]         shell in a host (default: first) or `net`
#   make ci                      build, run the M1 acceptance suite (test/e2e/m1), always clean up
#   make lanctl ARGS="block-dns h1-tp0"   the fault API
ROOT := $(abspath ../..)
PY ?= $(ROOT)/.venv/bin/python
LAYOUT ?= all
HOST ?=
ARTIFACTS ?= $(ROOT)/test/e2e/.artifacts

.PHONY: up down shell build status ci lanctl

build:
	./harness.sh build

up:
	./harness.sh up $(LAYOUT)

down:
	./harness.sh down

status:
	./harness.sh status

shell:
	./harness.sh shell $(HOST)

lanctl:
	./harness.sh lanctl $(ARGS)

# The suite builds its own throwaway-key release unless EXP_E2E_DIST + EXP_E2E_PUBKEY point at one.
ci: build
	@mkdir -p "$(ARTIFACTS)"; rc=0; \
	EXP_E2E_ARTIFACTS="$(ARTIFACTS)" $(PY) -m pytest $(ROOT)/test/e2e/m1 -q -rA -p no:cacheprovider \
	    --junitxml="$(ARTIFACTS)/m1-junit.xml" || rc=$$?; \
	./harness.sh down; exit $$rc
