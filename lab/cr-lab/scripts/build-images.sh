#!/usr/bin/env bash
# Build the two lab images (cr-lab/host:1, cr-lab/client:1). Re-run after editing images/.
source "$(dirname "$0")/common.sh"
docker build -t cr-lab/host:1 "$LAB_DIR/images/host"
docker build -t cr-lab/client:1 "$LAB_DIR/images/client"
say "built: $(docker images --format '{{.Repository}}:{{.Tag}}' | grep '^cr-lab/' | tr '\n' ' ')"
