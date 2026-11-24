#!/usr/bin/env bash
# Build images if missing, deploy the topology, then bring the clients onto their VLANs.
source "$(dirname "$0")/common.sh"
command -v containerlab >/dev/null || die "containerlab is not installed"
docker image inspect vrnetlab/aruba_arubaos-cx:20250822141147 >/dev/null 2>&1 || die "AOS-CX image vrnetlab/aruba_arubaos-cx:20250822141147 not found"
docker image inspect quay.io/frrouting/frr:9.1.0 >/dev/null 2>&1 || die "FRR image quay.io/frrouting/frr:9.1.0 not found"
for img in cr-lab/host:1 cr-lab/client:1; do
  docker image inspect "$img" >/dev/null 2>&1 || { say "$img missing: building"; "$LAB_DIR/scripts/build-images.sh"; break; }
done
cd "$LAB_DIR"
# fails cleanly if 172.31.250.0/24 (cr-lab-mgmt) overlaps an existing docker network
sudo containerlab deploy -t cr-lab.clab.yml
say "waiting for the AOS-CX to boot (5-10 min on first start)..."
"$LAB_DIR/scripts/net-up.sh"
say ""
say "Lab up. Next: put enrol tokens in $LAB_DIR/tokens.env and run scripts/enrol.sh (see README)."
