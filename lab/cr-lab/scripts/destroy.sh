#!/usr/bin/env bash
# Tear the lab down. Hosts stay listed in the manager: decommission them there (Hosts -> host -> Decommission).
source "$(dirname "$0")/common.sh"
cd "$LAB_DIR"
sudo containerlab destroy -t cr-lab.clab.yml --cleanup
