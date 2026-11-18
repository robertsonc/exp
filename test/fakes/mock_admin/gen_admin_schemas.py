#!/usr/bin/env python3
"""Regenerate admin_schemas.json from shared/openapi/admin.yaml (dev tooling; needs PyYAML).

The mock validates request bodies with the stdlib subset validator (exp_common.config), which cannot read
YAML and only understands local ``#/$defs/...`` refs plus plain schema-file refs. This script copies every
``components.schemas`` entry into one JSON document, rewriting refs:

    #/components/schemas/X                    -> #/$defs/X
    ../schemas/common.schema.json#/$defs/ts   -> common.schema.json#/$defs/ts

``test_mock_admin.py`` fails when the committed file differs from a fresh generation.
"""
from __future__ import annotations

import json
import re
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
ADMIN_YAML = HERE.parents[2] / "shared" / "openapi" / "admin.yaml"
OUT = HERE / "admin_schemas.json"


def convert(node):
    if isinstance(node, dict):
        out = {}
        for k, v in node.items():
            if k.startswith("x-"):
                continue
            if k == "$ref" and isinstance(v, str):
                v = re.sub(r"^#/components/schemas/", "#/$defs/", v)
                v = re.sub(r"^\.\./schemas/", "", v)
            out[k] = convert(v)
        return out
    if isinstance(node, list):
        return [convert(x) for x in node]
    return node


def generate() -> dict:
    import yaml  # dev-only dependency, imported lazily so the module loads without PyYAML

    doc = yaml.safe_load(ADMIN_YAML.read_text("utf-8"))
    return {k: convert(v) for k, v in sorted(doc["components"]["schemas"].items())}


def main() -> int:
    OUT.write_text(json.dumps(generate(), indent=1, sort_keys=True) + "\n", "utf-8")
    print(f"wrote {OUT}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
