"""Every measurement fixture agrees with the Python reference (ingest mode)."""
import json
from pathlib import Path

import pytest

from exp_common.schema import Measurement

FIX = Path(__file__).resolve().parents[3] / "test" / "fixtures"


def test_measurement_fixtures_match_expectation():
    idx = FIX / "INDEX.json"
    if not idx.exists():
        pytest.skip("test/fixtures/INDEX.json not present yet")
    n = 0
    for rel, meta in sorted(json.loads(idx.read_text()).items()):
        if meta["schema"] != "measurement.schema.json":
            continue
        doc = json.loads((FIX / rel).read_text())
        try:
            Measurement.from_dict(doc, require_id=True)
            accepted = True
        except ValueError:
            accepted = False
        assert accepted == (meta["expected"] == "valid"), rel
        n += 1
    assert n > 0
