import os
from pathlib import Path

import exp_common


def test_version_present():
    assert isinstance(exp_common.__version__, str) and exp_common.__version__


def test_schemas_dir_env_override(monkeypatch, tmp_path):
    monkeypatch.setenv("EXP_SCHEMAS_DIR", str(tmp_path))
    assert exp_common.schemas_dir() == tmp_path


def test_schemas_dir_default_is_shared_schemas(monkeypatch):
    monkeypatch.delenv("EXP_SCHEMAS_DIR", raising=False)
    d = exp_common.schemas_dir()
    assert d.name in ("schemas",) and isinstance(d, Path)
    if not (Path(exp_common.__file__).parent / "schemas").is_dir():
        assert d == Path(__file__).resolve().parents[2] / "schemas"
        assert os.path.isdir(d)
